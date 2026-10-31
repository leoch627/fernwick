package core

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const releaseSafeInteger int64 = 9007199254740991

type Artifact struct {
	ID                string `json:"id"`
	Version           string `json:"version"`
	Platform          string `json:"platform"`
	Arch              string `json:"arch"`
	Format            string `json:"format"`
	MinimumOS         string `json:"minimumOS"`
	URL               string `json:"url"`
	Bytes             int64  `json:"bytes"`
	SHA256            string `json:"sha256"`
	UnpackedBytes     int64  `json:"unpackedBytes"`
	BackupBytes       int64  `json:"backupBytes"`
	CoreVersion       string `json:"coreVersion"`
	CoreSHA256        string `json:"coreSha256"`
	HelperProtocol    int    `json:"helperProtocol"`
	SignatureIdentity string `json:"signatureIdentity"`
}

var artifactIDPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,160}$`)
var artifactHashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

func releaseTextLength(raw string, min, max int) bool {
	return boundedText(raw, min, max)
}

func (a Artifact) Validate() error {
	_, versionOK := parseReleaseVersion(a.Version)
	if !artifactIDPattern.MatchString(a.ID) || !versionOK ||
		(a.Platform != "win32" && a.Platform != "darwin" && a.Platform != "linux") ||
		(a.Arch != "x64" && a.Arch != "arm64") ||
		(a.Format != "nsis" && a.Format != "dmg" && a.Format != "zip" && a.Format != "deb") ||
		!releaseTextLength(a.MinimumOS, 1, 100) || !validURL(a.URL) ||
		a.Bytes < 1 || a.Bytes > 2147483648 || !artifactHashPattern.MatchString(a.SHA256) ||
		a.UnpackedBytes < 1 || a.UnpackedBytes > releaseSafeInteger || a.BackupBytes < 0 || a.BackupBytes > releaseSafeInteger ||
		!releaseTextLength(a.CoreVersion, 1, 64) || !artifactHashPattern.MatchString(a.CoreSHA256) ||
		a.HelperProtocol != 1 || !releaseTextLength(a.SignatureIdentity, 1, 256) {
		return NewAppError("UPDATE_VERIFY_FAILED")
	}
	return nil
}

type ReleaseIndex struct {
	SchemaVersion   int        `json:"schemaVersion"`
	ProductID       string     `json:"productId"`
	Environment     string     `json:"environment"`
	Channel         string     `json:"channel"`
	IssuedAt        string     `json:"issuedAt"`
	ExpiresAt       string     `json:"expiresAt"`
	ReleaseSequence int64      `json:"releaseSequence"`
	Artifacts       []Artifact `json:"artifacts"`
	WithdrawnIDs    []string   `json:"withdrawnIds"`
}

func (r ReleaseIndex) Validate() error {
	if r.SchemaVersion != 1 || (r.Environment != "test" && r.Environment != "production") ||
		(r.Channel != "test" && r.Channel != "stable") || !validUTC(r.IssuedAt) || !validUTC(r.ExpiresAt) ||
		r.ReleaseSequence < 1 || r.ReleaseSequence > releaseSafeInteger || len(r.Artifacts) > 32 || len(r.WithdrawnIDs) > 1024 {
		return NewAppError("UPDATE_VERIFY_FAILED")
	}
	for _, artifact := range r.Artifacts {
		if err := artifact.Validate(); err != nil {
			return err
		}
	}
	for _, id := range r.WithdrawnIDs {
		if !releaseTextLength(id, 0, 160) {
			return NewAppError("UPDATE_VERIFY_FAILED")
		}
	}
	return nil
}

type VerifiedRelease struct {
	Index     ReleaseIndex
	Watermark Watermark
	Unchanged bool
}

func VerifyRelease(raw string, build BuildConfig, current *Watermark, now int64) (VerifiedRelease, error) {
	invalid := NewAppError("UPDATE_VERIFY_FAILED")
	verified, err := VerifyEnvelope(raw, build.UpdateKeys, "v2board-client-release-v1")
	if err != nil {
		return VerifiedRelease{}, invalid
	}
	var index ReleaseIndex
	if err := DecodeStrict(verified.Payload, &index, signedJSONMaxBytes); err != nil {
		return VerifiedRelease{}, invalid
	}
	if index.ProductID != build.ProductID || index.Environment != build.Environment || index.Channel != build.Channel {
		return VerifiedRelease{}, invalid
	}
	issued, e1 := signedTime(index.IssuedAt)
	expires, e2 := signedTime(index.ExpiresAt)
	if e1 != nil || e2 != nil || issued > now+120000 || expires <= now || expires <= issued {
		return VerifiedRelease{}, invalid
	}
	ids := make(map[string]bool, len(index.Artifacts))
	for _, artifact := range index.Artifacts {
		if ids[artifact.ID] {
			return VerifiedRelease{}, invalid
		}
		ids[artifact.ID] = true
		if _, err := TrustedURL(artifact.URL, build.TrustedUpdateOrigins); err != nil {
			return VerifiedRelease{}, invalid
		}
		if artifact.Platform == "win32" && (artifact.Arch != "x64" || artifact.Format != "nsis") ||
			artifact.Platform == "linux" && (artifact.Arch != "x64" || artifact.Format != "deb") ||
			artifact.Platform == "darwin" && artifact.Format != "dmg" && artifact.Format != "zip" {
			return VerifiedRelease{}, invalid
		}
	}
	watermark := Watermark{Version: index.ReleaseSequence, Hash: verified.Hash}
	unchanged, err := CheckWatermark(current, watermark)
	if err != nil {
		return VerifiedRelease{}, invalid
	}
	return VerifiedRelease{Index: index, Watermark: watermark, Unchanged: unchanged}, nil
}

type UpdateTarget struct {
	Platform     string
	Arch         string
	Version      string
	OSCompatible func(minimum string) bool
}

func SelectUpdate(index ReleaseIndex, target UpdateTarget) *Artifact {
	current, ok := parseReleaseVersion(target.Version)
	if !ok || target.OSCompatible == nil {
		return nil
	}
	withdrawn := make(map[string]bool, len(index.WithdrawnIDs))
	for _, id := range index.WithdrawnIDs {
		withdrawn[id] = true
	}
	type candidate struct {
		artifact Artifact
		version  releaseVersion
	}
	available := make([]candidate, 0, len(index.Artifacts))
	for _, artifact := range index.Artifacts {
		version, ok := parseReleaseVersion(artifact.Version)
		if ok && artifact.Platform == target.Platform && artifact.Arch == target.Arch &&
			(artifact.Platform != "darwin" || artifact.Format == "zip") && !withdrawn[artifact.ID] &&
			compareReleaseVersion(version, current) > 0 && target.OSCompatible(artifact.MinimumOS) {
			available = append(available, candidate{artifact: artifact, version: version})
		}
	}
	if len(available) == 0 {
		return nil
	}
	sort.SliceStable(available, func(i, j int) bool { return compareReleaseVersion(available[i].version, available[j].version) > 0 })
	return &available[0].artifact
}

// Match the strict semver package used by the TypeScript client: optional v,
// three safe integer components, no leading zeroes, and SemVer prerelease order.
type releaseVersion struct {
	main [3]int64
	pre  []string
}

var releaseVersionPattern = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$`)
var releaseNumericIdentifier = regexp.MustCompile(`^[0-9]+$`)

func parseReleaseVersion(raw string) (releaseVersion, bool) {
	var version releaseVersion
	if !releaseTextLength(raw, 1, 256) {
		return version, false
	}
	parts := releaseVersionPattern.FindStringSubmatch(jsTrim(raw))
	if parts == nil {
		return version, false
	}
	for i := range version.main {
		value, err := strconv.ParseInt(parts[i+1], 10, 64)
		if err != nil || value > releaseSafeInteger {
			return releaseVersion{}, false
		}
		version.main[i] = value
	}
	if parts[4] != "" {
		version.pre = strings.Split(parts[4], ".")
		for _, part := range version.pre {
			if releaseNumericIdentifier.MatchString(part) && len(part) > 1 && part[0] == '0' {
				return releaseVersion{}, false
			}
		}
	}
	return version, true
}

func compareReleaseVersion(a, b releaseVersion) int {
	for i := range a.main {
		if a.main[i] < b.main[i] {
			return -1
		}
		if a.main[i] > b.main[i] {
			return 1
		}
	}
	if len(a.pre) == 0 && len(b.pre) > 0 {
		return 1
	}
	if len(a.pre) > 0 && len(b.pre) == 0 {
		return -1
	}
	for i := 0; i < max(len(a.pre), len(b.pre)); i++ {
		if i >= len(a.pre) {
			return -1
		}
		if i >= len(b.pre) {
			return 1
		}
		x, y := a.pre[i], b.pre[i]
		if x == y {
			continue
		}
		xNumeric, yNumeric := releaseNumericIdentifier.MatchString(x), releaseNumericIdentifier.MatchString(y)
		if xNumeric && yNumeric {
			// npm compares numeric prerelease identifiers as JavaScript Numbers.
			xNumber, _ := strconv.ParseFloat(x, 64)
			yNumber, _ := strconv.ParseFloat(y, 64)
			if xNumber < yNumber {
				return -1
			}
			if xNumber > yNumber {
				return 1
			}
			// Distinct numeric strings that round to the same Number end the
			// comparison in npm semver, even when more identifiers follow.
			return 0
		}
		if xNumeric || !yNumeric && x < y {
			return -1
		}
		return 1
	}
	return 0
}

var osVersionPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}$`)

func OSVersionAtLeast(actual, minimum string) bool {
	if !osVersionPattern.MatchString(actual) || !osVersionPattern.MatchString(minimum) {
		return false
	}
	a, b := strings.Split(actual, "."), strings.Split(minimum, ".")
	for i := 0; i < max(len(a), len(b)); i++ {
		var x, y float64
		if i < len(a) {
			x, _ = strconv.ParseFloat(a[i], 64)
		}
		if i < len(b) {
			y, _ = strconv.ParseFloat(b[i], 64)
		}
		if x > y {
			return true
		}
		if x < y {
			return false
		}
	}
	return true
}

type Battery struct {
	Percent  float64
	Charging bool
}

func AutomaticDownloadAllowed(metered *bool, battery *Battery) bool {
	return metered != nil && !*metered && battery != nil && (battery.Charging || battery.Percent >= 20)
}

func RequiredDiskBytes(artifact Artifact) int64 {
	return artifact.Bytes + artifact.UnpackedBytes + artifact.BackupBytes + 300*1024*1024
}

func VerifyArtifact(path string, artifact Artifact) error {
	invalid := NewAppError("UPDATE_VERIFY_FAILED")
	if artifact.Bytes < 1 || artifact.Bytes > 2147483648 {
		return invalid
	}
	file, err := os.Open(path)
	if err != nil {
		return invalid
	}
	defer file.Close()
	hash := sha256.New()
	length, err := io.Copy(hash, io.LimitReader(file, artifact.Bytes+1))
	if err != nil || length != artifact.Bytes || hex.EncodeToString(hash.Sum(nil)) != artifact.SHA256 {
		return invalid
	}
	return nil
}

func InstallationGate(artifact Artifact, index ReleaseIndex, now int64, networkClean bool) error {
	expires, err := signedTime(index.ExpiresAt)
	if err != nil || expires <= now {
		return NewAppError("UPDATE_VERIFY_FAILED")
	}
	for _, id := range index.WithdrawnIDs {
		if id == artifact.ID {
			return NewAppError("UPDATE_VERIFY_FAILED")
		}
	}
	found := false
	for _, candidate := range index.Artifacts {
		found = found || candidate.ID == artifact.ID && candidate.SHA256 == artifact.SHA256
	}
	if !found {
		return NewAppError("UPDATE_VERIFY_FAILED")
	}
	if !networkClean {
		return NewAppError("NETWORK_RECOVERY_REQUIRED")
	}
	return nil
}
