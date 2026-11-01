package main

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Release index and policy payloads. Field sets mirror the client's strict schemas in
// desktop/core/update.go (ReleaseIndex, Artifact) and desktop/core/schema.go (Policy).

type Links struct {
	Website string `json:"website"`
	Renew   string `json:"renew"`
	Help    string `json:"help"`
}
type Brand struct {
	ProductID   string   `json:"productId"`
	Name        string   `json:"name"`
	Environment string   `json:"environment"`
	Channel     string   `json:"channel"`
	EndpointIDs []string `json:"endpointIds"`
	Links       Links    `json:"links"`
}
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

// Download is everything shown on the download page, including DMGs the updater does not use.
type Download struct {
	File     string `json:"file"`
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
	Format   string `json:"format"`
	Bytes    int64  `json:"bytes"`
	SHA256   string `json:"sha256"`
	Signed   bool   `json:"signed"`
}
type RuleResource struct {
	ID        string `json:"id"`
	Version   int64  `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}
type ReleaseState struct {
	Sequence     int64      `json:"sequence"`
	Version      string     `json:"version"`
	PublishedAt  string     `json:"publishedAt"`
	Artifacts    []Artifact `json:"artifacts"`
	Downloads    []Download `json:"downloads"`
	WithdrawnIDs []string   `json:"withdrawnIds"`
	Envelope     string     `json:"envelope"`
	SignedAt     string     `json:"signedAt"`
}
type PolicyState struct {
	Version   int64         `json:"version"`
	Rules     *RuleResource `json:"rules"`
	Envelope  string        `json:"envelope"`
	SignedAt  string        `json:"signedAt"`
	ExpiresAt string        `json:"expiresAt"`
}

const (
	releaseValidity = 24 * time.Hour
	policyValidity  = 72 * time.Hour
	// Re-sign a policy once less than this remains, so rule descriptors change about daily.
	policyRenew = 48 * time.Hour
	skew        = 5 * time.Minute
	// Clients keep using their last full sync for up to this long when the panel API
	// is unreachable; the client caps it at the same seven days.
	maxSnapshotAgeSec = 7 * 24 * 3600
)

func iso(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// nextSequence is monotonic: the client rejects an equal sequence with different bytes.
func nextSequence(previous int64, now time.Time) int64 { return max(previous+1, now.Unix()) }

func releasePayload(brand Brand, sequence int64, artifacts []Artifact, withdrawn []string, now time.Time) map[string]any {
	return map[string]any{
		"schemaVersion": 1, "productId": brand.ProductID, "environment": brand.Environment, "channel": brand.Channel,
		"issuedAt": iso(now.Add(-skew)), "expiresAt": iso(now.Add(releaseValidity)),
		"releaseSequence": sequence, "artifacts": artifacts, "withdrawnIds": withdrawn,
	}
}

func policyPayload(brand Brand, version int64, rules *RuleResource, now time.Time) (map[string]any, string) {
	issued, expires := iso(now.Add(-skew)), iso(now.Add(policyValidity))
	var resource any
	if rules != nil {
		// A rule descriptor may not outlive the policy that carries it.
		r := *rules
		r.ExpiresAt = expires
		resource = r
	}
	return map[string]any{
		"schemaVersion": 2, "policyVersion": version, "productId": brand.ProductID, "environment": brand.Environment, "channel": brand.Channel,
		"issuedAt": issued, "notBefore": issued, "expiresAt": expires, "requiredCapabilities": []string{},
		"endpoints":      map[string]any{"orderedIds": brand.EndpointIDs, "temporarilyDisabledIds": []string{}},
		"refresh":        map[string]any{"subscriptionIntervalSec": 1800, "accountIntervalSec": 300, "policyIntervalSec": 900, "maxSnapshotAgeSec": maxSnapshotAgeSec},
		"ui":             map[string]any{"expiryReminderDays": []int{7, 3}, "showTrafficSummary": true, "announcement": nil},
		"links":          brand.Links,
		"nodeOperations": []any{},
		"routing":        map[string]any{"templateId": "cn-direct-default-proxy-v1", "dnsTemplateId": "real-dns-split-v1", "resource": resource},
		"maintenance":    nil,
		"update":         map[string]any{"checkIntervalSec": 21600, "noticeText": nil},
	}, expires
}

// ---- Admin input validation (the CI publish step is the only caller) ----

var (
	hex64       = regexp.MustCompile(`^[a-f0-9]{64}$`)
	semver      = regexp.MustCompile(`^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$`)
	fileKey     = regexp.MustCompile(`^(releases|rules)/[A-Za-z0-9._-]{1,64}/[A-Za-z0-9._-]{1,160}$`)
	productID   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)
	endpointID  = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	minimumOS   = regexp.MustCompile(`^\d+(?:\.\d+){0,3}$`)
	coreVersion = regexp.MustCompile(`^[0-9A-Za-z.+-]{1,64}$`)
	formats     = map[string][]string{"win32": {"nsis"}, "linux": {"deb"}, "darwin": {"dmg", "zip"}}
)

type inputError string

func (e inputError) Error() string { return string(e) }
func check(ok bool, field string) {
	if !ok {
		panic(inputError(field))
	}
}

// validate converts check panics into an error for the admin handler.
func validate(f func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if e, ok := r.(inputError); ok {
				err = e
				return
			}
			panic(r)
		}
	}()
	f()
	return nil
}

func httpsURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Host != ""
}

func (b Brand) check() {
	check(productID.MatchString(b.ProductID), "brand.productId")
	check(utf8.RuneCountInString(b.Name) > 0 && utf8.RuneCountInString(b.Name) <= 64, "brand.name")
	check((b.Environment == "production" || b.Environment == "test") && (b.Environment == "production") == (b.Channel == "stable") && (b.Channel == "stable" || b.Channel == "test"), "brand.environment/channel")
	check(len(b.EndpointIDs) > 0 && len(b.EndpointIDs) <= 8, "brand.endpointIds")
	for _, id := range b.EndpointIDs {
		check(endpointID.MatchString(id), "brand.endpointIds")
	}
	check(httpsURL(b.Links.Website) && httpsURL(b.Links.Renew) && httpsURL(b.Links.Help), "brand.links")
}

type PublishedFile struct {
	Key               string `json:"key"`
	Platform          string `json:"platform"`
	Arch              string `json:"arch"`
	Format            string `json:"format"`
	Bytes             int64  `json:"bytes"`
	SHA256            string `json:"sha256"`
	UnpackedBytes     int64  `json:"unpackedBytes"`
	MinimumOS         string `json:"minimumOS"`
	CoreVersion       string `json:"coreVersion"`
	CoreSHA256        string `json:"coreSha256"`
	SignatureIdentity string `json:"signatureIdentity"`
}
type releaseInput struct {
	Brand   Brand           `json:"brand"`
	Version string          `json:"version"`
	Files   []PublishedFile `json:"files"`
}

func (r releaseInput) check() {
	r.Brand.check()
	check(semver.MatchString(r.Version), "version")
	check(len(r.Files) > 0 && len(r.Files) <= 16, "files")
	seen := map[string]bool{}
	for i, f := range r.Files {
		at := fmt.Sprintf("files[%d]", i)
		check(fileKey.MatchString(f.Key) && strings.HasPrefix(f.Key, "releases/"+r.Version+"/"), at+".key")
		check(slices.Contains(formats[f.Platform], f.Format) && (f.Arch == "x64" || f.Arch == "arm64") && (f.Platform == "darwin" || f.Arch == "x64"), at+".platform/arch/format")
		check(f.Bytes > 0 && f.Bytes <= 2147483648 && f.UnpackedBytes > 0 && f.UnpackedBytes <= 1<<53, at+".bytes")
		check(hex64.MatchString(f.SHA256) && hex64.MatchString(f.CoreSHA256), at+".sha256")
		check(minimumOS.MatchString(f.MinimumOS), at+".minimumOS")
		check(coreVersion.MatchString(f.CoreVersion), at+".coreVersion")
		check(len(f.SignatureIdentity) > 0 && len(f.SignatureIdentity) <= 256, at+".signatureIdentity")
		target := f.Platform + "-" + f.Arch + "-" + f.Format
		check(!seen[target], "duplicate platform/arch/format")
		seen[target] = true
	}
}

type rulesInput struct {
	Key    string `json:"key"`
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

func (r rulesInput) check() {
	check(fileKey.MatchString(r.Key) && strings.HasPrefix(r.Key, "rules/"), "key")
	check(hex64.MatchString(r.SHA256), "sha256")
	check(r.Bytes > 0 && r.Bytes <= 33554432, "bytes")
}

// releaseArtifacts are the updater entries: the client installs NSIS, DEB and (on
// macOS) ZIP; DMGs are download-page only.
func releaseArtifacts(origin, version string, files []PublishedFile) []Artifact {
	out := []Artifact{}
	for _, f := range files {
		if f.Format == "dmg" {
			continue
		}
		out = append(out, Artifact{ID: f.Platform + "-" + f.Arch + "-" + f.Format + "-" + version, Version: version, Platform: f.Platform, Arch: f.Arch, Format: f.Format, MinimumOS: f.MinimumOS, URL: origin + "/files/" + f.Key, Bytes: f.Bytes, SHA256: f.SHA256, UnpackedBytes: f.UnpackedBytes, BackupBytes: f.UnpackedBytes, CoreVersion: f.CoreVersion, CoreSHA256: f.CoreSHA256, HelperProtocol: 1, SignatureIdentity: f.SignatureIdentity})
	}
	return out
}
