package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Envelope struct {
	KeyID     string `json:"keyId"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
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
type Release struct {
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
type Watermark struct {
	Version int64  `json:"version"`
	Hash    string `json:"hash"`
}
type UpdateJob struct {
	ID       string   `json:"id"`
	Artifact Artifact `json:"artifact"`
	Envelope string   `json:"envelope"`
	Path     string   `json:"path"`
	Owner    Peer     `json:"owner"`
	Created  int64    `json:"created"`
}

func newerVersion(next, current string) bool {
	parse := func(v string) ([]int, string) {
		v = strings.SplitN(v, "+", 2)[0]
		parts := strings.SplitN(v, "-", 2)
		numbers := strings.Split(parts[0], ".")
		if len(numbers) != 3 {
			return nil, ""
		}
		out := []int{}
		for _, n := range numbers {
			x, e := strconv.Atoi(n)
			if e != nil || x < 0 || x > 1000000 {
				return nil, ""
			}
			out = append(out, x)
		}
		pre := ""
		if len(parts) == 2 {
			pre = parts[1]
		}
		return out, pre
	}
	a, ap := parse(next)
	b, bp := parse(current)
	if a == nil || b == nil {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	if ap == "" || bp == "" {
		return ap == "" && bp != ""
	}
	return newerPrerelease(ap, bp)
}

// newerPrerelease orders pre-release tags per SemVer 2.0 §11, matching the client's semver.gt.
func newerPrerelease(next, current string) bool {
	x, y := strings.Split(next, "."), strings.Split(current, ".")
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] == y[i] {
			continue
		}
		xn, xe := strconv.Atoi(x[i])
		yn, ye := strconv.Atoi(y[i])
		switch {
		case xe == nil && ye == nil:
			return xn > yn
		case xe == nil:
			return false
		case ye == nil:
			return true
		default:
			return x[i] > y[i]
		}
	}
	return len(x) > len(y)
}
func verifiedRelease(raw, id string) (Artifact, Watermark, error) {
	invalid := func() (Artifact, Watermark, error) { return Artifact{}, Watermark{}, failure("UPDATE_VERIFY_FAILED") }
	var envelope Envelope
	if len(raw) > 262144 || strictJSON([]byte(raw), &envelope) != nil {
		return invalid()
	}
	key := build.UpdateKeys[envelope.KeyID]
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return invalid()
	}
	public, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return invalid()
	}
	ed, ok := public.(ed25519.PublicKey)
	if !ok {
		return invalid()
	}
	payload, e := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if e != nil {
		return invalid()
	}
	signature, e := base64.RawURLEncoding.DecodeString(envelope.Signature)
	if e != nil || !ed25519.Verify(ed, append([]byte("v2board-client-release-v1\n"), payload...), signature) {
		return invalid()
	}
	var index Release
	if strictJSON(payload, &index) != nil || index.SchemaVersion != 1 || index.ProductID != build.ProductID || index.Environment != build.Environment || index.Channel != build.Channel || index.ReleaseSequence < 1 || len(index.Artifacts) > 32 || contains(index.WithdrawnIDs, id) {
		return invalid()
	}
	issued, e1 := time.Parse(time.RFC3339Nano, index.IssuedAt)
	expires, e2 := time.Parse(time.RFC3339Nano, index.ExpiresAt)
	if e1 != nil || e2 != nil || issued.After(time.Now().Add(2*time.Minute)) || !expires.After(time.Now()) || !expires.After(issued) {
		return invalid()
	}
	h := sha256.Sum256(payload)
	watermark := Watermark{Version: index.ReleaseSequence, Hash: hex.EncodeToString(h[:])}
	var previous Watermark
	e = readJSON(filepath.Join(stateRoot(), "release-watermark.json"), &previous)
	if e != nil && !os.IsNotExist(e) {
		return invalid()
	}
	if previous.Version > watermark.Version || previous.Version == watermark.Version && previous.Hash != watermark.Hash {
		return invalid()
	}
	platform := targetOS()
	if platform == "windows" {
		platform = "win32"
	}
	target := strings.Split(targetID(), "-")
	seen := map[string]bool{}
	var selected *Artifact
	for i := range index.Artifacts {
		a := &index.Artifacts[i]
		if seen[a.ID] {
			return invalid()
		}
		seen[a.ID] = true
		if a.ID == id {
			selected = a
		}
	}
	if selected == nil {
		return invalid()
	}
	a := *selected
	if a.Platform != platform || a.Arch != target[1] || a.HelperProtocol != protocolVersion || !newerVersion(a.Version, build.Version) || !hex64.MatchString(a.SHA256) || !hex64.MatchString(a.CoreSHA256) || a.Bytes <= 0 || a.Bytes > 2*1024*1024*1024 || a.UnpackedBytes <= 0 || a.BackupBytes < 0 || !contains(build.TrustedUpdateOrigins, safeOrigin(a.URL)) {
		return invalid()
	}
	format := map[string]string{"win32": "nsis", "linux": "deb", "darwin": "zip"}[platform]
	if a.Format != format || a.SignatureIdentity == "" {
		return invalid()
	}
	return a, watermark, nil
}

// unsignedUpdate reports an artifact published without a platform code signature
// (tools/release-assets.mjs writes "unsigned"). Its integrity rests on the release
// index signature and the SHA-256 pinned there, as on Linux.
func unsignedUpdate(a Artifact) bool { return a.SignatureIdentity == "unsigned" }
func stageUpdate(p Peer, r Request) error {
	a, watermark, e := verifiedRelease(r.ReleaseEnvelope, r.ArtifactID)
	if e != nil {
		return e
	}
	if e = fileOwner(r.ArtifactPath, p); e != nil {
		return e
	}
	available, e := availableSpace()
	if e != nil || a.UnpackedBytes > 8*1024*1024*1024 || a.BackupBytes > 8*1024*1024*1024 || available < uint64(a.Bytes+a.UnpackedBytes+a.BackupBytes+300*1024*1024) {
		return failure("STORAGE_FAILED")
	}
	directory := filepath.Join(stateRoot(), "updates")
	if e = os.MkdirAll(directory, 0700); e != nil {
		return e
	}
	id := nonce()
	path := filepath.Join(directory, id+"."+a.Format)
	from, e := openDownload(r.ArtifactPath)
	if e != nil {
		return e
	}
	defer from.Close()
	to, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	accepted := false
	defer func() {
		if !accepted {
			os.Remove(path)
			os.Remove(filepath.Join(directory, id+".json"))
		}
	}()
	length, e := io.Copy(to, io.LimitReader(from, a.Bytes+1))
	if e == nil {
		e = to.Sync()
	}
	_ = to.Close()
	if e != nil || length != a.Bytes {
		return failure("UPDATE_VERIFY_FAILED")
	}
	hash, e := digestFile(path)
	if e != nil || hash != a.SHA256 {
		return failure("UPDATE_VERIFY_FAILED")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if e = validatePlatformUpdate(ctx, path, a); e != nil {
		return e
	}
	if e = atomicJSON(filepath.Join(stateRoot(), "release-watermark.json"), watermark); e != nil {
		return e
	}
	job := UpdateJob{ID: id, Artifact: a, Envelope: r.ReleaseEnvelope, Path: path, Owner: p, Created: time.Now().UnixMilli()}
	if e = atomicJSON(filepath.Join(directory, id+".json"), job); e != nil {
		return e
	}
	worker := filepath.Join(directory, "update-worker"+filepath.Ext(helperExecutable()))
	if e = copyFile(helperExecutable(), worker, 0700); e != nil {
		return e
	}
	if e = launchUpdateWorker(ctx, worker, id); e != nil {
		return e
	}
	accepted = true
	return nil
}
func applyUpdate(ctx context.Context, id string) error {
	if len(id) != 48 || !regexpHex(id) {
		return failure("INVALID_INPUT")
	}
	var job UpdateJob
	path := filepath.Join(stateRoot(), "updates", id+".json")
	if e := readJSON(path, &job); e != nil {
		return e
	}
	if job.ID != id || time.Now().UnixMilli()-job.Created > 120000 || !samePath(job.Path, filepath.Join(stateRoot(), "updates", id+"."+job.Artifact.Format)) {
		return failure("UPDATE_VERIFY_FAILED")
	}
	artifact, _, e := verifiedRelease(job.Envelope, job.Artifact.ID)
	if e != nil || artifact.SHA256 != job.Artifact.SHA256 {
		return failure("UPDATE_VERIFY_FAILED")
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		birth, e := processBirth(job.Owner.PID)
		if e != nil || birth != job.Owner.Birth {
			break
		}
		if time.Now().After(deadline) {
			return failure("CANCELLED")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if e = stopInstalledService(); e != nil {
		return e
	}
	if e = recoverAlone(); e != nil {
		return e
	}
	hash, e := digestFile(job.Path)
	if e != nil || hash != artifact.SHA256 {
		return failure("UPDATE_VERIFY_FAILED")
	}
	if e = validatePlatformUpdate(ctx, job.Path, artifact); e != nil {
		return e
	}
	e = installPlatformUpdate(ctx, job)
	if e != nil {
		var recovery UpdateRecovery
		if readJSON(updateRecoveryPath(), &recovery) == nil && recovery.Pending && recovery.ID == job.ID {
			if restoreErr := recoverInterruptedUpdate(job.ID); restoreErr != nil {
				return restoreErr
			}
		} else {
			_ = platformInstall(installed)
		}
		_ = atomicJSON(filepath.Join(stateRoot(), "last-update.json"), object{"status": "failed", "version": artifact.Version, "code": cleanError(e)})
		return e
	}
	if e = finishUpdateRecovery(); e != nil {
		return e
	}
	_ = atomicJSON(filepath.Join(stateRoot(), "last-update.json"), object{"status": "installed", "version": artifact.Version})
	_ = os.Remove(job.Path)
	_ = os.Remove(path)
	return nil
}
