package core

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func releaseFixture(f signedFixture) (Artifact, ReleaseIndex) {
	artifact := Artifact{ID: "linux-1.10.0", Version: "1.10.0", Platform: "linux", Arch: "x64", Format: "deb", MinimumOS: "24.04", URL: "https://host.leiterup.de/releases/app.deb", Bytes: 1024, SHA256: strings.Repeat("a", 64), UnpackedBytes: 4096, BackupBytes: 2048, CoreVersion: "fixture-core", CoreSHA256: strings.Repeat("b", 64), HelperProtocol: 1, SignatureIdentity: "test-only"}
	index := ReleaseIndex{SchemaVersion: 1, ProductID: f.build.ProductID, Environment: f.build.Environment, Channel: f.build.Channel, IssuedAt: time.UnixMilli(f.now).UTC().Format(time.RFC3339Nano), ExpiresAt: time.UnixMilli(f.now + 86400000).UTC().Format(time.RFC3339Nano), ReleaseSequence: 1, Artifacts: []Artifact{artifact}, WithdrawnIDs: []string{}}
	return artifact, index
}

func (f signedFixture) signRelease(t *testing.T, payload any) string {
	return f.sign(t, payload, "v2board-client-release-v1", "r1")
}

func TestReleasePurposeSchemaAndPlatformValidation(t *testing.T) {
	f := newSignedFixture(t)
	_, index := releaseFixture(f)
	if _, err := VerifyRelease(f.signPolicy(t, index), f.build, nil, f.now); CodeOf(err) != "UPDATE_VERIFY_FAILED" {
		t.Fatalf("policy used as release: %v", err)
	}
	checked, err := VerifyRelease(f.signRelease(t, index), f.build, nil, f.now)
	if err != nil || len(checked.Index.Artifacts) != 1 {
		t.Fatalf("valid release: %+v %v", checked, err)
	}
	for _, target := range []struct {
		platform, arch, format string
		valid                  bool
	}{
		{"linux", "x64", "deb", true}, {"linux", "arm64", "deb", false}, {"linux", "x64", "zip", false},
		{"win32", "x64", "nsis", true}, {"win32", "arm64", "nsis", false}, {"win32", "x64", "zip", false},
		{"darwin", "arm64", "zip", true}, {"darwin", "x64", "dmg", true}, {"darwin", "arm64", "deb", false},
	} {
		t.Run(target.platform+"-"+target.arch+"-"+target.format, func(t *testing.T) {
			next := index
			artifact := index.Artifacts[0]
			artifact.Platform, artifact.Arch, artifact.Format = target.platform, target.arch, target.format
			next.Artifacts = []Artifact{artifact}
			_, err := VerifyRelease(f.signRelease(t, next), f.build, nil, f.now)
			if (err == nil) != target.valid {
				t.Fatalf("valid=%v, error=%v", target.valid, err)
			}
		})
	}
	for name, mutate := range map[string]func(*ReleaseIndex){
		"wrong environment":  func(r *ReleaseIndex) { r.Environment = "production" },
		"wrong product":      func(r *ReleaseIndex) { r.ProductID = "other" },
		"wrong channel":      func(r *ReleaseIndex) { r.Channel = "stable" },
		"expired":            func(r *ReleaseIndex) { r.ExpiresAt = r.IssuedAt },
		"future":             func(r *ReleaseIndex) { r.IssuedAt = time.UnixMilli(f.now + 120001).UTC().Format(time.RFC3339Nano) },
		"comma fraction":     func(r *ReleaseIndex) { r.IssuedAt = "2026-10-31T00:00:00,5Z" },
		"one digit hour":     func(r *ReleaseIndex) { r.IssuedAt = "2026-10-31T0:00:00Z" },
		"comma expiry":       func(r *ReleaseIndex) { r.ExpiresAt = "2026-11-01T00:00:00,5Z" },
		"duplicate artifact": func(r *ReleaseIndex) { r.Artifacts = append([]Artifact{}, r.Artifacts[0], r.Artifacts[0]) },
		"untrusted artifact": func(r *ReleaseIndex) {
			a := r.Artifacts[0]
			a.URL = "https://evil.invalid/app.deb"
			r.Artifacts = []Artifact{a}
		},
		"fractional artifact version": func(r *ReleaseIndex) { a := r.Artifacts[0]; a.Version = "1.1"; r.Artifacts = []Artifact{a} },
	} {
		t.Run(name, func(t *testing.T) {
			r := index
			mutate(&r)
			if _, err := VerifyRelease(f.signRelease(t, r), f.build, nil, f.now); CodeOf(err) != "UPDATE_VERIFY_FAILED" {
				t.Fatalf("invalid release accepted: %v", err)
			}
		})
	}
	encoded, _ := json.Marshal(index)
	for name, raw := range map[string]string{
		"unknown field":           strings.Replace(string(encoded), `"schemaVersion":1`, `"schemaVersion":1,"command":"bad"`, 1),
		"unknown artifact field":  strings.Replace(string(encoded), `"helperProtocol":1`, `"helperProtocol":1,"script":"bad"`, 1),
		"missing helper protocol": strings.Replace(string(encoded), `"helperProtocol":1,`, "", 1),
		"null artifacts":          strings.Replace(string(encoded), `"artifacts":[`, `"artifacts":null,"other":[`, 1),
		"unsafe unpacked size":    strings.Replace(string(encoded), `"unpackedBytes":4096`, `"unpackedBytes":9007199254740992`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyRelease(f.signRelease(t, []byte(raw)), f.build, nil, f.now); err == nil {
				t.Fatal("accepted malformed release")
			}
		})
	}
}

func TestReleaseWatermarksAndInstallationGate(t *testing.T) {
	f := newSignedFixture(t)
	artifact, index := releaseFixture(f)
	raw := f.signRelease(t, index)
	first, err := VerifyRelease(raw, f.build, nil, f.now)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := VerifyRelease(raw, f.build, &first.Watermark, f.now)
	if err != nil || !replay.Unchanged {
		t.Fatalf("replay: %v %v", replay.Unchanged, err)
	}
	for _, watermark := range []Watermark{{Version: 2, Hash: first.Watermark.Hash}, {Version: 1, Hash: "different"}} {
		if _, err := VerifyRelease(raw, f.build, &watermark, f.now); CodeOf(err) != "UPDATE_VERIFY_FAILED" {
			t.Fatalf("bad watermark accepted: %v", err)
		}
	}
	if err := InstallationGate(artifact, index, f.now, true); err != nil {
		t.Fatal(err)
	}
	if err := InstallationGate(artifact, index, f.now, false); CodeOf(err) != "NETWORK_RECOVERY_REQUIRED" {
		t.Fatalf("dirty network gate: %v", err)
	}
	if err := InstallationGate(artifact, index, f.now+86400000, true); CodeOf(err) != "UPDATE_VERIFY_FAILED" {
		t.Fatalf("expired index: %v", err)
	}
	withdrawn := index
	withdrawn.WithdrawnIDs = []string{artifact.ID}
	if err := InstallationGate(artifact, withdrawn, f.now, true); err == nil {
		t.Fatal("withdrawn artifact accepted")
	}
	artifact.SHA256 = strings.Repeat("c", 64)
	if err := InstallationGate(artifact, index, f.now, true); err == nil {
		t.Fatal("different hash installed")
	}
}

func TestSelectUpdateSemanticVersionsAndTarget(t *testing.T) {
	f := newSignedFixture(t)
	artifact, index := releaseFixture(f)
	target := UpdateTarget{Platform: "linux", Arch: "x64", Version: "1.9.0", OSCompatible: func(s string) bool { return OSVersionAtLeast("24.04", s) }}
	if result := SelectUpdate(index, target); result == nil || result.Version != "1.10.0" {
		t.Fatalf("semantic 1.10 > 1.9: %+v", result)
	}
	target.Version = "2.0.0"
	if SelectUpdate(index, target) != nil {
		t.Fatal("downgrade selected")
	}
	target.Version = "1.9.0"
	newer := artifact
	newer.ID = "new"
	newer.Version = "1.11.0"
	index.Artifacts = append(index.Artifacts, newer)
	if result := SelectUpdate(index, target); result == nil || result.ID != "new" {
		t.Fatal("newest compatible not selected")
	}
	index.WithdrawnIDs = []string{"new"}
	if result := SelectUpdate(index, target); result == nil || result.ID != artifact.ID {
		t.Fatal("withdrawal ignored")
	}
	target.OSCompatible = func(string) bool { return false }
	if SelectUpdate(index, target) != nil {
		t.Fatal("incompatible OS selected")
	}
	target = UpdateTarget{Platform: "darwin", Arch: "arm64", Version: "1.0.0", OSCompatible: func(string) bool { return true }}
	dmg := artifact
	dmg.ID = "dmg"
	dmg.Platform = "darwin"
	dmg.Arch = "arm64"
	dmg.Format = "dmg"
	zip := dmg
	zip.ID = "zip"
	zip.Format = "zip"
	index.Artifacts = []Artifact{dmg, zip}
	index.WithdrawnIDs = []string{}
	if result := SelectUpdate(index, target); result == nil || result.ID != "zip" {
		t.Fatal("macOS in-app update must use zip")
	}
}

func TestReleaseVersionSyntaxAndPrecedence(t *testing.T) {
	for _, raw := range []string{"1.2.3", "v1.2.3", " 1.2.3 ", "\ufeff1.2.3\ufeff", "1.0.0-alpha.1+build.001", "9007199254740991.0.0", "1.0.0-999999999999999999999"} {
		if _, ok := parseReleaseVersion(raw); !ok {
			t.Errorf("valid version rejected: %q", raw)
		}
	}
	for _, raw := range []string{"1.2", "=1.2.3", "V1.2.3", "01.2.3", "1.02.3", "1.2.03", "1.0.0-01", "1.0.0-alpha..1", "1.0.0+", "9007199254740992.0.0", "\u00851.2.3", strings.Repeat(" ", 257) + "1.0.0"} {
		if _, ok := parseReleaseVersion(raw); ok {
			t.Errorf("invalid version accepted: %q", raw)
		}
	}
	ordered := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.1.0", "1.10.0", "2.0.0"}
	for i := 1; i < len(ordered); i++ {
		a, _ := parseReleaseVersion(ordered[i-1])
		b, _ := parseReleaseVersion(ordered[i])
		if compareReleaseVersion(a, b) >= 0 || compareReleaseVersion(b, a) <= 0 {
			t.Errorf("wrong order %s / %s", ordered[i-1], ordered[i])
		}
	}
	a, _ := parseReleaseVersion("1.0.0+build1")
	b, _ := parseReleaseVersion("1.0.0+build2")
	if compareReleaseVersion(a, b) != 0 {
		t.Fatal("build metadata affects version precedence")
	}
	a, _ = parseReleaseVersion("1.0.0-9007199254740992.a")
	b, _ = parseReleaseVersion("1.0.0-9007199254740993.b")
	if compareReleaseVersion(a, b) != 0 {
		t.Fatal("numeric prerelease comparison differs from npm Number semantics")
	}
}

func TestOSVersionAndDownloadBudget(t *testing.T) {
	for _, tt := range []struct {
		actual, minimum string
		want            bool
	}{{"10.0.22000", "10.0.22000", true}, {"10.0.19045", "10.0.22000", false}, {"24.04", "24.04.0", true}, {"14", "13.9", true}, {"14.0.0.1", "14", true}, {"14.0beta", "14", false}, {"1.2.3.4.5", "1", false}, {"", "1", false}} {
		if got := OSVersionAtLeast(tt.actual, tt.minimum); got != tt.want {
			t.Errorf("%q >= %q = %v", tt.actual, tt.minimum, got)
		}
	}
	metered, unmetered := true, false
	for _, tt := range []struct {
		metered *bool
		battery *Battery
		want    bool
	}{{nil, &Battery{Percent: 90}, false}, {&unmetered, nil, false}, {&metered, &Battery{Charging: true}, false}, {&unmetered, &Battery{Percent: 10}, false}, {&unmetered, &Battery{Percent: 10, Charging: true}, true}, {&unmetered, &Battery{Percent: 20}, true}} {
		if got := AutomaticDownloadAllowed(tt.metered, tt.battery); got != tt.want {
			t.Errorf("download gate = %v, want %v", got, tt.want)
		}
	}
	artifact := Artifact{Bytes: 1024, UnpackedBytes: 4096, BackupBytes: 2048}
	if RequiredDiskBytes(artifact) != 1024+4096+2048+300*1024*1024 {
		t.Fatal("insufficient disk reservation")
	}
}

func TestArtifactChecksExactLengthAndDigest(t *testing.T) {
	content := []byte("verified release bytes")
	sum := sha256.Sum256(content)
	artifact := Artifact{Bytes: int64(len(content)), SHA256: hex.EncodeToString(sum[:])}
	path := filepath.Join(t.TempDir(), "release.deb")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifact(path, artifact); err != nil {
		t.Fatal(err)
	}
	for _, data := range [][]byte{content[:len(content)-1], append(append([]byte{}, content...), 0), []byte(strings.Repeat("x", len(content)))} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := VerifyArtifact(path, artifact); CodeOf(err) != "UPDATE_VERIFY_FAILED" {
			t.Fatalf("corrupt artifact accepted: %v", err)
		}
	}
	if err := VerifyArtifact(path+"missing", artifact); CodeOf(err) != "UPDATE_VERIFY_FAILED" {
		t.Fatalf("missing artifact: %v", err)
	}
}

func TestArtifactTextUsesFrozenZodUnicodeLength(t *testing.T) {
	f := newSignedFixture(t)
	for _, field := range []struct {
		name  string
		limit int
		set   func(*Artifact, string)
	}{
		{"minimumOS", 100, func(a *Artifact, s string) { a.MinimumOS = s }},
		{"coreVersion", 64, func(a *Artifact, s string) { a.CoreVersion = s }},
		{"signatureIdentity", 256, func(a *Artifact, s string) { a.SignatureIdentity = s }},
	} {
		t.Run(field.name, func(t *testing.T) {
			artifact, _ := releaseFixture(f)
			field.set(&artifact, strings.Repeat("🌟", field.limit))
			if err := artifact.Validate(); err != nil {
				t.Fatalf("exact codepoint limit rejected: %v", err)
			}
			field.set(&artifact, strings.Repeat("🌟", field.limit+1))
			if err := artifact.Validate(); err == nil {
				t.Fatal("overlong codepoint text accepted")
			}
		})
	}
}
