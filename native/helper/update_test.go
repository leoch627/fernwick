package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type releaseFixture struct {
	key     ed25519.PrivateKey
	release Release
}

func newReleaseFixture(t *testing.T) *releaseFixture {
	t.Helper()
	if _, e := os.Stat(filepath.Join(stateRoot(), "release-watermark.json")); e == nil {
		t.Skip("an installed helper's release watermark would change the outcome")
	}
	public, private, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	der, _ := x509.MarshalPKIXPublicKey(public)
	withBuild(t, Build{
		ProductID: "starrail-test", HelperLabel: "work.starrail.test.helper", Environment: "test", Channel: "test", Version: "0.1.0",
		UpdateKeys:           map[string]string{"release-1": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))},
		TrustedUpdateOrigins: []string{"https://updates.example.com"},
	})
	platform := map[string]string{"windows": "win32"}[targetOS()]
	if platform == "" {
		platform = targetOS()
	}
	artifact := Artifact{
		ID: "client-0.2.0", Version: "0.2.0", Platform: platform, Arch: strings.Split(targetID(), "-")[1],
		Format: map[string]string{"win32": "nsis", "linux": "deb", "darwin": "zip"}[platform], URL: "https://updates.example.com/client-0.2.0",
		Bytes: 1024, SHA256: strings.Repeat("a", 64), UnpackedBytes: 4096, CoreVersion: "26.1.0", CoreSHA256: strings.Repeat("b", 64),
		HelperProtocol: protocolVersion, SignatureIdentity: "StarRail Test",
	}
	now := time.Now().UTC()
	return &releaseFixture{key: private, release: Release{
		SchemaVersion: 1, ProductID: "starrail-test", Environment: "test", Channel: "test",
		IssuedAt: now.Add(-time.Minute).Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
		ReleaseSequence: 7, Artifacts: []Artifact{artifact}, WithdrawnIDs: []string{},
	}}
}
func (f *releaseFixture) envelope(keyID string, domain string) string {
	payload, _ := json.Marshal(f.release)
	signature := ed25519.Sign(f.key, append([]byte(domain), payload...))
	raw, _ := json.Marshal(Envelope{KeyID: keyID, Payload: base64.RawURLEncoding.EncodeToString(payload), Signature: base64.RawURLEncoding.EncodeToString(signature)})
	return string(raw)
}
func (f *releaseFixture) signed() string {
	return f.envelope("release-1", "v2board-client-release-v1\n")
}

func TestVerifiedReleaseAcceptsSignedIndex(t *testing.T) {
	f := newReleaseFixture(t)
	artifact, watermark, e := verifiedRelease(f.signed(), "client-0.2.0")
	if e != nil {
		t.Fatal(e)
	}
	if artifact.Version != "0.2.0" || watermark.Version != 7 || !hex64.MatchString(watermark.Hash) {
		t.Fatalf("artifact=%+v watermark=%+v", artifact, watermark)
	}
}

func TestVerifiedReleaseRejects(t *testing.T) {
	cases := map[string]func(*releaseFixture) string{
		"unknown key":    func(f *releaseFixture) string { return f.envelope("release-2", "v2board-client-release-v1\n") },
		"missing domain": func(f *releaseFixture) string { return f.envelope("release-1", "") },
		"policy domain":  func(f *releaseFixture) string { return f.envelope("release-1", "v2board-client-policy-v1\n") },
		"other product":  func(f *releaseFixture) string { f.release.ProductID = "other"; return f.signed() },
		"other channel":  func(f *releaseFixture) string { f.release.Channel = "stable"; return f.signed() },
		"expired": func(f *releaseFixture) string {
			f.release.ExpiresAt = time.Now().Add(-time.Second).Format(time.RFC3339Nano)
			return f.signed()
		},
		"issued in the future": func(f *releaseFixture) string {
			f.release.IssuedAt = time.Now().Add(time.Hour).Format(time.RFC3339Nano)
			return f.signed()
		},
		"withdrawn":  func(f *releaseFixture) string { f.release.WithdrawnIDs = []string{"client-0.2.0"}; return f.signed() },
		"not listed": func(f *releaseFixture) string { f.release.Artifacts[0].ID = "client-0.3.0"; return f.signed() },
		"duplicate id": func(f *releaseFixture) string {
			f.release.Artifacts = append(f.release.Artifacts, f.release.Artifacts[0])
			return f.signed()
		},
		"downgrade": func(f *releaseFixture) string { f.release.Artifacts[0].Version = "0.1.0"; return f.signed() },
		"untrusted origin": func(f *releaseFixture) string {
			f.release.Artifacts[0].URL = "https://mirror.example.net/client"
			return f.signed()
		},
		"plain http": func(f *releaseFixture) string {
			f.release.Artifacts[0].URL = "http://updates.example.com/client"
			return f.signed()
		},
		"other platform": func(f *releaseFixture) string { f.release.Artifacts[0].Platform = "freebsd"; return f.signed() },
		"wrong format":   func(f *releaseFixture) string { f.release.Artifacts[0].Format = "appimage"; return f.signed() },
		"helper protocol": func(f *releaseFixture) string {
			f.release.Artifacts[0].HelperProtocol = protocolVersion + 1
			return f.signed()
		},
		"bad digest": func(f *releaseFixture) string { f.release.Artifacts[0].SHA256 = "abc"; return f.signed() },
		"unsigned identity": func(f *releaseFixture) string {
			f.release.Artifacts[0].SignatureIdentity = ""
			return f.signed()
		},
		"tampered payload": func(f *releaseFixture) string {
			var env Envelope
			_ = json.Unmarshal([]byte(f.signed()), &env)
			f.release.Artifacts[0].URL = "https://updates.example.com/other"
			payload, _ := json.Marshal(f.release)
			env.Payload = base64.RawURLEncoding.EncodeToString(payload)
			raw, _ := json.Marshal(env)
			return string(raw)
		},
		"unknown envelope field": func(f *releaseFixture) string { return strings.Replace(f.signed(), "{", `{"extra":1,`, 1) },
	}
	for name, envelope := range cases {
		t.Run(name, func(t *testing.T) {
			f := newReleaseFixture(t)
			if _, _, e := verifiedRelease(envelope(f), "client-0.2.0"); errorCode(e) != "UPDATE_VERIFY_FAILED" {
				t.Fatalf("verifiedRelease error = %v", e)
			}
		})
	}
}
