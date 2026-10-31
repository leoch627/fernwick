package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
)

func TestTrustedURLChecksExactOriginAndCanonicalizesSafeForms(t *testing.T) {
	origins := []string{"https://host.leiterup.de"}
	for raw, want := range map[string]string{
		"https://host.leiterup.de/renew":          "https://host.leiterup.de/renew",
		"https://HOST.LEITERUP.DE:0443":           "https://host.leiterup.de/",
		"https://host.leiterup.de/a/../renew":     "https://host.leiterup.de/renew",
		"https://host.leiterup.de/a/%2e%2E/renew": "https://host.leiterup.de/renew",
		"https://host.leiterup.de/a/.":            "https://host.leiterup.de/a/",
	} {
		got, err := TrustedURL(raw, origins)
		if err != nil || got != want {
			t.Errorf("%q: got %q %v; want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{"https://host.leiterup.de.evil.invalid/", "https://host.leiterup.de@evil.invalid/", "https://host.leiterup.de:444/", "http://host.leiterup.de/", "javascript:alert(1)", "https://host.leiterup.de/%2fsecret", "https://host.leiterup.de/%5Csecret", "https://host.leiterup.de/%00", "https://host.leiterup.de/a\\b", "https://host.leiterup.de/#fragment", "https://user:pass@host.leiterup.de/", "https://host.leiterup.de:65536/", "https://host.leiterup.de\n/"} {
		if _, err := TrustedURL(raw, origins); err == nil {
			t.Errorf("unsafe URL accepted: %q", raw)
		}
	}
	for _, origin := range []string{"https://host.leiterup.de/path", "https://host.leiterup.de/?query=1"} {
		if _, err := TrustedURL("https://host.leiterup.de/renew", []string{origin}); err == nil {
			t.Errorf("pathful origin accepted: %q", origin)
		}
	}
	if got, err := TrustedURL("https://[2001:0DB8:0000:0000::1]:443/", []string{"https://[2001:db8::1]"}); err != nil || got != "https://[2001:db8::1]/" {
		t.Fatalf("IPv6 canonicalization: %q %v", got, err)
	}
	if got, err := TrustedURL("https://[::FFFF:127.0.0.1]/", []string{"https://[::ffff:7f00:1]"}); err != nil || got != "https://[::ffff:7f00:1]/" {
		t.Fatalf("mapped IPv6 canonicalization: %q %v", got, err)
	}
	for _, raw := range []string{"https://127.1/", "https://0177.0.0.1/", "https://0x7f000001/", "https://127.0.0.1./", "https://例子.invalid/"} {
		if _, err := HTTPSURL(raw); err == nil {
			t.Errorf("noncanonical host accepted: %s", raw)
		}
	}
}

func TestBuildTrustValidatesIdentityDeploymentAndPublicKeys(t *testing.T) {
	raw, err := os.ReadFile("../../config/development.json")
	if err != nil {
		t.Fatal(err)
	}
	var base BuildConfig
	if err := DecodeStrict(raw, &base, 262144); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateBuild(base); err != nil {
		t.Fatal(err)
	}
	key, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	public := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	config := base
	config.Environment = "production"
	config.Channel = "stable"
	config.ProductID = "starrail-network"
	config.AppID = "work.starrail.client"
	config.DeploymentVerified = true
	config.NodeCapabilitiesConfirmed = true
	config.AllowUnverifiedNodeTrials = false
	config.PolicyURLs = []string{"https://host.leiterup.de/policy"}
	config.UpdateFeedURLs = []string{"https://host.leiterup.de/release"}
	config.PolicyKeys = map[string]string{"p": public}
	config.UpdateKeys = map[string]string{"r": public}
	if _, err := ValidateBuild(config); err != nil {
		t.Fatalf("complete production config rejected: %v", err)
	}
	for _, badKey := range []string{public + public, public + "trailing data", strings.ReplaceAll(public, "PUBLIC KEY", "UNRECOGNIZED KEY")} {
		candidate := config
		candidate.PolicyKeys = map[string]string{"p": badKey}
		if _, err := ValidateBuild(candidate); err == nil {
			t.Fatal("build accepted a key encoding that the envelope verifier rejects")
		}
	}
	for name, change := range map[string]func(*BuildConfig){
		"identity": func(b *BuildConfig) { b.ProductID = "../escape" }, "test identity": func(b *BuildConfig) { b.AppID = "work.test.client" }, "trial": func(b *BuildConfig) { b.AllowUnverifiedNodeTrials = true }, "unverified": func(b *BuildConfig) { b.DeploymentVerified = false }, "missing keys": func(b *BuildConfig) { b.PolicyKeys = map[string]string{} }, "missing link": func(b *BuildConfig) { b.Links.Renew = nil }, "one health domain": func(b *BuildConfig) { b.HealthTargets = []HealthTarget{b.HealthTargets[0], b.HealthTargets[0]} }, "missing capability": func(b *BuildConfig) { b.ProtocolCapabilities = b.ProtocolCapabilities[:4] }, "test host": func(b *BuildConfig) { b.PolicyURLs = []string{"https://api.example.com/policy"} },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := config
			change(&candidate)
			if _, err := ValidateBuild(candidate); err == nil {
				t.Fatal("invalid production build accepted")
			}
		})
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaDER, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	base.PolicyKeys = map[string]string{"rsa": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: rsaDER}))}
	if _, err := ValidateBuild(base); err == nil {
		t.Fatal("non-Ed25519 key accepted")
	}
	base.PolicyKeys = map[string]string{"bad": strings.Repeat("x", 10)}
	if _, err := ValidateBuild(base); err == nil {
		t.Fatal("malformed key accepted")
	}
}
