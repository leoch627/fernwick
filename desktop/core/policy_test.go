package core

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type signedFixture struct {
	build  BuildConfig
	policy Policy
	key    ed25519.PrivateKey
	now    int64
}

func newSignedFixture(t *testing.T) signedFixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	key := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	now := time.Date(2026, 10, 31, 0, 0, 0, 0, time.UTC).UnixMilli()
	build := BuildConfig{
		ProductID: "starrail-network-test", Environment: "test", Channel: "test",
		APIEndpoints: []APIEndpoint{{ID: "primary", BaseURL: "https://api.starrail.work", Priority: 10}, {ID: "backup", BaseURL: "https://host.leiterup.de", Priority: 20}},
		PolicyKeys:   map[string]string{"p1": key}, UpdateKeys: map[string]string{"r1": key},
		TrustedWebOrigins: []string{"https://host.leiterup.de"}, TrustedUpdateOrigins: []string{"https://host.leiterup.de"}, TrustedResourceOrigins: []string{"https://host.leiterup.de"},
	}
	policy := Policy{
		SchemaVersion: 2, PolicyVersion: 1, ProductID: build.ProductID, Environment: build.Environment, Channel: build.Channel,
		IssuedAt: time.UnixMilli(now).UTC().Format(time.RFC3339Nano), NotBefore: time.UnixMilli(now).UTC().Format(time.RFC3339Nano), ExpiresAt: time.UnixMilli(now + 7*86400000).UTC().Format(time.RFC3339Nano),
		RequiredCapabilities: []string{"tun", "policy-schema-2"}, Endpoints: PolicyEndpoints{OrderedIDs: []string{"primary", "backup"}, TemporarilyDisabledIDs: []string{}},
		Refresh: DefaultRefresh, UI: PolicyUI{ExpiryReminderDays: []int{7, 3}, ShowTrafficSummary: true}, Links: Links{Website: "https://host.leiterup.de/", Renew: "https://host.leiterup.de/", Help: "https://host.leiterup.de/"},
		NodeOperations: []NodeOperation{}, Routing: PolicyRouting{TemplateID: "cn-direct-default-proxy-v1", DNSTemplateID: "real-dns-split-v1"}, Update: PolicyUpdate{CheckIntervalSec: 21600},
	}
	return signedFixture{build: build, policy: policy, key: private, now: now}
}

func (f signedFixture) sign(t *testing.T, payload any, purpose, keyID string) string {
	t.Helper()
	raw, ok := payload.([]byte)
	if !ok {
		var err error
		raw, err = json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
	}
	signature := ed25519.Sign(f.key, append([]byte(purpose+"\n"), raw...))
	encoded, err := json.Marshal(Envelope{KeyID: keyID, Payload: base64.RawURLEncoding.EncodeToString(raw), Signature: base64.RawURLEncoding.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func (f signedFixture) signPolicy(t *testing.T, payload any) string {
	return f.sign(t, payload, "v2board-client-policy-v1", "p1")
}

func TestPolicySignatureReplayAndRollback(t *testing.T) {
	f := newSignedFixture(t)
	raw := f.signPolicy(t, f.policy)
	checked, err := VerifyPolicy(raw, f.build, nil, f.now)
	if err != nil || checked.Unchanged || checked.Watermark.Version != 1 {
		t.Fatalf("initial: %+v %v", checked, err)
	}
	replay, err := VerifyPolicy(raw, f.build, &checked.Watermark, f.now)
	if err != nil || !replay.Unchanged {
		t.Fatalf("identical replay: %+v %v", replay, err)
	}
	changed := f.policy
	changed.UI.ShowTrafficSummary = false
	if _, err := VerifyPolicy(f.signPolicy(t, changed), f.build, &checked.Watermark, f.now); CodeOf(err) != "POLICY_INVALID" {
		t.Fatalf("conflict: %v", err)
	}
	if _, err := VerifyPolicy(raw, f.build, &Watermark{Version: 2, Hash: "later"}, f.now); err == nil {
		t.Fatal("rollback accepted")
	}
	var envelope Envelope
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.Payload = base64.RawURLEncoding.EncodeToString([]byte(`{"changed":true}`))
	tampered, _ := json.Marshal(envelope)
	if _, err := VerifyPolicy(string(tampered), f.build, nil, f.now); err == nil {
		t.Fatal("tampered signature accepted")
	}
	if _, err := VerifyEnvelope(raw, f.build.PolicyKeys, "v2board-client-release-v1"); err == nil {
		t.Fatal("purpose crossover accepted")
	}
}

func TestPolicyRejectsInvalidSignedContent(t *testing.T) {
	f := newSignedFixture(t)
	cases := map[string]func(*Policy){
		"wrong environment":  func(p *Policy) { p.Environment = "production" },
		"wrong product":      func(p *Policy) { p.ProductID = "another" },
		"wrong channel":      func(p *Policy) { p.Channel = "stable" },
		"unknown endpoint":   func(p *Policy) { p.Endpoints.OrderedIDs = []string{"primary", "evil"} },
		"duplicate endpoint": func(p *Policy) { p.Endpoints.OrderedIDs = []string{"primary", "primary"} },
		"all disabled":       func(p *Policy) { p.Endpoints.TemporarilyDisabledIDs = []string{"primary", "backup"} },
		"duplicate disabled": func(p *Policy) { p.Endpoints.TemporarilyDisabledIDs = []string{"backup", "backup"} },
		"unknown disabled":   func(p *Policy) { p.Endpoints.TemporarilyDisabledIDs = []string{"evil"} },
		"duplicate nodes":    func(p *Policy) { p.NodeOperations = []NodeOperation{{NodeID: "a"}, {NodeID: "a"}} },
		"untrusted link":     func(p *Policy) { p.Links.Help = "https://evil.invalid/" },
		"expired":            func(p *Policy) { p.ExpiresAt = p.NotBefore },
		"not begun":          func(p *Policy) { p.NotBefore = time.UnixMilli(f.now + 1).UTC().Format(time.RFC3339Nano) },
		"future issued":      func(p *Policy) { p.IssuedAt = time.UnixMilli(f.now + 120001).UTC().Format(time.RFC3339Nano) },
		"issued after from":  func(p *Policy) { p.IssuedAt = time.UnixMilli(f.now + 1).UTC().Format(time.RFC3339Nano) },
		"maintenance too long": func(p *Policy) {
			p.Maintenance = &Maintenance{Reason: "maintenance", StartsAt: p.NotBefore, EndsAt: p.ExpiresAt, Platforms: []string{"linux"}}
		},
		"maintenance before policy": func(p *Policy) {
			p.Maintenance = &Maintenance{Reason: "maintenance", StartsAt: time.UnixMilli(f.now - 1).UTC().Format(time.RFC3339Nano), EndsAt: time.UnixMilli(f.now + 1000).UTC().Format(time.RFC3339Nano), Platforms: []string{"linux"}}
		},
		"resource expired": func(p *Policy) {
			p.Routing.Resource = &Resource{ID: "r", Version: 1, URL: "https://host.leiterup.de/r", SHA256: strings.Repeat("a", 64), Bytes: 1, ExpiresAt: p.NotBefore}
		},
		"resource outlives policy": func(p *Policy) {
			p.Routing.Resource = &Resource{ID: "r", Version: 1, URL: "https://host.leiterup.de/r", SHA256: strings.Repeat("a", 64), Bytes: 1, ExpiresAt: time.UnixMilli(f.now + 8*86400000).UTC().Format(time.RFC3339Nano)}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := f.policy
			mutate(&p)
			if _, err := VerifyPolicy(f.signPolicy(t, p), f.build, nil, f.now); CodeOf(err) != "POLICY_INVALID" {
				t.Fatalf("accepted invalid policy: %v", err)
			}
		})
	}
	encoded, _ := json.Marshal(f.policy)
	for name, raw := range map[string]string{
		"unknown field":     strings.Replace(string(encoded), `"schemaVersion":2`, `"schemaVersion":2,"script":"alert(1)"`, 1),
		"duplicate key":     strings.Replace(string(encoded), `"policyVersion":1`, `"policyVersion":1,"policyVersion":2`, 1),
		"escaped duplicate": strings.Replace(string(encoded), `"policyVersion":1`, `"policyVersion":1,"\u0070olicyVersion":2`, 1),
		"null array":        strings.Replace(string(encoded), `"nodeOperations":[]`, `"nodeOperations":null`, 1),
		"missing nullable":  strings.Replace(string(encoded), `"maintenance":null,`, "", 1),
		"unsafe integer":    strings.Replace(string(encoded), `"policyVersion":1`, `"policyVersion":9007199254740993`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyPolicy(f.signPolicy(t, []byte(raw)), f.build, nil, f.now); err == nil {
				t.Fatal("accepted malformed signed JSON")
			}
		})
	}
}

func TestEnvelopeStrictEncodingAndUTF8(t *testing.T) {
	f := newSignedFixture(t)
	for _, payload := range [][]byte{[]byte(`{"__proto__":{}}`), []byte(`{"constructor":{}}`), []byte(`{"a":1,"a":2}`), []byte(`{"x":9007199254740993}`), {'"', 0xff, '"'}} {
		if _, err := VerifyEnvelope(f.signPolicy(t, payload), f.build.PolicyKeys, "v2board-client-policy-v1"); err == nil {
			t.Fatalf("accepted payload %q", payload)
		}
	}
	var envelope Envelope
	_ = json.Unmarshal([]byte(f.signPolicy(t, f.policy)), &envelope)
	for _, mutate := range []func(*Envelope){func(e *Envelope) { e.KeyID = "missing" }, func(e *Envelope) { e.Signature += "=" }, func(e *Envelope) { e.Payload += "=" }, func(e *Envelope) { e.Signature = "A" }, func(e *Envelope) { e.KeyID = "" }} {
		e := envelope
		mutate(&e)
		raw, _ := json.Marshal(e)
		if _, err := VerifyEnvelope(string(raw), f.build.PolicyKeys, "v2board-client-policy-v1"); err == nil {
			t.Fatalf("accepted envelope %+v", e)
		}
	}
}

func TestEnvelopeTypeScriptOracle(t *testing.T) {
	// Generated with the original Node crypto sign(null, purpose + "\n" + raw)
	// using the fixed Ed25519 seed 00..1f. These bytes are not Go-generated.
	key := "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAA6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=\n-----END PUBLIC KEY-----\n"
	raw := `{"keyId":"ts","payload":"eyJ0ZXh0IjoiPD4mXHUyMDI46ZuqIiwidmVyc2lvbiI6MX0","signature":"eqjg5p5E-J7omnGax1JpfRaFILNIhsMycpiaes2c73aMI9gtQjUhzM8yIkHWQJaV8T08aM8x6yqOjYSUMQUiDQ"}`
	verified, err := VerifyEnvelope(raw, map[string]string{"ts": key}, "v2board-client-policy-v1")
	if err != nil {
		t.Fatal(err)
	}
	if string(verified.Payload) != `{"text":"<>&\u2028雪","version":1}` || verified.Hash != "54ebfb5a6e3596060d424f76995e8ea6fb4f694500869c804c5ad95b14f4850a" {
		t.Fatalf("original payload bytes or digest changed: %+v", verified)
	}
}

func TestEnvelopeKeyIDUsesFrozenZodUnicodeLength(t *testing.T) {
	f := newSignedFixture(t)
	for _, count := range []int{128, 129} {
		id := strings.Repeat("🌟", count)
		raw := f.sign(t, f.policy, "v2board-client-policy-v1", id)
		_, err := VerifyEnvelope(raw, map[string]string{id: f.build.PolicyKeys["p1"]}, "v2board-client-policy-v1")
		if (err == nil) != (count == 128) {
			t.Fatalf("%d codepoint key ID: %v", count, err)
		}
	}
}

func TestPolicyServicePreservesSignedSurrogateText(t *testing.T) {
	f := newSignedFixture(t)
	f.policy.UI.Announcement = &Announcement{ID: "announcement", Text: "placeholder"}
	raw, err := json.Marshal(f.policy)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"text":"placeholder"`, `"text":"\ud800"`, 1))
	service := NewPolicyService(f.build, func(PolicyRecord) error { return nil }, func() int64 { return f.now })
	if _, err := service.Accept(f.signPolicy(t, raw)); err != nil {
		t.Fatal(err)
	}
	if got := service.Active().UI.Announcement.Text; got != "\xed\xa0\x80" {
		t.Fatalf("signed surrogate changed: %q", got)
	}
	service.Active().UI.Announcement.Text = "mutated"
	if got := service.Active().UI.Announcement.Text; got != "\xed\xa0\x80" {
		t.Fatal("signed announcement pointer leaked")
	}
}

func TestPolicyServiceAtomicPersistenceExpiryAndRestore(t *testing.T) {
	f := newSignedFixture(t)
	var clock atomic.Int64
	clock.Store(f.now)
	var writes atomic.Int32
	fail := true
	service := NewPolicyService(f.build, func(record PolicyRecord) error {
		writes.Add(1)
		if fail {
			return errors.New("disk full")
		}
		return nil
	}, clock.Load)
	raw := f.signPolicy(t, f.policy)
	if _, err := service.Accept(raw); err == nil {
		t.Fatal("persistence should fail")
	}
	if service.Active() != nil || service.Watermark() != nil || service.Generation() != 0 || service.Envelope() != nil {
		t.Fatal("failed persistence activated state")
	}
	fail = false
	if changed, err := service.Accept(raw); err != nil || !changed {
		t.Fatalf("retry failed: %v %v", changed, err)
	}
	if changed, err := service.Accept(raw); err != nil || changed || writes.Load() != 2 {
		t.Fatalf("replay persisted: %v %v %d", changed, err, writes.Load())
	}
	active := service.Active()
	active.Endpoints.OrderedIDs[0] = "mutated"
	active.UI.ExpiryReminderDays[0] = 30
	if service.Active().Endpoints.OrderedIDs[0] != "primary" || service.Active().UI.ExpiryReminderDays[0] != 7 {
		t.Fatal("mutable signed snapshot leaked")
	}
	record := PolicyRecord{Envelope: raw, Watermark: *service.Watermark()}
	clock.Store(f.now + 7*86400000)
	if service.Active() != nil {
		t.Fatal("expired policy active")
	}
	if _, err := service.Accept(raw); err == nil {
		t.Fatal("expired replay accepted")
	}
	restored := NewPolicyService(f.build, func(PolicyRecord) error { return nil }, clock.Load)
	if err := restored.Restore(record); err != nil {
		t.Fatal(err)
	}
	if restored.Active() != nil || restored.Watermark() == nil || restored.Watermark().Version != 1 {
		t.Fatal("expired high water lost")
	}
	bad := record
	bad.Watermark.Hash = "forged"
	if err := restored.Restore(bad); err == nil {
		t.Fatal("forged persisted watermark trusted")
	}
	if *restored.Watermark() != record.Watermark {
		t.Fatal("failed restore mutated state")
	}
}

func TestPolicyServiceSerializesConcurrentAccepts(t *testing.T) {
	f := newSignedFixture(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var writes atomic.Int32
	service := NewPolicyService(f.build, func(record PolicyRecord) error {
		if writes.Add(1) == 1 {
			close(entered)
			<-release
		}
		return nil
	}, func() int64 { return f.now })
	raw := f.signPolicy(t, f.policy)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	wg.Add(1)
	go func() { defer wg.Done(); _, err := service.Accept(raw); results <- err }()
	<-entered
	if service.Active() != nil || service.Watermark() != nil {
		t.Fatal("activated before persistence returned")
	}
	wg.Add(1)
	go func() { defer wg.Done(); _, err := service.Accept(raw); results <- err }()
	close(release)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if writes.Load() != 1 || service.Generation() != 1 {
		t.Fatalf("duplicate activation: %d %d", writes.Load(), service.Generation())
	}
}
