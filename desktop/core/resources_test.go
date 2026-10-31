package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func resourceBaseline() Rules {
	return Rules{SchemaVersion: 1, DirectDomains: []string{"baseline.cn"}, ProxyDomains: []string{}, BlockedDomains: []string{}, DirectIPs: []string{}}
}
func resourceCandidate(t *testing.T, f signedFixture, version int64, domain, id string) (string, Resource, string) {
	t.Helper()
	rules := resourceBaseline()
	rules.DirectDomains = []string{domain}
	raw, err := EncodeJSON(rules)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	descriptor := Resource{ID: id, Version: version, URL: "https://host.leiterup.de/" + id + ".json", SHA256: hex.EncodeToString(hash[:]), Bytes: int64(len(raw)), ExpiresAt: isoTime(f.now + 3600000)}
	policy := f.policy
	policy.PolicyVersion = version
	policy.Routing.Resource = &descriptor
	return string(raw), descriptor, f.signPolicy(t, policy)
}
func TestResourceDurableActivationRestartAndExpiry(t *testing.T) {
	f := newSignedFixture(t)
	body, descriptor, envelope := resourceCandidate(t, f, 1, "new.cn", "rules-1")
	var now atomic.Int64
	now.Store(f.now)
	store := NewJSONStore[ResourceCache](filepath.Join(t.TempDir(), "rules.json"), 0)
	transport := transportFunc(func(context.Context, HTTPRequest) (HTTPResponse, error) {
		return HTTPResponse{Status: 200, Body: body}, nil
	})
	resources, err := NewResourceCoordinator(f.build, resourceBaseline(), store, transport, now.Load)
	if err != nil {
		t.Fatal(err)
	}
	if err = resources.Apply(context.Background(), envelope); err != nil {
		t.Fatal(err)
	}
	if resources.Fingerprint() != descriptor.SHA256 || resources.Rules().DirectDomains[0] != "new.cn" {
		t.Fatal("resource not activated")
	}
	saved, err := store.Load()
	if err != nil || saved.Body == nil || *saved.Body != body {
		t.Fatal("exact body not persisted")
	}
	restarted, _ := NewResourceCoordinator(f.build, resourceBaseline(), store, transport, now.Load)
	if err = restarted.Restore(); err != nil {
		t.Fatal(err)
	}
	if restarted.Fingerprint() != descriptor.SHA256 {
		t.Fatal("restart lost validated resource")
	}
	now.Add(3600000)
	if restarted.Rules().DirectDomains[0] != "baseline.cn" || restarted.Status() != "使用内置大陆分流规则" {
		t.Fatal("expired resource retained")
	}
}
func TestResourceCorruptionCannotReplaceValidRules(t *testing.T) {
	f := newSignedFixture(t)
	body, _, signed := resourceCandidate(t, f, 1, "new.cn", "rules-1")
	store := NewJSONStore[ResourceCache](filepath.Join(t.TempDir(), "rules.json"), 0)
	transport := transportFunc(func(context.Context, HTTPRequest) (HTTPResponse, error) {
		return HTTPResponse{Status: 200, Body: body}, nil
	})
	resources, _ := NewResourceCoordinator(f.build, resourceBaseline(), store, transport, func() int64 { return f.now })
	if err := resources.Apply(context.Background(), signed); err != nil {
		t.Fatal(err)
	}
	_, _, next := resourceCandidate(t, f, 2, "changed.cn", "rules-2")
	body = "truncated"
	if err := resources.Apply(context.Background(), next); err == nil {
		t.Fatal("corrupt rules accepted")
	}
	if resources.Rules().DirectDomains[0] != "new.cn" || !strings.Contains(resources.Status(), "未验证") {
		t.Fatal("valid rules discarded")
	}
	record, _ := store.Load()
	tampered := strings.Replace(*record.Body, "new.cn", "bad.cn", 1)
	record.Body = &tampered
	if err := store.Save(*record, nil); err != nil {
		t.Fatal(err)
	}
	restarted, _ := NewResourceCoordinator(f.build, resourceBaseline(), store, transport, func() int64 { return f.now })
	if err := restarted.Restore(); err == nil {
		t.Fatal("corrupted cache trusted")
	}
	if restarted.Rules().DirectDomains[0] != "baseline.cn" {
		t.Fatal("unsafe cached rules active")
	}
}
func TestResourceIdentityHighWaterSurvivesBaselineAndRestart(t *testing.T) {
	f := newSignedFixture(t)
	body, _, signed := resourceCandidate(t, f, 1, "first.cn", "rules-1")
	calls := 0
	store := NewJSONStore[ResourceCache](filepath.Join(t.TempDir(), "rules.json"), 0)
	transport := transportFunc(func(context.Context, HTTPRequest) (HTTPResponse, error) {
		calls++
		return HTTPResponse{Status: 200, Body: body}, nil
	})
	resources, _ := NewResourceCoordinator(f.build, resourceBaseline(), store, transport, func() int64 { return f.now })
	if err := resources.Apply(context.Background(), signed); err != nil {
		t.Fatal(err)
	}
	body, _, signed = resourceCandidate(t, f, 2, "second.cn", "rules-2")
	if err := resources.Apply(context.Background(), signed); err != nil {
		t.Fatal(err)
	}
	baseline := f.policy
	baseline.PolicyVersion = 3
	if err := resources.Apply(context.Background(), f.signPolicy(t, baseline)); err != nil {
		t.Fatal(err)
	}
	restarted, _ := NewResourceCoordinator(f.build, resourceBaseline(), store, transport, func() int64 { return f.now })
	if err := restarted.Restore(); err != nil {
		t.Fatal(err)
	}
	body, _, signed = resourceCandidate(t, f, 4, "replacement.cn", "rules-1")
	if err := restarted.Apply(context.Background(), signed); err == nil {
		t.Fatal("identity reuse accepted")
	}
	body, _, signed = resourceCandidate(t, f, 1, "first.cn", "rules-1")
	if err := restarted.Apply(context.Background(), signed); err == nil {
		t.Fatal("resource rollback accepted")
	}
	if calls != 2 || restarted.Rules().DirectDomains[0] != "baseline.cn" {
		t.Fatal("identity validation happened after fetching")
	}
}
func TestSupersededResourceCannotOverwriteNewCache(t *testing.T) {
	f := newSignedFixture(t)
	firstBody, first, signed1 := resourceCandidate(t, f, 1, "first.cn", "rules-1")
	secondBody, _, signed2 := resourceCandidate(t, f, 2, "current.cn", "rules-2")
	started := make(chan struct{})
	release := make(chan struct{})
	store := NewJSONStore[ResourceCache](filepath.Join(t.TempDir(), "rules.json"), 0)
	transport := transportFunc(func(_ context.Context, input HTTPRequest) (HTTPResponse, error) {
		if input.URL == first.URL {
			close(started)
			<-release
			return HTTPResponse{Status: 200, Body: firstBody}, nil
		}
		return HTTPResponse{Status: 200, Body: secondBody}, nil
	})
	resources, _ := NewResourceCoordinator(f.build, resourceBaseline(), store, transport, func() int64 { return f.now })
	old := make(chan error, 1)
	go func() { old <- resources.Apply(context.Background(), signed1) }()
	<-started
	next := make(chan error, 1)
	go func() { next <- resources.Apply(context.Background(), signed2) }()
	deadline := time.Now().Add(time.Second)
	for {
		resources.mu.RLock()
		sequence := resources.sequence
		resources.mu.RUnlock()
		if sequence == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("replacement not queued")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	if err := <-old; CodeOf(err) != "CANCELLED" {
		t.Fatalf("old response %v", err)
	}
	if err := <-next; err != nil {
		t.Fatal(err)
	}
	record, _ := store.Load()
	if *record.Body != secondBody || resources.Rules().DirectDomains[0] != "current.cn" {
		t.Fatal("stale resource won")
	}
}

type failResourceStore struct {
	ResourceStore
	fail bool
}

func (s *failResourceStore) Save(v ResourceCache, current func() bool) error {
	if s.fail {
		return errors.New("disk full")
	}
	return s.ResourceStore.Save(v, current)
}
func TestResourceDiskFailureAndUnknownKeysDoNotAdvance(t *testing.T) {
	f := newSignedFixture(t)
	body, _, signed := resourceCandidate(t, f, 1, "first.cn", "rules-1")
	directory := t.TempDir()
	store := &failResourceStore{ResourceStore: NewJSONStore[ResourceCache](filepath.Join(directory, "rules.json"), 0)}
	calls := 0
	transport := transportFunc(func(context.Context, HTTPRequest) (HTTPResponse, error) {
		calls++
		return HTTPResponse{Status: 200, Body: body}, nil
	})
	resources, _ := NewResourceCoordinator(f.build, resourceBaseline(), store, transport, func() int64 { return f.now })
	if err := resources.Apply(context.Background(), strings.Replace(signed, `"p1"`, `"unknown"`, 1)); err == nil || calls != 0 {
		t.Fatal("untrusted signature fetched")
	}
	if err := resources.Apply(context.Background(), signed); err != nil {
		t.Fatal(err)
	}
	body, _, signed = resourceCandidate(t, f, 2, "second.cn", "rules-2")
	store.fail = true
	if err := resources.Apply(context.Background(), signed); err == nil {
		t.Fatal("disk failure ignored")
	}
	if resources.Rules().DirectDomains[0] != "first.cn" {
		t.Fatal("undurable rules activated")
	}
	store.fail = false
	if err := resources.Apply(context.Background(), signed); err != nil {
		t.Fatal(err)
	}
	if resources.Rules().DirectDomains[0] != "second.cn" {
		t.Fatal("failed persistence advanced identity")
	}
	files, _ := os.ReadDir(directory)
	if len(files) != 1 {
		t.Fatal("temporary files leaked")
	}
}
