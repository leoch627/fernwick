package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type lifecyclePanel struct {
	DemoPanel
	mu      sync.Mutex
	wait    <-chan struct{}
	onRead  func()
	expired bool
	reads   int
	nodes   int
}

func (p *lifecyclePanel) FetchAccount(ctx context.Context, endpoint string, session Session) (Account, error) {
	p.mu.Lock()
	p.reads++
	wait, read, expired := p.wait, p.onRead, p.expired
	p.mu.Unlock()
	if read != nil {
		read()
	}
	if wait != nil {
		<-wait
	}
	account, err := p.DemoPanel.FetchAccount(ctx, endpoint, session)
	if expired {
		expiry := isoTime(time.Now().UnixMilli() - 10000)
		account.ExpiresAt = &expiry
		account.ServiceAllowed = "no"
	}
	return account, err
}
func (p *lifecyclePanel) FetchNodes(ctx context.Context, d SubscriptionDescriptor) (string, error) {
	if p.nodes == 0 {
		return p.DemoPanel.FetchNodes(ctx, d)
	}
	lines := []string{}
	for i := range p.nodes {
		lines = append(lines, fmt.Sprintf("vless://00000000-0000-4000-8000-000000000001@node%d.example.invalid:443?security=tls&type=tcp&sni=node%d.example.invalid#Node%d", i, i, i))
	}
	return strings.Join(lines, "\n"), nil
}
func (p *lifecyclePanel) readCount() int { p.mu.Lock(); defer p.mu.Unlock(); return p.reads }

type lifecycleDriver struct {
	starts, cleanups, inits atomic.Int32
	mu                      sync.Mutex
	initializeWait          <-chan struct{}
	initializeEntered       chan struct{}
	cleanError              error
}

func (d *lifecycleDriver) Verified() bool                                     { return true }
func (d *lifecycleDriver) Prepare(context.Context, Candidate) (string, error) { return "fixture", nil }
func (d *lifecycleDriver) Protect(context.Context, string, time.Time) error   { return nil }
func (d *lifecycleDriver) Start(context.Context, string) error                { d.starts.Add(1); return nil }
func (d *lifecycleDriver) Probe(context.Context, string) (NetworkProof, error) {
	return NetworkProof{true, true, true, true}, nil
}
func (d *lifecycleDriver) Commit(context.Context, string) error { return nil }
func (d *lifecycleDriver) Cleanup(context.Context) error {
	d.cleanups.Add(1)
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cleanError
}
func (d *lifecycleDriver) Initialize(ctx context.Context) error {
	d.inits.Add(1)
	d.mu.Lock()
	wait, entered := d.initializeWait, d.initializeEntered
	d.initializeEntered = nil
	d.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if wait != nil {
		select {
		case <-wait:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

type controllerHarness struct {
	controller *ClientController
	panel      *lifecyclePanel
	driver     *lifecycleDriver
	secure     *SecureStore[Persisted]
}

func newControllerHarness(t *testing.T, change func(*ControllerDeps), connect bool) *controllerHarness {
	t.Helper()
	var build BuildConfig
	raw, err := os.ReadFile("../../config/development.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = DecodeStrict(raw, &build, 262144); err != nil {
		t.Fatal(err)
	}
	build.NodeCapabilitiesConfirmed = true
	build.PolicyURLs = []string{}
	build.UpdateFeedURLs = []string{}
	directory := t.TempDir()
	panel := &lifecyclePanel{}
	driver := &lifecycleDriver{}
	secure := NewSecureStore[Persisted](filepath.Join(directory, "secret"), KeyProviderFunc(func(bool) ([]byte, error) { return nil, ErrKeyUnavailable }))
	deps := ControllerDeps{Build: build, Panel: panel, Secure: secure, Preferences: NewJSONStore[Preferences](filepath.Join(directory, "preferences"), 0), PolicyStore: NewJSONStore[PolicyRecord](filepath.Join(directory, "policy"), 0), ReleaseStore: NewJSONStore[PolicyRecord](filepath.Join(directory, "release"), 0), NetworkDriver: driver, Probe: func(context.Context, ProxyNode) (ProbeResult, error) {
		latency := 1.0
		return ProbeResult{Healthy: true, LatencyMs: &latency}, nil
	}, HTTP: transportFunc(func(context.Context, HTTPRequest) (HTTPResponse, error) {
		return HTTPResponse{}, errors.New("test has no live network")
	}), Parse: func(ctx context.Context, raw string, desc SubscriptionDescriptor) (ParsedNodes, error) {
		if ctx.Err() != nil {
			return ParsedNodes{}, NewAppError("CANCELLED")
		}
		return ParseSubscription(raw, ParserOptions{Capabilities: build.ProtocolCapabilities, ConfirmedTCPUDP: true, Source: "fixture", AuthoritativeEmpty: desc.AuthoritativeEmpty})
	}, OpenExternal: func(string, string) (bool, error) { return false, nil }, ExportDiagnostics: func(any) error { return nil }, LaunchAtLogin: func(bool) error { return nil }}
	if change != nil {
		change(&deps)
	}
	controller := NewClientController(deps)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = controller.Stop(ctx)
	})
	if err = controller.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	login := commandForTest(controller, map[string]any{"type": "login", "email": "test@example.invalid", "password": "fixture-only"})
	if !login.OK {
		t.Fatalf("login failed %+v", login)
	}
	if connect {
		result := commandForTest(controller, map[string]any{"type": "connect"})
		if !result.OK || result.State.Connection != "Connected" {
			t.Fatalf("connect failed %+v", result)
		}
	}
	return &controllerHarness{controller, panel, driver, secure}
}
func commandForTest(c *ClientController, value any) CommandResult {
	raw, _ := json.Marshal(value)
	return c.Command(context.Background(), raw)
}
func TestControllerNetworkRecoveryCoalescesAndManualDisconnectWins(t *testing.T) {
	h := newControllerHarness(t, nil, true)
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	h.panel.mu.Lock()
	h.panel.wait = release
	h.panel.onRead = func() { once.Do(func() { close(entered) }) }
	h.panel.mu.Unlock()
	before := h.panel.readCount()
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			if err := h.controller.NetworkChanged(context.Background(), true); err != nil {
				t.Error(err)
			}
		})
	}
	<-entered
	time.Sleep(10 * time.Millisecond)
	close(release)
	wg.Wait()
	if h.panel.readCount() != before+1 || h.driver.starts.Load() != 2 || h.controller.View().Connection != "Connected" {
		t.Fatal("network recovery did not coalesce")
	}
	entered = make(chan struct{})
	release = make(chan struct{})
	once = sync.Once{}
	h.panel.mu.Lock()
	h.panel.wait = release
	h.panel.onRead = func() { once.Do(func() { close(entered) }) }
	h.panel.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- h.controller.NetworkChanged(context.Background(), true) }()
	<-entered
	if result := commandForTest(h.controller, map[string]any{"type": "disconnect"}); !result.OK {
		t.Fatal(result)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if h.driver.starts.Load() != 2 || h.controller.View().Connection != "Disconnected" {
		t.Fatal("late reconnect undid user disconnect")
	}
}
func TestControllerSuspendResumePreservesIntentOnce(t *testing.T) {
	h := newControllerHarness(t, nil, true)
	if err := h.controller.Suspend(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.controller.View().Connection != "Disconnected" {
		t.Fatal("suspend did not clean")
	}
	if err := h.controller.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.controller.Resume(context.Background()); err != nil {
		t.Fatal(err)
	}
	if h.driver.starts.Load() != 2 || h.controller.View().Connection != "Connected" {
		t.Fatal("resume repeated or lost intent")
	}
}
func TestControllerSuspendedDisconnectLogoutAndExpiryForbidReconnect(t *testing.T) {
	for _, kind := range []string{"disconnect", "logout", "expired"} {
		t.Run(kind, func(t *testing.T) {
			h := newControllerHarness(t, nil, true)
			if err := h.controller.Suspend(context.Background()); err != nil {
				t.Fatal(err)
			}
			if kind == "expired" {
				h.panel.mu.Lock()
				h.panel.expired = true
				h.panel.mu.Unlock()
			} else {
				if result := commandForTest(h.controller, map[string]any{"type": kind}); !result.OK {
					t.Fatal(result)
				}
			}
			if err := h.controller.Resume(context.Background()); err != nil {
				t.Fatal(err)
			}
			if h.driver.starts.Load() != 1 || h.controller.View().Connection != "Disconnected" {
				t.Fatal("resume revived denied intent")
			}
		})
	}
}
func TestControllerNativeRecoveryCoalescesAndRespectsManualDisconnect(t *testing.T) {
	h := newControllerHarness(t, nil, true)
	entered := make(chan struct{})
	release := make(chan struct{})
	h.driver.mu.Lock()
	h.driver.initializeWait = release
	h.driver.initializeEntered = entered
	h.driver.mu.Unlock()
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { first <- h.controller.NativeFailure(context.Background(), "COMPONENTS_UNAVAILABLE") }()
	<-entered
	go func() { second <- h.controller.NativeFailure(context.Background(), "COMPONENTS_UNAVAILABLE") }()
	time.Sleep(10 * time.Millisecond)
	if result := commandForTest(h.controller, map[string]any{"type": "disconnect"}); !result.OK {
		t.Fatal(result)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if h.driver.inits.Load() != 2 || h.driver.starts.Load() != 1 || h.controller.View().Connection != "Disconnected" {
		t.Fatal("native recovery raced or reconnected")
	}
}
func TestControllerLateAccountAndProbeResultsAfterLogoutAreDiscarded(t *testing.T) {
	h := newControllerHarness(t, nil, false)
	entered := make(chan struct{})
	release := make(chan struct{})
	h.panel.mu.Lock()
	h.panel.wait = release
	h.panel.onRead = func() { close(entered) }
	h.panel.mu.Unlock()
	syncDone := make(chan error, 1)
	go func() { syncDone <- h.controller.refresh(context.Background(), true) }()
	<-entered
	if result := commandForTest(h.controller, map[string]any{"type": "logout"}); !result.OK {
		t.Fatal(result)
	}
	close(release)
	if err := <-syncDone; err != nil {
		t.Fatal(err)
	}
	view := h.controller.View()
	if view.LoggedIn || view.Account != nil || len(view.Nodes) != 0 {
		t.Fatal("logout resurrected account")
	}
}
func TestControllerPublicViewContainsNoSecrets(t *testing.T) {
	h := newControllerHarness(t, nil, false)
	raw, err := EncodeJSON(h.controller.View())
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"development-fixture-only", "00000000-0000-4000-8000-000000000000", "node0.example.invalid", "token", "credential", "subscribe_url"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("public state leaked %q", secret)
		}
	}
	if !strings.Contains(string(raw), `"nodes":[`) {
		t.Fatal("public nodes null")
	}
}
