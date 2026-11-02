package core

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type syncTestPanel struct {
	account    func(context.Context, string, Session) (Account, error)
	descriptor func(context.Context, string, Session) (SubscriptionDescriptor, error)
	nodes      func(context.Context, SubscriptionDescriptor) (string, error)
}

func (p *syncTestPanel) Login(context.Context, string, string, string) (Session, error) {
	return Session{}, nil
}
func (p *syncTestPanel) FetchAccount(ctx context.Context, e string, s Session) (Account, error) {
	return p.account(ctx, e, s)
}
func (p *syncTestPanel) FetchSubscriptionDescriptor(ctx context.Context, e string, s Session) (SubscriptionDescriptor, error) {
	return p.descriptor(ctx, e, s)
}
func (p *syncTestPanel) FetchNodes(ctx context.Context, d SubscriptionDescriptor) (string, error) {
	return p.nodes(ctx, d)
}
func (p *syncTestPanel) Logout(context.Context, string, Session) error { return nil }

type syncHarness struct {
	mu                         sync.Mutex
	active                     *Session
	saved                      Snapshot
	account                    Account
	restrictions               map[ErrorCode]bool
	done                       []ErrorCode
	commits                    int
	accounts                   []string
	nodeCalls, descriptorCalls int
	panel                      *syncTestPanel
	coordinator                *SyncCoordinator
}

func newSyncHarness(t *testing.T) *syncHarness {
	build, session, account, parsed, snapshot := authFixture(t)
	build.APIEndpoints = []APIEndpoint{{ID: "primary", Priority: 10}, {ID: "backup", Priority: 20}}
	h := &syncHarness{active: &session, saved: snapshot, account: account, restrictions: map[ErrorCode]bool{}}
	h.panel = &syncTestPanel{account: func(_ context.Context, e string, _ Session) (Account, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.accounts = append(h.accounts, e)
		return account, nil
	}, descriptor: func(context.Context, string, Session) (SubscriptionDescriptor, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.descriptorCalls++
		return SubscriptionDescriptor{URL: "https://example.invalid/", Format: "v2ray-uri-base64-v1"}, nil
	}, nodes: func(context.Context, SubscriptionDescriptor) (string, error) {
		h.mu.Lock()
		defer h.mu.Unlock()
		h.nodeCalls++
		return "fixture", nil
	}}
	hooks := SyncHooks{Session: func() *Session {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.active == nil {
			return nil
		}
		s := *h.active
		return &s
	}, Policy: func() *Policy { return nil }, Now: func() int64 { return authTestNow }, AccountCurrent: func(g string, a Account) bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.active == nil || h.active.Generation != g {
			return false
		}
		h.account = a
		return true
	}, RestrictCurrent: func(g string, c ErrorCode) bool {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.active == nil || h.active.Generation != g {
			return false
		}
		h.restrictions[c] = true
		return true
	}, Commit: func(ctx context.Context, s Snapshot) error {
		h.mu.Lock()
		defer h.mu.Unlock()
		if ctx.Err() != nil || h.active == nil || h.active.Generation != s.SessionGeneration {
			return NewAppError("CANCELLED")
		}
		h.saved = s
		h.commits++
		return nil
	}, DoneCurrent: func(g string, c ErrorCode) {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.active != nil && h.active.Generation == g {
			h.done = append(h.done, c)
		}
	}, Parse: func(context.Context, string, SubscriptionDescriptor) (ParsedNodes, error) { return parsed, nil }}
	h.coordinator = NewSyncCoordinator(build, h.panel, NewEndpointPool(build.APIEndpoints, func() int64 { return authTestNow }), hooks)
	return h
}
func runSync(t *testing.T, h *syncHarness, full bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := h.coordinator.Request(ctx, full); err != nil {
		t.Fatal(err)
	}
}
func TestSyncRestartsFullReadAtBackupAndDoesNotExtendOnFailure(t *testing.T) {
	h := newSyncHarness(t)
	var calls atomic.Int32
	h.panel.nodes = func(context.Context, SubscriptionDescriptor) (string, error) {
		if calls.Add(1) == 1 {
			return "", NewAppError("CONTROL_UNAVAILABLE")
		}
		return "fixture", nil
	}
	runSync(t, h, true)
	if h.commits != 1 || len(h.accounts) != 2 || h.accounts[0] != "primary" || h.accounts[1] != "backup" {
		t.Fatalf("failover %#v commits%d", h.accounts, h.commits)
	}
	failed := newSyncHarness(t)
	until := failed.saved.UsableUntil
	failed.panel.nodes = func(context.Context, SubscriptionDescriptor) (string, error) {
		return "", NewAppError("CONTROL_UNAVAILABLE")
	}
	runSync(t, failed, true)
	if failed.commits != 0 || failed.saved.UsableUntil != until || failed.done[0] != "CONTROL_UNAVAILABLE" {
		t.Fatal("failed subscription replaced snapshot")
	}
}
func TestSyncRateLimitAuthAndBanNeverFailOver(t *testing.T) {
	for _, code := range []ErrorCode{"RATE_LIMITED", "AUTH_INVALID", "ACCOUNT_BANNED"} {
		t.Run(string(code), func(t *testing.T) {
			h := newSyncHarness(t)
			calls := 0
			h.panel.account = func(context.Context, string, Session) (Account, error) {
				calls++
				if code == "ACCOUNT_BANNED" {
					a := h.account
					a.Banned = "yes"
					return a, nil
				}
				return Account{}, &AppError{Code: code, RetryAfterMs: 120000}
			}
			runSync(t, h, true)
			if calls != 1 || h.nodeCalls != 0 || h.commits != 0 {
				t.Fatalf("denial failed over %d", calls)
			}
			if code != "RATE_LIMITED" && !h.restrictions[code] {
				t.Fatal("denial not latched")
			}
			if len(h.done) != 1 || h.done[0] != code {
				t.Fatalf("done %#v", h.done)
			}
		})
	}
}
func TestSyncRefreshesSubscriptionCredentialsOnce(t *testing.T) {
	h := newSyncHarness(t)
	var calls atomic.Int32
	h.panel.nodes = func(context.Context, SubscriptionDescriptor) (string, error) {
		calls.Add(1)
		return "", NewAppError("SUBSCRIPTION_CREDENTIAL_INVALID")
	}
	runSync(t, h, true)
	if calls.Load() != 2 || h.descriptorCalls != 2 || h.restrictions["AUTH_INVALID"] || h.commits != 0 {
		t.Fatal("incorrect subscription retry")
	}
}
func TestSyncDelayedResponseCannotCommitOrRestrictAfterLogout(t *testing.T) {
	for _, denial := range []bool{false, true} {
		h := newSyncHarness(t)
		entered := make(chan struct{})
		release := make(chan struct{})
		h.panel.account = func(context.Context, string, Session) (Account, error) {
			close(entered)
			<-release
			if denial {
				return Account{}, NewAppError("AUTH_INVALID")
			}
			return h.account, nil
		}
		done := make(chan struct{})
		go func() { _ = h.coordinator.Request(context.Background(), true); close(done) }()
		<-entered
		h.mu.Lock()
		h.active = nil
		h.mu.Unlock()
		h.coordinator.Cancel()
		close(release)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("cancel stalled")
		}
		if h.commits != 0 || len(h.done) != 0 || len(h.restrictions) != 0 {
			t.Fatal("stale result reached new state")
		}
	}
}
func TestSyncCoalescesAndUpgradesPolling(t *testing.T) {
	for _, full := range []bool{false, true} {
		h := newSyncHarness(t)
		entered := make(chan struct{})
		release := make(chan struct{})
		original := h.panel.account
		var calls atomic.Int32
		h.panel.account = func(ctx context.Context, e string, s Session) (Account, error) {
			if calls.Add(1) == 1 {
				close(entered)
				<-release
			}
			return original(ctx, e, s)
		}
		first := make(chan struct{})
		second := make(chan struct{})
		go func() { _ = h.coordinator.Request(context.Background(), full); close(first) }()
		<-entered
		go func() { _ = h.coordinator.Request(context.Background(), true); close(second) }()
		deadline := time.Now().Add(time.Second)
		for {
			h.coordinator.mu.Lock()
			queued := h.coordinator.pendingFull
			h.coordinator.mu.Unlock()
			if full || queued {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("upgrade not queued")
			}
			time.Sleep(time.Millisecond)
		}
		if full {
			time.Sleep(5 * time.Millisecond)
		}
		close(release)
		<-first
		<-second
		want := int32(2)
		if full {
			want = 1
		}
		if calls.Load() != want || h.commits != 1 {
			t.Fatalf("full=%v calls%d commits%d", full, calls.Load(), h.commits)
		}
	}
}
func TestSyncNewSessionQueuesAfterCancellation(t *testing.T) {
	h := newSyncHarness(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	original := h.panel.account
	var calls atomic.Int32
	h.panel.account = func(ctx context.Context, e string, s Session) (Account, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
		}
		return original(ctx, e, s)
	}
	done := make(chan struct{})
	go func() { _ = h.coordinator.Request(context.Background(), true); close(done) }()
	<-entered
	h.coordinator.Cancel()
	h.mu.Lock()
	session := *h.active
	session.Generation = "new-session"
	h.active = &session
	h.mu.Unlock()
	next := make(chan struct{})
	go func() { _ = h.coordinator.Request(context.Background(), true); close(next) }()
	deadline := time.Now().Add(time.Second)
	for {
		h.coordinator.mu.Lock()
		queued := h.coordinator.pendingFull
		h.coordinator.mu.Unlock()
		if queued {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("new sync not queued")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	<-done
	<-next
	if h.commits != 1 || h.saved.SessionGeneration != "new-session" {
		t.Fatalf("startup lost: commits%d saved%s", h.commits, h.saved.SessionGeneration)
	}
}
func TestSyncPersistenceFailureNeverPublishes(t *testing.T) {
	h := newSyncHarness(t)
	h.coordinator.hooks.Commit = func(context.Context, Snapshot) error { return NewAppError("STORAGE_FAILED") }
	runSync(t, h, true)
	if h.commits != 0 || h.done[0] != "STORAGE_FAILED" {
		t.Fatal("disk failure published snapshot")
	}
}

// A sync inside the backoff reaches no server; counting it as a failure doubled the
// backoff on every retry and kept the app on RATE_LIMITED.
func TestSyncInsideBackoffDoesNotExtendIt(t *testing.T) {
	h := newSyncHarness(t)
	calls := 0
	h.panel.account = func(context.Context, string, Session) (Account, error) {
		calls++
		return Account{}, NewAppError("CONTROL_UNAVAILABLE")
	}
	runSync(t, h, true)
	h.coordinator.mu.Lock()
	failures, until := h.coordinator.failures, h.coordinator.blockedUntil
	h.coordinator.mu.Unlock()
	if failures != 1 || until <= authTestNow {
		t.Fatalf("failure not backed off: failures %d until %d", failures, until)
	}
	attempts := calls
	runSync(t, h, true)
	runSync(t, h, true)
	h.coordinator.mu.Lock()
	defer h.coordinator.mu.Unlock()
	if calls != attempts || h.coordinator.failures != 1 || h.coordinator.blockedUntil != until {
		t.Fatalf("backoff extended: calls %d->%d failures %d until %d->%d", attempts, calls, h.coordinator.failures, until, h.coordinator.blockedUntil)
	}
	if len(h.done) != 3 || h.done[1] != "RATE_LIMITED" || h.done[2] != "RATE_LIMITED" {
		t.Fatalf("done %#v", h.done)
	}
}
