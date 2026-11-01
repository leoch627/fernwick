package core

import (
	"context"
	"errors"
	"math/rand/v2"
	"sync"
	"time"
)

type SyncHooks struct {
	Session         func() *Session
	Policy          func() *Policy
	Now             func() int64
	Snapshot        func() *Snapshot
	Account         func(Account)
	Restrict        func(ErrorCode)
	Commit          func(context.Context, Snapshot) error
	Done            func(ErrorCode)
	Parse           func(context.Context, string, SubscriptionDescriptor) (ParsedNodes, error)
	AccountCurrent  func(string, Account) bool
	RestrictCurrent func(string, ErrorCode) bool
	DoneCurrent     func(string, ErrorCode)
}
type syncFuture struct{ done chan struct{} }
type SyncCoordinator struct {
	mu                      sync.Mutex
	build                   BuildConfig
	panel                   Panel
	pool                    *EndpointPool
	hooks                   SyncHooks
	running                 *syncFuture
	cancel                  context.CancelFunc
	sequence                int64
	pendingFull, activeFull bool
	cancelled               bool
	blockedUntil            int64
	failures                int
}

func NewSyncCoordinator(build BuildConfig, panel Panel, pool *EndpointPool, hooks SyncHooks) *SyncCoordinator {
	if hooks.Now == nil {
		hooks.Now = func() int64 { return time.Now().UnixMilli() }
	}
	return &SyncCoordinator{build: build, panel: panel, pool: pool, hooks: hooks}
}
func (s *SyncCoordinator) Cancel() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sequence++
	s.cancelled = true
	if s.cancel != nil {
		s.cancel()
	}
	s.pendingFull = false
}
func (s *SyncCoordinator) Request(ctx context.Context, full bool) error {
	s.mu.Lock()
	f := s.running
	if f != nil {
		if full && (!s.activeFull || s.cancelled) {
			s.pendingFull = true
		}
	} else {
		f = &syncFuture{done: make(chan struct{})}
		s.running = f
		s.activeFull = full
		go s.run(f, full)
	}
	s.mu.Unlock()
	select {
	case <-ctx.Done():
		return NewAppError("CANCELLED")
	case <-f.done:
		return nil
	}
}
func (s *SyncCoordinator) run(f *syncFuture, full bool) {
	for {
		s.execute(full)
		s.mu.Lock()
		if s.pendingFull {
			s.pendingFull = false
			s.activeFull = true
			s.mu.Unlock()
			full = true
			continue
		}
		s.running = nil
		s.activeFull = false
		s.mu.Unlock()
		close(f.done)
		return
	}
}
func (s *SyncCoordinator) execute(full bool) {
	session := s.hooks.Session()
	if session == nil {
		return
	}
	copySession := *session
	session = &copySession
	operation, cancel := context.WithCancel(context.Background())
	network, networkCancel := context.WithTimeout(operation, 20*time.Second)
	defer networkCancel()
	defer cancel()
	s.mu.Lock()
	s.sequence++
	sequence := s.sequence
	s.cancel = cancel
	s.cancelled = false
	blocked := s.blockedUntil
	s.mu.Unlock()
	networkFinished := false
	fresh := func() error {
		if operation.Err() != nil || !networkFinished && network.Err() != nil {
			return NewAppError("CANCELLED")
		}
		s.mu.Lock()
		same := sequence == s.sequence
		s.mu.Unlock()
		active := s.hooks.Session()
		if !same || active == nil || active.Generation != session.Generation {
			return NewAppError("CANCELLED")
		}
		return nil
	}
	restrict := func(code ErrorCode) error {
		if s.hooks.RestrictCurrent != nil {
			if !s.hooks.RestrictCurrent(session.Generation, code) {
				return NewAppError("CANCELLED")
			}
		} else if s.hooks.Restrict != nil {
			s.hooks.Restrict(code)
		}
		return nil
	}
	perform := func() error {
		if s.hooks.Now() < blocked {
			return &AppError{Code: "RATE_LIMITED", RetryAfterMs: blocked - s.hooks.Now()}
		}
		policy := s.hooks.Policy()
		endpoints := s.pool.Candidates(policy)
		if len(endpoints) == 0 {
			if s.build.DeploymentVerified {
				return NewAppError("CONTROL_UNAVAILABLE")
			}
			return NewAppError("CONFIGURATION_REQUIRED")
		}
		var result error
		for _, endpoint := range endpoints {
			attempt := func() error {
				if err := fresh(); err != nil {
					return err
				}
				account, err := s.panel.FetchAccount(network, endpoint.ID, *session)
				if err != nil {
					return err
				}
				if err = fresh(); err != nil {
					return err
				}
				if account.AccountID != session.AccountID {
					return NewAppError("CONTROL_UNAVAILABLE")
				}
				if s.hooks.AccountCurrent != nil {
					if !s.hooks.AccountCurrent(session.Generation, account) {
						return NewAppError("CANCELLED")
					}
				} else if s.hooks.Account != nil {
					s.hooks.Account(account)
				}
				if denied := Restriction(account, s.hooks.Now()); denied != "" {
					if err := restrict(denied); err != nil {
						return err
					}
					return NewAppError(denied)
				}
				if !full {
					s.pool.Success(endpoint.ID)
					return nil
				}
				descriptor, err := s.panel.FetchSubscriptionDescriptor(network, endpoint.ID, *session)
				if err != nil {
					return err
				}
				if err = fresh(); err != nil {
					return err
				}
				raw, err := s.panel.FetchNodes(network, descriptor)
				if CodeOf(err) == "SUBSCRIPTION_CREDENTIAL_INVALID" {
					if err = fresh(); err != nil {
						return err
					}
					descriptor, err = s.panel.FetchSubscriptionDescriptor(network, endpoint.ID, *session)
					if err != nil {
						return err
					}
					if err = fresh(); err != nil {
						return err
					}
					raw, err = s.panel.FetchNodes(network, descriptor)
				}
				if err != nil {
					return err
				}
				if err = fresh(); err != nil {
					return err
				}
				networkFinished = true
				networkCancel()
				parseContext, parseCancel := context.WithTimeout(operation, 3*time.Second)
				defer parseCancel()
				parsed, err := s.hooks.Parse(parseContext, raw, descriptor)
				if parseContext.Err() != nil {
					if operation.Err() == nil {
						return NewAppError("SUBSCRIPTION_INVALID")
					}
					return NewAppError("CANCELLED")
				}
				if err != nil {
					return err
				}
				if err = fresh(); err != nil {
					return err
				}
				if account.ServiceAllowed != "yes" {
					return NewAppError("NO_SERVICE")
				}
				now := s.hooks.Now()
				age := MaxSnapshotAgeSec
				if policy := s.hooks.Policy(); policy != nil {
					age = policy.Refresh.MaxSnapshotAgeSec
				}
				snapshot, err := CreateSnapshot(s.build, *session, account, parsed, now, age, sequence)
				if err != nil {
					return err
				}
				if denied := Restriction(account, now); denied != "" {
					return NewAppError(denied)
				}
				if err = fresh(); err != nil {
					return err
				}
				if err = s.hooks.Commit(operation, snapshot); err != nil {
					return err
				}
				if err = fresh(); err != nil {
					return err
				}
				s.pool.Success(endpoint.ID)
				return nil
			}
			err := attempt()
			if err == nil {
				return nil
			}
			if stale := fresh(); stale != nil {
				return stale
			}
			code := CodeOf(err)
			if code == "AUTH_INVALID" {
				if err := restrict(code); err != nil {
					return err
				}
			}
			if !networkFinished && (code == "CONTROL_UNAVAILABLE" || code == "SUBSCRIPTION_INVALID") {
				s.pool.Failure(endpoint.ID)
				result = err
				continue
			}
			return err
		}
		if result != nil {
			return result
		}
		return NewAppError("CONTROL_UNAVAILABLE")
	}
	err := perform()
	code := ErrorCode("")
	if err != nil {
		code = CodeOf(err)
	}
	s.mu.Lock()
	same := sequence == s.sequence
	s.mu.Unlock()
	active := s.hooks.Session()
	same = same && active != nil && active.Generation == session.Generation
	if code == "CANCELLED" && same && operation.Err() == nil && network.Err() != nil && !networkFinished {
		code = "CONTROL_UNAVAILABLE"
	}
	s.mu.Lock()
	if same {
		if code == "" {
			s.failures = 0
			s.blockedUntil = 0
		} else if code != "CANCELLED" {
			s.failures++
			backoff := int64(float64(min(30000<<min(s.failures-1, 4), 300000)) * (0.9 + rand.Float64()*0.2))
			var app *AppError
			if errors.As(err, &app) {
				backoff = max(backoff, app.RetryAfterMs)
			}
			s.blockedUntil = s.hooks.Now() + backoff
		}
	}
	if sequence == s.sequence {
		s.cancel = nil
	}
	s.mu.Unlock()
	if same {
		if s.hooks.DoneCurrent != nil {
			s.hooks.DoneCurrent(session.Generation, code)
		} else if s.hooks.Done != nil {
			s.hooks.Done(code)
		}
	}
}
