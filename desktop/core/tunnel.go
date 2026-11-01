package core

import (
	"context"
	"sync"
	"time"
)

// TunnelDriver sends each connection to the system proxy driver or the TUN driver, as
// the candidate's tunnel asks. Cleanup covers both, so whatever an interrupted session
// left behind is undone at the next start, whichever tunnel is chosen then.
type TunnelDriver struct {
	Proxy, TUN NetworkDriver
	mu         sync.Mutex
	active     NetworkDriver
}

func NewTunnelDriver(proxy, tun NetworkDriver) *TunnelDriver {
	return &TunnelDriver{Proxy: proxy, TUN: tun}
}
func (t *TunnelDriver) pick(tunnel string) NetworkDriver {
	if tunnel == "tun" {
		return t.TUN
	}
	return t.Proxy
}

// Verified reports the network service, which the window shows as component state.
func (t *TunnelDriver) Verified() bool { return t.TUN.Verified() }

// VerifiedFor reports whether a connection through tunnel can start now.
func (t *TunnelDriver) VerifiedFor(tunnel string) bool { return t.pick(tunnel).Verified() }

// EnsureReadyFor installs the network service when TUN needs it; system proxy mode
// has nothing to install.
func (t *TunnelDriver) EnsureReadyFor(ctx context.Context, tunnel string) error {
	if tunnel != "tun" {
		return nil
	}
	if driver, ok := t.TUN.(interface{ EnsureReady(context.Context) error }); ok {
		return driver.EnsureReady(ctx)
	}
	return nil
}
func (t *TunnelDriver) Repair(ctx context.Context) error {
	if driver, ok := t.TUN.(interface{ Repair(context.Context) error }); ok {
		return driver.Repair(ctx)
	}
	return NewAppError("COMPONENTS_UNAVAILABLE")
}
func (t *TunnelDriver) Initialize(ctx context.Context) error {
	if driver, ok := t.TUN.(interface{ Initialize(context.Context) error }); ok {
		return driver.Initialize(ctx)
	}
	return nil
}

// ProxyPort is the loopback proxy port while connected in system proxy mode.
func (t *TunnelDriver) ProxyPort() int {
	if driver, ok := t.Proxy.(interface{ Port() int }); ok {
		return driver.Port()
	}
	return 0
}
func (t *TunnelDriver) current() NetworkDriver {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active == nil {
		return UnavailableDriver{}
	}
	return t.active
}
func (t *TunnelDriver) Prepare(ctx context.Context, candidate Candidate) (string, error) {
	driver := t.pick(candidate.Tunnel)
	t.mu.Lock()
	t.active = driver
	t.mu.Unlock()
	return driver.Prepare(ctx, candidate)
}
func (t *TunnelDriver) Protect(ctx context.Context, ticket string, deadline time.Time) error {
	return t.current().Protect(ctx, ticket, deadline)
}
func (t *TunnelDriver) Start(ctx context.Context, ticket string) error {
	return t.current().Start(ctx, ticket)
}
func (t *TunnelDriver) Probe(ctx context.Context, ticket string) (NetworkProof, error) {
	return t.current().Probe(ctx, ticket)
}
func (t *TunnelDriver) Commit(ctx context.Context, ticket string) error {
	return t.current().Commit(ctx, ticket)
}
func (t *TunnelDriver) Cleanup(ctx context.Context) error {
	proxyErr := t.Proxy.Cleanup(ctx)
	tunErr := t.TUN.Cleanup(ctx)
	t.mu.Lock()
	t.active = nil
	t.mu.Unlock()
	if proxyErr != nil {
		return proxyErr
	}
	return tunErr
}
