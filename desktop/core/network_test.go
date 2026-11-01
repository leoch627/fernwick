package core

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testNetworkDriver struct {
	prepare                                                           func(context.Context) (string, error)
	start                                                             func(context.Context) error
	proof                                                             NetworkProof
	cleanErr                                                          error
	prepareCount, protectCount, startCount, commitCount, cleanupCount atomic.Int32
}

func (d *testNetworkDriver) Verified() bool { return true }
func (d *testNetworkDriver) Prepare(ctx context.Context, _ Candidate) (string, error) {
	d.prepareCount.Add(1)
	if d.prepare != nil {
		return d.prepare(ctx)
	}
	return "ticket", nil
}
func (d *testNetworkDriver) Protect(context.Context, string, time.Time) error {
	d.protectCount.Add(1)
	return nil
}
func (d *testNetworkDriver) Start(ctx context.Context, _ string) error {
	d.startCount.Add(1)
	if d.start != nil {
		return d.start(ctx)
	}
	return nil
}
func (d *testNetworkDriver) Probe(context.Context, string) (NetworkProof, error) { return d.proof, nil }
func (d *testNetworkDriver) Commit(context.Context, string) error                { d.commitCount.Add(1); return nil }
func (d *testNetworkDriver) Cleanup(context.Context) error                       { d.cleanupCount.Add(1); return d.cleanErr }
func healthyNetworkDriver() *testNetworkDriver {
	return &testNetworkDriver{proof: NetworkProof{true, true, true, true}}
}
func TestNetworkUnavailableNeverConnects(t *testing.T) {
	n := NewNetworkController(UnavailableDriver{}, nil)
	if err := n.Connect(context.Background(), Candidate{}, nil); CodeOf(err) != "COMPONENTS_UNAVAILABLE" {
		t.Fatal(err)
	}
	if v := n.View(); v.State != "Disconnected" || v.DesiredConnected {
		t.Fatal(v)
	}
}
func TestNetworkTCPAndDNSProofsRequired(t *testing.T) {
	for _, broken := range []func(*NetworkProof){func(p *NetworkProof) { p.TCP = false }, func(p *NetworkProof) { p.DNS = false }} {
		d := healthyNetworkDriver()
		broken(&d.proof)
		n := NewNetworkController(d, nil)
		if err := n.Connect(context.Background(), Candidate{}, nil); CodeOf(err) != "CONNECT_TIMEOUT" {
			t.Fatal(err)
		}
		if d.commitCount.Load() != 0 || d.cleanupCount.Load() != 1 || n.View().State != "Disconnected" {
			t.Fatal(n.View())
		}
	}
}
func TestNetworkConnectsWithoutUDPOrIPv6(t *testing.T) {
	d := healthyNetworkDriver()
	d.proof.UDP, d.proof.IPv6 = false, false
	n := NewNetworkController(d, nil)
	if err := n.Connect(context.Background(), Candidate{}, nil); err != nil {
		t.Fatal(err)
	}
	if d.commitCount.Load() != 1 || n.View().State != "Connected" {
		t.Fatal(n.View())
	}
}
func TestNetworkRevocationDuringPreparation(t *testing.T) {
	d := healthyNetworkDriver()
	started, release := make(chan struct{}), make(chan struct{})
	d.prepare = func(context.Context) (string, error) { close(started); <-release; return "ticket", nil }
	n := NewNetworkController(d, nil)
	var valid atomic.Bool
	valid.Store(true)
	result := make(chan error, 1)
	go func() { result <- n.Connect(context.Background(), Candidate{}, valid.Load) }()
	<-started
	valid.Store(false)
	close(release)
	if err := <-result; err == nil {
		t.Fatal("revoked preparation succeeded")
	}
	if d.protectCount.Load() != 0 || n.View().State != "Disconnected" {
		t.Fatal(n.View())
	}
}
func TestNetworkDisconnectCancelsLatePreparation(t *testing.T) {
	d := healthyNetworkDriver()
	started := make(chan struct{})
	d.prepare = func(ctx context.Context) (string, error) { close(started); <-ctx.Done(); return "ticket", nil }
	n := NewNetworkController(d, nil)
	result := make(chan error, 1)
	go func() { result <- n.Connect(context.Background(), Candidate{}, nil) }()
	<-started
	if err := n.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-result; CodeOf(err) != "CANCELLED" {
		t.Fatal(err)
	}
	if v := n.View(); v.State != "Disconnected" || v.DesiredConnected || d.startCount.Load() != 0 {
		t.Fatal(v)
	}
}
func TestNetworkAttemptReservesCleanupBudget(t *testing.T) {
	d := healthyNetworkDriver()
	d.start = func(ctx context.Context) error { <-ctx.Done(); return NewAppError("CANCELLED") }
	n := NewNetworkController(d, nil)
	n.attemptLimit = 20 * time.Millisecond
	n.transactionLimit = 200 * time.Millisecond
	n.cleanupLimit = 100 * time.Millisecond
	if err := n.Connect(context.Background(), Candidate{}, nil); CodeOf(err) != "CONNECT_TIMEOUT" {
		t.Fatal(err)
	}
	if d.cleanupCount.Load() != 1 || n.View().State != "Disconnected" {
		t.Fatal(n.View())
	}
}
func TestNetworkFailedCleanupRequiresRecovery(t *testing.T) {
	d := healthyNetworkDriver()
	d.start = func(context.Context) error { return NewAppError("CONNECT_TIMEOUT") }
	d.cleanErr = NewAppError("NETWORK_RECOVERY_REQUIRED")
	n := NewNetworkController(d, nil)
	if err := n.Connect(context.Background(), Candidate{}, nil); CodeOf(err) != "NETWORK_RECOVERY_REQUIRED" {
		t.Fatal(err)
	}
	if n.View().State != "RecoveryRequired" {
		t.Fatal(n.View())
	}
}
func TestNetworkSharedConnectAndDisconnect(t *testing.T) {
	d := healthyNetworkDriver()
	started, release := make(chan struct{}), make(chan struct{})
	d.prepare = func(context.Context) (string, error) { close(started); <-release; return "ticket", nil }
	n := NewNetworkController(d, nil)
	first := make(chan error, 1)
	go func() { first <- n.Connect(context.Background(), Candidate{}, nil) }()
	<-started
	var wait sync.WaitGroup
	for range 10 {
		wait.Go(func() {
			if err := n.Connect(context.Background(), Candidate{}, nil); err != nil {
				t.Error(err)
			}
		})
	}
	time.Sleep(10 * time.Millisecond)
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	wait.Wait()
	if d.prepareCount.Load() != 1 {
		t.Fatal(d.prepareCount.Load())
	}
	if err := n.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if v := n.View(); v.State != "Disconnected" || v.DesiredConnected {
		t.Fatal(v)
	}
}
