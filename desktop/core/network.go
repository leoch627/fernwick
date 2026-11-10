package core

import (
	"context"
	"sync"
	"time"
)

type ConnectionState string

// Candidate is one connection. Node is the user's node, or the best probed node when
// Automatic; Pool holds further nodes for the core's automatic and AI balancers.
// Tunnel picks the driver ("proxy" or "tun") and never reaches the network service.
type Candidate struct {
	Node            ProxyNode   `json:"node"`
	Pool            []ProxyNode `json:"pool,omitempty"`
	Automatic       bool        `json:"automatic,omitempty"`
	Mode            string      `json:"mode"`
	Tunnel          string      `json:"tunnel,omitempty"`
	Rules           Rules       `json:"rules"`
	AuthorizedUntil int64       `json:"authorizedUntil"`
}
type NetworkProof struct {
	TCP  bool `json:"tcp"`
	UDP  bool `json:"udp"`
	DNS  bool `json:"dns"`
	IPv6 bool `json:"ipv6"`
}
type NetworkDriver interface {
	Verified() bool
	Prepare(context.Context, Candidate) (string, error)
	Protect(context.Context, string, time.Time) error
	Start(context.Context, string) error
	Probe(context.Context, string) (NetworkProof, error)
	Commit(context.Context, string) error
	Cleanup(context.Context) error
}
type UnavailableDriver struct{}

func (UnavailableDriver) Verified() bool { return false }
func (UnavailableDriver) Prepare(context.Context, Candidate) (string, error) {
	return "", NewAppError("COMPONENTS_UNAVAILABLE")
}
func (UnavailableDriver) Protect(context.Context, string, time.Time) error {
	return NewAppError("COMPONENTS_UNAVAILABLE")
}
func (UnavailableDriver) Start(context.Context, string) error {
	return NewAppError("COMPONENTS_UNAVAILABLE")
}
func (UnavailableDriver) Probe(context.Context, string) (NetworkProof, error) {
	return NetworkProof{}, NewAppError("COMPONENTS_UNAVAILABLE")
}
func (UnavailableDriver) Commit(context.Context, string) error {
	return NewAppError("COMPONENTS_UNAVAILABLE")
}
func (UnavailableDriver) Cleanup(context.Context) error { return nil }

type NetworkStatus struct {
	State            ConnectionState
	DesiredConnected bool
	Generation       uint64
	LastError        *ErrorCode
	// Stage is the last connection step started (prepare, protect, start, probe,
	// commit) and Proof the last data-path check, for troubleshooting reports.
	Stage string
	Proof *NetworkProof
}
type networkFuture struct {
	done chan struct{}
	err  error
}
type NetworkController struct {
	mu                                                             sync.Mutex
	driver                                                         NetworkDriver
	changed                                                        func()
	status                                                         NetworkStatus
	running, stopping                                              *networkFuture
	abort                                                          context.CancelFunc
	preparationLimit, attemptLimit, transactionLimit, cleanupLimit time.Duration
}

func NewNetworkController(driver NetworkDriver, changed func()) *NetworkController {
	if driver == nil {
		driver = UnavailableDriver{}
	}
	if changed == nil {
		changed = func() {}
	}
	return &NetworkController{driver: driver, changed: changed, status: NetworkStatus{State: "Disconnected"}, preparationLimit: 10 * time.Second, attemptLimit: 12 * time.Second, transactionLimit: 15 * time.Second, cleanupLimit: 3 * time.Second}
}
func (n *NetworkController) Ready() bool { return n.driver.Verified() }

// ReadyFor reports whether a connection through tunnel can start. Drivers without a
// choice of tunnel answer with their own readiness.
func (n *NetworkController) ReadyFor(tunnel string) bool {
	if driver, ok := n.driver.(interface{ VerifiedFor(string) bool }); ok {
		return driver.VerifiedFor(tunnel)
	}
	return n.driver.Verified()
}

// EnsureReadyFor installs or repairs what tunnel needs, when the driver can.
func (n *NetworkController) EnsureReadyFor(ctx context.Context, tunnel string) error {
	if driver, ok := n.driver.(interface {
		EnsureReadyFor(context.Context, string) error
	}); ok {
		return driver.EnsureReadyFor(ctx, tunnel)
	}
	if driver, ok := n.driver.(interface{ EnsureReady(context.Context) error }); ok {
		return driver.EnsureReady(ctx)
	}
	return nil
}

// ProxyPort is the loopback proxy port while connected in system proxy mode, else 0.
func (n *NetworkController) ProxyPort() int {
	if driver, ok := n.driver.(interface{ ProxyPort() int }); ok && n.View().State == "Connected" {
		return driver.ProxyPort()
	}
	return 0
}

// Traffic is the core's byte counters while connected.
func (n *NetworkController) Traffic(ctx context.Context) (TrafficSample, bool) {
	if reader, ok := n.driver.(trafficReader); ok && n.View().State == "Connected" {
		return reader.Traffic(ctx)
	}
	return TrafficSample{}, false
}
func (n *NetworkController) View() NetworkStatus {
	n.mu.Lock()
	defer n.mu.Unlock()
	v := n.status
	if v.LastError != nil {
		code := *v.LastError
		v.LastError = &code
	}
	return v
}
func (n *NetworkController) set(state ConnectionState) {
	n.mu.Lock()
	n.status.State = state
	n.mu.Unlock()
	n.changed()
}
func waitNetwork(ctx context.Context, f *networkFuture) error {
	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return NewAppError("CANCELLED")
	}
}
func (n *NetworkController) Connect(ctx context.Context, candidate Candidate, gate func() bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if gate == nil {
		gate = func() bool { return true }
	}
	n.mu.Lock()
	if n.stopping != nil {
		n.mu.Unlock()
		return NewAppError("CANCELLED")
	}
	if n.running != nil {
		f := n.running
		n.mu.Unlock()
		return waitNetwork(ctx, f)
	}
	if !n.ReadyFor(candidate.Tunnel) {
		code := ErrorCode("COMPONENTS_UNAVAILABLE")
		n.status.LastError = &code
		n.mu.Unlock()
		n.changed()
		return NewAppError(code)
	}
	n.status.DesiredConnected = true
	n.status.Generation++
	generation := n.status.Generation
	runCtx, cancel := context.WithCancel(ctx)
	n.abort = cancel
	f := &networkFuture{done: make(chan struct{})}
	n.running = f
	n.mu.Unlock()
	err := n.connect(runCtx, candidate, gate, generation)
	cancel()
	n.mu.Lock()
	f.err = err
	n.running = nil
	n.abort = nil
	close(f.done)
	n.mu.Unlock()
	return err
}
func (n *NetworkController) valid(ctx context.Context, generation uint64, gate func() bool) error {
	n.mu.Lock()
	valid := n.status.DesiredConnected && generation == n.status.Generation
	n.mu.Unlock()
	if ctx.Err() != nil || !valid || !gate() {
		return NewAppError("CANCELLED")
	}
	return nil
}
func (n *NetworkController) connect(ctx context.Context, candidate Candidate, gate func() bool, generation uint64) (result error) {
	prepared := false
	var transactionDeadline time.Time
	defer func() {
		if result == nil {
			return
		}
		code := CodeOf(result)
		if ctx.Err() != nil {
			code = "CANCELLED"
		}
		n.mu.Lock()
		if code == "CANCELLED" && n.status.DesiredConnected && generation == n.status.Generation {
			code = "CONNECT_TIMEOUT"
		}
		n.status.LastError = &code
		n.status.DesiredConnected = false
		n.mu.Unlock()
		if prepared {
			n.set("Disconnecting")
			duration := n.cleanupLimit
			if !transactionDeadline.IsZero() {
				duration = min(duration, max(0, time.Until(transactionDeadline)))
			}
			cleanup, cancel := context.WithTimeout(context.Background(), duration)
			err := n.driver.Cleanup(cleanup)
			if cleanup.Err() != nil {
				err = cleanup.Err()
			}
			cancel()
			if err != nil {
				code = "NETWORK_RECOVERY_REQUIRED"
				n.mu.Lock()
				n.status.LastError = &code
				n.mu.Unlock()
				n.set("RecoveryRequired")
			} else {
				n.set("Disconnected")
			}
		} else {
			n.set("Disconnected")
		}
		result = NewAppError(code)
	}()
	stage := func(name string) {
		n.mu.Lock()
		n.status.Stage = name
		n.mu.Unlock()
	}
	n.mu.Lock()
	n.status.Proof = nil
	n.mu.Unlock()
	stage("prepare")
	n.set("Preparing")
	if err := n.valid(ctx, generation, gate); err != nil {
		return err
	}
	preparation, cancel := context.WithTimeout(ctx, n.preparationLimit)
	prepared = true
	ticket, err := n.driver.Prepare(preparation, candidate)
	if preparation.Err() != nil {
		err = NewAppError("CANCELLED")
	}
	cancel()
	if err != nil {
		return err
	}
	if err = n.valid(ctx, generation, gate); err != nil {
		return err
	}
	n.set("Connecting")
	transactionDeadline = time.Now().Add(n.transactionLimit)
	attempt, cancel := context.WithTimeout(ctx, n.attemptLimit)
	defer cancel()
	step := func(fn func() error) error {
		if err := fn(); err != nil {
			return err
		}
		return n.valid(attempt, generation, gate)
	}
	stage("protect")
	if err = step(func() error { return n.driver.Protect(attempt, ticket, transactionDeadline) }); err != nil {
		return err
	}
	stage("start")
	if err = step(func() error { return n.driver.Start(attempt, ticket) }); err != nil {
		return err
	}
	stage("probe")
	proof, err := n.driver.Probe(attempt, ticket)
	if err != nil {
		return err
	}
	n.mu.Lock()
	n.status.Proof = &proof
	n.mu.Unlock()
	if err = n.valid(attempt, generation, gate); err != nil {
		return err
	}
	if !proof.TCP || !proof.DNS {
		return NewAppError("CONNECT_TIMEOUT")
	}
	stage("commit")
	if err = step(func() error { return n.driver.Commit(attempt, ticket) }); err != nil {
		return err
	}
	n.mu.Lock()
	if generation != n.status.Generation || !n.status.DesiredConnected {
		n.mu.Unlock()
		return NewAppError("CANCELLED")
	}
	n.status.LastError = nil
	n.status.State = "Connected"
	n.mu.Unlock()
	n.changed()
	return nil
}
func (n *NetworkController) Disconnect(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	n.mu.Lock()
	if n.stopping != nil {
		f := n.stopping
		n.mu.Unlock()
		return waitNetwork(ctx, f)
	}
	n.status.DesiredConnected = false
	n.status.Generation++
	if n.abort != nil {
		n.abort()
	}
	running := n.running
	f := &networkFuture{done: make(chan struct{})}
	n.stopping = f
	n.mu.Unlock()
	var err error
	if running != nil {
		<-running.done
		if n.View().State == "RecoveryRequired" {
			err = NewAppError("NETWORK_RECOVERY_REQUIRED")
		}
	} else {
		n.set("Disconnecting")
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = n.driver.Cleanup(cleanup)
		if cleanup.Err() != nil {
			err = cleanup.Err()
		}
		cancel()
		n.mu.Lock()
		if err != nil {
			code := ErrorCode("NETWORK_RECOVERY_REQUIRED")
			n.status.LastError = &code
			n.status.State = "RecoveryRequired"
			err = NewAppError(code)
		} else {
			n.status.LastError = nil
			n.status.State = "Disconnected"
		}
		n.mu.Unlock()
		n.changed()
	}
	n.mu.Lock()
	f.err = err
	n.stopping = nil
	close(f.done)
	n.mu.Unlock()
	return err
}
func (n *NetworkController) ExternalFailure(code ErrorCode) {
	n.mu.Lock()
	n.status.DesiredConnected = false
	n.status.Generation++
	if n.abort != nil {
		n.abort()
	}
	n.status.LastError = &code
	n.status.State = "Disconnected"
	if code == "NETWORK_RECOVERY_REQUIRED" {
		n.status.State = "RecoveryRequired"
	}
	n.mu.Unlock()
	n.changed()
}
