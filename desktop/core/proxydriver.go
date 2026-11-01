package core

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

// PreferredProxyPort is tried first so that tools configured for the common local
// proxy port keep working; a busy port falls back to any free one.
const PreferredProxyPort = 7890

// ProxyDriver connects in system proxy mode: it runs the pinned core as the user with a
// loopback HTTP/SOCKS port, proves the proxy path, then points the system proxy at the
// port. Nothing here needs administrator rights or the network service.
type ProxyDriver struct {
	mu        sync.Mutex
	core      *CoreRuntime
	system    SystemProxy
	journal   string
	targets   []HealthTarget
	failed    func(ErrorCode)
	preferred int

	ticket    string
	config    map[string]any
	ports     ProxyPorts
	saved     json.RawMessage
	process   *probeProcess
	stop      context.CancelFunc
	connected bool
}

func NewProxyDriver(core *CoreRuntime, system SystemProxy, journal string, targets []HealthTarget, failed func(ErrorCode)) *ProxyDriver {
	if failed == nil {
		failed = func(ErrorCode) {}
	}
	return &ProxyDriver{core: core, system: system, journal: journal, targets: targets, failed: failed, preferred: PreferredProxyPort}
}

func (d *ProxyDriver) Verified() bool { return d.core != nil && d.system != nil }

// Port is the loopback proxy port while connected, and 0 otherwise.
func (d *ProxyDriver) Port() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.connected {
		return 0
	}
	return d.ports.Local
}
func freeLoopbackPort(preferred int, avoid int) (int, error) {
	if preferred >= 1024 && preferred != avoid {
		if listener, err := net.Listen("tcp4", "127.0.0.1:"+strconv.Itoa(preferred)); err == nil {
			_ = listener.Close()
			return preferred, nil
		}
	}
	for range 8 {
		port, err := availableProbePort()
		if err != nil {
			return 0, err
		}
		if port != avoid && port >= 1024 {
			return port, nil
		}
	}
	return 0, NewAppError("COMPONENTS_UNAVAILABLE")
}
func (d *ProxyDriver) current(ticket string) error {
	if ticket == "" || ticket != d.ticket {
		return NewAppError("CANCELLED")
	}
	return nil
}
func (d *ProxyDriver) Prepare(ctx context.Context, candidate Candidate) (string, error) {
	if !d.Verified() {
		return "", NewAppError("COMPONENTS_UNAVAILABLE")
	}
	local, err := freeLoopbackPort(d.preferred, 0)
	if err != nil {
		return "", err
	}
	health, err := freeLoopbackPort(0, local)
	if err != nil {
		return "", err
	}
	var user [16]byte
	var password [24]byte
	if _, err = rand.Read(user[:]); err != nil {
		return "", err
	}
	if _, err = rand.Read(password[:]); err != nil {
		return "", err
	}
	ports := ProxyPorts{Local: local, Health: ProbeAuth{Port: health, User: hex.EncodeToString(user[:]), Password: base64.RawURLEncoding.EncodeToString(password[:])}}
	config, err := CompileSystemProxy(candidate, ports)
	if err != nil {
		return "", err
	}
	check, err := d.core.launchProxy(ctx, config, true)
	if err != nil {
		return "", err
	}
	select {
	case <-ctx.Done():
		_ = check.stop()
		return "", NewAppError("CANCELLED")
	case <-check.done:
		if check.err != nil {
			return "", NewAppError("NO_COMPATIBLE_NODES")
		}
	}
	// Settings left by an interrupted session are the user's real settings; keep them
	// rather than saving this app's own proxy as "previous".
	var saved json.RawMessage
	if journal, err := readProxyJournal(d.journal); err != nil {
		return "", err
	} else if journal != nil {
		saved = journal.Saved
	} else if saved, err = d.system.Snapshot(ctx); err != nil {
		return "", err
	}
	var id [24]byte
	if _, err = rand.Read(id[:]); err != nil {
		return "", err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ticket = hex.EncodeToString(id[:])
	d.config, d.ports, d.saved, d.connected = config, ports, saved, false
	return d.ticket, nil
}

// Protect has nothing to guard: the system proxy changes only once the path is proven.
func (d *ProxyDriver) Protect(_ context.Context, ticket string, _ time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.current(ticket)
}
func (d *ProxyDriver) Start(ctx context.Context, ticket string) error {
	d.mu.Lock()
	if err := d.current(ticket); err != nil || d.process != nil {
		d.mu.Unlock()
		return NewAppError("CANCELLED")
	}
	config, ports := d.config, d.ports
	d.mu.Unlock()
	// The core outlives this call; Cleanup ends it.
	run, stop := context.WithCancel(context.Background())
	process, err := d.core.launchProxy(run, config, false)
	if err != nil {
		stop()
		return err
	}
	d.mu.Lock()
	if d.current(ticket) != nil {
		d.mu.Unlock()
		stop()
		_ = process.stop()
		return NewAppError("CANCELLED")
	}
	d.process, d.stop = process, stop
	d.mu.Unlock()
	go func() {
		<-process.done
		d.mu.Lock()
		report := d.process == process && d.connected
		d.mu.Unlock()
		if report {
			d.failed("CONNECT_TIMEOUT")
		}
	}()
	for _, port := range []int{ports.Local, ports.Health.Port} {
		if err := waitProbeListener(ctx, port, process.done); err != nil {
			return err
		}
	}
	return nil
}

// Probe fetches a health target through the core's authenticated health port, which
// always uses the proxy path. DNS is reported proven with it: apps hand the proxy names.
func (d *ProxyDriver) Probe(ctx context.Context, ticket string) (NetworkProof, error) {
	d.mu.Lock()
	if err := d.current(ticket); err != nil {
		d.mu.Unlock()
		return NetworkProof{}, err
	}
	auth := d.ports.Health
	d.mu.Unlock()
	if len(d.targets) == 0 {
		return NetworkProof{TCP: true, DNS: true}, nil
	}
	for _, target := range d.targets {
		attempt, cancel := context.WithTimeout(ctx, 4*time.Second)
		_, err := probeHTTPSWithTLS(attempt, auth, target, d.core.probeTLS)
		cancel()
		if ctx.Err() != nil {
			return NetworkProof{}, NewAppError("CANCELLED")
		}
		if err == nil {
			return NetworkProof{TCP: true, DNS: true}, nil
		}
	}
	return NetworkProof{}, nil
}
func (d *ProxyDriver) Commit(ctx context.Context, ticket string) error {
	d.mu.Lock()
	if err := d.current(ticket); err != nil || d.process == nil {
		d.mu.Unlock()
		return NewAppError("CANCELLED")
	}
	saved, port := d.saved, d.ports.Local
	d.mu.Unlock()
	if err := writeProxyJournal(d.journal, proxyJournal{SchemaVersion: 1, Port: port, Saved: saved}); err != nil {
		return NewAppError("STORAGE_FAILED")
	}
	if err := d.system.Apply(ctx, saved, port); err != nil {
		// The failed connection's Cleanup puts back whatever part was already changed.
		return NewAppError("SYSTEM_PROXY_FAILED")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.current(ticket); err != nil {
		return err
	}
	d.connected = true
	return nil
}

// Cleanup ends the core and restores the system proxy from the journal. At startup it
// undoes a session that crashed; a restore that fails keeps the journal for a retry.
func (d *ProxyDriver) Cleanup(ctx context.Context) error {
	d.mu.Lock()
	process, stop := d.process, d.stop
	d.ticket, d.config, d.saved, d.process, d.stop, d.connected = "", nil, nil, nil, nil, false
	d.mu.Unlock()
	var result error
	if journal, err := readProxyJournal(d.journal); err != nil {
		result = err
	} else if journal != nil {
		if d.system == nil {
			result = NewAppError("SYSTEM_PROXY_FAILED")
		} else if err = d.system.Restore(ctx, journal.Saved); err != nil {
			result = err
		} else if err = os.Remove(d.journal); err != nil && !os.IsNotExist(err) {
			result = err
		}
	}
	// The system proxy goes back first, so apps never point at a port that just closed.
	if stop != nil {
		stop()
	}
	if process != nil {
		if err := process.stop(); err != nil && result == nil {
			result = err
		}
	}
	return result
}
