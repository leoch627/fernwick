package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type service struct {
	mu             sync.Mutex
	operations     sync.Mutex
	journal        *Journal
	candidate      *Candidate
	configuration  []byte
	core           *exec.Cmd
	coreExit       chan error
	ticket         string
	heartbeat      time.Time
	authUntil      int64
	authDeadline   time.Time
	state          string
	cancel         context.CancelFunc
	deadline       time.Time
	transactionEnd time.Time
	recoveryAfter  time.Time
	recoveryDelay  time.Duration
	cleaning       bool
	started        bool
	proven         bool
}

func (s *service) base(p Peer, id string) Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Response{ID: id, OK: true, Protocol: protocolVersion, ProductID: build.ProductID, BuildID: build.BuildID, Version: build.Version, State: s.state, Ready: installed.BuildID == build.BuildID, Owned: s.journal != nil && s.journal.Owner.key() == p.key()}
}
func (s *service) authorized(p Peer, ticket string) bool {
	return s.journal != nil && s.journal.Owner.key() == p.key() && ticket != "" && ticket == s.ticket
}
func (s *service) request(p Peer, r Request) Response {
	response := s.base(p, r.ID)
	if r.Protocol != protocolVersion || r.ProductID != build.ProductID || len(r.ID) > 128 {
		response.OK = false
		response.Error = "COMPONENTS_UNAVAILABLE"
		return response
	}
	e := s.perform(p, r, &response)
	if e != nil && r.Action != "status" && r.Action != "heartbeat" && r.Action != "control" {
		logEvent("%s: %s", r.Action, cleanError(e))
	}
	current := s.base(p, r.ID)
	current.Ticket = response.Ticket
	current.Proof = response.Proof
	current.HTTP = response.HTTP
	if e != nil {
		current.OK = false
		current.Error = cleanError(e)
	}
	return current
}
func (s *service) perform(p Peer, r Request, response *Response) error {
	switch r.Action {
	case "status":
		return nil
	case "control":
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		// The interface of the default route now: while connected it can have changed
		// since the connection was made (Windows and macOS stay connected across it).
		physical, e := discoverInterface(ctx)
		if e != nil {
			s.mu.Lock()
			if s.journal != nil {
				physical, e = s.journal.Interface, nil
			}
			s.mu.Unlock()
			if e != nil {
				return e
			}
		}
		response.HTTP, e = controlRequest(ctx, r.HTTP, physical)
		return e
	case "heartbeat":
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.authorized(p, r.Ticket) {
			return failure("NETWORK_CONFLICT")
		}
		s.heartbeat = time.Now()
		if r.AuthorizedUntil != s.authUntil && r.AuthorizedUntil >= 0 && r.AuthorizedUntil <= time.Now().Add(maxAuthorization).UnixMilli()+2000 {
			s.authUntil = r.AuthorizedUntil
			s.authDeadline = time.Now().Add(time.Duration(r.AuthorizedUntil-time.Now().UnixMilli()) * time.Millisecond)
		}
		return nil
	case "stop", "recover":
		s.mu.Lock()
		if s.journal != nil && s.journal.Owner.key() != p.key() {
			s.mu.Unlock()
			return failure("NETWORK_CONFLICT")
		}
		if s.cancel != nil {
			s.cancel()
		}
		s.mu.Unlock()
		return s.cleanup()
	}
	s.operations.Lock()
	defer s.operations.Unlock()
	if r.Action == "stage-update" {
		s.mu.Lock()
		busy := s.journal != nil || s.cleaning || s.state == "RecoveryRequired"
		s.mu.Unlock()
		if busy {
			return failure("NETWORK_CONFLICT")
		}
		return stageUpdate(p, r)
	}
	if r.Action == "prepare" {
		s.mu.Lock()
		busy := s.journal != nil || s.cleaning || s.state == "RecoveryRequired"
		s.mu.Unlock()
		if busy {
			return failure("NETWORK_CONFLICT")
		}
		if e := r.Candidate.validate(); e != nil {
			return e
		}
		if e := ensureSameInstallation(); e != nil {
			return e
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		physical, e := discoverInterface(ctx)
		if e != nil {
			return e
		}
		address, e := resolvePhysical(ctx, r.Candidate.Node.Host, physical)
		if e != nil {
			return failure("CONNECT_TIMEOUT")
		}
		bypass := []string{address, "223.5.5.5"}
		pool := resolvePool(ctx, r.Candidate.Pool, physical)
		for _, ip := range pool {
			if ip != "" && !contains(bypass, ip) {
				bypass = append(bypass, ip)
			}
		}
		for _, host := range build.ControlHosts {
			if ip, e := resolvePhysical(ctx, host, physical); e == nil && !contains(bypass, ip) {
				bypass = append(bypass, ip)
			}
		}
		j := &Journal{SchemaVersion: 1, ID: nonce(), ProductID: build.ProductID, Owner: p, Phase: "Preparing", Interface: physical, Tun: tunName(), RouteIPv6: hasGlobalIPv6(), NodeAddress: address, PoolAddresses: pool, Bypass: bypass, CorePath: installed.CorePath, AuthorizedUntil: r.Candidate.AuthorizedUntil, Deadline: time.Now().Add(30 * time.Second).UnixMilli()}
		if e = platformPrepare(ctx, j); e != nil {
			return e
		}
		configuration := compileCore(*r.Candidate, *j)
		// Validate the in-memory candidate through the immutable, hash-checked core. Never re-open a user path.
		command := exec.CommandContext(ctx, installed.CorePath, "run", "-test", "-format", "json", "-config", "stdin:")
		command.Stdin = bytes.NewReader(configuration)
		command.Env = safeEnvironment()
		output := coreLog()
		command.Stdout = output
		command.Stderr = output
		configureChild(command)
		e = command.Run()
		output.Close()
		if e != nil {
			logEvent("prepare: the core rejected the configuration (see core.log): %v", e)
			return failure("NO_COMPATIBLE_NODES")
		}
		if e = writeJournal(j); e != nil {
			return failure("STORAGE_FAILED")
		}
		s.mu.Lock()
		s.journal = j
		s.candidate = r.Candidate
		s.configuration = configuration
		s.ticket = nonce()
		s.started = false
		s.proven = false
		s.heartbeat = time.Now()
		s.authUntil = j.AuthorizedUntil
		s.authDeadline = time.Now().Add(time.Duration(j.AuthorizedUntil-time.Now().UnixMilli()) * time.Millisecond)
		s.state = "Preparing"
		s.deadline = time.Now().Add(30 * time.Second)
		response.Ticket = s.ticket
		s.mu.Unlock()
		return nil
	}
	s.mu.Lock()
	if !s.authorized(p, r.Ticket) {
		s.mu.Unlock()
		return failure("NETWORK_CONFLICT")
	}
	j := s.journal
	s.mu.Unlock()
	if r.Action == "protect" {
		s.mu.Lock()
		if s.state != "Preparing" {
			s.mu.Unlock()
			return failure("INVALID_INPUT")
		}
		now := time.Now()
		s.deadline = now.Add(12 * time.Second)
		s.transactionEnd = now.Add(15 * time.Second)
		j.Deadline = s.transactionEnd.UnixMilli()
		// Where the core owns the routes, nothing guards the transition: like v2rayN,
		// traffic goes out directly until the core's routes are in place.
		j.Protection = !coreOwnsRoutes(runtime.GOOS)
		j.Phase = "Connecting"
		s.state = "Connecting"
		s.mu.Unlock()
		if e := writeJournal(j); e != nil {
			return failure("STORAGE_FAILED")
		}
		ctx, cancel := s.operationContext()
		defer cancel()
		return platformProtect(ctx, j)
	}
	if r.Action == "start" {
		ctx, cancel := s.operationContext()
		defer cancel()
		if e := s.current(j); e != nil {
			return e
		}
		s.mu.Lock()
		if s.started || s.state != "Connecting" {
			s.mu.Unlock()
			return failure("INVALID_INPUT")
		}
		s.started = true
		s.mu.Unlock()
		command := exec.Command(installed.CorePath, "run", "-format", "json", "-config", "stdin:")
		command.Stdin = bytes.NewReader(s.configuration)
		// The core logs nothing about traffic; what it prints is its version and why it
		// could not start (a missing driver, a refused route or filter).
		output := coreLog()
		command.Stdout = output
		command.Stderr = output
		command.Env = safeEnvironment()
		command.Dir = filepath.Dir(installed.CorePath)
		configureChild(command)
		if e := command.Start(); e != nil {
			output.Close()
			logEvent("start: the core could not be started: %v", e)
			return failure("COMPONENTS_UNAVAILABLE")
		}
		exited := make(chan error, 1)
		go func() { exited <- command.Wait(); output.Close(); close(exited) }()
		s.mu.Lock()
		s.core = command
		s.coreExit = exited
		j.CorePID = command.Process.Pid
		s.mu.Unlock()
		j.CoreBirth, _ = processBirth(command.Process.Pid)
		if e := attachCore(command); e != nil {
			_ = command.Process.Kill()
			return e
		}
		if e := writeJournal(j); e != nil {
			_ = command.Process.Kill()
			return failure("STORAGE_FAILED")
		}
		for {
			if _, e := net.InterfaceByName(j.Tun); e == nil {
				break
			}
			select {
			case <-ctx.Done():
				logEvent("start: the TUN %s did not appear in time", j.Tun)
				return errCancelled
			case <-exited:
				logEvent("start: the core exited before its TUN appeared (see core.log)")
				return failure("CONNECT_TIMEOUT")
			case <-time.After(30 * time.Millisecond):
			}
		}
		if e := s.current(j); e != nil {
			return e
		}
		j.Routes = true
		j.DNS = true
		if e := writeJournal(j); e != nil {
			return failure("STORAGE_FAILED")
		}
		return platformApply(ctx, j)
	}
	if r.Action == "probe" {
		ctx, cancel := s.operationContext()
		defer cancel()
		proof, e := probeDataPath(ctx, j)
		if e != nil {
			logEvent("probe: tcp=%t dns=%t udp=%t ipv6=%t", proof.TCP, proof.DNS, proof.UDP, proof.IPv6)
			return e
		}
		response.Proof = &proof
		s.mu.Lock()
		s.proven = proof.TCP && proof.DNS
		s.mu.Unlock()
		return s.current(j)
	}
	if r.Action == "commit" {
		if e := s.current(j); e != nil {
			return e
		}
		s.mu.Lock()
		proven := s.proven
		s.mu.Unlock()
		if !proven {
			return failure("CONNECT_TIMEOUT")
		}
		ctx, cancel := s.operationContext()
		defer cancel()
		if e := platformUnprotect(ctx, j); e != nil {
			return e
		}
		if e := s.current(j); e != nil {
			return e
		}
		s.mu.Lock()
		j.Protection = false
		j.Phase = "Connected"
		j.Deadline = 0
		s.transactionEnd = time.Time{}
		s.state = "Connected"
		s.mu.Unlock()
		return writeJournal(j)
	}
	return failure("INVALID_INPUT")
}

// resolvePool looks up the balancer nodes concurrently over the physical interface.
// A node that does not resolve in time is left out rather than failing the connection.
func resolvePool(parent context.Context, nodes []Node, physical Interface) []string {
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	addresses := make([]string, len(nodes))
	slots := make(chan struct{}, 8)
	var wait sync.WaitGroup
	for i, n := range nodes {
		wait.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			if ip, e := resolvePhysical(ctx, n.Host, physical); e == nil {
				addresses[i] = ip
			}
		})
	}
	wait.Wait()
	return addresses
}
func (s *service) operationContext() (context.Context, context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ctx, cancel := context.WithDeadline(context.Background(), s.deadline)
	s.cancel = cancel
	return ctx, cancel
}
func (s *service) current(j *Journal) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.journal != j || s.cleaning || time.Now().After(s.deadline) || time.Now().After(s.authDeadline) || time.Now().UnixMilli() >= s.authUntil || s.state == "Connecting" && time.Now().UnixMilli() >= j.Deadline-3000 {
		return errCancelled
	}
	return nil
}
func (s *service) cleanup() error {
	s.operations.Lock()
	defer s.operations.Unlock()
	s.mu.Lock()
	j := s.journal
	core := s.core
	exit := s.coreExit
	cleanupEnd := time.Now().Add(5 * time.Second)
	if !s.transactionEnd.IsZero() {
		cleanupEnd = time.Now().Add(3 * time.Second)
		if s.transactionEnd.Before(cleanupEnd) {
			cleanupEnd = s.transactionEnd
		}
	}
	s.cleaning = true
	s.state = "Disconnecting"
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	ctx, cancel := context.WithDeadline(context.Background(), cleanupEnd)
	defer cancel()
	var e error
	if core != nil && core.Process != nil {
		_ = terminateChild(core)
		grace := time.NewTimer(400 * time.Millisecond)
		select {
		case <-exit:
		case <-grace.C:
		case <-ctx.Done():
		}
		grace.Stop()
		select {
		case <-exit:
		default:
			_ = core.Process.Kill()
			select {
			case <-exit:
			case <-time.After(100 * time.Millisecond):
				e = failure("NETWORK_RECOVERY_REQUIRED")
			case <-ctx.Done():
				e = failure("NETWORK_RECOVERY_REQUIRED")
			}
		}
	} else if j != nil && j.CorePID > 0 {
		e = terminateOrphan(j)
	}
	if j != nil {
		// Reserve a separate portion of the same budget for removing the transition
		// guard. A slow route/DNS command must not consume its entire lifetime.
		recoverEnd := cleanupEnd
		if j.Protection {
			reserve := min(time.Second, max(time.Duration(0), time.Until(cleanupEnd)/2))
			recoverEnd = cleanupEnd.Add(-reserve)
		}
		recoverCtx, recoverCancel := context.WithDeadline(ctx, recoverEnd)
		if recoverErr := platformRecover(recoverCtx, j); recoverErr != nil {
			e = recoverErr
		} else if recoverCtx.Err() != nil {
			e = recoverCtx.Err()
		}
		recoverCancel()
		if guardErr := platformUnprotect(ctx, j); guardErr != nil {
			e = guardErr
		} else {
			j.Protection = false
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.core = nil
	s.coreExit = nil
	s.candidate = nil
	for i := range s.configuration {
		s.configuration[i] = 0
	}
	s.configuration = nil
	s.cancel = nil
	s.cleaning = false
	s.transactionEnd = time.Time{}
	if e == nil {
		if removeErr := os.Remove(filepath.Join(stateRoot(), "network.json")); removeErr != nil && !os.IsNotExist(removeErr) {
			e = removeErr
		}
	}
	if e != nil {
		s.state = "RecoveryRequired"
		if s.recoveryDelay == 0 {
			s.recoveryDelay = time.Second
		} else {
			s.recoveryDelay = min(30*time.Second, 2*s.recoveryDelay)
		}
		s.recoveryAfter = time.Now().Add(s.recoveryDelay)
		if j != nil {
			j.Phase = s.state
			_ = writeJournal(j)
		}
		return failure("NETWORK_RECOVERY_REQUIRED")
	}
	s.journal = nil
	s.ticket = ""
	s.state = "Disconnected"
	s.recoveryAfter = time.Time{}
	s.recoveryDelay = 0
	return nil
}
func (s *service) supervise(ctx context.Context) {
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.mu.Lock()
			j := s.journal
			expired := false
			if !s.cleaning && (j != nil || s.state == "RecoveryRequired") {
				now := time.Now().UnixMilli()
				if s.state == "RecoveryRequired" {
					// Retry removal only. Never start a core, renew protection, or reconnect.
					expired = !time.Now().Before(s.recoveryAfter)
				} else {
					expired = now >= s.authUntil || time.Now().After(s.authDeadline) || time.Since(s.heartbeat) > 3*time.Second || j.Phase != "Connected" && (now >= j.Deadline-3000 || time.Now().After(s.deadline))
				}
				if s.coreExit != nil {
					select {
					case <-s.coreExit:
						expired = true
					default:
					}
				}
				if expired {
					s.cleaning = true
					if s.cancel != nil {
						s.cancel()
					}
				}
			}
			s.mu.Unlock()
			if expired {
				go func() {
					if e := s.cleanup(); e != nil {
						logCode("NETWORK_RECOVERY_REQUIRED")
					}
				}()
			}
		}
	}
}
func serve(ctx context.Context) error {
	lock, e := machineLock()
	if e != nil {
		return e
	}
	defer lock.Close()
	j, e := loadJournal()
	if e != nil {
		return e
	}
	s := &service{journal: j, state: "Disconnected"}
	if e = s.cleanup(); e != nil {
		logCode("NETWORK_RECOVERY_REQUIRED")
	}
	listener, e := listenIPC()
	if e != nil {
		return e
	}
	defer listener.Close()
	go func() { <-ctx.Done(); _ = listener.Close() }()
	go s.supervise(ctx)
	go s.monitorNetwork(ctx)
	slots := make(chan struct{}, 12)
	for {
		connection, e := listener.Accept()
		if e != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		select {
		case slots <- struct{}{}:
		default:
			connection.Close()
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()
			defer func() { <-slots }()
			_ = conn.SetDeadline(time.Now().Add(12 * time.Second))
			// Refusals are logged: the client only sees the connection close.
			peer, e := peerForConnection(conn)
			if e != nil {
				logEvent("connection: peer unknown: %v", e)
				return
			}
			if e = verifyPeer(peer); e != nil {
				logEvent("connection: refused %s (pid %d): %s", peer.Executable, peer.PID, cleanError(e))
				return
			}
			reader := bufio.NewReader(io.LimitReader(conn, maxMessage+4096))
			helloRaw, e := reader.ReadBytes('\n')
			if e != nil || len(helloRaw) > 2048 {
				return
			}
			var hello Request
			if strictJSON(helloRaw, &hello) != nil || hello.Action != "hello" || hello.Protocol != protocolVersion || hello.ProductID != build.ProductID {
				logEvent("hello: refused, not a hello for this product and protocol")
				return
			}
			signature, e := signHello(hello.Challenge)
			if e != nil {
				logEvent("hello: not signed: %s", cleanError(e))
				return
			}
			helloReply := s.base(peer, hello.ID)
			helloReply.Signature = signature
			if _, e = conn.Write(append(jsonBytes(helloReply), '\n')); e != nil {
				return
			}
			raw, e := reader.ReadBytes('\n')
			if e != nil || len(raw) > maxMessage {
				return
			}
			var request Request
			if strictJSON(raw, &request) != nil {
				return
			}
			if request.Action == "stage-update" {
				_ = conn.SetDeadline(time.Now().Add(120 * time.Second))
			}
			response := s.request(peer, request)
			_, _ = conn.Write(append(jsonBytes(response), '\n'))
		}(connection)
	}
	if e = s.cleanup(); e != nil && !errors.Is(e, context.Canceled) {
		return e
	}
	return nil
}
