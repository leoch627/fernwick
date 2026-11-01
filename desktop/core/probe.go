package core

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"time"
)

type CoreRuntime struct {
	Executable               string
	digest                   string
	helperPath, helperDigest string
	probeTLS                 *tls.Config
}

func LoadCoreRuntime(root string, manifest NativeManifest) (*CoreRuntime, error) {
	var err error
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, NewAppError("COMPONENTS_UNAVAILABLE")
	}
	target := NativeTarget()
	name := "xray"
	helperName := "helper"
	if runtime.GOOS == "windows" {
		name += ".exe"
		helperName += ".exe"
	}
	core := &CoreRuntime{Executable: filepath.Join(root, target, name)}
	for _, component := range manifest.Components {
		if component.Target != target {
			continue
		}
		if component.Type == "core" {
			core.digest = component.SHA256
		}
		if component.Type == "helper" {
			core.helperPath = filepath.Join(root, target, helperName)
			core.helperDigest = component.SHA256
		}
	}
	if err := core.verify(); err != nil {
		return nil, err
	}
	return core, nil
}
func (c *CoreRuntime) verify() error {
	if err := verifyNativeExecutable(c.Executable, c.digest, 100*1024*1024); err != nil {
		return err
	}
	if c.helperPath != "" {
		return verifyNativeExecutable(c.helperPath, c.helperDigest, 64*1024*1024)
	}
	return nil
}

type probeProcess struct {
	cmd     *exec.Cmd
	done    chan struct{}
	err     error
	once    sync.Once
	stopErr error
}

func (c *CoreRuntime) launch(ctx context.Context, config map[string]any, check bool) (*probeProcess, error) {
	return c.start(ctx, config, check, "probe-core", 2*1024*1024)
}

// maxProxyConfig matches the helper worker's limit; the configuration carries every rule.
const maxProxyConfig = 32 * 1024 * 1024

// launchProxy runs the system proxy core until ctx ends or the core exits. Installed
// apps run it through the helper's unprivileged proxy-core worker, which also ends the
// core if the app itself goes away.
func (c *CoreRuntime) launchProxy(ctx context.Context, config map[string]any, check bool) (*probeProcess, error) {
	if err := c.verify(); err != nil {
		return nil, err
	}
	return c.start(ctx, config, check, "proxy-core", maxProxyConfig)
}
func (c *CoreRuntime) start(ctx context.Context, config map[string]any, check bool, worker string, limit int) (*probeProcess, error) {
	if ctx.Err() != nil {
		return nil, NewAppError("CANCELLED")
	}
	data, err := EncodeJSON(config)
	if err != nil || len(data) > limit {
		return nil, NewAppError("INVALID_INPUT")
	}
	program := c.Executable
	args := []string{"run", "-format", "json", "-config", "stdin:"}
	if check {
		args = append(args, "-test")
	}
	if c.helperPath != "" {
		program = c.helperPath
		args = []string{worker, probeParentID()}
		if check {
			args = append(args, "--check")
		}
	}
	cmd := exec.Command(program, args...)
	cmd.Dir = filepath.Dir(c.Executable)
	cmd.Env = []string{"LANG=C", "XRAY_LOCATION_ASSET=" + cmd.Dir}
	if runtime.GOOS == "windows" {
		cmd.Env = append(cmd.Env, "SystemRoot="+os.Getenv("SystemRoot"), "WINDIR="+os.Getenv("WINDIR"))
	}
	cmd.Stdin = bytes.NewReader(data)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	configureNativeChild(cmd)
	if err := cmd.Start(); err != nil {
		return nil, NewAppError("COMPONENTS_UNAVAILABLE")
	}
	process := &probeProcess{cmd: cmd, done: make(chan struct{})}
	go func() { process.err = cmd.Wait(); close(process.done) }()
	go func() {
		select {
		case <-ctx.Done():
			_ = process.stop()
		case <-process.done:
		}
	}()
	return process, nil
}
func (p *probeProcess) stop() error {
	p.once.Do(func() {
		select {
		case <-p.done:
			return
		default:
		}
		_ = terminateNativeChild(p.cmd, false)
		soft := time.NewTimer(300 * time.Millisecond)
		defer soft.Stop()
		select {
		case <-p.done:
			return
		case <-soft.C:
			_ = terminateNativeChild(p.cmd, true)
		}
		hard := time.NewTimer(700 * time.Millisecond)
		defer hard.Stop()
		select {
		case <-p.done:
		case <-hard.C:
			p.stopErr = NewAppError("COMPONENTS_UNAVAILABLE")
		}
	})
	return p.stopErr
}
func (c *CoreRuntime) Check(ctx context.Context, node ProxyNode) error {
	if err := c.verify(); err != nil {
		return err
	}
	config, err := CompileProbe(node, ProbeAuth{Port: 49151, User: "check", Password: "check-only-not-a-session"})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()
	process, err := c.launch(ctx, config, true)
	if err != nil {
		return err
	}
	defer process.stop()
	select {
	case <-ctx.Done():
		return NewAppError("CANCELLED")
	case <-process.done:
		if process.err != nil {
			return NewAppError("NO_COMPATIBLE_NODES")
		}
		return nil
	}
}
func (c *CoreRuntime) Probe(ctx context.Context, node ProxyNode, targets []HealthTarget) (result ProbeResult, resultErr error) {
	if err := validateProbeTargets(targets); err != nil {
		return ProbeResult{}, err
	}
	budget := NewBudget(5500*time.Millisecond, ctx)
	defer budget.Dispose()
	ctx = budget.Context()
	if err := c.verify(); err != nil {
		return ProbeResult{}, err
	}
	if ctx.Err() != nil {
		return ProbeResult{}, NewAppError("CANCELLED")
	}
	port, err := availableProbePort()
	if err != nil {
		return ProbeResult{}, err
	}
	var user [16]byte
	var password [24]byte
	if _, err = rand.Read(user[:]); err != nil {
		return ProbeResult{}, err
	}
	if _, err = rand.Read(password[:]); err != nil {
		return ProbeResult{}, err
	}
	auth := ProbeAuth{Port: port, User: hex.EncodeToString(user[:]), Password: base64.RawURLEncoding.EncodeToString(password[:])}
	config, err := CompileProbe(node, auth)
	if err != nil {
		return ProbeResult{}, err
	}
	process, err := c.launch(ctx, config, false)
	if err != nil {
		return ProbeResult{}, err
	}
	defer func() {
		if err := process.stop(); err != nil && resultErr == nil {
			resultErr = err
		}
	}()
	if err = waitProbeListener(ctx, port, process.done); err != nil {
		return ProbeResult{}, err
	}
	for _, target := range targets {
		attempt, cancel := context.WithTimeout(ctx, min(2*time.Second, budget.Remaining()))
		started := time.Now()
		err := probeHTTPSWithTLS(attempt, auth, target, c.probeTLS)
		cancel()
		if ctx.Err() != nil {
			return ProbeResult{}, NewAppError("CANCELLED")
		}
		if err == nil {
			latency := float64(time.Since(started).Round(time.Millisecond) / time.Millisecond)
			return ProbeResult{Healthy: true, LatencyMs: &latency}, nil
		}
	}
	return ProbeResult{Healthy: false, LatencyMs: nil}, nil
}
func validateProbeTargets(targets []HealthTarget) error {
	if len(targets) < 2 || len(targets) > 3 {
		return NewAppError("CONFIGURATION_REQUIRED")
	}
	domains := map[string]bool{}
	for _, target := range targets {
		u, err := url.Parse(target.URL)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(target.BodySHA256) != 64 || !isLowerHexDigest(target.BodySHA256) || target.Status < 200 || target.Status > 299 {
			return NewAppError("CONFIGURATION_REQUIRED")
		}
		if target.FailureDomain == "" || domains[target.FailureDomain] {
			return NewAppError("CONFIGURATION_REQUIRED")
		}
		domains[target.FailureDomain] = true
	}
	return nil
}
func isLowerHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}
func availableProbePort() (int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, NewAppError("COMPONENTS_UNAVAILABLE")
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err = listener.Close(); err != nil {
		return 0, err
	}
	return port, nil
}
func waitProbeListener(ctx context.Context, port int, done <-chan struct{}) error {
	for {
		select {
		case <-ctx.Done():
			return NewAppError("CANCELLED")
		case <-done:
			return NewAppError("COMPONENTS_UNAVAILABLE")
		default:
		}
		connection, err := (&net.Dialer{Timeout: 100 * time.Millisecond}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err == nil {
			_ = connection.Close()
			return nil
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return NewAppError("CANCELLED")
		case <-done:
			timer.Stop()
			return NewAppError("COMPONENTS_UNAVAILABLE")
		case <-timer.C:
		}
	}
}

// ProbeHTTPS authenticates to the isolated loopback SOCKS port and performs a
// certificate-verified request through it. It never falls back to direct HTTP.
func ProbeHTTPS(ctx context.Context, auth ProbeAuth, target HealthTarget) error {
	return probeHTTPSWithTLS(ctx, auth, target, nil)
}
func probeHTTPSWithTLS(ctx context.Context, auth ProbeAuth, target HealthTarget, roots *tls.Config) error {
	u, err := url.Parse(target.URL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" || u.RawQuery != "" {
		return NewAppError("CONFIGURATION_REQUIRED")
	}
	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(auth.Port)))
	if err != nil {
		return probeError(ctx)
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetDeadline(deadline)
	}
	if err = socksHandshake(connection, auth, u); err != nil {
		return probeError(ctx)
	}
	config := &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}}
	if roots != nil {
		config.RootCAs = roots.RootCAs
	}
	secure := tls.Client(connection, config)
	defer secure.Close()
	if err = secure.HandshakeContext(ctx); err != nil {
		return probeError(ctx)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return NewAppError("CONFIGURATION_REQUIRED")
	}
	request.Header.Set("User-Agent", "v2board-client-health/0.1")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-store")
	request.Close = true
	if err = request.Write(secure); err != nil {
		return probeError(ctx)
	}
	response, err := http.ReadResponse(bufio.NewReaderSize(io.LimitReader(secure, 128*1024), 16*1024), request)
	if err != nil {
		return probeError(ctx)
	}
	defer response.Body.Close()
	if response.StatusCode != target.Status {
		return NewAppError("CONNECT_TIMEOUT")
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(response.Body, 65537))
	if err != nil || count > 65536 || hex.EncodeToString(hash.Sum(nil)) != target.BodySHA256 {
		return probeError(ctx)
	}
	return nil
}
func probeError(ctx context.Context) error {
	if ctx.Err() != nil {
		return NewAppError("CANCELLED")
	}
	return NewAppError("CONNECT_TIMEOUT")
}
func socksHandshake(connection net.Conn, auth ProbeAuth, u *url.URL) error {
	write := func(data []byte) error {
		for len(data) > 0 {
			n, err := connection.Write(data)
			if err != nil {
				return err
			}
			data = data[n:]
		}
		return nil
	}
	read := func(n int) ([]byte, error) {
		value := make([]byte, n)
		_, err := io.ReadFull(connection, value)
		return value, err
	}
	if err := write([]byte{5, 1, 2}); err != nil {
		return err
	}
	method, err := read(2)
	if err != nil || !bytes.Equal(method, []byte{5, 2}) {
		return fmt.Errorf("SOCKS authentication unavailable")
	}
	user, password := []byte(auth.User), []byte(auth.Password)
	if len(user) < 1 || len(user) > 255 || len(password) < 1 || len(password) > 255 {
		return NewAppError("INVALID_INPUT")
	}
	authentication := append([]byte{1, byte(len(user))}, user...)
	authentication = append(authentication, byte(len(password)))
	authentication = append(authentication, password...)
	if err = write(authentication); err != nil {
		return err
	}
	answer, err := read(2)
	if err != nil || !bytes.Equal(answer, []byte{1, 0}) {
		return fmt.Errorf("SOCKS authentication rejected")
	}
	host := []byte(u.Hostname())
	if len(host) == 0 || len(host) > 255 {
		return NewAppError("INVALID_INPUT")
	}
	port := 443
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return NewAppError("INVALID_INPUT")
		}
	}
	request := append([]byte{5, 1, 0, 3, byte(len(host))}, host...)
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	request = append(request, portBytes[:]...)
	if err = write(request); err != nil {
		return err
	}
	reply, err := read(4)
	if err != nil || reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		return fmt.Errorf("SOCKS connect rejected")
	}
	size := 0
	switch reply[3] {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		length, err := read(1)
		if err != nil {
			return err
		}
		size = int(length[0])
	}
	if size == 0 {
		return fmt.Errorf("invalid SOCKS address")
	}
	_, err = read(size + 2)
	return err
}
