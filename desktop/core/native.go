package core

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type NativeComponent struct {
	Target string `json:"target"`
	Type   string `json:"type"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}
type NativeManifest struct {
	SchemaVersion  int               `json:"schemaVersion"`
	Verified       bool              `json:"verified"`
	BuildID        string            `json:"buildId"`
	Core           string            `json:"core"`
	CoreVersion    string            `json:"coreVersion"`
	HelperProtocol int               `json:"helperProtocol"`
	Components     []NativeComponent `json:"components"`
	Reason         string            `json:"reason,omitempty"`
}
type nativeReply struct {
	ID        string        `json:"id"`
	OK        bool          `json:"ok"`
	Error     string        `json:"error,omitempty"`
	Protocol  int           `json:"protocol"`
	ProductID string        `json:"productId"`
	BuildID   string        `json:"buildId"`
	Version   string        `json:"version"`
	State     string        `json:"state"`
	Ready     bool          `json:"ready"`
	Owned     bool          `json:"owned"`
	Ticket    string        `json:"ticket,omitempty"`
	Signature string        `json:"signature,omitempty"`
	Proof     *NetworkProof `json:"proof,omitempty"`
	HTTP      *HTTPResponse `json:"http,omitempty"`
}
type NativeDriver struct {
	mu                 sync.Mutex
	build              BuildConfig
	manifest           NativeManifest
	resources, appRoot string
	packaged           bool
	failed             func(ErrorCode)
	verified           bool
	ticket             string
	deadline           int64
	heartbeatCancel    context.CancelFunc
	closing            bool
	installRunning     *networkFuture
	dial               func(context.Context, string) (net.Conn, error)
	checkSocket        func(string) error
	readIdentity       func(string) ([]byte, error)
}

func NewNativeDriver(build BuildConfig, manifest NativeManifest, resources, appRoot string, packaged bool, failed func(ErrorCode)) *NativeDriver {
	if failed == nil {
		failed = func(ErrorCode) {}
	}
	return &NativeDriver{build: build, manifest: manifest, resources: resources, appRoot: appRoot, packaged: packaged, failed: failed, dial: dialNative, checkSocket: checkNativeSocket, readIdentity: readNativeIdentity}
}
func NativeTarget() string {
	platform := runtime.GOOS
	if platform == "windows" {
		platform = "win32"
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x64"
	}
	return platform + "-" + arch
}
func (n *NativeDriver) Verified() bool { n.mu.Lock(); defer n.mu.Unlock(); return n.verified }
func randomNativeID() string {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("random source unavailable")
	}
	return hex.EncodeToString(b[:])
}
func nativeFailure(ctx context.Context) error {
	if ctx.Err() != nil {
		return NewAppError("CANCELLED")
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return NewAppError("CANCELLED")
	}
	return NewAppError("COMPONENTS_UNAVAILABLE")
}
func (n *NativeDriver) rpc(ctx context.Context, action string, input map[string]any) (nativeReply, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return nativeReply{}, NewAppError("CANCELLED")
	}
	limit := 11500 * time.Millisecond
	if action == "heartbeat" {
		limit = 1800 * time.Millisecond
	}
	if action == "stage-update" {
		limit = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	socket := HelperSocket(n.build)
	if err := n.checkSocket(socket); err != nil {
		return nativeReply{}, nativeFailure(ctx)
	}
	bytes, err := n.readIdentity(filepath.Join(HelperRoot(n.build, n.appRoot), "server-public.pem"))
	if err != nil {
		return nativeReply{}, nativeFailure(ctx)
	}
	block, _ := pem.Decode(bytes)
	if block == nil {
		return nativeReply{}, nativeFailure(ctx)
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nativeReply{}, nativeFailure(ctx)
	}
	public, ok := key.(ed25519.PublicKey)
	if !ok {
		return nativeReply{}, nativeFailure(ctx)
	}
	connection, err := n.dial(ctx, socket)
	if err != nil {
		return nativeReply{}, nativeFailure(ctx)
	}
	defer connection.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	_ = connection.SetDeadline(deadline)
	reader := bufio.NewReaderSize(connection, 64*1024)
	send := func(id, action string, fields map[string]any) error {
		message := map[string]any{"protocol": 1, "productId": n.build.ProductID, "id": id, "action": action}
		for k, v := range fields {
			message[k] = v
		}
		encoded, err := EncodeJSON(message)
		if err != nil || len(encoded) > 34*1024*1024 {
			return NewAppError("INVALID_INPUT")
		}
		encoded = append(encoded, '\n')
		for len(encoded) > 0 {
			count, err := connection.Write(encoded)
			if err != nil {
				return err
			}
			encoded = encoded[count:]
		}
		return nil
	}
	receive := func(id string) (nativeReply, error) {
		raw := make([]byte, 0, 4096)
		for {
			fragment, err := reader.ReadSlice('\n')
			if len(raw)+len(fragment) > 72*1024*1024 {
				return nativeReply{}, nativeFailure(ctx)
			}
			raw = append(raw, fragment...)
			if err == nil {
				break
			}
			if err != bufio.ErrBufferFull {
				return nativeReply{}, nativeFailure(ctx)
			}
		}
		var reply nativeReply
		if DecodeStrict(raw, &reply, 72*1024*1024) != nil || reply.Protocol != 1 || reply.ID != id || reply.ProductID != n.build.ProductID || reply.BuildID != n.manifest.BuildID {
			return nativeReply{}, nativeFailure(ctx)
		}
		return reply, nil
	}
	helloID, challenge := randomNativeID(), randomNativeID()
	if err = send(helloID, "hello", map[string]any{"challenge": challenge}); err != nil {
		return nativeReply{}, nativeFailure(ctx)
	}
	hello, err := receive(helloID)
	if err != nil {
		return nativeReply{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(hello.Signature)
	proof := []byte("starrail-helper-v1\n" + challenge + "\n" + n.build.ProductID + "\n" + n.manifest.BuildID)
	if err != nil || !hello.OK || !ed25519.Verify(public, proof, signature) {
		return nativeReply{}, nativeFailure(ctx)
	}
	id := randomNativeID()
	if err = send(id, action, input); err != nil {
		return nativeReply{}, nativeFailure(ctx)
	}
	reply, err := receive(id)
	if err != nil {
		return nativeReply{}, err
	}
	if !reply.OK {
		code := ErrorCode(reply.Error)
		if _, known := Messages[code]; !known {
			code = "COMPONENTS_UNAVAILABLE"
		}
		return nativeReply{}, NewAppError(code)
	}
	if ctx.Err() != nil {
		return nativeReply{}, NewAppError("CANCELLED")
	}
	return reply, nil
}
func (n *NativeDriver) Initialize(ctx context.Context) error {
	reply, err := n.rpc(ctx, "status", nil)
	n.mu.Lock()
	n.verified = err == nil && reply.Ready
	n.mu.Unlock()
	if err == nil && reply.State == "RecoveryRequired" {
		n.failed("NETWORK_RECOVERY_REQUIRED")
	}
	return nil
}
func (n *NativeDriver) EnsureReady(ctx context.Context) error {
	_ = n.Initialize(ctx)
	if n.Verified() {
		return nil
	}
	return n.Repair(ctx)
}
func (n *NativeDriver) Repair(ctx context.Context) error {
	n.mu.Lock()
	if n.installRunning != nil {
		f := n.installRunning
		n.mu.Unlock()
		return waitNetwork(ctx, f)
	}
	f := &networkFuture{done: make(chan struct{})}
	n.installRunning = f
	n.mu.Unlock()
	err := n.repair(ctx)
	n.mu.Lock()
	f.err = err
	n.installRunning = nil
	close(f.done)
	n.mu.Unlock()
	return err
}
func (n *NativeDriver) repair(ctx context.Context) error {
	if !n.packaged {
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	if n.Verified() {
		status, err := n.rpc(ctx, "status", nil)
		if err != nil {
			return err
		}
		if status.State != "Disconnected" && !status.Owned {
			return NewAppError("NETWORK_CONFLICT")
		}
	}
	name := "helper"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(n.resources, "native", NativeTarget(), name)
	pin := ""
	for _, component := range n.manifest.Components {
		if component.Type == "helper" && component.Target == NativeTarget() {
			pin = component.SHA256
			break
		}
	}
	if err := verifyNativeExecutable(path, pin, 64*1024*1024); err != nil {
		return err
	}
	installCtx, cancel := context.WithTimeout(ctx, 180*time.Second)
	defer cancel()
	var command *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		command = exec.CommandContext(installCtx, "/usr/bin/pkexec", path, "install", "--app", n.appRoot)
	case "darwin":
		quote := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }
		shell := quote(path) + " install --app " + quote(n.appRoot)
		apple := strings.NewReplacer("\\", "\\\\", "\"", "\\\"").Replace(shell)
		command = exec.CommandContext(installCtx, "/usr/bin/osascript", "-e", "do shell script \""+apple+"\" with administrator privileges")
	case "windows":
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = `C:\Windows`
		}
		script := `$p=Start-Process -FilePath $env:STARRAIL_HELPER -ArgumentList ('install --app "'+$env:STARRAIL_APP+'"') -Verb RunAs -Wait -PassThru; exit $p.ExitCode`
		command = exec.CommandContext(installCtx, filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), "-NoProfile", "-NonInteractive", "-Command", script)
		command.Env = append(os.Environ(), "STARRAIL_HELPER="+path, "STARRAIL_APP="+n.appRoot)
	default:
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	configureNativeChild(command)
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	if err := command.Run(); err != nil {
		return NewAppError("PERMISSION_REQUIRED")
	}
	_ = n.Initialize(ctx)
	if !n.Verified() {
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	return nil
}
func (n *NativeDriver) SetAuthorizedUntil(deadline int64) {
	n.mu.Lock()
	n.deadline = deadline
	n.mu.Unlock()
}

// nativeNode is the helper's frozen node shape; only these fields cross the IPC boundary.
func nativeNode(node ProxyNode) map[string]any {
	fields := map[string]any{"protocol": node.Protocol, "host": node.Host, "port": node.Port, "credential": node.Credential, "transport": node.Transport, "security": node.Security, "ai": AICapable(node)}
	for key, value := range map[string]*string{"method": node.Method, "sni": node.SNI, "flow": node.Flow, "publicKey": node.PublicKey, "shortId": node.ShortID, "fingerprint": node.Fingerprint, "wsPath": node.WSPath, "wsHost": node.WSHost} {
		if value != nil {
			fields[key] = *value
		}
	}
	return fields
}
func (n *NativeDriver) Prepare(ctx context.Context, candidate Candidate) (string, error) {
	if err := candidate.Rules.Validate(); err != nil {
		return "", err
	}
	if candidate.Mode != "rule" && candidate.Mode != "global" {
		return "", NewAppError("INVALID_INPUT")
	}
	n.mu.Lock()
	n.deadline = candidate.AuthorizedUntil
	n.closing = false
	n.mu.Unlock()
	pool := make([]map[string]any, len(candidate.Pool))
	for i, node := range candidate.Pool {
		pool[i] = nativeNode(node)
	}
	reply, err := n.rpc(ctx, "prepare", map[string]any{"candidate": map[string]any{"node": nativeNode(candidate.Node), "pool": pool, "automatic": candidate.Automatic, "mode": candidate.Mode, "rules": candidate.Rules, "authorizedUntil": candidate.AuthorizedUntil}})
	if err != nil {
		return "", err
	}
	if reply.Ticket == "" {
		return "", NewAppError("COMPONENTS_UNAVAILABLE")
	}
	n.mu.Lock()
	n.ticket = reply.Ticket
	if n.heartbeatCancel != nil {
		n.heartbeatCancel()
	}
	beatCtx, cancel := context.WithCancel(context.Background())
	n.heartbeatCancel = cancel
	n.mu.Unlock()
	go n.heartbeat(beatCtx, reply.Ticket)
	return reply.Ticket, nil
}
func (n *NativeDriver) heartbeat(ctx context.Context, ticket string) {
	ticker := time.NewTicker(750 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n.mu.Lock()
			deadline := n.deadline
			closing := n.closing || n.ticket != ticket
			n.mu.Unlock()
			if closing {
				return
			}
			reply, err := n.rpc(ctx, "heartbeat", map[string]any{"ticket": ticket, "authorizedUntil": deadline})
			if err != nil || !reply.Owned || reply.State == "Disconnected" || reply.State == "RecoveryRequired" {
				n.mu.Lock()
				report := !n.closing && n.ticket == ticket && ctx.Err() == nil
				if report {
					n.verified = false
				}
				n.mu.Unlock()
				if report {
					n.failed("NETWORK_RECOVERY_REQUIRED")
				}
				return
			}
		}
	}
}
func (n *NativeDriver) Protect(ctx context.Context, ticket string, _ time.Time) error {
	_, err := n.rpc(ctx, "protect", map[string]any{"ticket": ticket})
	return err
}
func (n *NativeDriver) Start(ctx context.Context, ticket string) error {
	_, err := n.rpc(ctx, "start", map[string]any{"ticket": ticket})
	return err
}
func (n *NativeDriver) Probe(ctx context.Context, ticket string) (NetworkProof, error) {
	reply, err := n.rpc(ctx, "probe", map[string]any{"ticket": ticket})
	if err != nil {
		return NetworkProof{}, err
	}
	if reply.Proof == nil {
		return NetworkProof{}, NewAppError("CONNECT_TIMEOUT")
	}
	return *reply.Proof, nil
}
func (n *NativeDriver) Commit(ctx context.Context, ticket string) error {
	_, err := n.rpc(ctx, "commit", map[string]any{"ticket": ticket})
	return err
}
func (n *NativeDriver) Cleanup(ctx context.Context) error {
	n.mu.Lock()
	n.closing = true
	if n.heartbeatCancel != nil {
		n.heartbeatCancel()
		n.heartbeatCancel = nil
	}
	ticket, verified := n.ticket, n.verified
	n.mu.Unlock()
	if ticket == "" && !verified {
		return nil
	}
	_, err := n.rpc(ctx, "stop", map[string]any{"ticket": ticket})
	n.mu.Lock()
	if err != nil {
		n.verified = false
	} else {
		n.ticket = ""
	}
	n.mu.Unlock()
	return err
}
func (n *NativeDriver) Control(ctx context.Context, input HTTPRequest) (HTTPResponse, error) {
	reply, err := n.rpc(ctx, "control", map[string]any{"http": input})
	if err != nil {
		return HTTPResponse{}, err
	}
	if reply.HTTP == nil {
		return HTTPResponse{}, NewAppError("CONTROL_UNAVAILABLE")
	}
	return *reply.HTTP, nil
}
func (n *NativeDriver) Install(ctx context.Context, artifact Artifact, path, envelope string) error {
	if !n.Verified() {
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	_, err := n.rpc(ctx, "stage-update", map[string]any{"artifactId": artifact.ID, "artifactPath": path, "releaseEnvelope": envelope})
	return err
}

type HelperTransport struct {
	native *NativeDriver
	direct Transport
}

func NewHelperTransport(native *NativeDriver) *HelperTransport {
	return &HelperTransport{native: native, direct: NewDirectHTTPSTransport()}
}
func (h *HelperTransport) Request(ctx context.Context, input HTTPRequest) (HTTPResponse, error) {
	if h.native != nil && h.native.Verified() {
		return h.native.Control(ctx, input)
	}
	return h.direct.Request(ctx, input)
}
func verifyNativeExecutable(path, pin string, limit int64) error {
	if len(pin) != 64 {
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() >= limit || runtime.GOOS != "windows" && info.Mode().Perm()&0022 != 0 {
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	f, err := os.Open(path)
	if err != nil {
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	defer f.Close()
	current, err := f.Stat()
	if err != nil || !os.SameFile(info, current) {
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	hash := sha256.New()
	count, err := io.Copy(hash, io.LimitReader(f, limit))
	if err != nil || count >= limit || hex.EncodeToString(hash.Sum(nil)) != pin {
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	return nil
}

// Keep strconv linked to native identity formatting for the isolated helper.
func probeParentID() string { return strconv.Itoa(os.Getpid()) }
