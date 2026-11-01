package core

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func probeTestSOCKS(t *testing.T, destination string) (ProbeAuth, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	seen := make(chan string, 4)
	auth := ProbeAuth{Port: listener.Addr().(*net.TCPAddr).Port, User: "probe-user", Password: "probe-random-password"}
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
				read := func(n int) ([]byte, error) { b := make([]byte, n); _, err := io.ReadFull(connection, b); return b, err }
				greeting, err := read(3)
				if err != nil || string(greeting) != string([]byte{5, 1, 2}) {
					return
				}
				_, _ = connection.Write([]byte{5, 2})
				header, err := read(2)
				if err != nil {
					return
				}
				user, err := read(int(header[1]))
				if err != nil {
					return
				}
				passlen, err := read(1)
				if err != nil {
					return
				}
				password, err := read(int(passlen[0]))
				if err != nil || string(user) != auth.User || string(password) != auth.Password {
					_, _ = connection.Write([]byte{1, 1})
					return
				}
				_, _ = connection.Write([]byte{1, 0})
				header, err = read(5)
				if err != nil || header[3] != 3 {
					return
				}
				host, err := read(int(header[4]))
				if err != nil {
					return
				}
				if _, err = read(2); err != nil {
					return
				}
				seen <- string(host)
				upstream, err := net.Dial("tcp", destination)
				if err != nil {
					return
				}
				defer upstream.Close()
				_, _ = connection.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 1})
				done := make(chan struct{})
				go func() { _, _ = io.Copy(upstream, connection); close(done) }()
				_, _ = io.Copy(connection, upstream)
				_ = connection.Close()
				<-done
			}()
		}
	}()
	return auth, seen
}
func TestProbeHTTPSAuthenticatesChecksCertificateStatusAndBody(t *testing.T) {
	body := "expected-health-body"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Error("probe compression enabled")
		}
		_, _ = io.WriteString(w, body)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	auth, seen := probeTestSOCKS(t, u.Host)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	sum := sha256.Sum256([]byte(body))
	target := HealthTarget{URL: server.URL, Status: 200, BodySHA256: hex.EncodeToString(sum[:]), FailureDomain: "test"}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := probeHTTPSWithTLS(ctx, auth, target, &tls.Config{RootCAs: pool}); err != nil {
		t.Fatal(err)
	}
	if host := <-seen; host != u.Hostname() {
		t.Fatal(host)
	}
	target.BodySHA256 = strings.Repeat("0", 64)
	if _, err := probeHTTPSWithTLS(ctx, auth, target, &tls.Config{RootCAs: pool}); CodeOf(err) != "CONNECT_TIMEOUT" {
		t.Fatal(err)
	}
	target.Status = 204
	if _, err := probeHTTPSWithTLS(ctx, auth, target, &tls.Config{RootCAs: pool}); err == nil {
		t.Fatal("unexpected status accepted")
	}
}
func TestProbeTimesOneRoundTripOnAReusedConnection(t *testing.T) {
	requests, connections := 0, map[string]bool{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		connections[r.RemoteAddr] = true
		if requests == 1 {
			time.Sleep(300 * time.Millisecond) // the handshake-heavy first exchange
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	auth, _ := probeTestSOCKS(t, u.Host)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	sum := sha256.Sum256(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	took, err := probeHTTPSWithTLS(ctx, auth, HealthTarget{URL: server.URL, Status: 204, BodySHA256: hex.EncodeToString(sum[:])}, &tls.Config{RootCAs: pool})
	if err != nil || requests != 2 || len(connections) != 1 || took >= 300*time.Millisecond {
		t.Fatalf("took %v err %v requests %d connections %d", took, err, requests, len(connections))
	}
}
func TestProbeHTTPSRejectsUntrustedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	auth, _ := probeTestSOCKS(t, u.Host)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := ProbeHTTPS(ctx, auth, HealthTarget{URL: server.URL, Status: 200, BodySHA256: strings.Repeat("0", 64)}); CodeOf(err) != "CONNECT_TIMEOUT" {
		t.Fatal(err)
	}
}
func TestProbeHTTPSRejectsOversizeResponse(t *testing.T) {
	body := strings.Repeat("x", 65537)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }))
	defer server.Close()
	u, _ := url.Parse(server.URL)
	auth, _ := probeTestSOCKS(t, u.Host)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	sum := sha256.Sum256([]byte(body))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := probeHTTPSWithTLS(ctx, auth, HealthTarget{URL: server.URL, Status: 200, BodySHA256: hex.EncodeToString(sum[:])}, &tls.Config{RootCAs: pool}); err == nil {
		t.Fatal("oversized response accepted")
	}
}
func TestCoreRuntimePinsAndSafeEnvironment(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX test executable")
	}
	root := t.TempDir()
	directory := filepath.Join(root, NativeTarget())
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "xray")
	script := []byte("#!/bin/sh\n[ -z \"$STARRAIL_TEST_SECRET\" ] || exit 2\n[ -z \"$XRAY_CONF_TEST\" ] || exit 3\n/bin/cat >/dev/null\nexit 0\n")
	if err := os.WriteFile(path, script, 0755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(script)
	manifest := NativeManifest{Components: []NativeComponent{{Target: NativeTarget(), Type: "core", SHA256: hex.EncodeToString(sum[:])}}}
	core, err := LoadCoreRuntime(root, manifest)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("STARRAIL_TEST_SECRET", "secret")
	t.Setenv("XRAY_CONF_TEST", "/tmp/injection")
	nodes, err := ParseSubscription(subscriptionTestURI, subscriptionTestOptions())
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Check(context.Background(), nodes.Nodes[0]); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("tampered"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := core.Check(context.Background(), nodes.Nodes[0]); CodeOf(err) != "COMPONENTS_UNAVAILABLE" {
		t.Fatal(err)
	}
}
func TestCoreRuntimeRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privileges")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "binary")
	bytes := []byte("binary")
	if err := os.WriteFile(path, bytes, 0755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bytes)
	if err := verifyNativeExecutable(link, hex.EncodeToString(sum[:]), 1000); err == nil {
		t.Fatal("symlink trusted")
	}
}
func TestProbeTargetsRequireIndependentTrustedHTTPS(t *testing.T) {
	target := HealthTarget{URL: "https://example.invalid/health", Status: 204, BodySHA256: strings.Repeat("0", 64), FailureDomain: "one"}
	other := target
	other.FailureDomain = "two"
	if err := validateProbeTargets([]HealthTarget{target, other}); err != nil {
		t.Fatal(err)
	}
	if err := validateProbeTargets([]HealthTarget{target, target}); err == nil {
		t.Fatal("duplicate failure domains accepted")
	}
	for _, bad := range []string{"http://example.invalid/health", "https://user:secret@example.invalid/", "https://example.invalid/?token=secret", "https://example.invalid/#fragment"} {
		other.URL = bad
		if err := validateProbeTargets([]HealthTarget{target, other}); err == nil {
			t.Fatal(bad)
		}
	}
}
func TestCoreSmoke(t *testing.T) {
	if os.Getenv("STARRAIL_CORE_SMOKE") != "1" {
		t.Skip("set STARRAIL_CORE_SMOKE=1 with pinned native binaries")
	}
	manifestRaw, err := os.ReadFile("../../resources/native-manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest NativeManifest
	if err = json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	// A go test process is deliberately not an approved application parent.
	// Exercise the pinned, unprivileged core directly; installed apps use helper.
	coreOnly := make([]NativeComponent, 0, len(manifest.Components))
	for _, component := range manifest.Components {
		if component.Type == "core" {
			coreOnly = append(coreOnly, component)
		}
	}
	manifest.Components = coreOnly
	core, err := LoadCoreRuntime("../../resources/native", manifest)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("testdata/subscriptions.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Fixtures []struct {
			Raw     string        `json:"raw"`
			Options ParserOptions `json:"options"`
		} `json:"fixtures"`
	}
	if err = json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	checked := map[string]bool{}
	for _, fixture := range fixtures.Fixtures {
		parsed, err := ParseSubscription(fixture.Raw, fixture.Options)
		if err != nil {
			t.Fatal(err)
		}
		for _, node := range parsed.Nodes {
			kind := node.Protocol + "/" + node.Security
			if node.Compatible && !checked[kind] {
				if err := core.Check(context.Background(), node); err != nil {
					t.Fatalf("%s: %v", node.Protocol, err)
				}
				checked[kind] = true
			}
		}
	}
	t.Run("encrypted-loopback", func(t *testing.T) { testCoreEncryptedLoopback(t, core) })
	t.Run("system-proxy", func(t *testing.T) { testSystemProxySmoke(t, core) })
}

// testSystemProxySmoke connects in system proxy mode with the bundled rules through a
// local Shadowsocks node, then checks the loopback port, the journal and the restore.
func testSystemProxySmoke(t *testing.T, core *CoreRuntime) {
	web := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	defer web.Close()
	roots := x509.NewCertPool()
	roots.AddCert(web.Certificate())
	core.probeTLS = &tls.Config{RootCAs: roots}
	defer func() { core.probeTLS = nil }()
	port, err := availableProbePort()
	if err != nil {
		t.Fatal(err)
	}
	password := "ephemeral-loopback-password-123456789"
	serverConfig := map[string]any{"log": map[string]any{"loglevel": "none", "access": "none", "error": "none"}, "inbounds": []any{map[string]any{"protocol": "shadowsocks", "listen": "127.0.0.1", "port": port, "settings": map[string]any{"method": "aes-128-gcm", "password": password, "network": "tcp,udp"}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}}}}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	server, err := core.launch(ctx, serverConfig, false)
	if err != nil {
		t.Fatal(err)
	}
	defer server.stop()
	if err = waitProbeListener(ctx, port, server.done); err != nil {
		t.Fatal(err)
	}
	node := proxyTestNode(t, "ss://"+base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:"+password))+"@127.0.0.1:"+strconv.Itoa(port)+"#local")
	raw, err := os.ReadFile("../../resources/rules/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	var rules Rules
	if err = DecodeStrict(raw, &rules, 64*1024*1024); err != nil {
		t.Fatal(err)
	}
	empty := sha256.Sum256(nil)
	targets := []HealthTarget{{URL: web.URL + "/health", Status: 204, BodySHA256: hex.EncodeToString(empty[:]), FailureDomain: "one"}, {URL: web.URL + "/second", Status: 204, BodySHA256: hex.EncodeToString(empty[:]), FailureDomain: "two"}}
	journal := filepath.Join(t.TempDir(), "system-proxy.json")
	system := &recordingSystemProxy{}
	driver := NewProxyDriver(core, system, journal, targets, nil)
	driver.preferred = 0
	network := NewNetworkController(driver, nil)
	candidate := Candidate{Node: node, Mode: "rule", Tunnel: "proxy", Rules: rules, AuthorizedUntil: time.Now().Add(time.Hour).UnixMilli()}
	if err = network.Connect(ctx, candidate, nil); err != nil {
		t.Fatalf("connect: %v (stage %s)", err, network.View().Stage)
	}
	local := driver.Port()
	if network.View().State != "Connected" || local == 0 || !reflect.DeepEqual(system.history(), []string{"snapshot", "apply"}) {
		t.Fatalf("connected state %+v port %d calls %v", network.View(), local, system.history())
	}
	if _, err = os.Stat(journal); err != nil {
		t.Fatal("journal missing while the system proxy is set")
	}
	proxyURL, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(local))
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: roots}}}
	response, err := client.Get(web.URL + "/through-proxy")
	if err != nil || response.StatusCode != 204 {
		t.Fatalf("HTTP proxy port: %v %v", response, err)
	}
	response.Body.Close()
	client.CloseIdleConnections()
	if err = network.Disconnect(ctx); err != nil {
		t.Fatal(err)
	}
	if calls := system.history(); calls[len(calls)-1] != "restore" || string(system.saved) != `{"previous":true}` {
		t.Fatalf("restore: %v %s", calls, system.saved)
	}
	if _, err = os.Stat(journal); !os.IsNotExist(err) {
		t.Fatal("journal kept after disconnect")
	}
	if connection, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(local), 300*time.Millisecond); err == nil {
		connection.Close()
		t.Fatal("proxy port still open after disconnect")
	}
	// A failed proof never touches the system proxy.
	before := len(system.history())
	for i := range targets {
		targets[i].Status = 200
	}
	if err = network.Connect(ctx, candidate, nil); CodeOf(err) != "CONNECT_TIMEOUT" {
		t.Fatalf("unproven path connected: %v", err)
	}
	for _, call := range system.history()[before:] {
		if call == "apply" {
			t.Fatal("system proxy set before the path was proven")
		}
	}
}

func testCoreEncryptedLoopback(t *testing.T, core *CoreRuntime) {
	before, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	web := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/hang" {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(204)
	}))
	defer web.Close()
	roots := x509.NewCertPool()
	roots.AddCert(web.Certificate())
	core.probeTLS = &tls.Config{RootCAs: roots}
	defer func() { core.probeTLS = nil }()
	port, err := availableProbePort()
	if err != nil {
		t.Fatal(err)
	}
	password := "ephemeral-loopback-password-123456789"
	serverConfig := map[string]any{"log": map[string]any{"loglevel": "none", "access": "none", "error": "none"}, "inbounds": []any{map[string]any{"protocol": "shadowsocks", "listen": "127.0.0.1", "port": port, "settings": map[string]any{"method": "aes-128-gcm", "password": password, "network": "tcp,udp"}}}, "outbounds": []any{map[string]any{"protocol": "freedom", "settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow", "ip": []string{"127.0.0.1/32"}}}}}}}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	server, err := core.launch(ctx, serverConfig, false)
	if err != nil {
		t.Fatal(err)
	}
	defer server.stop()
	if err = waitProbeListener(ctx, port, server.done); err != nil {
		t.Fatal(err)
	}
	uri := "ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:"+password)) + "@127.0.0.1:" + strconv.Itoa(port) + "#local"
	parsed, err := ParseSubscription(uri, subscriptionTestOptions())
	if err != nil {
		t.Fatal(err)
	}
	empty := sha256.Sum256(nil)
	targets := []HealthTarget{{URL: web.URL + "/health", Status: 204, BodySHA256: hex.EncodeToString(empty[:]), FailureDomain: "one"}, {URL: web.URL + "/second", Status: 204, BodySHA256: hex.EncodeToString(empty[:]), FailureDomain: "two"}}
	result, err := core.Probe(ctx, parsed.Nodes[0], targets)
	if err != nil || !result.Healthy || requests.Load() == 0 {
		t.Fatalf("encrypted path failed: %#v %v", result, err)
	}
	previous := requests.Load()
	targets[0].Status = 200
	result, err = core.Probe(ctx, parsed.Nodes[0], targets)
	if err != nil || !result.Healthy || requests.Load() < previous+2 {
		t.Fatalf("fallback failed: %#v %v", result, err)
	}
	targets[0].Status = 204
	for i := range targets {
		targets[i].BodySHA256 = strings.Repeat("0", 64)
	}
	result, err = core.Probe(ctx, parsed.Nodes[0], targets)
	if err != nil || result.Healthy {
		t.Fatalf("wrong body accepted: %#v %v", result, err)
	}
	for i := range targets {
		targets[i].BodySHA256 = hex.EncodeToString(empty[:])
		targets[i].URL = web.URL + "/hang"
	}
	short, stop := context.WithTimeout(ctx, 400*time.Millisecond)
	_, err = core.Probe(short, parsed.Nodes[0], targets)
	stop()
	if CodeOf(err) != "CANCELLED" {
		t.Fatalf("hanging probe did not cancel: %v", err)
	}
	for i := range targets {
		targets[i].URL = web.URL + "/health"
	}
	core.probeTLS = nil
	result, err = core.Probe(ctx, parsed.Nodes[0], targets)
	if err != nil || result.Healthy {
		t.Fatalf("untrusted TLS accepted: %#v %v", result, err)
	}
	after, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatal("isolated probes changed network interfaces")
	}
}
