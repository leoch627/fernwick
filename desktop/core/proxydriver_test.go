package core

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func proxyTestNode(t *testing.T, uri string) ProxyNode {
	t.Helper()
	parsed, err := ParseSubscription(uri, subscriptionTestOptions())
	if err != nil || len(parsed.Nodes) != 1 || !parsed.Nodes[0].Compatible {
		t.Fatalf("fixture node: %+v %v", parsed, err)
	}
	return parsed.Nodes[0]
}
func proxyTestPorts() ProxyPorts {
	return ProxyPorts{Local: 17890, Health: ProbeAuth{Port: 17891, User: "health", Password: "health-password-123456"}}
}
func proxyTestRules() Rules {
	return Rules{SchemaVersion: 2, Sections: []RuleSection{
		{Target: "block", Domains: []string{"domain:ads.example"}},
		{Target: "direct", Domains: []string{"domain:cn.example"}},
		{Target: "ai", Domains: []string{"domain:ai.example"}},
		{Target: "proxy", Domains: []string{"domain:blocked.example"}},
		{Target: "direct", IPs: []string{"1.0.1.0/24"}},
	}}
}
func configJSON(t *testing.T, config map[string]any) map[string]any {
	t.Helper()
	data, err := EncodeJSON(config)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err = json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestCompileSystemProxyListensOnLoopbackOnly(t *testing.T) {
	node := proxyTestNode(t, "vless://00000000-0000-4000-8000-000000000001@jp.example.invalid:443?security=tls&type=tcp&sni=jp.example.invalid#JP")
	config, err := CompileSystemProxy(Candidate{Node: node, Mode: "rule", Rules: proxyTestRules()}, proxyTestPorts())
	if err != nil {
		t.Fatal(err)
	}
	decoded := configJSON(t, config)
	inbounds := decoded["inbounds"].([]any)
	if len(inbounds) != 2 {
		t.Fatalf("inbounds: %v", inbounds)
	}
	for _, raw := range inbounds {
		in := raw.(map[string]any)
		if in["listen"] != "127.0.0.1" || in["protocol"] == "tun" {
			t.Fatalf("inbound leaves loopback: %v", in)
		}
	}
	if local := inbounds[0].(map[string]any); local["protocol"] != "mixed" || local["port"] != float64(17890) {
		t.Fatalf("local port: %v", local)
	}
	if health := inbounds[1].(map[string]any)["settings"].(map[string]any); health["auth"] != "password" {
		t.Fatalf("health port must be authenticated: %v", health)
	}
	routing := decoded["routing"].(map[string]any)
	if routing["domainStrategy"] != "IPIfNonMatch" {
		t.Fatalf("rule mode must resolve unmatched domains: %v", routing["domainStrategy"])
	}
	rules := routing["rules"].([]any)
	first, last := rules[0].(map[string]any), rules[len(rules)-1].(map[string]any)
	if !reflect.DeepEqual(first["inboundTag"], []any{"health"}) || first["outboundTag"] != "node-0" {
		t.Fatalf("health port must use the proxy first: %v", first)
	}
	if _, network := last["network"]; network || !reflect.DeepEqual(last["ip"], []any{"0.0.0.0/0", "::/0"}) {
		t.Fatalf("rule mode must end on an address rule so unmatched names resolve: %v", last)
	}
	// No DNS leak: the mainland resolver sees only names a direct list names; the rest
	// resolve through the proxy (with a mainland ECS subnet) and never fall back.
	servers := decoded["dns"].(map[string]any)["servers"].([]any)
	for _, raw := range servers {
		if s := raw.(map[string]any); s["tag"] == "dns-direct" && (s["domains"] == nil || s["skipFallback"] != true || s["finalQuery"] != true) {
			t.Fatalf("mainland resolver answers unlisted names: %v", s)
		}
	}
	fallback := servers[len(servers)-1].(map[string]any)
	if fallback["tag"] != "dns-proxy" || fallback["address"] != UnlistedResolver || fallback["clientIP"] != MainlandClientSubnet || fallback["finalQuery"] != true || fallback["domains"] != nil {
		t.Fatalf("unlisted names must resolve through the proxy: %v", fallback)
	}
	if !reflect.DeepEqual(rules[1].(map[string]any)["inboundTag"], []any{"dns-direct"}) || rules[1].(map[string]any)["outboundTag"] != "direct" || !reflect.DeepEqual(rules[2].(map[string]any)["inboundTag"], []any{"dns-proxy"}) || rules[2].(map[string]any)["outboundTag"] != "node-0" {
		t.Fatalf("resolver traffic must follow its tag: %v %v", rules[1], rules[2])
	}
	for _, raw := range decoded["outbounds"].([]any) {
		if out := raw.(map[string]any); out["tag"] == "direct" && out["settings"].(map[string]any)["domainStrategy"] != "UseIPv4v6" {
			t.Fatalf("direct connections must prefer IPv4: %v", out)
		}
		stream, _ := raw.(map[string]any)["streamSettings"].(map[string]any)
		if _, bound := stream["sockopt"]; bound {
			t.Fatalf("system proxy outbounds must not bind interfaces: %v", raw)
		}
	}
	global, err := CompileSystemProxy(Candidate{Node: node, Mode: "global", Rules: proxyTestRules()}, proxyTestPorts())
	if err != nil {
		t.Fatal(err)
	}
	globalRouting := configJSON(t, global)["routing"].(map[string]any)
	globalRules := globalRouting["rules"].([]any)
	if globalRouting["domainStrategy"] != "AsIs" || globalRules[len(globalRules)-1].(map[string]any)["network"] != "tcp,udp" {
		t.Fatalf("global mode: %v", globalRouting)
	}
	text, _ := json.Marshal(globalRules)
	if strings.Contains(string(text), "cn.example") || !strings.Contains(string(text), "ads.example") || !strings.Contains(string(text), "ai.example") {
		t.Fatalf("global mode keeps only blocking and AI sections: %s", text)
	}
	for _, bad := range []ProxyPorts{{Local: 80, Health: proxyTestPorts().Health}, {Local: 17891, Health: proxyTestPorts().Health}, {Local: 17890, Health: ProbeAuth{Port: 17891, User: "u", Password: "short"}}} {
		if _, err := CompileSystemProxy(Candidate{Node: node, Mode: "rule", Rules: proxyTestRules()}, bad); CodeOf(err) != "INVALID_INPUT" {
			t.Fatalf("ports %+v accepted: %v", bad, err)
		}
	}
}
func TestCompileSystemProxyBalancesPoolAndSkipsUnusableNodes(t *testing.T) {
	hk := proxyTestNode(t, "vless://00000000-0000-4000-8000-000000000001@hk.example.invalid:443?security=tls&type=tcp&sni=hk.example.invalid#HK")
	jp := proxyTestNode(t, "vless://00000000-0000-4000-8000-000000000002@jp.example.invalid:443?security=tls&type=tcp&sni=jp.example.invalid#JP")
	hkRegion, jpRegion := "HK", "JP"
	hk.Region, jp.Region = &hkRegion, &jpRegion
	broken := jp
	broken.Compatible = false
	config, err := CompileSystemProxy(Candidate{Node: hk, Pool: []ProxyNode{broken, jp}, Automatic: true, Mode: "rule", Rules: proxyTestRules()}, proxyTestPorts())
	if err != nil {
		t.Fatal(err)
	}
	decoded := configJSON(t, config)
	tags := []string{}
	for _, raw := range decoded["outbounds"].([]any) {
		tags = append(tags, raw.(map[string]any)["tag"].(string))
	}
	if !reflect.DeepEqual(tags, []string{"node-0", "node-ai-1", "direct", "dns-out", "block"}) {
		t.Fatalf("outbounds: %v", tags)
	}
	balancers := decoded["routing"].(map[string]any)["balancers"].([]any)
	if len(balancers) != 2 || decoded["observatory"] == nil {
		t.Fatalf("balancers: %v", balancers)
	}
	for _, raw := range decoded["routing"].(map[string]any)["rules"].([]any) {
		rule := raw.(map[string]any)
		if reflect.DeepEqual(rule["domain"], []any{"domain:ai.example"}) && rule["balancerTag"] != "ai" {
			t.Fatalf("AI traffic must use the AI balancer: %v", rule)
		}
	}
}
func TestRulesWithoutTargetDropsAdBlocking(t *testing.T) {
	rules := proxyTestRules()
	kept := rules.WithoutTarget("block")
	if len(kept.Sections) != len(rules.Sections)-1 || kept.Validate() != nil {
		t.Fatalf("sections: %+v", kept)
	}
	for _, section := range kept.Sections {
		if section.Target == "block" {
			t.Fatal("block section kept")
		}
	}
	if len(rules.Sections) != 5 {
		t.Fatal("original rules changed")
	}
}

type recordingSystemProxy struct {
	mu         sync.Mutex
	calls      []string
	saved      json.RawMessage
	restoreErr error
	applyErr   error
}

func (r *recordingSystemProxy) record(call string) {
	r.mu.Lock()
	r.calls = append(r.calls, call)
	r.mu.Unlock()
}
func (r *recordingSystemProxy) Snapshot(context.Context) (json.RawMessage, error) {
	r.record("snapshot")
	return json.RawMessage(`{"previous":true}`), nil
}
func (r *recordingSystemProxy) Apply(_ context.Context, saved json.RawMessage, port int) error {
	r.record("apply")
	return r.applyErr
}
func (r *recordingSystemProxy) Restore(_ context.Context, saved json.RawMessage) error {
	r.record("restore")
	r.mu.Lock()
	r.saved = saved
	r.mu.Unlock()
	return r.restoreErr
}
func (r *recordingSystemProxy) history() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string{}, r.calls...)
}

func TestProxyDriverCleanupRestoresInterruptedSession(t *testing.T) {
	journal := filepath.Join(t.TempDir(), "system-proxy.json")
	system := &recordingSystemProxy{restoreErr: errors.New("busy")}
	driver := NewProxyDriver(nil, system, journal, nil, nil)
	if driver.Verified() {
		t.Fatal("a driver without a core cannot connect")
	}
	if err := driver.Cleanup(context.Background()); err != nil || len(system.history()) != 0 {
		t.Fatalf("nothing to restore: %v %v", err, system.history())
	}
	if err := writeProxyJournal(journal, proxyJournal{SchemaVersion: 1, Port: 7890, Saved: json.RawMessage(`{"server":"corp:8080"}`)}); err != nil {
		t.Fatal(err)
	}
	if err := driver.Cleanup(context.Background()); err == nil {
		t.Fatal("failed restore reported as clean")
	}
	if _, err := os.Stat(journal); err != nil {
		t.Fatal("journal must survive a failed restore")
	}
	system.restoreErr = nil
	if err := driver.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if string(system.saved) != `{"server":"corp:8080"}` {
		t.Fatalf("restored %s", system.saved)
	}
	if _, err := os.Stat(journal); !os.IsNotExist(err) {
		t.Fatal("journal kept after restore")
	}
}

type tunnelTestDriver struct {
	lifecycleDriver
	verified   bool
	candidates []Candidate
	repairs    atomic.Int32
	ensures    atomic.Int32
}

func (d *tunnelTestDriver) Verified() bool { return d.verified }
func (d *tunnelTestDriver) Prepare(_ context.Context, c Candidate) (string, error) {
	d.mu.Lock()
	d.candidates = append(d.candidates, c)
	d.mu.Unlock()
	return "fixture", nil
}
func (d *tunnelTestDriver) Repair(context.Context) error      { d.repairs.Add(1); return nil }
func (d *tunnelTestDriver) EnsureReady(context.Context) error { d.ensures.Add(1); return nil }
func (d *tunnelTestDriver) prepared() []Candidate {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]Candidate{}, d.candidates...)
}

func TestTunnelDriverRoutesByTunnelAndCleansBoth(t *testing.T) {
	proxy, tun := &tunnelTestDriver{verified: true}, &tunnelTestDriver{}
	driver := NewTunnelDriver(proxy, tun)
	if driver.Verified() || !driver.VerifiedFor("proxy") || driver.VerifiedFor("tun") {
		t.Fatal("readiness must follow the tunnel")
	}
	if _, err := driver.Prepare(context.Background(), Candidate{Tunnel: "proxy"}); err != nil {
		t.Fatal(err)
	}
	if err := driver.Start(context.Background(), "fixture"); err != nil {
		t.Fatal(err)
	}
	if proxy.starts.Load() != 1 || tun.starts.Load() != 0 || len(tun.prepared()) != 0 {
		t.Fatal("proxy candidate reached the TUN driver")
	}
	if err := driver.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if proxy.cleanups.Load() != 1 || tun.cleanups.Load() != 1 {
		t.Fatal("cleanup must cover both tunnels")
	}
	if err := driver.Start(context.Background(), "fixture"); CodeOf(err) != "COMPONENTS_UNAVAILABLE" {
		t.Fatalf("no active tunnel after cleanup: %v", err)
	}
	if err := driver.EnsureReadyFor(context.Background(), "proxy"); err != nil || tun.ensures.Load() != 0 {
		t.Fatal("system proxy mode must not install the network service")
	}
	if err := driver.EnsureReadyFor(context.Background(), "tun"); err != nil || tun.ensures.Load() != 1 {
		t.Fatal("TUN mode installs the network service")
	}
}

func TestControllerConnectsThroughChosenTunnel(t *testing.T) {
	proxy, tun := &tunnelTestDriver{verified: true}, &tunnelTestDriver{}
	h := newControllerHarness(t, func(deps *ControllerDeps) { deps.NetworkDriver = NewTunnelDriver(proxy, tun) }, true)
	candidates := proxy.prepared()
	if len(candidates) != 1 || candidates[0].Tunnel != "proxy" || tun.ensures.Load() != 0 {
		t.Fatalf("default connection must use the system proxy without the network service: %+v", candidates)
	}
	if result := commandForTest(h.controller, map[string]any{"type": "repair"}); !result.OK || tun.repairs.Load() != 0 {
		t.Fatalf("repair in system proxy mode must not reinstall the network service: %+v", result)
	}
	state := h.controller.View()
	change := state.Preferences
	change.Tunnel = "tun"
	if result := commandForTest(h.controller, map[string]any{"type": "connect"}); !result.OK {
		t.Fatal(result)
	}
	// Switching to TUN while connected reconnects; the service is not verified here.
	result := commandForTest(h.controller, map[string]any{"type": "preferences", "preferences": change})
	if result.OK || tun.ensures.Load() != 1 || result.State.Preferences.Tunnel != "tun" {
		t.Fatalf("switching to TUN must ask for the network service: %+v", result)
	}
	change.Tunnel, change.AdBlock = "proxy", false
	if result := commandForTest(h.controller, map[string]any{"type": "preferences", "preferences": change}); !result.OK {
		t.Fatal(result)
	}
	if result := commandForTest(h.controller, map[string]any{"type": "connect"}); !result.OK {
		t.Fatal(result)
	}
	if got := proxy.prepared(); got[len(got)-1].Tunnel != "proxy" {
		t.Fatalf("back to system proxy: %+v", got[len(got)-1])
	}
}

func TestControllerChecksNodeBeforeInstallingTheService(t *testing.T) {
	proxy, tun := &tunnelTestDriver{verified: true}, &tunnelTestDriver{}
	h := newControllerHarness(t, func(deps *ControllerDeps) { deps.NetworkDriver = NewTunnelDriver(proxy, tun) }, true)
	change := h.controller.View().Preferences
	change.Tunnel, change.NodeID = "tun", authPointer("removed-node")
	result := commandForTest(h.controller, map[string]any{"type": "preferences", "preferences": change})
	if result.OK || result.Error != "NO_AUTHORIZED_NODES" || tun.ensures.Load() != 0 {
		t.Fatalf("a node that cannot be used must fail before the password prompt: %+v ensures=%d", result.Error, tun.ensures.Load())
	}
}

func TestFreeLoopbackPortFallsBackWhenBusy(t *testing.T) {
	busy, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	taken := busy.Addr().(*net.TCPAddr).Port
	port, err := freeLoopbackPort(taken, 0)
	if err != nil || port == taken || port < 1024 {
		t.Fatalf("busy preferred port: %d %v", port, err)
	}
	if port, err = freeLoopbackPort(80, 0); err != nil || port < 1024 {
		t.Fatalf("privileged preferred port: %d %v", port, err)
	}
	other, err := freeLoopbackPort(0, port)
	if err != nil || other == port {
		t.Fatalf("ports must differ: %d %d %v", port, other, err)
	}
}
