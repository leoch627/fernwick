package main

import (
	"encoding/json"
	"runtime"
	"testing"
)

type coreConfig struct {
	Log       map[string]string `json:"log"`
	Inbounds  []map[string]any  `json:"inbounds"`
	Outbounds []struct {
		Tag            string         `json:"tag"`
		Protocol       string         `json:"protocol"`
		Settings       map[string]any `json:"settings"`
		StreamSettings map[string]any `json:"streamSettings"`
	} `json:"outbounds"`
	DNS struct {
		Servers []map[string]any `json:"servers"`
	} `json:"dns"`
	Routing struct {
		Rules     []map[string]any `json:"rules"`
		Balancers []map[string]any `json:"balancers"`
	} `json:"routing"`
	Observatory map[string]any `json:"observatory"`
}

func compile(t *testing.T, c Candidate) coreConfig {
	t.Helper()
	j := Journal{Interface: Interface{Name: "eth0"}, Tun: tunName(), NodeAddress: "203.0.113.10"}
	for i := range c.Pool {
		j.PoolAddresses = append(j.PoolAddresses, "203.0.113."+itoa(20+i))
	}
	var out coreConfig
	if e := json.Unmarshal(compileCore(c, j), &out); e != nil {
		t.Fatal(e)
	}
	return out
}
func ruleIndex(rules []map[string]any, tag string, key string) int {
	for i, r := range rules {
		if r["outboundTag"] == tag && r[key] != nil {
			return i
		}
	}
	return -1
}

var testRules = Rules{SchemaVersion: 2, Sections: []RuleSection{
	{Target: "block", Domains: []string{"domain:ads.example"}},
	{Target: "ai", Domains: []string{"domain:openai.com"}},
	{Target: "proxy", Domains: []string{"domain:google.com", "keyword:google"}},
	{Target: "direct", Domains: []string{"domain:cn", "full:example.cn", "regexp:^cdn[0-9]+\\.example\\.cn$"}},
	{Target: "direct", IPs: []string{"1.0.1.0/24", "2001:db8::/32"}},
}}

func TestCompileCoreRuleMode(t *testing.T) {
	c := validCandidate()
	c.Node.Fingerprint = "hellochrome_120"
	c.Node.AI = true
	c.Rules = testRules
	cfg := compile(t, c)

	for _, key := range []string{"loglevel", "access", "error"} {
		if cfg.Log[key] != "none" {
			t.Errorf("log %s = %q; traffic must not be logged", key, cfg.Log[key])
		}
	}
	proxy := cfg.Outbounds[0]
	if proxy.Tag != "node-ai-0" || proxy.Protocol != "vless" {
		t.Fatalf("first outbound = %s/%s", proxy.Tag, proxy.Protocol)
	}
	server := proxy.Settings["vnext"].([]any)[0].(map[string]any)
	if server["address"] != "203.0.113.10" {
		t.Errorf("proxy dials %v instead of the pre-resolved address", server["address"])
	}
	tls := proxy.StreamSettings["tlsSettings"].(map[string]any)
	if tls["allowInsecure"] != false || tls["serverName"] != "node.example.com" || tls["fingerprint"] != "hellochrome_120" {
		t.Errorf("tls settings = %v", tls)
	}
	// Linux binds the proxy itself; on Windows and macOS the core binds every outbound
	// to the default route's interface (TestCompileCoreCoreOwnedRouting).
	if sock := proxy.StreamSettings["sockopt"].(map[string]any); !coreOwnsRoutes(runtime.GOOS) && sock["interface"] != "eth0" {
		t.Errorf("proxy is not bound to the physical interface: %v", sock)
	}

	rules := cfg.Routing.Rules
	lan := -1
	for i, r := range rules {
		if r["outboundTag"] == "direct" && r["ip"] != nil && lan < 0 {
			lan = i
		}
	}
	blocked, ai, proxied, direct := ruleIndex(rules, "block", "domain"), -1, -1, ruleIndex(rules, "direct", "domain")
	for i, r := range rules {
		if r["domain"] != nil && r["outboundTag"] == "node-ai-0" {
			if ai < 0 {
				ai = i
			} else if proxied < 0 {
				proxied = i
			}
		}
	}
	if lan < 0 || blocked < 0 || ai < 0 || proxied < 0 || direct < 0 || !(lan < blocked && blocked < ai && ai < proxied && proxied < direct) {
		t.Errorf("rule order lan=%d block=%d ai=%d proxy=%d direct=%d", lan, blocked, ai, proxied, direct)
	}
	if domains := rules[direct]["domain"].([]any); len(domains) != 3 || domains[2] != "regexp:^cdn[0-9]+\\.example\\.cn$" {
		t.Errorf("direct domains = %v", domains)
	}
	last := rules[len(rules)-1]
	if last["outboundTag"] != "node-ai-0" || last["network"] != "tcp,udp" {
		t.Errorf("unmatched traffic does not default to the chosen node: %v", last)
	}
	if len(cfg.Routing.Balancers) != 0 || cfg.Observatory != nil {
		t.Errorf("a manual AI-capable node needs no balancer: %v %v", cfg.Routing.Balancers, cfg.Observatory)
	}
	// Blocked domains need no resolver; the others are resolved in section order.
	servers := cfg.DNS.Servers
	if len(servers) != 4 || servers[0]["tag"] != "dns-proxy" || servers[1]["tag"] != "dns-proxy" || servers[2]["tag"] != "dns-direct" || len(servers[2]["domains"].([]any)) != 3 || servers[3]["domains"] != nil {
		t.Errorf("dns servers = %v", servers)
	}
	assertNoDNSLeak(t, servers)
	for _, raw := range cfg.Outbounds {
		if raw.Tag == "direct" && raw.Settings["domainStrategy"] != "UseIPv4v6" {
			t.Errorf("direct connections must prefer IPv4: %v", raw)
		}
	}
}

// assertNoDNSLeak: the mainland resolver only ever sees names a direct list names; every
// other name goes through the proxy, with a mainland ECS subnet, and is final.
func assertNoDNSLeak(t *testing.T, servers []map[string]any) {
	t.Helper()
	for _, s := range servers {
		if s["tag"] == "dns-direct" && (s["domains"] == nil || s["skipFallback"] != true || s["finalQuery"] != true) {
			t.Errorf("mainland resolver answers unlisted names: %v", s)
		}
	}
	last := servers[len(servers)-1]
	if last["tag"] != "dns-proxy" || last["address"] != "https://8.8.8.8/dns-query" || last["clientIP"] != "223.5.5.0" || last["finalQuery"] != true {
		t.Errorf("unlisted names must resolve through the proxy with a mainland subnet: %v", last)
	}
}

func TestCompileCoreGlobalMode(t *testing.T) {
	c := validCandidate()
	c.Mode = "global"
	c.Rules = testRules
	cfg := compile(t, c)
	if ruleIndex(cfg.Routing.Rules, "direct", "domain") >= 0 {
		t.Error("global mode applies domain split rules")
	}
	for _, r := range cfg.Routing.Rules {
		if ips, ok := r["ip"].([]any); ok && r["outboundTag"] == "direct" && len(ips) == 2 {
			t.Error("global mode sends rule IPs direct")
		}
	}
	if ruleIndex(cfg.Routing.Rules, "block", "domain") < 0 {
		t.Error("global mode dropped blocked domains")
	}
	if len(cfg.DNS.Servers) != 1 || cfg.DNS.Servers[0]["tag"] != "dns-proxy" {
		t.Errorf("global dns servers = %v", cfg.DNS.Servers)
	}
}

func balancer(cfg coreConfig, tag string) map[string]any {
	for _, b := range cfg.Routing.Balancers {
		if b["tag"] == tag {
			return b
		}
	}
	return nil
}
func targetOf(rules []map[string]any, domain string) string {
	for _, r := range rules {
		if domains, ok := r["domain"].([]any); ok && len(domains) > 0 && domains[0] == domain {
			if tag, ok := r["balancerTag"].(string); ok {
				return "balancer:" + tag
			}
			return r["outboundTag"].(string)
		}
	}
	return ""
}

func TestCompileCoreAutomaticPool(t *testing.T) {
	c := validCandidate()
	c.Rules = testRules
	c.Automatic = true
	hk := validCandidate().Node
	hk.Host = "hk.example.com"
	us := validCandidate().Node
	us.Host, us.AI = "us.example.com", true
	c.Pool = []Node{hk, us}
	cfg := compile(t, c)
	if len(cfg.Outbounds) != 6 || cfg.Outbounds[0].Tag != "node-0" || cfg.Outbounds[1].Tag != "node-1" || cfg.Outbounds[2].Tag != "node-ai-2" {
		t.Fatalf("outbounds = %v", cfg.Outbounds)
	}
	if address := cfg.Outbounds[2].Settings["vnext"].([]any)[0].(map[string]any)["address"]; address != "203.0.113.21" {
		t.Errorf("pool node dials %v", address)
	}
	auto, ai := balancer(cfg, "auto"), balancer(cfg, "ai")
	if auto == nil || auto["fallbackTag"] != "node-0" || auto["selector"].([]any)[0] != "node-" || ai == nil || ai["fallbackTag"] != "node-ai-2" || ai["selector"].([]any)[0] != "node-ai-" {
		t.Fatalf("balancers = %v", cfg.Routing.Balancers)
	}
	if got := targetOf(cfg.Routing.Rules, "domain:google.com"); got != "balancer:auto" {
		t.Errorf("proxy traffic goes to %s", got)
	}
	if got := targetOf(cfg.Routing.Rules, "domain:openai.com"); got != "balancer:ai" {
		t.Errorf("AI traffic goes to %s", got)
	}
	if last := cfg.Routing.Rules[len(cfg.Routing.Rules)-1]; last["balancerTag"] != "auto" {
		t.Errorf("unmatched traffic goes to %v", last)
	}
	if cfg.Observatory == nil || cfg.Observatory["subjectSelector"].([]any)[0] != "node-" || cfg.Observatory["probeInterval"] != "5m" {
		t.Errorf("observatory = %v", cfg.Observatory)
	}
}

func TestCompileCoreManualNodeKeepsAIOffUnsuitableExit(t *testing.T) {
	c := validCandidate()
	c.Rules = testRules
	us := validCandidate().Node
	us.Host, us.AI = "us.example.com", true
	c.Pool = []Node{us}
	cfg := compile(t, c)
	if got := targetOf(cfg.Routing.Rules, "domain:google.com"); got != "node-0" {
		t.Errorf("manual node traffic goes to %s", got)
	}
	if got := targetOf(cfg.Routing.Rules, "domain:openai.com"); got != "balancer:ai" {
		t.Errorf("AI traffic goes to %s", got)
	}
	if balancer(cfg, "auto") != nil || cfg.Observatory["subjectSelector"].([]any)[0] != "node-ai-" {
		t.Errorf("balancers %v observatory %v", cfg.Routing.Balancers, cfg.Observatory)
	}
}

func TestCompileCoreSkipsUnresolvedPoolNodes(t *testing.T) {
	c := validCandidate()
	c.Automatic = true
	c.Pool = []Node{validCandidate().Node, validCandidate().Node}
	j := Journal{Interface: Interface{Name: "eth0"}, Tun: tunName(), NodeAddress: "203.0.113.10", PoolAddresses: []string{"", "203.0.113.30"}}
	var cfg coreConfig
	if e := json.Unmarshal(compileCore(c, j), &cfg); e != nil {
		t.Fatal(e)
	}
	if len(cfg.Outbounds) != 5 || cfg.Outbounds[1].Tag != "node-1" || cfg.Outbounds[1].Settings["vnext"].([]any)[0].(map[string]any)["address"] != "203.0.113.30" {
		t.Fatalf("outbounds = %v", cfg.Outbounds)
	}
}

func TestCompileCoreProtocols(t *testing.T) {
	ss := validCandidate()
	ss.Node = Node{Protocol: "shadowsocks", Host: "ss.example.com", Port: 8388, Credential: "secret", Method: "aes-256-gcm", Transport: "tcp", Security: "none"}
	server := compile(t, ss).Outbounds[0].Settings["servers"].([]any)[0].(map[string]any)
	if server["method"] != "aes-256-gcm" || server["password"] != "secret" || server["address"] != "203.0.113.10" {
		t.Errorf("shadowsocks server = %v", server)
	}

	vmess := validCandidate()
	vmess.Node = Node{Protocol: "vmess", Host: "vm.example.com", Port: 443, Credential: testUUID, Transport: "ws", Security: "tls", SNI: "vm.example.com", WSPath: "/ws", WSHost: "cdn.example.com"}
	out := compile(t, vmess).Outbounds[0]
	user := out.Settings["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
	if user["security"] != "auto" || user["alterId"] != float64(0) {
		t.Errorf("vmess user = %v", user)
	}
	ws := out.StreamSettings["wsSettings"].(map[string]any)
	if ws["path"] != "/ws" || ws["headers"].(map[string]any)["Host"] != "cdn.example.com" {
		t.Errorf("ws settings = %v", ws)
	}

	reality := validCandidate()
	reality.Node.Security, reality.Node.PublicKey, reality.Node.ShortID, reality.Node.Flow = "reality", testRealityKey, "abcd", "xtls-rprx-vision"
	out = compile(t, reality).Outbounds[0]
	if settings := out.StreamSettings["realitySettings"].(map[string]any); settings["publicKey"] != testRealityKey || settings["shortId"] != "abcd" {
		t.Errorf("reality settings = %v", settings)
	}
	if out.StreamSettings["tlsSettings"] != nil {
		t.Error("reality outbound also carries tls settings")
	}
}

func compileFor(t *testing.T, goos string, j Journal) coreConfig {
	t.Helper()
	var out coreConfig
	if e := json.Unmarshal(compileCoreFor(goos, validCandidate(), j), &out); e != nil {
		t.Fatal(e)
	}
	return out
}

func TestCompileCorePlatformTun(t *testing.T) {
	tun := compile(t, validCandidate()).Inbounds[0]["settings"].(map[string]any)
	routes := tun["autoSystemRoutingTable"].([]any)
	if coreOwnsRoutes(runtime.GOOS) != (len(routes) > 0) {
		t.Errorf("%s tun routes = %v", runtime.GOOS, routes)
	}
}

// Windows and macOS run the TUN as v2rayN does: the core routes the system into it and
// keeps its own connections on the default route's interface, whichever that is.
func TestCompileCoreCoreOwnedRouting(t *testing.T) {
	for _, goos := range []string{"windows", "darwin"} {
		for _, ipv6 := range []bool{false, true} {
			j := Journal{Interface: Interface{Name: "en0"}, Tun: "utun50", RouteIPv6: ipv6, NodeAddress: "203.0.113.10"}
			cfg := compileFor(t, goos, j)
			tun := cfg.Inbounds[0]["settings"].(map[string]any)
			want := []any{"0.0.0.0/0"}
			if ipv6 {
				want = append(want, "::/0")
			}
			if routes := tun["autoSystemRoutingTable"].([]any); len(routes) != len(want) || routes[0] != want[0] || len(want) == 2 && routes[1] != want[1] {
				t.Errorf("%s ipv6=%t routes = %v", goos, ipv6, routes)
			}
			if tun["autoOutboundsInterface"] != "auto" {
				t.Errorf("%s: core does not follow the default route: %v", goos, tun["autoOutboundsInterface"])
			}
			gateway := tun["gateway"].([]any)
			if gateway[0] != "172.19.0.1/30" || goos == "darwin" && len(gateway) != 1 || goos == "windows" && len(gateway) != map[bool]int{false: 1, true: 2}[ipv6] {
				t.Errorf("%s ipv6=%t gateway = %v", goos, ipv6, gateway)
			}
			if goos == "windows" {
				if dns := tun["dns"].([]any); len(dns) != 1 || dns[0] != "172.19.0.2" || tun["autoSystemWfpBlockLeak"] == nil {
					t.Errorf("windows DNS stays outside the TUN: %v", tun)
				}
			} else if tun["dns"] != nil || tun["autoSystemWfpBlockLeak"] != nil {
				t.Errorf("darwin tun has Windows-only settings: %v", tun)
			}
			for _, out := range cfg.Outbounds {
				if sock, _ := out.StreamSettings["sockopt"].(map[string]any); sock != nil && (sock["interface"] != nil || sock["mark"] != nil) {
					t.Errorf("%s: %s is pinned to an interface the core no longer follows: %v", goos, out.Tag, sock)
				}
			}
			blocked := false
			for _, rule := range cfg.Routing.Rules {
				if rule["outboundTag"] == "block" && rule["ip"] != nil && rule["ip"].([]any)[0] == "224.0.0.0/3" {
					blocked = true
				}
			}
			if !blocked {
				t.Errorf("%s: multicast is sent to the node", goos)
			}
		}
	}
	linux := compileFor(t, "linux", Journal{Interface: Interface{Name: "eth0"}, Tun: "vbtun0", NodeAddress: "203.0.113.10"})
	if sock := linux.Outbounds[0].StreamSettings["sockopt"].(map[string]any); sock["interface"] != "eth0" || sock["mark"] == nil {
		t.Errorf("linux proxy is not bound and marked: %v", sock)
	}
	if tun := linux.Inbounds[0]["settings"].(map[string]any); len(tun["autoSystemRoutingTable"].([]any)) != 0 {
		t.Errorf("linux core also routes: %v", tun)
	}
}
