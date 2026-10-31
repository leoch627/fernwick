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
		Rules []map[string]any `json:"rules"`
	} `json:"routing"`
}

func compile(t *testing.T, c Candidate) coreConfig {
	t.Helper()
	j := Journal{Interface: Interface{Name: "eth0"}, Tun: tunName(), NodeAddress: "203.0.113.10"}
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

func TestCompileCoreRuleMode(t *testing.T) {
	c := validCandidate()
	c.Node.Fingerprint = "hellochrome_120"
	c.Rules = Rules{SchemaVersion: 1, DirectDomains: []string{"cn"}, DirectFullDomains: []string{"example.cn"}, ProxyDomains: []string{"google.com"}, BlockedDomains: []string{"ads.example"}, DirectIPs: []string{"1.0.1.0/24"}}
	cfg := compile(t, c)

	for _, key := range []string{"loglevel", "access", "error"} {
		if cfg.Log[key] != "none" {
			t.Errorf("log %s = %q; traffic must not be logged", key, cfg.Log[key])
		}
	}
	proxy := cfg.Outbounds[0]
	if proxy.Tag != "proxy" || proxy.Protocol != "vless" {
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
	if sock := proxy.StreamSettings["sockopt"].(map[string]any); sock["interface"] != "eth0" {
		t.Errorf("proxy is not bound to the physical interface: %v", sock)
	}

	rules := cfg.Routing.Rules
	blocked, lan, proxied, direct := ruleIndex(rules, "block", "domain"), -1, ruleIndex(rules, "proxy", "domain"), ruleIndex(rules, "direct", "domain")
	for i, r := range rules {
		if r["outboundTag"] == "direct" && r["ip"] != nil && lan < 0 {
			lan = i
		}
	}
	if blocked < 0 || lan < 0 || proxied < 0 || direct < 0 || !(blocked < lan && lan < proxied && proxied < direct) {
		t.Errorf("rule order block=%d lan=%d proxy=%d direct=%d", blocked, lan, proxied, direct)
	}
	last := rules[len(rules)-1]
	if last["outboundTag"] != "proxy" || last["network"] != "tcp,udp" {
		t.Errorf("unmatched traffic does not default to the proxy: %v", last)
	}
	if len(cfg.DNS.Servers) != 3 {
		t.Errorf("dns servers = %v", cfg.DNS.Servers)
	}
}

func TestCompileCoreGlobalMode(t *testing.T) {
	c := validCandidate()
	c.Mode = "global"
	c.Rules = Rules{SchemaVersion: 1, DirectDomains: []string{"cn"}, ProxyDomains: []string{"google.com"}, BlockedDomains: []string{"ads.example"}, DirectIPs: []string{"1.0.1.0/24"}}
	cfg := compile(t, c)
	if ruleIndex(cfg.Routing.Rules, "direct", "domain") >= 0 || ruleIndex(cfg.Routing.Rules, "proxy", "domain") >= 0 {
		t.Error("global mode applies domain split rules")
	}
	for _, r := range cfg.Routing.Rules {
		if ips, ok := r["ip"].([]any); ok && r["outboundTag"] == "direct" && len(ips) == 1 {
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

func TestCompileCorePlatformTun(t *testing.T) {
	tun := compile(t, validCandidate()).Inbounds[0]["settings"].(map[string]any)
	routes := tun["autoSystemRoutingTable"].([]any)
	if runtime.GOOS == "windows" {
		if len(routes) != 2 || tun["autoSystemWfpBlockLeak"] == nil {
			t.Errorf("windows tun does not own routes and leak protection: %v", tun)
		}
	} else if len(routes) != 0 {
		t.Errorf("helper-owned routing also configured in xray: %v", routes)
	}
}
