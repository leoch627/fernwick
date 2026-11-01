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
	if sock := proxy.StreamSettings["sockopt"].(map[string]any); sock["interface"] != "eth0" {
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
	if len(servers) != 4 || servers[0]["tag"] != "dns-proxy" || servers[1]["tag"] != "dns-proxy" || servers[2]["tag"] != "dns-direct" || len(servers[2]["domains"].([]any)) != 3 || servers[3]["tag"] != "dns-proxy" || servers[3]["domains"] != nil {
		t.Errorf("dns servers = %v", servers)
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
