package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func testRoutingRules() Rules {
	return Rules{SchemaVersion: 1, DirectDomains: []string{"example.cn"}, ProxyDomains: []string{"example.org"}, BlockedDomains: []string{}, DirectIPs: []string{}}
}

func TestRulesRejectInvalidDomainAndCIDR(t *testing.T) {
	for _, value := range []string{"999.1.2.3/24", "192.0.2.0/64", "2001:db8::/129", "1.1.1.1/01", "bad", "fe80::1%bad_zone", "192.168.001.1", "192.0.2.0/24/extra"} {
		rules := testRoutingRules()
		rules.DirectIPs = []string{value}
		if err := rules.Validate(); err == nil {
			t.Errorf("accepted invalid IP/CIDR %q", value)
		}
	}
	for _, value := range []string{"bad..domain", "-bad.domain", "bad-.domain", ".bad.domain", "bad.domain.", "", strings.Repeat("x", 64) + ".test"} {
		rules := testRoutingRules()
		rules.DirectDomains = []string{value}
		if err := rules.Validate(); err == nil {
			t.Errorf("accepted invalid domain %q", value)
		}
	}
	rules := testRoutingRules()
	rules.DirectIPs = []string{"192.0.2.0/24", "2001:db8::/32", "192.0.2.1", "::ffff:192.0.2.1/128", "fe80::1%en0/64"}
	if err := rules.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"schemaVersion":1,"directDomains":[],"proxyDomains":[],"blockedDomains":[],"directIPs":[],"executable":"evil"}`, `{"schemaVersion":1,"directDomains":null,"proxyDomains":[],"blockedDomains":[],"directIPs":[]}`, `{"schemaVersion":1,"directDomains":[],"proxyDomains":[],"blockedDomains":[],"directIPs":[],"directFullDomains":null}`} {
		var decoded Rules
		if err := DecodeStrict([]byte(raw), &decoded, 1024); err == nil {
			t.Errorf("accepted invalid rule object %s", raw)
		}
	}
}

func TestRoutingSafetyOrdering(t *testing.T) {
	rules := testRoutingRules()
	rules.BlockedDomains = []string{"blocked.invalid"}
	rules.DirectFullDomains = []string{"exact.invalid"}
	routing, err := CompileRouting("rule", rules)
	if err != nil {
		t.Fatal(err)
	}
	sequence := routing["rules"].([]any)
	if sequence[0].(map[string]any)["outboundTag"] != "proxy" || sequence[1].(map[string]any)["outboundTag"] != "dns-out" || sequence[len(sequence)-1].(map[string]any)["outboundTag"] != "proxy" {
		t.Fatal("health, DNS, or fallback routing order changed")
	}
	global, err := CompileRouting("global", rules)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(global)
	if strings.Contains(string(raw), "example.cn") || strings.Contains(string(raw), "exact.invalid") || strings.Contains(string(raw), "100.64.0.0/10") || !strings.Contains(string(raw), "blocked.invalid") {
		t.Fatalf("unsafe global rules: %s", raw)
	}
}

func TestCompileProbeIsolationAndCredentials(t *testing.T) {
	parsed, err := ParseSubscription(subscriptionTestURI, subscriptionTestOptions())
	if err != nil {
		t.Fatal(err)
	}
	node := parsed.Nodes[0]
	auth := ProbeAuth{Port: 49152, User: "random-session", Password: "random-session-password"}
	config, err := CompileProbe(node, auth)
	if err != nil {
		t.Fatal(err)
	}
	inbounds := config["inbounds"].([]any)
	outbounds := config["outbounds"].([]any)
	if len(inbounds) != 1 || len(outbounds) != 1 || inbounds[0].(map[string]any)["listen"] != "127.0.0.1" {
		t.Fatal("probe is not isolated")
	}
	settings := inbounds[0].(map[string]any)["settings"].(map[string]any)
	if settings["auth"] != "password" || settings["udp"] != false {
		t.Fatal("probe authentication missing")
	}
	raw, _ := json.Marshal(config)
	if strings.Contains(string(raw), "freedom") || strings.Contains(string(raw), "tun") {
		t.Fatalf("probe can alter network: %s", raw)
	}
	for _, bad := range []ProbeAuth{{Port: 1023, User: auth.User, Password: auth.Password}, {Port: 65536, User: auth.User, Password: auth.Password}, {Port: auth.Port, Password: auth.Password}, {Port: auth.Port, User: auth.User, Password: "short"}, {Port: auth.Port, User: strings.Repeat("x", 256), Password: auth.Password}} {
		if _, err := CompileProbe(node, bad); err == nil {
			t.Errorf("invalid probe auth accepted: %#v", bad)
		}
	}
	node.UDP = false
	if _, err := CompileProbe(node, auth); CodeOf(err) != "NO_COMPATIBLE_NODES" {
		t.Fatalf("UDP unconfirmed node compiled: %v", err)
	}
}
