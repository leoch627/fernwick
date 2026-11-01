package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func testRoutingRules() Rules {
	return Rules{SchemaVersion: 2, Sections: []RuleSection{{Target: "direct", Domains: []string{"domain:example.cn"}}, {Target: "proxy", Domains: []string{"domain:example.org"}}}}
}

func TestRulesRejectInvalidDomainAndCIDR(t *testing.T) {
	for _, value := range []string{"999.1.2.3/24", "192.0.2.0/64", "2001:db8::/129", "1.1.1.1/01", "bad", "fe80::1%en0/64", "192.168.001.1", "192.0.2.0/24/extra"} {
		rules := testRoutingRules()
		rules.Sections = append(rules.Sections, RuleSection{Target: "direct", IPs: []string{value}})
		if err := rules.Validate(); err == nil {
			t.Errorf("accepted invalid IP/CIDR %q", value)
		}
	}
	for _, value := range []string{"domain:bad..domain", "domain:-bad.domain", "full:bad-.domain", "domain:.bad.domain", "domain:bad.domain.", "domain:", "domain:" + strings.Repeat("x", 64) + ".test", "example.cn", "geosite:cn", "ext:rules.dat:cn", "keyword:UPPER", "regexp:(?=lookahead)", "regexp:"} {
		rules := testRoutingRules()
		rules.Sections[0].Domains = []string{value}
		if err := rules.Validate(); err == nil {
			t.Errorf("accepted invalid domain %q", value)
		}
	}
	rules := testRoutingRules()
	rules.Sections = append(rules.Sections, RuleSection{Target: "ai", Domains: []string{"full:chat.example", "keyword:openai", `regexp:^ai[0-9]\.example$`}}, RuleSection{Target: "block", IPs: []string{"192.0.2.0/24", "2001:db8::/32", "192.0.2.1", "::ffff:192.0.2.1/128"}})
	if err := rules.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"schemaVersion":2,"sections":[],"executable":"evil"}`, `{"schemaVersion":2,"sections":null}`, `{"schemaVersion":1,"sections":[]}`, `{"schemaVersion":2,"sections":[{"target":"reject"}]}`, `{"schemaVersion":2,"sections":[{"target":"direct","file":"x"}]}`} {
		var decoded Rules
		if err := DecodeStrict([]byte(raw), &decoded, 1024); err == nil {
			t.Errorf("accepted invalid rule object %s", raw)
		}
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
