package main

import (
	"strings"
	"testing"
	"time"
)

const testUUID = "123e4567-e89b-12d3-a456-426614174000"
const testRealityKey = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJ0123456"

func validCandidate() Candidate {
	return Candidate{
		Node:            Node{Protocol: "vless", Host: "node.example.com", Port: 443, Credential: testUUID, Transport: "tcp", Security: "tls", SNI: "node.example.com"},
		Mode:            "rule",
		Rules:           Rules{SchemaVersion: 2},
		AuthorizedUntil: time.Now().Add(time.Hour).UnixMilli(),
	}
}

func TestCandidateValidate(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Candidate)
		want   string
	}{
		{"vless tls", func(*Candidate) {}, ""},
		{"global mode", func(c *Candidate) { c.Mode = "global" }, ""},
		{"unknown mode", func(c *Candidate) { c.Mode = "direct" }, "INVALID_INPUT"},
		{"authorization expired", func(c *Candidate) { c.AuthorizedUntil = time.Now().Add(-time.Second).UnixMilli() }, "INVALID_INPUT"},
		{"authorization within 7 days", func(c *Candidate) { c.AuthorizedUntil = time.Now().Add(6 * 24 * time.Hour).UnixMilli() }, ""},
		{"authorization beyond 7 days", func(c *Candidate) { c.AuthorizedUntil = time.Now().Add(8 * 24 * time.Hour).UnixMilli() }, "INVALID_INPUT"},
		{"port zero", func(c *Candidate) { c.Node.Port = 0 }, "INVALID_INPUT"},
		{"port too large", func(c *Candidate) { c.Node.Port = 65536 }, "INVALID_INPUT"},
		{"host with space", func(c *Candidate) { c.Node.Host = "bad host" }, "INVALID_INPUT"},
		{"host with leading hyphen", func(c *Candidate) { c.Node.Host = "-node.example.com" }, "INVALID_INPUT"},
		{"ip host", func(c *Candidate) { c.Node.Host = "2001:db8::1" }, ""},
		{"empty credential", func(c *Candidate) { c.Node.Credential = "" }, "INVALID_INPUT"},
		{"oversized credential", func(c *Candidate) { c.Node.Protocol = "trojan"; c.Node.Credential = strings.Repeat("a", 2049) }, "INVALID_INPUT"},
		{"unsupported transport", func(c *Candidate) { c.Node.Transport = "grpc" }, "INVALID_INPUT"},
		{"explicit fingerprint", func(c *Candidate) { c.Node.Fingerprint = "firefox" }, ""},
		{"x25519 is not a fingerprint", func(c *Candidate) { c.Node.Fingerprint = "x25519" }, "NO_COMPATIBLE_NODES"},
		{"tls without sni", func(c *Candidate) { c.Node.SNI = "" }, "NO_COMPATIBLE_NODES"},
		{"vless needs uuid", func(c *Candidate) { c.Node.Credential = "password" }, "NO_COMPATIBLE_NODES"},
		{"vless without security", func(c *Candidate) { c.Node.Security = "none" }, "NO_COMPATIBLE_NODES"},
		{"vless tls rejects flow", func(c *Candidate) { c.Node.Flow = "xtls-rprx-vision" }, "NO_COMPATIBLE_NODES"},
		{"vless reality", func(c *Candidate) {
			c.Node.Security, c.Node.PublicKey, c.Node.ShortID, c.Node.Flow = "reality", testRealityKey, "abcd", "xtls-rprx-vision"
		}, ""},
		{"reality over ws", func(c *Candidate) {
			c.Node.Security, c.Node.PublicKey, c.Node.Transport, c.Node.WSPath, c.Node.WSHost = "reality", testRealityKey, "ws", "/ws", "cdn.example.com"
		}, "NO_COMPATIBLE_NODES"},
		{"reality short public key", func(c *Candidate) { c.Node.Security, c.Node.PublicKey = "reality", testRealityKey[:42] }, "NO_COMPATIBLE_NODES"},
		{"reality odd short id", func(c *Candidate) {
			c.Node.Security, c.Node.PublicKey, c.Node.ShortID = "reality", testRealityKey, "abc"
		}, "NO_COMPATIBLE_NODES"},
		{"reality short id over 8 bytes", func(c *Candidate) {
			c.Node.Security, c.Node.PublicKey, c.Node.ShortID = "reality", testRealityKey, strings.Repeat("ab", 9)
		}, "NO_COMPATIBLE_NODES"},
		{"reality unknown flow", func(c *Candidate) {
			c.Node.Security, c.Node.PublicKey, c.Node.Flow = "reality", testRealityKey, "xtls-rprx-direct"
		}, "NO_COMPATIBLE_NODES"},
		{"vmess ws tls", func(c *Candidate) {
			c.Node.Protocol, c.Node.Transport, c.Node.WSPath, c.Node.WSHost, c.Node.Method = "vmess", "ws", "/ws", "cdn.example.com", "auto"
		}, ""},
		{"vmess over tcp", func(c *Candidate) { c.Node.Protocol = "vmess" }, "NO_COMPATIBLE_NODES"},
		{"vmess unknown cipher", func(c *Candidate) {
			c.Node.Protocol, c.Node.Transport, c.Node.WSPath, c.Node.WSHost, c.Node.Method = "vmess", "ws", "/ws", "cdn.example.com", "none"
		}, "NO_COMPATIBLE_NODES"},
		{"ws path without slash", func(c *Candidate) {
			c.Node.Protocol, c.Node.Transport, c.Node.WSPath, c.Node.WSHost = "vmess", "ws", "ws", "cdn.example.com"
		}, "NO_COMPATIBLE_NODES"},
		{"ws path header injection", func(c *Candidate) {
			c.Node.Protocol, c.Node.Transport, c.Node.WSPath, c.Node.WSHost = "vmess", "ws", "/ws\r\nX-Injected: 1", "cdn.example.com"
		}, "NO_COMPATIBLE_NODES"},
		{"ws without host", func(c *Candidate) { c.Node.Protocol, c.Node.Transport, c.Node.WSPath = "vmess", "ws", "/ws" }, "NO_COMPATIBLE_NODES"},
		{"trojan tls", func(c *Candidate) { c.Node.Protocol, c.Node.Credential = "trojan", "password" }, ""},
		{"trojan over ws", func(c *Candidate) {
			c.Node.Protocol, c.Node.Credential, c.Node.Transport, c.Node.WSPath, c.Node.WSHost = "trojan", "password", "ws", "/ws", "cdn.example.com"
		}, "NO_COMPATIBLE_NODES"},
		{"shadowsocks aead", func(c *Candidate) {
			c.Node.Protocol, c.Node.Credential, c.Node.Security, c.Node.SNI, c.Node.Method = "shadowsocks", "password", "none", "", "aes-256-gcm"
		}, ""},
		{"shadowsocks legacy cipher", func(c *Candidate) {
			c.Node.Protocol, c.Node.Credential, c.Node.Security, c.Node.SNI, c.Node.Method = "shadowsocks", "password", "none", "", "rc4-md5"
		}, "NO_COMPATIBLE_NODES"},
		{"unknown protocol", func(c *Candidate) { c.Node.Protocol = "hysteria2" }, "NO_COMPATIBLE_NODES"},
		{"vless ws tls", func(c *Candidate) { c.Node.Transport, c.Node.WSPath, c.Node.WSHost = "ws", "/ws", "cdn.example.com" }, ""},
		{"vless ws tls ech", func(c *Candidate) {
			c.Node.Transport, c.Node.WSPath, c.Node.WSHost, c.Node.ECH = "ws", "/ws", "cdn.example.com", "cloudflare-ech.com+https://1.1.1.1/dns-query"
		}, ""},
		{"ech with spaces", func(c *Candidate) {
			c.Node.Transport, c.Node.WSPath, c.Node.WSHost, c.Node.ECH = "ws", "/ws", "cdn.example.com", "a b"
		}, "NO_COMPATIBLE_NODES"},
		{"vless ws reality", func(c *Candidate) {
			c.Node.Security, c.Node.PublicKey, c.Node.Transport, c.Node.WSPath, c.Node.WSHost = "reality", testRealityKey, "ws", "/ws", "cdn.example.com"
		}, "NO_COMPATIBLE_NODES"},
		{"vless xhttp reality", func(c *Candidate) {
			c.Node.Security, c.Node.PublicKey, c.Node.Transport, c.Node.WSPath, c.Node.Mode = "reality", testRealityKey, "xhttp", "/x", "auto"
		}, ""},
		{"xhttp vision", func(c *Candidate) {
			c.Node.Security, c.Node.PublicKey, c.Node.Transport, c.Node.WSPath, c.Node.Mode, c.Node.Flow = "reality", testRealityKey, "xhttp", "/x", "auto", "xtls-rprx-vision"
		}, "NO_COMPATIBLE_NODES"},
		{"xhttp unknown mode", func(c *Candidate) { c.Node.Transport, c.Node.WSPath, c.Node.Mode = "xhttp", "/x", "bogus" }, "NO_COMPATIBLE_NODES"},
		{"mode outside xhttp", func(c *Candidate) { c.Node.Mode = "auto" }, "NO_COMPATIBLE_NODES"},
		{"shadowsocks 2022", func(c *Candidate) {
			c.Node.Protocol, c.Node.Credential, c.Node.Security, c.Node.SNI, c.Node.Method = "shadowsocks", "c2VydmVyLWtleQ==:dXNlci1rZXk=", "none", "", "2022-blake3-aes-256-gcm"
		}, ""},
		{"rules schema", func(c *Candidate) { c.Rules.SchemaVersion = 1 }, "INVALID_INPUT"},
		{"rule target", func(c *Candidate) { c.Rules.Sections = []RuleSection{{Target: "reject"}} }, "INVALID_INPUT"},
		{"rule domain forms", func(c *Candidate) {
			c.Rules.Sections = []RuleSection{{Target: "direct", Domains: []string{"domain:example.cn", "full:a.example.cn", "keyword:taobao", `regexp:^ad[0-9]+\.example$`}}}
		}, ""},
		{"rule domain", func(c *Candidate) {
			c.Rules.Sections = []RuleSection{{Target: "proxy", Domains: []string{"domain:exa mple.com"}}}
		}, "INVALID_INPUT"},
		{"rule bare domain", func(c *Candidate) {
			c.Rules.Sections = []RuleSection{{Target: "proxy", Domains: []string{"example.com"}}}
		}, "INVALID_INPUT"},
		{"rule geosite file", func(c *Candidate) {
			c.Rules.Sections = []RuleSection{{Target: "proxy", Domains: []string{"geosite:cn"}}}
		}, "INVALID_INPUT"},
		{"rule external file", func(c *Candidate) {
			c.Rules.Sections = []RuleSection{{Target: "proxy", Domains: []string{"ext:geo.dat:cn"}}}
		}, "INVALID_INPUT"},
		{"rule bad regexp", func(c *Candidate) {
			c.Rules.Sections = []RuleSection{{Target: "proxy", Domains: []string{"regexp:(?=x)"}}}
		}, "INVALID_INPUT"},
		{"rule addresses", func(c *Candidate) {
			c.Rules.Sections = []RuleSection{{Target: "direct", IPs: []string{"10.0.0.0/8", "1.1.1.1", "2001:db8::/32"}}}
		}, ""},
		{"rule bad address", func(c *Candidate) { c.Rules.Sections = []RuleSection{{Target: "direct", IPs: []string{"300.1.1.1"}}} }, "INVALID_INPUT"},
		{"pool node", func(c *Candidate) { c.Pool = []Node{validCandidate().Node} }, ""},
		{"bad pool node", func(c *Candidate) { n := validCandidate().Node; n.Port = 0; c.Pool = []Node{n} }, "INVALID_INPUT"},
		{"pool too large", func(c *Candidate) { c.Pool = make([]Node, maxPool+1) }, "INVALID_INPUT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := validCandidate()
			tc.mutate(&c)
			if got := errorCode(c.validate()); got != tc.want {
				t.Fatalf("validate() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCandidateValidateDefaultsFingerprint(t *testing.T) {
	c := validCandidate()
	if e := c.validate(); e != nil {
		t.Fatal(e)
	}
	if c.Node.Fingerprint != "hellochrome_120" {
		t.Fatalf("fingerprint = %q", c.Node.Fingerprint)
	}
	c.Node.Fingerprint = "safari"
	if e := c.validate(); e != nil || c.Node.Fingerprint != "safari" {
		t.Fatalf("explicit fingerprint changed to %q (%v)", c.Node.Fingerprint, e)
	}
	var missing *Candidate
	if errorCode(missing.validate()) != "INVALID_INPUT" {
		t.Fatal("nil candidate accepted")
	}
}

func TestSafeOrigin(t *testing.T) {
	cases := map[string]string{
		"https://api.starrail.work/api/v1?x=1":   "https://api.starrail.work",
		"https://api.starrail.work:8443/":        "https://api.starrail.work:8443",
		"http://api.starrail.work/":              "",
		"https://user@api.starrail.work/":        "",
		"https://api.starrail.work/#fragment":    "",
		"https://api.starrail.work.evil.example": "https://api.starrail.work.evil.example",
		"::not a url":                            "",
	}
	for input, want := range cases {
		if got := safeOrigin(input); got != want {
			t.Errorf("safeOrigin(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestStrictJSON(t *testing.T) {
	type target struct {
		A int `json:"a"`
	}
	deep := strings.Repeat("[", 26) + strings.Repeat("]", 26)
	cases := []struct {
		name, input string
		ok          bool
	}{
		{"valid", `{"a":1}`, true},
		{"duplicate key", `{"a":1,"a":2}`, false},
		{"unknown field", `{"a":1,"b":2}`, false},
		{"trailing value", `{"a":1} {}`, false},
		{"invalid utf8", "{\"a\":1,\"\xff\":2}", false},
		{"too deep", `{"a":1,"x":` + deep + `}`, false},
		{"truncated", `{"a":`, false},
	}
	for _, tc := range cases {
		var out target
		if got := strictJSON([]byte(tc.input), &out) == nil; got != tc.ok {
			t.Errorf("%s: accepted = %v, want %v", tc.name, got, tc.ok)
		}
	}
}

func TestCleanErrorHidesDetails(t *testing.T) {
	if got := cleanError(failure("NETWORK_CONFLICT")); got != "NETWORK_CONFLICT" {
		t.Fatalf("known code changed to %q", got)
	}
	if got := cleanError(failure("open /var/lib/starrail-network/network.json: permission denied")); got != "COMPONENTS_UNAVAILABLE" {
		t.Fatalf("internal error leaked as %q", got)
	}
	if cleanError(nil) != "" {
		t.Fatal("nil error produced a code")
	}
}

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		next, current string
		want          bool
	}{
		{"0.2.0", "0.1.0", true},
		{"0.10.0", "0.9.0", true},
		{"0.1.1+build.5", "0.1.0", true},
		{"0.1.0", "0.1.0", false},
		{"0.1.0", "0.2.0", false},
		{"0.1.0", "0.1.0-beta", true},
		{"0.1.0-beta", "0.1.0", false},
		{"0.2.0-beta.2", "0.2.0-beta.1", true},
		{"0.2.0-beta.10", "0.2.0-beta.9", true},
		{"0.2.0-beta.1", "0.2.0-beta.2", false},
		{"0.2.0-rc.1", "0.2.0-beta.5", true},
		{"0.2.0-beta", "0.2.0-1", true},
		{"0.2.0-beta.1", "0.2.0-beta", true},
		{"0.2.0-beta", "0.2.0-beta", false},
		{"1.0", "0.1.0", false},
		{"1.0.x", "0.1.0", false},
		{"1.0.-1", "0.1.0", false},
	}
	for _, tc := range cases {
		if got := newerVersion(tc.next, tc.current); got != tc.want {
			t.Errorf("newerVersion(%q, %q) = %v, want %v", tc.next, tc.current, got, tc.want)
		}
	}
}
