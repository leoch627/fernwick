package core

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
)

const subscriptionTestURI = "vless://00000000-0000-4000-8000-000000000001@node.example.invalid:443?security=tls&type=tcp&sni=node.example.invalid#Tokyo"

func subscriptionTestOptions() ParserOptions {
	return ParserOptions{Source: "test-fixture", ConfirmedTCPUDP: true, Capabilities: []string{"vless-tls", "vless-reality", "vmess-ws-tls", "trojan-tls", "shadowsocks-aead"}}
}

// These expectations are emitted by the retained TypeScript implementation,
// not reconstructed by Go. Node IDs are compared byte-for-byte.
func TestSubscriptionTypeScriptOracle(t *testing.T) {
	raw, err := os.ReadFile("testdata/subscriptions.json")
	if err != nil {
		t.Fatal(err)
	}
	var data struct {
		Auth     ProbeAuth `json:"auth"`
		Fixtures []struct {
			Name      string            `json:"name"`
			Raw       string            `json:"raw"`
			Options   ParserOptions     `json:"options"`
			Parsed    json.RawMessage   `json:"parsed"`
			Outbounds []json.RawMessage `json:"outbounds"`
			Probes    []json.RawMessage `json:"probes"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	for _, test := range data.Fixtures {
		t.Run(test.Name, func(t *testing.T) {
			actual, err := ParseSubscription(test.Raw, test.Options)
			if err != nil {
				t.Fatal(err)
			}
			var expected ParsedNodes
			if err := DecodeStrict(test.Parsed, &expected, 1024*1024); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(actual, expected) {
				t.Fatalf("parsed subscription differs from TypeScript\ngot  %#v\nwant %#v", actual, expected)
			}
			for i, node := range actual.Nodes {
				if !node.Compatible {
					if _, err := CompileOutbound(node); CodeOf(err) != "NO_COMPATIBLE_NODES" {
						t.Fatalf("incompatible node compiled: %v", err)
					}
					continue
				}
				outbound, err := CompileOutbound(node)
				if err != nil {
					t.Fatal(err)
				}
				assertSubscriptionJSON(t, outbound, test.Outbounds[i])
				probe, err := CompileProbe(node, data.Auth)
				if err != nil {
					t.Fatal(err)
				}
				assertSubscriptionJSON(t, probe, test.Probes[i])
			}
		})
	}
}

func assertSubscriptionJSON(t *testing.T, actual any, expectedRaw []byte) {
	t.Helper()
	expected, err := StrictJSON(expectedRaw, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	actualBytes, err := json.Marshal(actual)
	if err != nil {
		t.Fatal(err)
	}
	actualTree, err := StrictJSON(actualBytes, 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actualTree, expected) {
		t.Fatalf("compiler differs from TypeScript\ngot  %s\nwant %s", actualBytes, expectedRaw)
	}
}

func TestSubscriptionRejectsIncompleteResponses(t *testing.T) {
	cases := []string{"", "  ", "<html>WAF</html>", "dHJ1bmNhdGVk", "###", subscriptionTestURI + "\nbroken boundary", "vless://bad@node.invalid:443", "garbage://unknown", strings.Repeat(subscriptionTestURI+"\n", 5001)}
	for _, raw := range cases {
		if _, err := ParseSubscription(raw, subscriptionTestOptions()); CodeOf(err) != "SUBSCRIPTION_INVALID" {
			t.Errorf("input length %d: %v", len(raw), err)
		}
	}
}

func TestSubscriptionAuthoritativeEmpty(t *testing.T) {
	options := subscriptionTestOptions()
	options.AuthoritativeEmpty = true
	parsed, err := ParseSubscription("\ufeff \n", options)
	if err != nil || !parsed.AuthoritativeEmpty || parsed.Nodes == nil || parsed.Quarantined == nil || len(parsed.Nodes) != 0 {
		t.Fatalf("invalid authoritative empty result: %#v %v", parsed, err)
	}
}

func TestSubscriptionIdentityAndQuarantine(t *testing.T) {
	options := subscriptionTestOptions()
	original, err := ParseSubscription(subscriptionTestURI, options)
	if err != nil {
		t.Fatal(err)
	}
	renamed, _ := ParseSubscription(strings.ReplaceAll(subscriptionTestURI, "Tokyo", "New Name"), options)
	changed, _ := ParseSubscription(strings.ReplaceAll(subscriptionTestURI, "000000000001", "000000000002"), options)
	if original.Nodes[0].ID != renamed.Nodes[0].ID || original.Nodes[0].ID == changed.Nodes[0].ID {
		t.Fatal("identity does not depend exclusively on connection fields")
	}
	for _, bad := range []string{
		strings.Replace(subscriptionTestURI, "security=tls", "security=tls&evil=on", 1),
		strings.Replace(subscriptionTestURI, "security=tls", "security=tls&%73ecurity=tls", 1),
		strings.Replace(subscriptionTestURI, "security=tls", "security=tls&fp=", 1),
		strings.Replace(subscriptionTestURI, "security=tls", "security=tls&pbk=", 1),
		strings.Replace(subscriptionTestURI, ":443?", ":443/illegal?", 1),
		strings.Replace(subscriptionTestURI, "443?", "0?", 1),
		"trojan://secret%00@node.invalid:443",
		"trojan://secret@[fe80::1%25en0]:443",
		"trojan://secret@fe80::1:443",
	} {
		parsed, err := ParseSubscription(subscriptionTestURI+"\n"+bad, options)
		if err != nil || len(parsed.Nodes) != 1 || len(parsed.Quarantined) != 1 || parsed.Quarantined[0].Index != 1 {
			t.Errorf("malformed node was not quarantined: %q: %#v %v", bad, parsed, err)
		}
	}
}

func TestDecodeBase64CanonicalAndUTF8(t *testing.T) {
	for _, raw := range []string{"Zg", "Zg=", "Zg==", "_w", "/w=="} {
		if _, err := DecodeBase64(raw); err != nil {
			t.Errorf("valid base64 rejected %q: %v", raw, err)
		}
	}
	for _, raw := range []string{"", "A", "Zh", "Zg===", "Z g==", "=Zg", "Zg==\n"} {
		if _, err := DecodeBase64(raw); err == nil {
			t.Errorf("invalid base64 accepted %q", raw)
		}
	}
	if _, err := ParseSubscription(base64.StdEncoding.EncodeToString([]byte{0xff}), subscriptionTestOptions()); err == nil {
		t.Fatal("invalid UTF-8 accepted")
	}
	withBOM := base64.StdEncoding.EncodeToString([]byte("\ufeff" + subscriptionTestURI))
	if _, err := ParseSubscription(withBOM, subscriptionTestOptions()); err != nil {
		t.Fatalf("TextDecoder BOM behavior lost: %v", err)
	}
}

func TestJSStringMatchesJSONStringify(t *testing.T) {
	cases := []struct{ raw, expected string }{
		{"\"\\\b\f\n\r\t\x00\x1f", `"\"\\\b\f\n\r\t\u0000\u001f"`},
		{"<>&\u2028\u2029🚄", "\"<>&\u2028\u2029🚄\""},
		{string([]byte{0xed, 0xa0, 0x80}), `"\ud800"`},
	}
	for _, test := range cases {
		if got := JSString(test.raw); got != test.expected {
			t.Errorf("got %q, want %q", got, test.expected)
		}
	}
}

func TestSubscriptionBoundsUseUTF16AndBytes(t *testing.T) {
	options := subscriptionTestOptions()
	for _, name := range []string{strings.Repeat("🚄", 128), strings.Repeat("x", 256)} {
		if _, err := ParseSubscription(strings.Replace(subscriptionTestURI, "Tokyo", name, 1), options); err != nil {
			t.Errorf("maximum valid name rejected: %v", err)
		}
	}
	for _, name := range []string{strings.Repeat("🚄", 129), strings.Repeat("x", 257)} {
		if _, err := ParseSubscription(strings.Replace(subscriptionTestURI, "Tokyo", name, 1), options); err == nil {
			t.Error("overlong name accepted")
		}
	}
	if _, err := ParseSubscription(strings.Repeat("x", 14*1024*1024+1), options); err == nil {
		t.Error("overlarge response accepted")
	}
}

func TestSubscriptionLayeredTransportsECHAndShadowsocks2022(t *testing.T) {
	const id = "00000000-0000-4000-8000-000000000001"
	key := strings.Repeat("A", 43)
	cases := []struct {
		name, uri       string
		transport       string
		path, host, ech string
		compatible      bool
	}{
		{"vless ws tls", "vless://" + id + "@cdn.invalid:443?encryption=none&type=ws&host=edge.invalid&path=%2Fws&security=tls&sni=edge.invalid&fp=chrome#ws", "ws", "/ws", "edge.invalid", "", true},
		{"ws host defaults to sni", "vless://" + id + "@cdn.invalid:443?type=ws&path=%2F&security=tls&sni=edge.invalid#ws", "ws", "/", "edge.invalid", "", true},
		{"ws with ech", "vless://" + id + "@cdn.invalid:443?type=ws&host=edge.invalid&path=%2Fws&security=tls&sni=edge.invalid&ech=cloudflare-ech.com%2Bhttps%3A%2F%2F1.1.1.1%2Fdns-query#ech", "ws", "/ws", "edge.invalid", "cloudflare-ech.com+https://1.1.1.1/dns-query", true},
		{"xhttp reality", "vless://" + id + "@node.invalid:443?encryption=none&type=xhttp&host=&path=%2Fx&headerType=none&quicSecurity=none&serviceName=&security=reality&fp=edge&insecure=0&sni=www.example.com&pbk=" + key + "&sid=ab&mode=auto#xhttp", "xhttp", "/x", "", "", true},
		{"ws reality is not a thing", "vless://" + id + "@node.invalid:443?type=ws&path=%2F&security=reality&sni=www.example.com&pbk=" + key + "&sid=ab#bad", "tcp", "", "", "", false},
		{"vision only over tcp", "vless://" + id + "@node.invalid:443?type=xhttp&path=%2Fx&security=reality&sni=www.example.com&pbk=" + key + "&sid=ab&flow=xtls-rprx-vision#bad", "xhttp", "/x", "", "", false},
		{"unknown xhttp mode", "vless://" + id + "@node.invalid:443?type=xhttp&path=%2Fx&security=reality&sni=www.example.com&pbk=" + key + "&sid=ab&mode=bogus#bad", "xhttp", "/x", "", "", false},
		{"ech needs tls", "vless://" + id + "@node.invalid:443?type=tcp&security=reality&sni=www.example.com&pbk=" + key + "&sid=ab&ech=AEX%2B#bad", "tcp", "", "", "AEX+", false},
		{"path on plain tcp", "vless://" + id + "@node.invalid:443?type=tcp&path=%2Fx&security=tls&sni=node.invalid#bad", "tcp", "", "", "", false},
		{"trojan ws stays unsupported", "trojan://secret@node.invalid:443?type=ws&path=%2F&security=tls&sni=node.invalid#bad", "tcp", "", "", "", false},
		{"shadowsocks 2022", "ss://2022-blake3-aes-256-gcm:" + url.QueryEscape("c2VydmVyLWtleQ==:dXNlci1rZXk=") + "@node.invalid:443#ss2022", "tcp", "", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			parsed, err := ParseSubscription(tc.uri, subscriptionTestOptions())
			if err != nil || len(parsed.Nodes) != 1 {
				t.Fatalf("parse: %v %+v", err, parsed)
			}
			n := parsed.Nodes[0]
			if n.Compatible != tc.compatible || n.Transport != tc.transport || deref(n.WSPath) != tc.path || deref(n.WSHost) != tc.host || deref(n.ECH) != tc.ech {
				t.Fatalf("compatible=%v (%v) transport=%s path=%q host=%q ech=%q", n.Compatible, deref(n.Incompatibility), n.Transport, deref(n.WSPath), deref(n.WSHost), deref(n.ECH))
			}
			if !n.Compatible {
				return
			}
			outbound, err := CompileOutbound(n)
			if err != nil {
				t.Fatal(err)
			}
			stream := outbound["streamSettings"].(map[string]any)
			if tc.transport == "xhttp" && stream["xhttpSettings"].(map[string]any)["mode"] != "auto" || tc.ech != "" && stream["tlsSettings"].(map[string]any)["echConfigList"] != tc.ech {
				t.Fatalf("stream = %v", stream)
			}
		})
	}
	// TCP nodes keep their IDs: the new fields only enter the fingerprint when present.
	before, _ := ParseSubscription(subscriptionTestURI, subscriptionTestOptions())
	if before.Nodes[0].WSPath != nil || before.Nodes[0].Mode != nil || before.Nodes[0].ECH != nil {
		t.Fatal("tcp node gained layered fields")
	}
}

func deref(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
