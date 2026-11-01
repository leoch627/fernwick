package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

// TestCompiledConfigLoadsInXray checks the generated configuration, with the shipped
// rules and both balancers, against a real core. Opt-in: set XRAY_TEST_BINARY to a
// pinned xray executable (resources/native/<target>/xray after core:fetch).
func TestCompiledConfigLoadsInXray(t *testing.T) {
	binary := os.Getenv("XRAY_TEST_BINARY")
	if binary == "" {
		t.Skip("XRAY_TEST_BINARY not set")
	}
	raw, err := os.ReadFile("../../resources/rules/baseline.json")
	if err != nil {
		t.Fatal(err)
	}
	c := validCandidate()
	if err := json.Unmarshal(raw, &c.Rules); err != nil {
		t.Fatal(err)
	}
	hk, us := validCandidate().Node, validCandidate().Node
	hk.Host, us.Host, us.AI = "hk.example.com", "us.example.com", true
	// The layered transports and ciphers the subscription parser accepts.
	ws := Node{Protocol: "vless", Host: "cdn.example.com", Port: 443, Credential: testUUID, Transport: "ws", Security: "tls", SNI: "edge.example.com", WSPath: "/ws", WSHost: "edge.example.com", ECH: "cloudflare-ech.com+https://1.1.1.1/dns-query", AI: true}
	xhttp := Node{Protocol: "vless", Host: "de.example.com", Port: 443, Credential: testUUID, Transport: "xhttp", Security: "reality", SNI: "www.example.com", PublicKey: testRealityKey, ShortID: "ab", WSPath: "/x", Mode: "auto", AI: true}
	ss := Node{Protocol: "shadowsocks", Host: "tw.example.com", Port: 443, Credential: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Transport: "tcp", Security: "none", Method: "2022-blake3-aes-256-gcm"}
	c.Pool, c.Automatic = []Node{hk, us, ws, xhttp, ss}, true
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"rule", "global"} {
		c.Mode = mode
		j := Journal{Interface: Interface{Name: "lo0"}, Tun: tunName(), NodeAddress: "203.0.113.10", PoolAddresses: []string{"203.0.113.11", "203.0.113.12", "203.0.113.13", "203.0.113.14", "203.0.113.15"}}
		command := exec.Command(binary, "run", "-test", "-format", "json", "-config", "stdin:")
		command.Stdin = bytes.NewReader(compileCore(c, j))
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s mode rejected by xray: %v\n%s", mode, err, out)
		}
	}
}
