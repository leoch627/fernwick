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
	c.Pool, c.Automatic = []Node{hk, us}, true
	if err := c.validate(); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"rule", "global"} {
		c.Mode = mode
		j := Journal{Interface: Interface{Name: "lo0"}, Tun: tunName(), NodeAddress: "203.0.113.10", PoolAddresses: []string{"203.0.113.11", "203.0.113.12"}}
		command := exec.Command(binary, "run", "-test", "-format", "json", "-config", "stdin:")
		command.Stdin = bytes.NewReader(compileCore(c, j))
		if out, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s mode rejected by xray: %v\n%s", mode, err, out)
		}
	}
}
