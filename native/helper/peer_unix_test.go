//go:build linux || darwin

package main

import (
	"os"
	"testing"
)

func TestValidAppArguments(t *testing.T) {
	app := "/opt/StarRail/starrail"
	cases := []struct {
		args string
		want bool
	}{
		{app + "\x00", true},
		{app + "\x00--hidden\x00--autostart\x00", true},
		{app + "\x00--inspect=9229\x00", false},
		{app + "-evil\x00", false},
		{"/tmp/starrail\x00", false},
		{app, true},
		{app + " --updated", true},
		{app + " -psn_0_12345", true},
		{app + " --remote-debugging-port=9222", false},
		{app + "x --hidden", false},
		{"/usr/bin/env " + app, false},
	}
	for _, tc := range cases {
		if got := validAppArguments(tc.args, app); got != tc.want {
			t.Errorf("validAppArguments(%q) = %v, want %v", tc.args, got, tc.want)
		}
	}
}

// The Wails executable embeds the complete frontend; there is no separate archive.
func installApp(t *testing.T) (Peer, string) {
	t.Helper()
	dir := t.TempDir()
	app := writeFile(t, dir, "starrail", "application")
	appHash, _ := digestFile(app)
	withInstalled(t, Installation{AppExecutable: app, AppSHA256: appHash})
	previous := peerCache.app
	t.Cleanup(func() { peerCache.app = previous })
	peerCache.app = nil
	return Peer{PID: 4242, User: "501", Birth: "1", Executable: app, Arguments: app + "\x00"}, app
}

func TestVerifyPeerRejectsOtherProcesses(t *testing.T) {
	peer, app := installApp(t)
	cases := map[string]func(*Peer){
		"no pid":             func(p *Peer) { p.PID = 0 },
		"no user":            func(p *Peer) { p.User = "" },
		"other executable":   func(p *Peer) { p.Executable = "/usr/bin/python3" },
		"inspector":          func(p *Peer) { p.Arguments = app + "\x00--inspect\x00" },
		"run as node":        func(p *Peer) { p.Arguments = app + "\x00ELECTRON_RUN_AS_NODE=1\x00" },
		"renderer child":     func(p *Peer) { p.Arguments = app + "\x00--type=renderer\x00" },
		"unknown flag":       func(p *Peer) { p.Arguments = app + "\x00--no-sandbox\x00" },
		"arguments mismatch": func(p *Peer) { p.Arguments = "/tmp/other\x00" },
	}
	for name, mutate := range cases {
		p := peer
		mutate(&p)
		if got := errorCode(verifyPeer(p)); got != "PERMISSION_REQUIRED" {
			t.Errorf("%s: verifyPeer = %q, want PERMISSION_REQUIRED", name, got)
		}
	}
}

func TestVerifyPeerRequiresProtectedFiles(t *testing.T) {
	// Temporary files are user-writable, so an uncached peer must be rejected.
	peer, _ := installApp(t)
	if got := errorCode(verifyPeer(peer)); got != "PERMISSION_REQUIRED" {
		t.Fatalf("verifyPeer = %q, want PERMISSION_REQUIRED", got)
	}
}

func TestVerifyPeerCacheInvalidatedByTampering(t *testing.T) {
	peer, app := installApp(t)
	appInfo, _ := os.Stat(installed.AppExecutable)
	peerCache.app = appInfo
	if e := verifyPeer(peer); e != nil {
		t.Fatalf("cached peer rejected: %v", e)
	}
	if e := os.WriteFile(app, []byte("replaced application"), 0755); e != nil {
		t.Fatal(e)
	}
	if got := errorCode(verifyPeer(peer)); got != "PERMISSION_REQUIRED" {
		t.Fatalf("tampered application accepted: %q", got)
	}
}
