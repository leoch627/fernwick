package core

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCommandBoundariesAndDiscriminatedShapes(t *testing.T) {
	for _, kind := range []string{"state", "sync", "connect", "disconnect", "logout", "repair", "check-update", "download-update", "pause-update", "cancel-update", "install-update", "diagnostics", "renewal-return"} {
		if command, err := ParseCommand([]byte(`{"type":"` + kind + `"}`)); err != nil || command.Type != kind {
			t.Fatalf("%s: %#v %v", kind, command, err)
		}
	}
	valid := []string{
		`{"type":"login","email":"alice@example.invalid","password":"secret"}`,
		`{"type":"login","email":"alice@example.invalid","password":"` + strings.Repeat(`\ud800`, 1024) + `"}`,
		`{"type":"login","email":"alice@example.invalid","password":"` + strings.Repeat(`🚄`, 1024) + `"}`,
		`{"type":"preferences","preferences":{"mode":"rule","nodeId":null,"autoConnect":false,"launchAtLogin":false,"closeBehavior":"tray","theme":"system"}}`,
		`{"type":"probe-nodes","nodeIds":["node"]}`, `{"type":"open-link","link":"renew"}`,
	}
	for _, raw := range valid {
		if _, err := ParseCommand([]byte(raw)); err != nil {
			t.Fatalf("valid command rejected: %s %v", raw, err)
		}
		var c Command
		if err := DecodeStrict([]byte(raw), &c, 16384); err != nil {
			t.Fatal(err)
		}
	}
	invalid := []string{`null`, `[]`, `{}`, `{"type":null}`, `{"type":"unknown"}`, `{"type":"state","email":"alice@example.invalid"}`, `{"type":"state","type":"sync"}`,
		`{"type":"login","email":"a@b","password":"x"}`, `{"type":"login","email":"alice@example.invalid","password":""}`, `{"type":"login","email":"alice@example.invalid","password":null}`, `{"type":"login","email":"alice@example.invalid","password":"` + strings.Repeat(`\ud800`, 1025) + `"}`,
		`{"type":"login","email":"alice@example.invalid","password":"` + strings.Repeat(`🚄`, 1025) + `"}`,
		`{"type":"probe-nodes","nodeIds":[]}`, `{"type":"probe-nodes","nodeIds":[null]}`, `{"type":"probe-nodes","nodeIds":[""]}`, `{"type":"probe-nodes","nodeIds":[` + strings.Repeat(`"n",`, 64) + `"n"]}`,
		`{"type":"open-link","link":"https://evil.invalid"}`, `{"type":"preferences","preferences":null}`,
	}
	for _, raw := range invalid {
		if _, err := ParseCommand([]byte(raw)); err == nil || CodeOf(err) != "INVALID_INPUT" {
			t.Fatalf("invalid command accepted: %s %v", raw, err)
		}
	}
}

func TestSchemaDefaultsAndStrictBuildFields(t *testing.T) {
	raw, err := os.ReadFile("../../config/development.json")
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if err = json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	delete(object, "healthTargets")
	delete(object, "allowUnverifiedNodeTrials")
	encoded, _ := json.Marshal(object)
	var build BuildConfig
	if err = DecodeStrict(encoded, &build, 262144); err != nil {
		t.Fatal(err)
	}
	if build.HealthTargets == nil || len(build.HealthTargets) != 0 || build.AllowUnverifiedNodeTrials {
		t.Fatalf("defaults not applied: %#v", build)
	}
	for _, key := range []string{"healthTargets", "apiEndpoints", "trustedWebOrigins", "policyKeys", "allowUnverifiedNodeTrials"} {
		saved, present := object[key]
		object[key] = nil
		encoded, _ = json.Marshal(object)
		if err = DecodeStrict(encoded, &build, 262144); err == nil {
			t.Fatalf("null accepted for %s", key)
		}
		if present {
			object[key] = saved
		} else {
			delete(object, key)
		}
	}
	object["shellCommand"] = "bad"
	encoded, _ = json.Marshal(object)
	if err = DecodeStrict(encoded, &build, 262144); err == nil {
		t.Fatal("unknown build field accepted")
	}
}

func TestSchemaDatesAndCodePointLengths(t *testing.T) {
	for _, value := range []string{"2026-10-31T00:00:00Z", "2024-02-29T12:15:59.123456789012Z", "2026-10-31T23:59:59+23:59", "0000-01-01T00:00:00Z"} {
		if !validUTC(value) {
			t.Errorf("rejected valid date %s", value)
		}
	}
	for _, value := range []string{"2026-02-29T00:00:00Z", "2026-10-31T00:00Z", "2026-10-31t00:00:00z", "2026-10-31T00:00:00+24:00", "2026-10-31T00:00:00+00:60", "2026-10-31T24:00:00Z", "2026-10-31T00:00:60Z", "2026-10-31T00:00:00", "2026-10-31T00:00:00,5Z"} {
		if validUTC(value) {
			t.Errorf("accepted invalid date %s", value)
		}
	}
	if stringLength("a😀文") != 3 {
		t.Fatal("length does not match Zod Unicode code points")
	}
}

// Preference files written before a field existed load with its default; automatic update
// checks must come on for existing users, not off.
func TestOlderPreferencesLoadWithDefaults(t *testing.T) {
	var prefs Preferences
	raw := `{"mode":"rule","nodeId":null,"autoConnect":false,"launchAtLogin":false,"closeBehavior":"tray","theme":"system"}`
	if err := DecodeStrict([]byte(raw), &prefs, 16384); err != nil {
		t.Fatal(err)
	}
	if prefs != DefaultPreferences {
		t.Fatalf("got %+v, want %+v", prefs, DefaultPreferences)
	}
	if !prefs.AutoUpdate || !prefs.AdBlock || prefs.Tunnel != "proxy" {
		t.Fatalf("defaults not applied: %+v", prefs)
	}
}
