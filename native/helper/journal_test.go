package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validJournal() Journal {
	return Journal{SchemaVersion: 1, ID: nonce(), ProductID: "starrail-test", Owner: owner, Phase: "Connected", Tun: tunName(), CorePath: installed.CorePath, NodeAddress: "203.0.113.10", Bypass: []string{}}
}

func TestJournalRoundTrip(t *testing.T) {
	withInstalled(t, Installation{CorePath: "/opt/starrail/xray"})
	path := filepath.Join(t.TempDir(), "state", "network.json")
	if j, e := readJournal(path); j != nil || e != nil {
		t.Fatalf("missing journal = %v, %v", j, e)
	}
	want := validJournal()
	want.Routes, want.DNS, want.Protection = true, true, true
	if e := atomicJSON(path, want); e != nil {
		t.Fatal(e)
	}
	got, e := readJournal(path)
	if e != nil || got.ID != want.ID || !got.Routes || !got.DNS || !got.Protection || got.Owner.key() != owner.key() {
		t.Fatalf("readJournal = %+v, %v", got, e)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
	if info, _ := os.Stat(path); info.Mode().Perm()&0077 != 0 && targetOS() != "windows" {
		t.Fatalf("journal readable by others: %v", info.Mode())
	}
}

func TestJournalRejectsForeignState(t *testing.T) {
	withInstalled(t, Installation{CorePath: "/opt/starrail/xray"})
	cases := map[string]func(*Journal){
		"schema":     func(j *Journal) { j.SchemaVersion = 2 },
		"short id":   func(j *Journal) { j.ID = j.ID[:46] },
		"non-hex id": func(j *Journal) { j.ID = strings.Repeat("z", 48) },
		"other tun":  func(j *Journal) { j.Tun = "eth0" },
		"other core": func(j *Journal) { j.CorePath = "/tmp/xray" },
		"empty core": func(j *Journal) { j.CorePath = "" },
	}
	for name, mutate := range cases {
		j := validJournal()
		mutate(&j)
		path := filepath.Join(t.TempDir(), "network.json")
		if e := atomicJSON(path, j); e != nil {
			t.Fatal(e)
		}
		if got, e := readJournal(path); got != nil || errorCode(e) != "NETWORK_RECOVERY_REQUIRED" {
			t.Errorf("%s: readJournal = %v, %v", name, got, e)
		}
	}

	path := filepath.Join(t.TempDir(), "network.json")
	for name, content := range map[string]string{"unknown field": `{"schemaVersion":1,"injected":true}`, "corrupt": `{"schemaVersion":`} {
		if e := os.WriteFile(path, []byte(content), 0600); e != nil {
			t.Fatal(e)
		}
		if got, e := readJournal(path); got != nil || errorCode(e) != "INVALID_INPUT" {
			t.Errorf("%s: readJournal = %v, %v", name, got, e)
		}
	}
}
