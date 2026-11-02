package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestSessionKeyFileRoundTrip(t *testing.T) {
	dir := t.TempDir()
	provider := &systemKeyProvider{dir: dir, service: "work.starrail.client.test"}
	if _, err := provider.Key(false); err == nil {
		t.Fatal("a missing key was not reported")
	}
	key, err := provider.Key(true)
	if err != nil || len(key) != 32 {
		t.Fatal(key, err)
	}
	info, err := os.Stat(filepath.Join(dir, "session-key.key"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("key file: %v %v", info, err)
	}
	again, err := (&systemKeyProvider{dir: dir, service: "work.starrail.client.test"}).Key(false)
	if err != nil || !bytes.Equal(again, key) {
		t.Fatal("a new provider read a different key", err)
	}
	if err = os.Chmod(filepath.Join(dir, "session-key.key"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = (&systemKeyProvider{dir: dir}).Key(false); err == nil {
		t.Fatal("a key readable by others was used")
	}
}

func TestForgetKeychainSession(t *testing.T) {
	dir := t.TempDir()
	session := filepath.Join(dir, "session.v2.enc")
	if err := os.WriteFile(session, []byte("sealed by the Keychain key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeSystemSecret(dir, "", "session-key", bytes.Repeat([]byte{1}, 32)); err != nil {
		t.Fatal(err)
	}
	forgetKeychainSession(dir, "session-key", session)
	if _, err := os.Stat(session); err != nil {
		t.Fatal("a session with its key file was removed")
	}
	if err := os.Remove(filepath.Join(dir, "session-key.key")); err != nil {
		t.Fatal(err)
	}
	forgetKeychainSession(dir, "session-key", session)
	if _, err := os.Stat(session); !os.IsNotExist(err) {
		t.Fatal("a session nothing can unlock was kept")
	}
}
