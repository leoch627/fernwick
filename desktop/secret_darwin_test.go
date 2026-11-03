package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"work.starrail/client/desktop/core"
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

func legacySessionFixture(t *testing.T) (string, []byte, core.Persisted) {
	t.Helper()
	dir := t.TempDir()
	key := bytes.Repeat([]byte{7}, 32)
	value := core.Persisted{SchemaVersion: 1, ProductID: "starrail", Environment: "test", Session: core.Session{AccountID: "fixture", Email: "test@example.invalid", Token: "fixture-only", Generation: "same-login"}, Restrictions: []core.ErrorCode{}}
	store := core.NewSecureStore[core.Persisted](filepath.Join(dir, "session.v2.enc"), core.KeyProviderFunc(func(bool) ([]byte, error) { return key, nil }))
	if err := store.Save(value, nil); err != nil {
		t.Fatal(err)
	}
	return dir, key, value
}

func TestSessionKeyMigratesLegacyKeychainWithoutChangingLogin(t *testing.T) {
	dir, key, value := legacySessionFixture(t)
	path := filepath.Join(dir, "session.v2.enc")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	reads := 0
	legacy := func(service, account string) ([]byte, error) {
		reads++
		if service != "work.starrail.client.test" || account != "session-key" {
			t.Fatal("migration used a different Keychain identity")
		}
		return key, nil
	}
	migrating := core.NewSecureStore[core.Persisted](path, core.KeyProviderFunc(func(bool) ([]byte, error) {
		return readSessionKey(dir, "work.starrail.client.test", "session-key", legacy)
	}))
	saved, err := migrating.Load()
	if err != nil || saved == nil || saved.Session != value.Session || reads != 1 {
		t.Fatalf("migration did not restore the same login: %v (legacy reads %d)", err, reads)
	}
	info, err := os.Stat(secretPath(dir, "session-key"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("migrated key permissions: %v %v", info, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("migration changed the saved session", err)
	}
	// A later version uses the migrated file without requesting Keychain again.
	if again, err := readSessionKey(dir, "work.starrail.client.test", "session-key", legacy); err != nil || !bytes.Equal(again, key) || reads != 1 {
		t.Fatal("migrated key was not reused", err)
	}
	restarted := core.NewSecureStore[core.Persisted](path, &systemKeyProvider{dir: dir, service: "work.starrail.client.test"})
	if saved, err := restarted.Load(); err != nil || saved == nil || saved.Session != value.Session {
		t.Fatal("restart lost the migrated login", err)
	}
}

func TestSessionKeyMigrationFailuresPreserveCiphertext(t *testing.T) {
	for _, failure := range []string{"missing", "denied", "short-key", "wrong-key", "corrupted-session", "write-failed", "invalid-local-key"} {
		t.Run(failure, func(t *testing.T) {
			dir, key, _ := legacySessionFixture(t)
			path := filepath.Join(dir, "session.v2.enc")
			if failure == "corrupted-session" {
				if err := os.WriteFile(path, []byte("corrupted ciphertext"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "invalid-local-key" {
				if err := os.WriteFile(secretPath(dir, "session-key"), []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			legacy := func(string, string) ([]byte, error) {
				switch failure {
				case "missing":
					return nil, errSecretMissing
				case "denied":
					return nil, errors.New("Keychain access denied")
				case "short-key":
					return key[:31], nil
				case "wrong-key":
					return bytes.Repeat([]byte{9}, 32), nil
				case "write-failed":
					if err := os.Mkdir(secretPath(dir, "session-key"), 0700); err != nil {
						t.Fatal(err)
					}
				case "invalid-local-key":
					t.Fatal("invalid local key triggered a Keychain read")
				}
				return key, nil
			}
			store := core.NewSecureStore[core.Persisted](path, core.KeyProviderFunc(func(bool) ([]byte, error) {
				key, err := readSessionKey(dir, "work.starrail.client.test", "session-key", legacy)
				if errors.Is(err, errSecretMissing) {
					t.Fatal("migration failure would allow generating a replacement key")
				}
				return key, err
			}))
			if _, err := store.Load(); core.CodeOf(err) != "STORAGE_LOCKED" || store.Mode() != "locked" {
				t.Fatal("failed migration did not lock the saved session", err)
			}
			if err := store.Save(core.Persisted{}, nil); core.CodeOf(err) != "STORAGE_LOCKED" {
				t.Fatal("locked session could be overwritten", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed migration changed or deleted the saved login", err)
			}
			if failure == "invalid-local-key" {
				if raw, err := os.ReadFile(secretPath(dir, "session-key")); err != nil || string(raw) != "invalid" {
					t.Fatal("existing key was overwritten", err)
				}
			} else if failure != "write-failed" {
				if _, err := os.Stat(secretPath(dir, "session-key")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("failed migration installed a new key", err)
				}
			}
			if failure == "denied" {
				// A later launch can retry after the user grants Keychain access.
				if _, err := readSessionKey(dir, "work.starrail.client.test", "session-key", func(string, string) ([]byte, error) { return key, nil }); err != nil {
					t.Fatal("denying access prevented later recovery", err)
				}
			}
		})
	}
}

func TestSessionKeyFreshInstallDoesNotReadLegacyKeychain(t *testing.T) {
	dir := t.TempDir()
	_, err := readSessionKey(dir, "work.starrail.client.test", "session-key", func(string, string) ([]byte, error) {
		t.Fatal("fresh install requested Keychain access")
		return nil, nil
	})
	if !errors.Is(err, errSecretMissing) {
		t.Fatal(err)
	}
}
