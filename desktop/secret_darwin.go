package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"work.starrail/client/desktop/core"
)

// Keep the key outside the application bundle so replacing the app preserves login.
// Older builds stored the same key in Keychain; migrate it only when needed to unlock
// an existing session, without asking fresh installs for Keychain access.
func secretPath(dir, account string) string { return filepath.Join(dir, account+".key") }

func readSystemSecret(dir, service, account string) ([]byte, error) {
	return readSessionKey(dir, service, account, readLegacyKeychainSecret)
}

func readKeyFile(dir, account string) ([]byte, error) {
	path := secretPath(dir, account)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errSecretMissing
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 32 {
		return nil, fmt.Errorf("session key unreadable")
	}
	return os.ReadFile(path)
}

func readSessionKey(dir, service, account string, legacy func(string, string) ([]byte, error)) ([]byte, error) {
	key, err := readKeyFile(dir, account)
	if !errors.Is(err, errSecretMissing) {
		return key, err
	}
	sessionPath := filepath.Join(dir, "session.v2.enc")
	info, err := os.Lstat(sessionPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, errSecretMissing
	}
	if err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("saved session unreadable")
	}
	key, err = legacy(service, account)
	if err != nil || len(key) != 32 {
		// Do not return errSecretMissing: Key(true) must not generate a replacement
		// key while ciphertext still exists, even if Keychain access was denied.
		return nil, fmt.Errorf("legacy session key unavailable")
	}
	store := core.NewSecureStore[core.Persisted](sessionPath, core.KeyProviderFunc(func(bool) ([]byte, error) { return key, nil }))
	if saved, err := store.Load(); err != nil || saved == nil {
		return nil, fmt.Errorf("legacy session could not be unlocked")
	}
	if err := writeSystemSecret(dir, service, account, key); err != nil {
		return nil, err
	}
	return key, nil
}

func writeSystemSecret(dir, _, account string, key []byte) error {
	return core.AtomicWrite(secretPath(dir, account), key, nil)
}
