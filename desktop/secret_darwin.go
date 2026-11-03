package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"work.starrail/client/desktop/core"
)

// macOS keeps the session key in a file only this user can read, in the data directory
// beside the session it seals. The Keychain asked every newly installed build for access,
// and refusing left the session locked.
func secretPath(dir, account string) string { return filepath.Join(dir, account+".key") }

func readSystemSecret(dir, _, account string) ([]byte, error) {
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
func writeSystemSecret(dir, _, account string, key []byte) error {
	return core.AtomicWrite(secretPath(dir, account), key, nil)
}

// forgetKeychainSession removes a session sealed with a key this build cannot read: one
// kept in the Keychain by an earlier version, or one whose key file is gone. Signing in
// again replaces it; left in place it would stay locked.
func forgetKeychainSession(dir, account, session string) {
	if _, err := os.Lstat(secretPath(dir, account)); errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(session)
	}
}
