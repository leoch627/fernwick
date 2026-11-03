//go:build windows || linux

package main

import (
	"encoding/base64"
	"errors"
	"github.com/zalando/go-keyring"
)

// Windows uses Credential Manager; Linux uses Secret Service over DBus.
func readSystemSecret(_, service, account string) ([]byte, error) {
	value, err := keyring.Get(service, account)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, errSecretMissing
	}
	if err != nil {
		return nil, err
	}
	return base64.StdEncoding.Strict().DecodeString(value)
}
func writeSystemSecret(_, service, account string, key []byte) error {
	return keyring.Set(service, account, base64.StdEncoding.EncodeToString(key))
}
