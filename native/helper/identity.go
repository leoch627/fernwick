package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"path/filepath"
)

func ensureServerIdentity() error {
	privatePath := filepath.Join(stateRoot(), "server-key.pk8")
	if _, e := os.Stat(privatePath); os.IsNotExist(e) {
		_, key, e := ed25519.GenerateKey(rand.Reader)
		if e != nil {
			return e
		}
		bytes, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return e
		}
		f, e := os.OpenFile(privatePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		_, e = f.Write(bytes)
		if e == nil {
			e = f.Sync()
		}
		f.Close()
		if e != nil {
			return e
		}
	}
	key, e := serverKey()
	if e != nil {
		return e
	}
	public, e := x509.MarshalPKIXPublicKey(key.Public())
	if e != nil {
		return e
	}
	return os.WriteFile(filepath.Join(helperRoot(), "server-public.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), 0644)
}
func serverKey() (ed25519.PrivateKey, error) {
	path := filepath.Join(stateRoot(), "server-key.pk8")
	if e := protectedFile(path); e != nil {
		return nil, e
	}
	bytes, e := os.ReadFile(path)
	if e != nil {
		return nil, e
	}
	value, e := x509.ParsePKCS8PrivateKey(bytes)
	if e != nil {
		return nil, e
	}
	key, ok := value.(ed25519.PrivateKey)
	if !ok {
		return nil, failure("COMPONENTS_UNAVAILABLE")
	}
	return key, nil
}
func signHello(challenge string) (string, error) {
	if !uuidPattern.MatchString(challenge) {
		return "", failure("INVALID_INPUT")
	}
	key, e := serverKey()
	if e != nil {
		return "", e
	}
	bytes := []byte("starrail-helper-v1\n" + challenge + "\n" + build.ProductID + "\n" + build.BuildID)
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, bytes)), nil
}
