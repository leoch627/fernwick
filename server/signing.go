package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"regexp"
	"strings"
)

// One key signs both the release index and the policy; the purpose prefix keeps them apart.
// The envelope format is what the client verifies (desktop/core/policy.go VerifyEnvelope):
// an Ed25519 signature over "<purpose>\n" + payload bytes, both base64url without padding.
const keyID = "key-1"
const (
	purposeRelease = "v2board-client-release-v1"
	purposePolicy  = "v2board-client-policy-v1"
)

type envelope struct {
	KeyID     string `json:"keyId"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

var pemArmor = regexp.MustCompile(`-----(BEGIN|END) [A-Z ]+-----`)

func pemBody(key string) string {
	return strings.Join(strings.Fields(pemArmor.ReplaceAllString(key, "")), "")
}

func parseSigningKey(key string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, errors.New("signing key is not PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not Ed25519")
	}
	return private, nil
}

func sign(key ed25519.PrivateKey, purpose string, payload any) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(key, append([]byte(purpose+"\n"), data...))
	out, err := json.Marshal(envelope{KeyID: keyID, Payload: base64.RawURLEncoding.EncodeToString(data), Signature: base64.RawURLEncoding.EncodeToString(signature)})
	return string(out), err
}

// adminToken derives the /admin bearer token from the signing key, so CI and the
// server share no second secret. tools/admin-token.mjs computes the same value.
func adminToken(signingKey string) string {
	digest := sha256.Sum256([]byte("v2board-client-admin-v1\n" + pemBody(signingKey)))
	return hex.EncodeToString(digest[:])
}

func sameSecret(presented, expected string) bool {
	a, b := sha256.Sum256([]byte(presented)), sha256.Sum256([]byte(expected))
	return expected != "" && subtle.ConstantTimeCompare(a[:], b[:]) == 1
}
