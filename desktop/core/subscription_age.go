package core

import (
	"io"
	"strings"

	"filippo.io/age"
	"filippo.io/age/armor"
)

// A subscription may come back age-encrypted, the way mihomo's proxy providers take
// it (age-secret-key): the request names a recipient in X-Age-Public-Key and a panel
// that knows the header answers with the official ASCII armor instead of the list.
// The key pair is made for one request and never stored, so nothing on disk opens a
// recorded response. A panel that ignores the header answers in the clear, as before.
const subscriptionAgeHeader = "x-age-public-key"

// subscriptionPlainLimit is the largest list ParseSubscription reads; the armor of
// that many bytes is a third longer, plus the age header.
const (
	subscriptionPlainLimit   = 14 * 1024 * 1024
	subscriptionArmoredLimit = 20 * 1024 * 1024
)

func newSubscriptionIdentity() *age.X25519Identity {
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil
	}
	return identity
}

func subscriptionArmored(body string) bool {
	return strings.HasPrefix(jsTrim(body), armor.Header)
}

// openSubscription returns a clear body unchanged and decrypts an armored one. An
// armored body this request's key does not open is not a subscription.
func openSubscription(body string, identity *age.X25519Identity) (string, error) {
	if !subscriptionArmored(body) {
		if len(body) > subscriptionPlainLimit {
			return "", NewAppError("CONTROL_UNAVAILABLE")
		}
		return body, nil
	}
	if identity == nil {
		return "", invalidSubscription()
	}
	clear, err := age.Decrypt(armor.NewReader(strings.NewReader(jsTrim(body))), identity)
	if err != nil {
		return "", invalidSubscription()
	}
	raw, err := io.ReadAll(io.LimitReader(clear, subscriptionPlainLimit+1))
	if err != nil || len(raw) > subscriptionPlainLimit {
		return "", invalidSubscription()
	}
	return string(raw), nil
}
