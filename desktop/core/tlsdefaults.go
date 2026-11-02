package core

import "strings"

// DefaultTLSFingerprint stands in a parsed node for a subscription that names no
// fingerprint. It is part of the node's ID, which must not change; what the core sends is
// chosen by ModernTLSFingerprint.
const DefaultTLSFingerprint = "hellochrome_120"

// The client sends a current browser's ClientHello whatever fingerprint the subscription
// names: Safari 26.3 for nodes that ask for Safari or iOS, else Chrome 133. Both send an
// X25519 key share, which REALITY needs, beside the X25519MLKEM768 hybrid those browsers
// send.
const (
	ChromeTLSFingerprint = "hellochrome_133"
	SafariTLSFingerprint = "hellosafari_26_3"
)

func ModernTLSFingerprint(requested *string) string {
	if requested != nil {
		value := strings.ToLower(*requested)
		if value == "safari" || value == "ios" || strings.HasPrefix(value, "hellosafari") || strings.HasPrefix(value, "helloios") {
			return SafariTLSFingerprint
		}
	}
	return ChromeTLSFingerprint
}
