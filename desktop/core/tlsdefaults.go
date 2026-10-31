package core

// DefaultTLSFingerprint is the pinned core's Chrome 120 profile with X25519.
const DefaultTLSFingerprint = "hellochrome_120"

var supportedTLSFingerprints = map[string]bool{
	"chrome": true, "firefox": true, "safari": true, "edge": true,
	"ios": true, "android": true, "randomized": true, DefaultTLSFingerprint: true,
}
