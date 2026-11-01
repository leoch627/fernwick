package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"time"
)

// Restriction preserves the display priority of independent account restrictions.
// An empty code means that no explicit restriction was observed, not that access
// was authorized; SnapshotGate also requires affirmative service evidence.
func Restriction(account Account, now int64) ErrorCode {
	switch {
	case account.SessionStatus == "invalid":
		return "AUTH_INVALID"
	case account.Banned == "yes":
		return "ACCOUNT_BANNED"
	case account.HasPlan == "no" || account.ServiceAllowed == "no":
		return "NO_SERVICE"
	case account.ExpiryKind == "finite" && expiryMillis(account.ExpiresAt) <= now:
		return "ACCOUNT_EXPIRED"
	case account.TrafficExhausted == "yes":
		return "QUOTA_EXHAUSTED"
	default:
		return ""
	}
}

// expiryMillis treats an absent expiry as unbounded and a malformed expiry as
// already expired. Normal inputs have passed Account.Validate before reaching it.
func expiryMillis(expiry *string) int64 {
	if expiry == nil {
		return math.MaxInt64
	}
	parsed, err := time.Parse(time.RFC3339Nano, *expiry)
	if err != nil {
		return math.MinInt64
	}
	return parsed.UnixMilli()
}

func CreateSnapshot(build BuildConfig, session Session, account Account, parsed ParsedNodes, now int64, age int, opSeq int64) (Snapshot, error) {
	if err := account.Validate(); err != nil {
		return Snapshot{}, err
	}
	if age < 600 || age > MaxSnapshotAgeSec || now < 0 || now > 9007199254740991-int64(age)*1000 || opSeq < 0 || opSeq > 9007199254740991 {
		return Snapshot{}, NewAppError("INVALID_INPUT")
	}
	nodes := append([]ProxyNode{}, parsed.Nodes...)
	var content bytes.Buffer
	encoder := json.NewEncoder(&content)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(struct {
		Account Account     `json:"account"`
		Nodes   []ProxyNode `json:"nodes"`
	}{account, nodes}); err != nil {
		return Snapshot{}, NewAppError("INVALID_INPUT")
	}
	hash := sha256.Sum256(bytes.TrimSuffix(content.Bytes(), []byte{'\n'}))
	return Snapshot{
		ProductID: build.ProductID, Environment: build.Environment, AdapterID: build.AdapterID,
		AccountID: session.AccountID, SessionGeneration: session.Generation, OpSeq: opSeq,
		Account: account, Nodes: nodes, FullSyncCompletedAt: now,
		UsableUntil:       min(now+int64(age)*1000, expiryMillis(account.ExpiresAt)),
		MaxAgeAtCommitSec: age, QuarantinedNodeCount: len(parsed.Quarantined),
		AuthoritativeEmpty: parsed.AuthoritativeEmpty, ContentHash: hex.EncodeToString(hash[:]),
	}, nil
}

// TightenSnapshot never extends authorization, even after a successful account
// poll, a relaxed policy, or a renewed subscription. Only a full sync can do so.
func TightenSnapshot(snapshot Snapshot, maxAge int, account *Account) Snapshot {
	expires := int64(math.MaxInt64)
	if account != nil {
		expires = expiryMillis(account.ExpiresAt)
	}
	// Limit arithmetic to the local hard limit even for callers with an invalid
	// remote policy. An invalid negative age denies rather than extends access.
	age := max(0, min(maxAge, MaxSnapshotAgeSec))
	snapshot.UsableUntil = min(snapshot.UsableUntil, snapshot.FullSyncCompletedAt+int64(age)*1000, expires)
	return snapshot
}

type SnapshotGateInput struct {
	Build            BuildConfig
	Session          *Session
	Snapshot         *Snapshot
	StartupAttempted bool
	TrustedTime      bool
	Now              int64
	Restrictions     map[ErrorCode]bool
}

func SnapshotGate(input SnapshotGateInput) ErrorCode {
	session, snapshot := input.Session, input.Snapshot
	if session == nil || input.Restrictions["AUTH_INVALID"] {
		return "AUTH_INVALID"
	}
	if !input.StartupAttempted {
		return "CONTROL_UNAVAILABLE"
	}
	if !input.TrustedTime {
		return "CLOCK_UNTRUSTED"
	}
	if snapshot == nil || snapshot.ProductID != input.Build.ProductID || snapshot.Environment != input.Build.Environment || snapshot.AdapterID != input.Build.AdapterID || snapshot.AccountID != session.AccountID || snapshot.SessionGeneration != session.Generation {
		return "CONTROL_UNAVAILABLE"
	}
	for _, code := range []ErrorCode{"ACCOUNT_BANNED", "NO_SERVICE", "ACCOUNT_EXPIRED", "QUOTA_EXHAUSTED", "NO_AUTHORIZED_NODES"} {
		if input.Restrictions[code] {
			return code
		}
	}
	if denied := Restriction(snapshot.Account, input.Now); denied != "" {
		return denied
	}
	if snapshot.Account.ServiceAllowed != "yes" {
		return "NO_SERVICE"
	}
	if input.Now >= snapshot.UsableUntil {
		return "SNAPSHOT_EXPIRED"
	}
	if len(snapshot.Nodes) == 0 {
		return "NO_AUTHORIZED_NODES"
	}
	for _, node := range snapshot.Nodes {
		if node.Compatible && node.TCP && node.UDP {
			return ""
		}
	}
	return "NO_COMPATIBLE_NODES"
}
