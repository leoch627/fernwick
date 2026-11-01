package core

type Persisted struct {
	SchemaVersion int         `json:"schemaVersion"`
	ProductID     string      `json:"productId"`
	Environment   string      `json:"environment"`
	Session       Session     `json:"session"`
	Snapshot      *Snapshot   `json:"snapshot,nullable"`
	Account       *Account    `json:"account,nullable"`
	Restrictions  []ErrorCode `json:"restrictions"`
	TimeUpper     int64       `json:"timeUpper"`
}

func (p Persisted) Validate() error {
	if p.SchemaVersion != 1 || p.TimeUpper > MaxSafeInteger || p.TimeUpper < -MaxSafeInteger {
		return NewAppError("INVALID_INPUT")
	}
	if err := p.Session.Validate(); err != nil {
		return err
	}
	if p.Snapshot != nil {
		if err := p.Snapshot.Validate(); err != nil {
			return err
		}
	}
	if p.Account != nil {
		if err := p.Account.Validate(); err != nil {
			return err
		}
	}
	for _, code := range p.Restrictions {
		if _, ok := Messages[code]; !ok {
			return NewAppError("INVALID_INPUT")
		}
	}
	return nil
}
func (s Session) Validate() error {
	return invalidUnless(s.AccountID != "" && validEmail(s.Email) && boundedText(s.Token, 0, 8192) && s.Generation != "")
}
func (n ProxyNode) Validate() error {
	return invalidUnless(sha256Pattern.MatchString(n.ID) && boundedText(n.Name, 0, 256) && boundedText(n.Group, 0, 256) && oneOf(n.Protocol, "vless", "vmess", "trojan", "shadowsocks", "unsupported") && boundedText(n.Host, 0, 253) && inRange(n.Port, 0, 65535) && boundedText(n.Credential, 0, 2048) && oneOf(n.Transport, "tcp", "ws") && oneOf(n.Security, "tls", "reality", "none") && oneOf(n.IPv6, "unknown", "verified") && sha256Pattern.MatchString(n.ConnectionFingerprint))
}
func (s Snapshot) Validate() error {
	if s.OpSeq > MaxSafeInteger || s.OpSeq < -MaxSafeInteger || len(s.Nodes) > 5000 || !inRange(s.MaxAgeAtCommitSec, 600, MaxSnapshotAgeSec) || s.QuarantinedNodeCount < 0 || !sha256Pattern.MatchString(s.ContentHash) || s.FullSyncCompletedAt > MaxSafeInteger || s.FullSyncCompletedAt < -MaxSafeInteger || s.UsableUntil > MaxSafeInteger || s.UsableUntil < -MaxSafeInteger || s.UsableUntil > s.FullSyncCompletedAt+int64(s.MaxAgeAtCommitSec)*1000 {
		return NewAppError("INVALID_INPUT")
	}
	if err := s.Account.Validate(); err != nil {
		return err
	}
	for _, n := range s.Nodes {
		if err := n.Validate(); err != nil {
			return err
		}
	}
	return nil
}
