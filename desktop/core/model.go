package core

// ProxyNode contains private connection material and must never be sent to the UI.
type ProxyNode struct {
	ID                    string  `json:"id"`
	Name                  string  `json:"name"`
	Group                 string  `json:"group"`
	Region                *string `json:"region,nullable"`
	Order                 int     `json:"order"`
	Protocol              string  `json:"protocol"`
	Host                  string  `json:"host"`
	Port                  int     `json:"port"`
	Credential            string  `json:"credential"`
	Method                *string `json:"method,omitempty"`
	Transport             string  `json:"transport"`
	Security              string  `json:"security"`
	SNI                   *string `json:"sni,omitempty"`
	Flow                  *string `json:"flow,omitempty"`
	PublicKey             *string `json:"publicKey,omitempty"`
	ShortID               *string `json:"shortId,omitempty"`
	Fingerprint           *string `json:"fingerprint,omitempty"`
	WSPath                *string `json:"wsPath,omitempty"`
	WSHost                *string `json:"wsHost,omitempty"`
	Compatible            bool    `json:"compatible"`
	Incompatibility       *string `json:"incompatibility,nullable"`
	TCP                   bool    `json:"tcp"`
	UDP                   bool    `json:"udp"`
	IPv6                  string  `json:"ipv6"`
	ConnectionFingerprint string  `json:"connectionFingerprint"`
	Source                string  `json:"source"`
}

type Session struct {
	AccountID  string `json:"accountId"`
	Email      string `json:"email"`
	Token      string `json:"token"`
	Generation string `json:"generation"`
}

type Snapshot struct {
	ProductID            string      `json:"productId"`
	Environment          string      `json:"environment"`
	AdapterID            string      `json:"adapterId"`
	AccountID            string      `json:"accountId"`
	SessionGeneration    string      `json:"sessionGeneration"`
	OpSeq                int64       `json:"opSeq"`
	Account              Account     `json:"account"`
	Nodes                []ProxyNode `json:"nodes"`
	FullSyncCompletedAt  int64       `json:"fullSyncCompletedAt"`
	UsableUntil          int64       `json:"usableUntil"`
	MaxAgeAtCommitSec    int         `json:"maxAgeAtCommitSec"`
	QuarantinedNodeCount int         `json:"quarantinedNodeCount"`
	AuthoritativeEmpty   bool        `json:"authoritativeEmpty"`
	ContentHash          string      `json:"contentHash"`
}

type QuarantinedNode struct {
	Index  int    `json:"index"`
	Reason string `json:"reason"`
}

type ParsedNodes struct {
	Nodes              []ProxyNode       `json:"nodes"`
	Quarantined        []QuarantinedNode `json:"quarantined"`
	AuthoritativeEmpty bool              `json:"authoritativeEmpty"`
}

type SubscriptionDescriptor struct {
	URL                string `json:"url"`
	Format             string `json:"format"`
	AuthoritativeEmpty bool   `json:"authoritativeEmpty"`
}
