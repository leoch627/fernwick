package core

import (
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

type Account struct {
	AccountID             string  `json:"accountId"`
	Email                 string  `json:"email"`
	PlanName              string  `json:"planName"`
	SessionStatus         string  `json:"sessionStatus"`
	ServiceAllowed        string  `json:"serviceAllowed"`
	Banned                string  `json:"banned"`
	HasPlan               string  `json:"hasPlan"`
	TrafficExhausted      string  `json:"trafficExhausted"`
	ExpiryKind            string  `json:"expiryKind"`
	ExpiresAt             *string `json:"expiresAt,nullable"`
	QuotaKind             string  `json:"quotaKind"`
	UsedBytes             *string `json:"usedBytes,nullable"`
	QuotaBytes            *string `json:"quotaBytes,nullable"`
	ResetAt               *string `json:"resetAt,nullable"`
	ObservedAt            string  `json:"observedAt"`
	SourceEndpointID      string  `json:"sourceEndpointId"`
	AuthorizationEvidence string  `json:"authorizationEvidence"`
}

type Refresh struct {
	SubscriptionIntervalSec int `json:"subscriptionIntervalSec"`
	AccountIntervalSec      int `json:"accountIntervalSec"`
	PolicyIntervalSec       int `json:"policyIntervalSec"`
	MaxSnapshotAgeSec       int `json:"maxSnapshotAgeSec"`
}

// MaxSnapshotAgeSec is how long the last full sync stays usable while the panel API is
// unreachable. Mainland users can lose the API for days when a domain gets blocked;
// plan expiry still ends access on time.
const MaxSnapshotAgeSec = 7 * 24 * 3600

var DefaultRefresh = Refresh{1800, 300, 900, MaxSnapshotAgeSec}

type APIEndpoint struct {
	ID       string `json:"id"`
	BaseURL  string `json:"baseUrl"`
	Priority int    `json:"priority"`
}

type BuildLinks struct {
	Website *string `json:"website,nullable"`
	Renew   *string `json:"renew,nullable"`
	Help    *string `json:"help,nullable"`
	// Support is the operator's customer service chat (e.g. a Crisp chat page).
	Support *string `json:"support,nullable" default:"null"`
}

type Links struct {
	Website string `json:"website"`
	Renew   string `json:"renew"`
	Help    string `json:"help"`
}

type HealthTarget struct {
	URL           string `json:"url"`
	Status        int    `json:"status"`
	BodySHA256    string `json:"bodySha256"`
	FailureDomain string `json:"failureDomain"`
}

type HardLimits struct {
	StartupNetworkBudgetSec     int `json:"startupNetworkBudgetSec"`
	NetworkTransactionSec       int `json:"networkTransactionSec"`
	MaxSnapshotAgeSec           int `json:"maxSnapshotAgeSec"`
	SubscriptionDecodedMaxBytes int `json:"subscriptionDecodedMaxBytes"`
	SubscriptionMaxNodes        int `json:"subscriptionMaxNodes"`
}

type BuildConfig struct {
	SchemaVersion              int               `json:"schemaVersion"`
	ProductID                  string            `json:"productId"`
	AppID                      string            `json:"appId"`
	Name                       string            `json:"name"`
	Environment                string            `json:"environment"`
	Channel                    string            `json:"channel"`
	TenantID                   string            `json:"tenantId"`
	AdapterID                  string            `json:"adapterId"`
	DeploymentVerified         bool              `json:"deploymentVerified"`
	SubscriptionFormatID       string            `json:"subscriptionFormatId"`
	APIEndpoints               []APIEndpoint     `json:"apiEndpoints"`
	TrustedSubscriptionOrigins []string          `json:"trustedSubscriptionOrigins"`
	TrustedWebOrigins          []string          `json:"trustedWebOrigins"`
	TrustedResourceOrigins     []string          `json:"trustedResourceOrigins"`
	PolicyURLs                 []string          `json:"policyUrls"`
	UpdateFeedURLs             []string          `json:"updateFeedUrls"`
	TrustedUpdateOrigins       []string          `json:"trustedUpdateOrigins"`
	Links                      BuildLinks        `json:"links"`
	PolicyKeys                 map[string]string `json:"policyKeys"`
	UpdateKeys                 map[string]string `json:"updateKeys"`
	ProtocolCapabilities       []string          `json:"protocolCapabilities"`
	NodeCapabilitiesConfirmed  bool              `json:"nodeCapabilitiesConfirmed"`
	AllowUnverifiedNodeTrials  bool              `json:"allowUnverifiedNodeTrials" default:"false"`
	HealthTargets              []HealthTarget    `json:"healthTargets" default:"[]"`
	HardLimits                 HardLimits        `json:"hardLimits"`
}

type NodeOperation struct {
	NodeID                string  `json:"nodeId"`
	HiddenFromList        bool    `json:"hiddenFromList"`
	EligibleForAuto       bool    `json:"eligibleForAuto"`
	DisabledForConnection bool    `json:"disabledForConnection"`
	Order                 *int    `json:"order,omitempty"`
	Group                 *string `json:"group,omitempty"`
}

type Resource struct {
	ID        string `json:"id"`
	Version   int64  `json:"version"`
	URL       string `json:"url"`
	SHA256    string `json:"sha256"`
	Bytes     int64  `json:"bytes"`
	ExpiresAt string `json:"expiresAt"`
}

type PolicyEndpoints struct {
	OrderedIDs             []string `json:"orderedIds"`
	TemporarilyDisabledIDs []string `json:"temporarilyDisabledIds"`
}

type Announcement struct {
	ID   string `json:"id"`
	Text string `json:"text"`
}

type PolicyUI struct {
	ExpiryReminderDays []int         `json:"expiryReminderDays"`
	ShowTrafficSummary bool          `json:"showTrafficSummary"`
	Announcement       *Announcement `json:"announcement,nullable"`
}

type PolicyRouting struct {
	TemplateID    string    `json:"templateId"`
	DNSTemplateID string    `json:"dnsTemplateId"`
	Resource      *Resource `json:"resource,nullable"`
}

type Maintenance struct {
	Reason    string   `json:"reason"`
	StartsAt  string   `json:"startsAt"`
	EndsAt    string   `json:"endsAt"`
	Platforms []string `json:"platforms"`
}

type PolicyUpdate struct {
	CheckIntervalSec int     `json:"checkIntervalSec"`
	NoticeText       *string `json:"noticeText,nullable"`
}

type Policy struct {
	SchemaVersion        int             `json:"schemaVersion"`
	PolicyVersion        int64           `json:"policyVersion"`
	ProductID            string          `json:"productId"`
	Environment          string          `json:"environment"`
	Channel              string          `json:"channel"`
	IssuedAt             string          `json:"issuedAt"`
	NotBefore            string          `json:"notBefore"`
	ExpiresAt            string          `json:"expiresAt"`
	RequiredCapabilities []string        `json:"requiredCapabilities"`
	Endpoints            PolicyEndpoints `json:"endpoints"`
	Refresh              Refresh         `json:"refresh"`
	UI                   PolicyUI        `json:"ui"`
	Links                Links           `json:"links"`
	NodeOperations       []NodeOperation `json:"nodeOperations"`
	Routing              PolicyRouting   `json:"routing"`
	Maintenance          *Maintenance    `json:"maintenance,nullable"`
	Update               PolicyUpdate    `json:"update"`
}

type Preferences struct {
	Mode          string  `json:"mode"`
	NodeID        *string `json:"nodeId,nullable"`
	AutoConnect   bool    `json:"autoConnect"`
	LaunchAtLogin bool    `json:"launchAtLogin"`
	CloseBehavior string  `json:"closeBehavior"`
	Theme         string  `json:"theme"`
	// Tunnel is how traffic reaches the core: "proxy" sets the system proxy and needs no
	// administrator rights; "tun" captures every app through the network service.
	// Files written before these fields existed load with the defaults.
	Tunnel          string   `json:"tunnel" default:"\"proxy\""`
	AdBlock         bool     `json:"adBlock" default:"true"`
	FavoriteNodeIDs []string `json:"favoriteNodeIds" default:"[]"`
	RecentNodeIDs   []string `json:"recentNodeIds" default:"[]"`
}

var DefaultPreferences = Preferences{Mode: "rule", CloseBehavior: "tray", Theme: "system", Tunnel: "proxy", AdBlock: true, FavoriteNodeIDs: []string{}, RecentNodeIDs: []string{}}

// Command is decoded with ParseCommand, which enforces its discriminated shape.
type Command struct {
	Type        string       `json:"type"`
	Email       string       `json:"email,omitempty"`
	Password    string       `json:"password,omitempty"`
	Preferences *Preferences `json:"preferences,omitempty"`
	NodeIDs     []string     `json:"nodeIds,omitempty"`
	Link        string       `json:"link,omitempty"`
	Note        string       `json:"note,omitempty"`
	NodeID      string       `json:"nodeId,omitempty"`
	Favorite    bool         `json:"favorite,omitempty"`
	EmailCode   string       `json:"emailCode,omitempty"`
	InviteCode  string       `json:"inviteCode,omitempty"`
	Purpose     string       `json:"purpose,omitempty"`
}

const MaxSafeInteger int64 = 9007199254740991

var decimalPattern = regexp.MustCompile(`^(0|[1-9][0-9]{0,29})$`)
var sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)

// Matches the default Zod email validator, including its ASCII TLD rule.
var emailPattern = regexp.MustCompile(`^[A-Za-z0-9_'+\-.]*[A-Za-z0-9_+\-]@(?:[A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}$`)
var utcPattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]+)?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$`)

// Zod 4.6 string bounds count Unicode code points, including lone surrogates.
func stringLength(s string) int {
	n := 0
	for i := 0; i < len(s); {
		if i+2 < len(s) && s[i] == 0xed && s[i+1] >= 0xa0 && s[i+1] <= 0xbf && s[i+2] >= 0x80 && s[i+2] <= 0xbf {
			i += 3
			n++
			continue
		}
		_, size := utf8.DecodeRuneInString(s[i:])
		i += size
		n++
	}
	return n
}
func boundedText(s string, min, max int) bool { n := stringLength(s); return n >= min && n <= max }
func textField(s string) bool                 { return boundedText(s, 1, 256) }
func oneOf(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func validEmail(s string) bool {
	return boundedText(s, 1, 254) && !strings.HasPrefix(s, ".") && !strings.Contains(s, "..") && emailPattern.MatchString(s)
}
func validUTC(s string) bool {
	if !utcPattern.MatchString(s) {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, s)
	return err == nil
}
func validURL(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme != "" && (u.Opaque != "" || u.Host != "")
}
func nullableCheck(v *string, check func(string) bool) bool { return v == nil || check(*v) }
func inRange(v, min, max int) bool                          { return v >= min && v <= max }
func invalidUnless(ok bool) error {
	if !ok {
		return NewAppError("INVALID_INPUT")
	}
	return nil
}

func (a Account) Validate() error {
	return invalidUnless(textField(a.AccountID) && validEmail(a.Email) && boundedText(a.PlanName, 0, 256) && oneOf(a.SessionStatus, "valid", "invalid", "unknown") && oneOf(a.ServiceAllowed, "yes", "no", "unknown") && oneOf(a.Banned, "yes", "no", "unknown") && oneOf(a.HasPlan, "yes", "no", "unknown") && oneOf(a.TrafficExhausted, "yes", "no", "unknown") && oneOf(a.ExpiryKind, "finite", "unlimited", "unknown") && nullableCheck(a.ExpiresAt, validUTC) && oneOf(a.QuotaKind, "finite", "unlimited", "unknown") && nullableCheck(a.UsedBytes, decimalPattern.MatchString) && nullableCheck(a.QuotaBytes, decimalPattern.MatchString) && nullableCheck(a.ResetAt, validUTC) && validUTC(a.ObservedAt) && textField(a.SourceEndpointID) && boundedText(a.AuthorizationEvidence, 0, 512) && ((a.ExpiryKind == "finite") == (a.ExpiresAt != nil)) && (a.QuotaKind != "finite" || a.QuotaBytes != nil) && (a.ServiceAllowed != "yes" || a.AuthorizationEvidence != ""))
}
func (r Refresh) Validate() error {
	return invalidUnless(inRange(r.SubscriptionIntervalSec, 300, 21600) && inRange(r.AccountIntervalSec, 60, 3600) && inRange(r.PolicyIntervalSec, 300, 3600) && inRange(r.MaxSnapshotAgeSec, 600, MaxSnapshotAgeSec) && r.AccountIntervalSec <= r.SubscriptionIntervalSec && float64(r.SubscriptionIntervalSec)*1.1+80 < float64(r.MaxSnapshotAgeSec))
}
func (e APIEndpoint) Validate() error {
	return invalidUnless(textField(e.ID) && validURL(e.BaseURL) && int64(e.Priority) >= -MaxSafeInteger && int64(e.Priority) <= MaxSafeInteger)
}
func (l BuildLinks) Validate() error {
	return invalidUnless(nullableCheck(l.Website, validURL) && nullableCheck(l.Renew, validURL) && nullableCheck(l.Help, validURL) && nullableCheck(l.Support, validURL))
}
func (l Links) Validate() error {
	return invalidUnless(validURL(l.Website) && validURL(l.Renew) && validURL(l.Help))
}
func (h HealthTarget) Validate() error {
	return invalidUnless(validURL(h.URL) && inRange(h.Status, 200, 299) && sha256Pattern.MatchString(h.BodySHA256) && textField(h.FailureDomain))
}
func (h HardLimits) Validate() error {
	return invalidUnless(h.StartupNetworkBudgetSec == 20 && h.NetworkTransactionSec == 15 && h.MaxSnapshotAgeSec == MaxSnapshotAgeSec && h.SubscriptionDecodedMaxBytes == 10485760 && h.SubscriptionMaxNodes == 5000)
}
func (b BuildConfig) Validate() error {
	if !(b.SchemaVersion == 2 && textField(b.ProductID) && textField(b.AppID) && textField(b.Name) && oneOf(b.Environment, "test", "production") && oneOf(b.Channel, "test", "stable") && textField(b.TenantID) && b.AdapterID == "v2board-explicit-v1" && b.SubscriptionFormatID == "v2ray-uri-base64-v1" && len(b.APIEndpoints) <= 8 && len(b.HealthTargets) <= 3) {
		return NewAppError("INVALID_INPUT")
	}
	for _, group := range []struct {
		values []string
		max    int
	}{{b.TrustedSubscriptionOrigins, 16}, {b.TrustedWebOrigins, 16}, {b.TrustedResourceOrigins, 16}, {b.TrustedUpdateOrigins, 16}, {b.PolicyURLs, 8}, {b.UpdateFeedURLs, 8}} {
		if len(group.values) > group.max {
			return NewAppError("INVALID_INPUT")
		}
		for _, v := range group.values {
			if !validURL(v) {
				return NewAppError("INVALID_INPUT")
			}
		}
	}
	for _, keys := range []map[string]string{b.PolicyKeys, b.UpdateKeys} {
		for _, v := range keys {
			if !boundedText(v, 0, 2048) {
				return NewAppError("INVALID_INPUT")
			}
		}
	}
	for _, v := range b.ProtocolCapabilities {
		if !oneOf(v, "vless-tls", "vless-reality", "vmess-ws-tls", "trojan-tls", "shadowsocks-aead") {
			return NewAppError("INVALID_INPUT")
		}
	}
	for _, e := range b.APIEndpoints {
		if err := e.Validate(); err != nil {
			return err
		}
	}
	for _, h := range b.HealthTargets {
		if err := h.Validate(); err != nil {
			return err
		}
	}
	if err := b.Links.Validate(); err != nil {
		return err
	}
	return b.HardLimits.Validate()
}
func (n NodeOperation) Validate() error {
	return invalidUnless(textField(n.NodeID) && nullableCheck(n.Group, textField) && (n.Order == nil || int64(*n.Order) >= -MaxSafeInteger && int64(*n.Order) <= MaxSafeInteger))
}
func (r Resource) Validate() error {
	return invalidUnless(textField(r.ID) && r.Version > 0 && r.Version <= MaxSafeInteger && validURL(r.URL) && sha256Pattern.MatchString(r.SHA256) && r.Bytes >= 1 && r.Bytes <= 33554432 && validUTC(r.ExpiresAt))
}
func (p PolicyEndpoints) Validate() error {
	if !inRange(len(p.OrderedIDs), 1, 8) || len(p.TemporarilyDisabledIDs) > 8 {
		return NewAppError("INVALID_INPUT")
	}
	for _, group := range [][]string{p.OrderedIDs, p.TemporarilyDisabledIDs} {
		for _, v := range group {
			if !textField(v) {
				return NewAppError("INVALID_INPUT")
			}
		}
	}
	return nil
}
func (a Announcement) Validate() error {
	return invalidUnless(textField(a.ID) && boundedText(a.Text, 0, 2000))
}
func (u PolicyUI) Validate() error {
	if len(u.ExpiryReminderDays) > 5 {
		return NewAppError("INVALID_INPUT")
	}
	for _, v := range u.ExpiryReminderDays {
		if !inRange(v, 1, 30) {
			return NewAppError("INVALID_INPUT")
		}
	}
	if u.Announcement != nil {
		return u.Announcement.Validate()
	}
	return nil
}
func (r PolicyRouting) Validate() error {
	if r.TemplateID != "cn-direct-default-proxy-v1" || r.DNSTemplateID != "real-dns-split-v1" {
		return NewAppError("INVALID_INPUT")
	}
	if r.Resource != nil {
		return r.Resource.Validate()
	}
	return nil
}
func (m Maintenance) Validate() error {
	if !boundedText(m.Reason, 1, 500) || !validUTC(m.StartsAt) || !validUTC(m.EndsAt) || len(m.Platforms) == 0 {
		return NewAppError("INVALID_INPUT")
	}
	for _, v := range m.Platforms {
		if !oneOf(v, "win32", "darwin", "linux") {
			return NewAppError("INVALID_INPUT")
		}
	}
	return nil
}
func (u PolicyUpdate) Validate() error {
	return invalidUnless(inRange(u.CheckIntervalSec, 3600, 86400) && nullableCheck(u.NoticeText, func(s string) bool { return boundedText(s, 0, 1000) }))
}
func (p Policy) Validate() error {
	if !(p.SchemaVersion == 2 && p.PolicyVersion > 0 && p.PolicyVersion <= MaxSafeInteger && textField(p.ProductID) && oneOf(p.Environment, "test", "production") && oneOf(p.Channel, "test", "stable") && validUTC(p.IssuedAt) && validUTC(p.NotBefore) && validUTC(p.ExpiresAt) && len(p.RequiredCapabilities) <= 10 && len(p.NodeOperations) <= 5000) {
		return NewAppError("INVALID_INPUT")
	}
	for _, c := range p.RequiredCapabilities {
		if !oneOf(c, "tun", "policy-schema-2") {
			return NewAppError("INVALID_INPUT")
		}
	}
	for _, n := range p.NodeOperations {
		if err := n.Validate(); err != nil {
			return err
		}
	}
	for _, check := range []func() error{p.Endpoints.Validate, p.Refresh.Validate, p.UI.Validate, p.Links.Validate, p.Routing.Validate, p.Update.Validate} {
		if err := check(); err != nil {
			return err
		}
	}
	if p.Maintenance != nil {
		return p.Maintenance.Validate()
	}
	return nil
}
func (p Preferences) Validate() error {
	if !oneOf(p.Mode, "rule", "global") || !nullableCheck(p.NodeID, textField) || !oneOf(p.CloseBehavior, "tray", "ask") || !oneOf(p.Theme, "light", "dark", "system") || !oneOf(p.Tunnel, "proxy", "tun") || len(p.FavoriteNodeIDs) > 256 || len(p.RecentNodeIDs) > 8 {
		return NewAppError("INVALID_INPUT")
	}
	for _, ids := range [][]string{p.FavoriteNodeIDs, p.RecentNodeIDs} {
		seen := map[string]bool{}
		for _, id := range ids {
			if !textField(id) || seen[id] {
				return NewAppError("INVALID_INPUT")
			}
			seen[id] = true
		}
	}
	return nil
}
