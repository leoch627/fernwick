package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const protocolVersion = 1
const maxMessage = 34 * 1024 * 1024
const mark = 0x5352

var errCancelled = errors.New("CANCELLED")

func failure(code string) error { return errors.New(code) }

type Node struct {
	Protocol    string `json:"protocol"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Credential  string `json:"credential"`
	Method      string `json:"method,omitempty"`
	Transport   string `json:"transport"`
	Security    string `json:"security"`
	SNI         string `json:"sni,omitempty"`
	Flow        string `json:"flow,omitempty"`
	PublicKey   string `json:"publicKey,omitempty"`
	ShortID     string `json:"shortId,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	WSPath      string `json:"wsPath,omitempty"`
	WSHost      string `json:"wsHost,omitempty"`
	// AI marks nodes whose exit region AI services accept (not mainland China, Hong Kong or Macao).
	AI bool `json:"ai,omitempty"`
}

// RuleSection routes matching domains or addresses to one target. Sections are
// evaluated in order; domains use Xray's domain:, full:, keyword: and regexp: forms.
type RuleSection struct {
	Target  string   `json:"target"`
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}
type Rules struct {
	SchemaVersion int           `json:"schemaVersion"`
	Sections      []RuleSection `json:"sections"`
}

// Candidate is one connection. Node is the user's node, or the best probed node when
// Automatic; Pool holds the other usable nodes for the automatic and AI balancers.
type Candidate struct {
	Node            Node   `json:"node"`
	Pool            []Node `json:"pool,omitempty"`
	Automatic       bool   `json:"automatic,omitempty"`
	Mode            string `json:"mode"`
	Rules           Rules  `json:"rules"`
	AuthorizedUntil int64  `json:"authorizedUntil"`
}
type Request struct {
	Challenge       string          `json:"challenge,omitempty"`
	Protocol        int             `json:"protocol"`
	ProductID       string          `json:"productId"`
	ID              string          `json:"id"`
	Action          string          `json:"action"`
	Ticket          string          `json:"ticket,omitempty"`
	Candidate       *Candidate      `json:"candidate,omitempty"`
	ReleaseEnvelope string          `json:"releaseEnvelope,omitempty"`
	ArtifactID      string          `json:"artifactId,omitempty"`
	ArtifactPath    string          `json:"artifactPath,omitempty"`
	AuthorizedUntil int64           `json:"authorizedUntil,omitempty"`
	HTTP            *ControlRequest `json:"http,omitempty"`
}
type ControlRequest struct {
	URL      string            `json:"url"`
	Method   string            `json:"method,omitempty"`
	Headers  map[string]string `json:"headers,omitempty"`
	Body     string            `json:"body,omitempty"`
	MaxBytes int64             `json:"maxBytes,omitempty"`
}
type ControlResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}
type Proof struct {
	TCP  bool `json:"tcp"`
	UDP  bool `json:"udp"`
	DNS  bool `json:"dns"`
	IPv6 bool `json:"ipv6"`
}
type Response struct {
	Signature string           `json:"signature,omitempty"`
	ID        string           `json:"id"`
	OK        bool             `json:"ok"`
	Error     string           `json:"error,omitempty"`
	Protocol  int              `json:"protocol"`
	ProductID string           `json:"productId"`
	BuildID   string           `json:"buildId"`
	Version   string           `json:"version"`
	State     string           `json:"state"`
	Ready     bool             `json:"ready"`
	Owned     bool             `json:"owned"`
	Ticket    string           `json:"ticket,omitempty"`
	Proof     *Proof           `json:"proof,omitempty"`
	HTTP      *ControlResponse `json:"http,omitempty"`
}
type Peer struct {
	PID        int    `json:"pid"`
	User       string `json:"user"`
	Birth      string `json:"birth"`
	Executable string `json:"executable"`
	Arguments  string `json:"-"`
}

func (p Peer) key() string {
	return p.User + ":" + p.Birth + ":" + stringHash(p.Executable) + ":" + itoa(p.PID)
}

type Interface struct {
	Name      string      `json:"name"`
	Index     int         `json:"index"`
	Gateway   string      `json:"gateway"`
	Addresses []string    `json:"addresses"`
	DNS       []DNSBackup `json:"dns"`
}
type DNSBackup struct {
	Service   string   `json:"service"`
	Addresses []string `json:"addresses"`
	Applied   string   `json:"applied"`
}
type Journal struct {
	SchemaVersion   int       `json:"schemaVersion"`
	ID              string    `json:"id"`
	ProductID       string    `json:"productId"`
	Owner           Peer      `json:"owner"`
	Phase           string    `json:"phase"`
	Interface       Interface `json:"interface"`
	Tun             string    `json:"tun"`
	NodeAddress     string    `json:"nodeAddress"`
	PoolAddresses   []string  `json:"poolAddresses,omitempty"`
	Bypass          []string  `json:"bypass"`
	CorePID         int       `json:"corePid"`
	CoreBirth       string    `json:"coreBirth"`
	CorePath        string    `json:"corePath"`
	Protection      bool      `json:"protection"`
	Routes          bool      `json:"routes"`
	DNS             bool      `json:"dns"`
	FilterToken     string    `json:"filterToken,omitempty"`
	Deadline        int64     `json:"deadline"`
	AuthorizedUntil int64     `json:"authorizedUntil"`
}
type Installation struct {
	ProductID     string `json:"productId"`
	AppExecutable string `json:"appExecutable"`
	AppRoot       string `json:"appRoot"`
	AppSHA256     string `json:"appSha256"`
	CorePath      string `json:"corePath"`
	CoreSHA256    string `json:"coreSha256"`
	HelperPath    string `json:"helperPath"`
	BuildID       string `json:"buildId"`
}
type HealthTarget struct {
	URL           string `json:"url"`
	Status        int    `json:"status"`
	BodySHA256    string `json:"bodySha256"`
	FailureDomain string `json:"failureDomain"`
}
type Build struct {
	ProductID            string            `json:"productId"`
	DisplayName          string            `json:"displayName"`
	HelperLabel          string            `json:"helperLabel"`
	Environment          string            `json:"environment"`
	Channel              string            `json:"channel"`
	Version              string            `json:"version"`
	BuildID              string            `json:"buildId"`
	CoreVersion          string            `json:"coreVersion"`
	CoreHashes           map[string]string `json:"coreHashes"`
	ControlHosts         []string          `json:"controlHosts"`
	HealthTargets        []HealthTarget    `json:"healthTargets"`
	UpdateKeys           map[string]string `json:"updateKeys"`
	TrustedUpdateOrigins []string          `json:"trustedUpdateOrigins"`
	ControlOrigins       []string          `json:"controlOrigins"`
	AppExecutableName    string            `json:"appExecutableName"`
	AppExecutableNames   map[string]string `json:"appExecutableNames"`
	NativeHashes         map[string]string `json:"nativeHashes"`
}

var build Build
var installed Installation
var hex64 = regexp.MustCompile(`^[a-f0-9]{64}$`)
var uuidPattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var labelPattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
var realityKeyPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
var shortIDPattern = regexp.MustCompile(`^(?:[a-fA-F0-9]{2}){0,8}$`)

func domain(value string) bool {
	if len(value) < 1 || len(value) > 253 {
		return false
	}
	for _, part := range strings.Split(value, ".") {
		if !labelPattern.MatchString(part) {
			return false
		}
	}
	return true
}
func host(value string) bool { return net.ParseIP(value) != nil || domain(value) }
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func stringHash(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}

const maxAuthorization = 7 * 24 * time.Hour
const maxPool = 63

var targets = []string{"direct", "proxy", "ai", "block"}
var keywordPattern = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)

func (c *Candidate) validate() error {
	if c == nil || c.Mode != "rule" && c.Mode != "global" || c.AuthorizedUntil <= time.Now().UnixMilli() || c.AuthorizedUntil > time.Now().Add(maxAuthorization).UnixMilli()+2000 || len(c.Pool) > maxPool {
		return failure("INVALID_INPUT")
	}
	if e := c.Node.validate(); e != nil {
		return e
	}
	for i := range c.Pool {
		if e := c.Pool[i].validate(); e != nil {
			return e
		}
	}
	return c.Rules.validate()
}
func (n *Node) validate() error {
	if !host(n.Host) || n.Port < 1 || n.Port > 65535 || len(n.Credential) < 1 || len(n.Credential) > 2048 || !contains([]string{"tcp", "ws"}, n.Transport) {
		return failure("INVALID_INPUT")
	}
	if n.Fingerprint == "" {
		n.Fingerprint = "hellochrome_120"
	}
	if !contains([]string{"hellochrome_120", "chrome", "firefox", "safari", "edge", "ios", "android", "randomized"}, n.Fingerprint) {
		return failure("NO_COMPATIBLE_NODES")
	}
	if n.Security != "none" && !host(n.SNI) {
		return failure("NO_COMPATIBLE_NODES")
	}
	switch n.Protocol {
	case "vless":
		if !uuidPattern.MatchString(n.Credential) || !contains([]string{"tls", "reality"}, n.Security) {
			return failure("NO_COMPATIBLE_NODES")
		}
		if n.Security == "reality" && (n.Transport != "tcp" || !realityKeyPattern.MatchString(n.PublicKey) || !shortIDPattern.MatchString(n.ShortID) || !contains([]string{"", "xtls-rprx-vision"}, n.Flow)) {
			return failure("NO_COMPATIBLE_NODES")
		}
		if n.Security == "tls" && n.Flow != "" {
			return failure("NO_COMPATIBLE_NODES")
		}
	case "vmess":
		if !uuidPattern.MatchString(n.Credential) || n.Transport != "ws" || n.Security != "tls" || !contains([]string{"", "auto", "aes-128-gcm", "chacha20-poly1305"}, n.Method) {
			return failure("NO_COMPATIBLE_NODES")
		}
	case "trojan":
		if n.Security != "tls" || n.Transport != "tcp" {
			return failure("NO_COMPATIBLE_NODES")
		}
	case "shadowsocks":
		if n.Transport != "tcp" || n.Security != "none" || !contains([]string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"}, n.Method) {
			return failure("NO_COMPATIBLE_NODES")
		}
	default:
		return failure("NO_COMPATIBLE_NODES")
	}
	if n.Transport == "ws" && (!strings.HasPrefix(n.WSPath, "/") || len(n.WSPath) > 2048 || strings.ContainsAny(n.WSPath, "\r\n\x00") || !host(n.WSHost)) {
		return failure("NO_COMPATIBLE_NODES")
	}
	return nil
}

// validRuleDomain accepts only the matcher forms the rule data uses. In particular
// geosite:/ext: are rejected so that no rule can make the core open a file.
func validRuleDomain(value string) bool {
	kind, rest, ok := strings.Cut(value, ":")
	if !ok {
		return false
	}
	switch kind {
	case "domain", "full":
		return domain(rest)
	case "keyword":
		return keywordPattern.MatchString(rest)
	case "regexp":
		if len(rest) < 1 || len(rest) > 512 {
			return false
		}
		for _, r := range rest {
			if r < 0x20 || r > 0x7e {
				return false
			}
		}
		_, e := regexp.Compile(rest)
		return e == nil
	}
	return false
}
func (r Rules) validate() error {
	if r.SchemaVersion != 2 || len(r.Sections) > 64 {
		return failure("INVALID_INPUT")
	}
	domains, addresses := 0, 0
	for _, section := range r.Sections {
		if !contains(targets, section.Target) {
			return failure("INVALID_INPUT")
		}
		domains += len(section.Domains)
		addresses += len(section.IPs)
		if domains > 200000 || addresses > 100000 {
			return failure("INVALID_INPUT")
		}
		for _, v := range section.Domains {
			if !validRuleDomain(v) {
				return failure("INVALID_INPUT")
			}
		}
		for _, v := range section.IPs {
			if _, e := netip.ParsePrefix(v); e != nil {
				if _, e = netip.ParseAddr(v); e != nil {
					return failure("INVALID_INPUT")
				}
			}
		}
	}
	return nil
}
func safeOrigin(raw string) string {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
func jsonBytes(value any) []byte { b, _ := json.Marshal(value); return b }
