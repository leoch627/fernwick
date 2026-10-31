package core

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

const signedJSONMaxBytes = 262144

type Envelope struct {
	KeyID     string `json:"keyId"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

var envelopeBase64 = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

func (e Envelope) Validate() error {
	if !boundedText(e.KeyID, 1, 128) || !envelopeBase64.MatchString(e.Payload) || !envelopeBase64.MatchString(e.Signature) {
		return NewAppError("POLICY_INVALID")
	}
	return nil
}

type Watermark struct {
	Version int64  `json:"version"`
	Hash    string `json:"hash"`
}

type VerifiedEnvelope struct {
	Payload json.RawMessage
	Hash    string
}

// VerifyEnvelope authenticates the original payload bytes, including their exact
// JSON formatting. Re-encoding the JSON before checking the signature is unsafe.
func VerifyEnvelope(raw string, keys map[string]string, purpose string) (VerifiedEnvelope, error) {
	invalid := NewAppError("POLICY_INVALID")
	var envelope Envelope
	if err := DecodeStrict([]byte(raw), &envelope, signedJSONMaxBytes); err != nil {
		return VerifiedEnvelope{}, invalid
	}
	block, rest := pem.Decode([]byte(keys[envelope.KeyID]))
	if block == nil || block.Type != "PUBLIC KEY" || strings.TrimSpace(string(rest)) != "" {
		return VerifiedEnvelope{}, invalid
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return VerifiedEnvelope{}, invalid
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return VerifiedEnvelope{}, invalid
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Payload)
	if err != nil || !utf8.Valid(payload) {
		return VerifiedEnvelope{}, invalid
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(envelope.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return VerifiedEnvelope{}, invalid
	}
	message := append([]byte(purpose+"\n"), payload...)
	if !ed25519.Verify(key, message, signature) {
		return VerifiedEnvelope{}, invalid
	}
	if _, err := StrictJSON(payload, signedJSONMaxBytes); err != nil {
		return VerifiedEnvelope{}, invalid
	}
	hash := sha256.Sum256(payload)
	return VerifiedEnvelope{Payload: payload, Hash: hex.EncodeToString(hash[:])}, nil
}

func CheckWatermark(current *Watermark, next Watermark) (bool, error) {
	if current != nil && (next.Version < current.Version || next.Version == current.Version && next.Hash != current.Hash) {
		return false, NewAppError("POLICY_INVALID")
	}
	return current != nil && current.Version == next.Version, nil
}

type VerifiedPolicy struct {
	Policy    Policy
	Watermark Watermark
	Unchanged bool
}

func signedTime(raw string) (int64, error) {
	t, err := time.Parse(time.RFC3339Nano, raw)
	return t.UnixMilli(), err
}

func VerifyPolicy(raw string, build BuildConfig, watermark *Watermark, now int64) (VerifiedPolicy, error) {
	invalid := NewAppError("POLICY_INVALID")
	signed, err := VerifyEnvelope(raw, build.PolicyKeys, "v2board-client-policy-v1")
	if err != nil {
		return VerifiedPolicy{}, invalid
	}
	var policy Policy
	if err := DecodeStrict(signed.Payload, &policy, signedJSONMaxBytes); err != nil {
		return VerifiedPolicy{}, invalid
	}
	if policy.ProductID != build.ProductID || policy.Environment != build.Environment || policy.Channel != build.Channel {
		return VerifiedPolicy{}, invalid
	}
	issued, e1 := signedTime(policy.IssuedAt)
	from, e2 := signedTime(policy.NotBefore)
	until, e3 := signedTime(policy.ExpiresAt)
	if e1 != nil || e2 != nil || e3 != nil || issued > now+120000 || from > now || until <= now || issued > from || from >= until {
		return VerifiedPolicy{}, invalid
	}
	ids := make(map[string]bool, len(build.APIEndpoints))
	for _, endpoint := range build.APIEndpoints {
		ids[endpoint.ID] = true
	}
	ordered, disabled := policy.Endpoints.OrderedIDs, policy.Endpoints.TemporarilyDisabledIDs
	seen := make(map[string]bool, len(ordered))
	if len(ordered) != len(ids) {
		return VerifiedPolicy{}, invalid
	}
	for _, id := range ordered {
		if !ids[id] || seen[id] {
			return VerifiedPolicy{}, invalid
		}
		seen[id] = true
	}
	blocked := make(map[string]bool, len(disabled))
	for _, id := range disabled {
		if !ids[id] || blocked[id] {
			return VerifiedPolicy{}, invalid
		}
		blocked[id] = true
	}
	if len(blocked) == len(ids) {
		return VerifiedPolicy{}, invalid
	}
	for _, link := range []string{policy.Links.Website, policy.Links.Renew, policy.Links.Help} {
		if _, err := TrustedURL(link, build.TrustedWebOrigins); err != nil {
			return VerifiedPolicy{}, invalid
		}
	}
	if resource := policy.Routing.Resource; resource != nil {
		expires, err := signedTime(resource.ExpiresAt)
		if err != nil || expires > until || expires <= now {
			return VerifiedPolicy{}, invalid
		}
		if _, err := TrustedURL(resource.URL, build.TrustedResourceOrigins); err != nil {
			return VerifiedPolicy{}, invalid
		}
	}
	if maintenance := policy.Maintenance; maintenance != nil {
		a, e1 := signedTime(maintenance.StartsAt)
		b, e2 := signedTime(maintenance.EndsAt)
		if e1 != nil || e2 != nil || a >= b || b-a > 86400000 || b > until || a < from {
			return VerifiedPolicy{}, invalid
		}
	}
	nodes := make(map[string]bool, len(policy.NodeOperations))
	for _, operation := range policy.NodeOperations {
		if nodes[operation.NodeID] {
			return VerifiedPolicy{}, invalid
		}
		nodes[operation.NodeID] = true
	}
	next := Watermark{Version: policy.PolicyVersion, Hash: signed.Hash}
	unchanged, err := CheckWatermark(watermark, next)
	if err != nil {
		return VerifiedPolicy{}, invalid
	}
	return VerifiedPolicy{Policy: policy, Watermark: next, Unchanged: unchanged}, nil
}

type PolicyRecord struct {
	Envelope  string    `json:"envelope"`
	Watermark Watermark `json:"watermark"`
}

// PolicyService serializes persistence before activation. Call its mutating
// methods inside the controller's Await: waiting on opMu must not hold that loop.
type PolicyService struct {
	opMu       sync.Mutex
	mu         sync.RWMutex
	build      BuildConfig
	persist    func(PolicyRecord) error
	now        func() int64
	record     *PolicyRecord
	policy     *Policy
	generation uint64
}

func NewPolicyService(build BuildConfig, persist func(PolicyRecord) error, now func() int64) *PolicyService {
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	return &PolicyService{build: build, persist: persist, now: now}
}

func (s *PolicyService) Restore(record PolicyRecord) error {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	signed, err := VerifyEnvelope(record.Envelope, s.build.PolicyKeys, "v2board-client-policy-v1")
	if err != nil {
		return err
	}
	var historical Policy
	if err := DecodeStrict(signed.Payload, &historical, signedJSONMaxBytes); err != nil {
		return NewAppError("POLICY_INVALID")
	}
	from, err := signedTime(historical.NotBefore)
	if err != nil {
		return NewAppError("POLICY_INVALID")
	}
	checked, err := VerifyPolicy(record.Envelope, s.build, nil, from)
	if err != nil || checked.Watermark != record.Watermark {
		return NewAppError("POLICY_INVALID")
	}
	s.mu.Lock()
	s.record, s.policy = &record, &checked.Policy
	s.mu.Unlock()
	return nil
}

func (s *PolicyService) Active() *Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.policy == nil {
		return nil
	}
	from, _ := signedTime(s.policy.NotBefore)
	until, _ := signedTime(s.policy.ExpiresAt)
	now := s.now()
	if from > now || until <= now {
		return nil
	}
	// Clone without JSON round-tripping, which would replace lone surrogate code
	// units preserved by the strict decoder in signed announcement text.
	return cloneSignedPolicy(s.policy)
}

func cloneSignedPolicy(source *Policy) *Policy {
	result := *source
	result.RequiredCapabilities = append([]string{}, source.RequiredCapabilities...)
	result.Endpoints.OrderedIDs = append([]string{}, source.Endpoints.OrderedIDs...)
	result.Endpoints.TemporarilyDisabledIDs = append([]string{}, source.Endpoints.TemporarilyDisabledIDs...)
	result.UI.ExpiryReminderDays = append([]int{}, source.UI.ExpiryReminderDays...)
	if source.UI.Announcement != nil {
		announcement := *source.UI.Announcement
		result.UI.Announcement = &announcement
	}
	result.NodeOperations = append([]NodeOperation{}, source.NodeOperations...)
	for i := range result.NodeOperations {
		if source.NodeOperations[i].Order != nil {
			order := *source.NodeOperations[i].Order
			result.NodeOperations[i].Order = &order
		}
		if source.NodeOperations[i].Group != nil {
			group := *source.NodeOperations[i].Group
			result.NodeOperations[i].Group = &group
		}
	}
	if source.Routing.Resource != nil {
		resource := *source.Routing.Resource
		result.Routing.Resource = &resource
	}
	if source.Maintenance != nil {
		maintenance := *source.Maintenance
		maintenance.Platforms = append([]string{}, source.Maintenance.Platforms...)
		result.Maintenance = &maintenance
	}
	if source.Update.NoticeText != nil {
		notice := *source.Update.NoticeText
		result.Update.NoticeText = &notice
	}
	return &result
}

func (s *PolicyService) Watermark() *Watermark {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.record == nil {
		return nil
	}
	watermark := s.record.Watermark
	return &watermark
}

func (s *PolicyService) Envelope() *string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.record == nil {
		return nil
	}
	envelope := s.record.Envelope
	return &envelope
}

func (s *PolicyService) Generation() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.generation
}

func (s *PolicyService) Accept(envelope string) (bool, error) {
	s.opMu.Lock()
	defer s.opMu.Unlock()
	checked, err := VerifyPolicy(envelope, s.build, s.Watermark(), s.now())
	if err != nil || checked.Unchanged {
		return false, err
	}
	record := PolicyRecord{Envelope: envelope, Watermark: checked.Watermark}
	if s.persist == nil {
		return false, NewAppError("STORAGE_FAILED")
	}
	if err := s.persist(record); err != nil {
		return false, err
	}
	s.mu.Lock()
	s.record, s.policy = &record, &checked.Policy
	s.generation++
	s.mu.Unlock()
	return true, nil
}
