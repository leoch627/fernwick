package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"strconv"
	"sync"
	"time"
)

type ActiveResource struct {
	Descriptor Resource `json:"descriptor"`
	Rules      Rules    `json:"rules"`
}

func ValidateResource(body []byte, descriptor Resource, build BuildConfig, now int64) (Rules, error) {
	if err := descriptor.Validate(); err != nil {
		return Rules{}, NewAppError("POLICY_INVALID")
	}
	if _, err := TrustedURL(descriptor.URL, build.TrustedResourceOrigins); err != nil {
		return Rules{}, err
	}
	expires, err := signedTime(descriptor.ExpiresAt)
	hash := sha256.Sum256(body)
	if err != nil || descriptor.Bytes != int64(len(body)) || len(body) > 33554432 || expires <= now || hex.EncodeToString(hash[:]) != descriptor.SHA256 {
		return Rules{}, NewAppError("POLICY_INVALID")
	}
	var rules Rules
	if err := DecodeStrict(body, &rules, 33554432); err != nil {
		return Rules{}, err
	}
	return rules, nil
}
func cloneRules(rules Rules) Rules {
	rules.DirectDomains = append([]string{}, rules.DirectDomains...)
	if rules.DirectFullDomains != nil {
		rules.DirectFullDomains = append([]string{}, rules.DirectFullDomains...)
	}
	rules.ProxyDomains = append([]string{}, rules.ProxyDomains...)
	rules.BlockedDomains = append([]string{}, rules.BlockedDomains...)
	rules.DirectIPs = append([]string{}, rules.DirectIPs...)
	return rules
}

type RoutingResources struct {
	opMu       sync.Mutex
	mu         sync.RWMutex
	build      BuildConfig
	persist    func(ActiveResource) error
	active     *ActiveResource
	identities map[string]string
}

func NewRoutingResources(build BuildConfig, persist func(ActiveResource) error) *RoutingResources {
	return &RoutingResources{build: build, persist: persist, identities: map[string]string{}}
}
func (r *RoutingResources) Activate(body []byte, descriptor Resource, now int64) error {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	rules, err := ValidateResource(body, descriptor, r.build, now)
	if err != nil {
		return err
	}
	r.mu.RLock()
	prior := r.identities[descriptor.ID]
	active := r.active
	r.mu.RUnlock()
	if prior != "" && prior != descriptor.SHA256 || active != nil && descriptor.Version < active.Descriptor.Version {
		return NewAppError("POLICY_INVALID")
	}
	next := ActiveResource{descriptor, rules}
	if r.persist == nil {
		return NewAppError("STORAGE_FAILED")
	}
	if err = r.persist(next); err != nil {
		return err
	}
	r.mu.Lock()
	r.active = &next
	r.identities[descriptor.ID] = descriptor.SHA256
	r.mu.Unlock()
	return nil
}
func (r *RoutingResources) Current(now int64, baseline Rules) Rules {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active != nil {
		expiry, _ := signedTime(r.active.Descriptor.ExpiresAt)
		if expiry > now {
			return cloneRules(r.active.Rules)
		}
	}
	return cloneRules(baseline)
}
func (r *RoutingResources) Active() *ActiveResource {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.active == nil {
		return nil
	}
	result := *r.active
	result.Rules = cloneRules(result.Rules)
	return &result
}

type ResourceIdentity struct {
	ID      string `json:"id"`
	SHA256  string `json:"sha256"`
	Version int64  `json:"version"`
}

func (i ResourceIdentity) Validate() error {
	return invalidUnless(boundedText(i.ID, 0, 160) && sha256Pattern.MatchString(i.SHA256) && i.Version > 0 && i.Version <= MaxSafeInteger)
}

type ResourceCache struct {
	PolicyEnvelope string             `json:"policyEnvelope"`
	Body           *string            `json:"body,nullable"`
	Identities     []ResourceIdentity `json:"identities" default:"[]"`
}

func (c ResourceCache) Validate() error {
	if !boundedText(c.PolicyEnvelope, 0, 262144) || !nullableCheck(c.Body, func(s string) bool { return boundedText(s, 0, 33554432) }) || len(c.Identities) > 4096 {
		return NewAppError("INVALID_INPUT")
	}
	for _, i := range c.Identities {
		if err := i.Validate(); err != nil {
			return err
		}
	}
	return nil
}

type ResourceStore interface {
	Load() (*ResourceCache, error)
	Save(ResourceCache, func() bool) error
}
type ResourceCoordinator struct {
	opMu            sync.Mutex
	mu              sync.RWMutex
	build           BuildConfig
	baseline        Rules
	baselineHash    string
	store           ResourceStore
	http            Transport
	now             func() int64
	active          *ActiveResource
	sequence        uint64
	cancel          context.CancelFunc
	pending, failed bool
	changed         func()
	identities      []ResourceIdentity
}

func NewResourceCoordinator(build BuildConfig, baseline Rules, store ResourceStore, http Transport, now func() int64) (*ResourceCoordinator, error) {
	if err := baseline.Validate(); err != nil {
		return nil, err
	}
	raw, err := EncodeJSON(baseline)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(raw)
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	return &ResourceCoordinator{build: build, baseline: cloneRules(baseline), baselineHash: hex.EncodeToString(hash[:]), store: store, http: http, now: now, changed: func() {}, identities: []ResourceIdentity{}}, nil
}
func (r *ResourceCoordinator) OnChange(listener func()) {
	if listener == nil {
		listener = func() {}
	}
	r.mu.Lock()
	r.changed = listener
	r.mu.Unlock()
}
func (r *ResourceCoordinator) validLocked(now int64) *ActiveResource {
	if r.active != nil {
		expiry, _ := signedTime(r.active.Descriptor.ExpiresAt)
		if expiry > now {
			return r.active
		}
	}
	return nil
}
func (r *ResourceCoordinator) Rules() Rules {
	now := r.now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	if active := r.validLocked(now); active != nil {
		return cloneRules(active.Rules)
	}
	return cloneRules(r.baseline)
}
func (r *ResourceCoordinator) Fingerprint() string {
	now := r.now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	if active := r.validLocked(now); active != nil {
		return active.Descriptor.SHA256
	}
	return r.baselineHash
}
func (r *ResourceCoordinator) Status() string {
	now := r.now()
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.pending {
		return "规则正在更新，继续使用当前规则"
	}
	if r.failed {
		return "新规则未验证，保留有效规则或内置规则"
	}
	if active := r.validLocked(now); active != nil {
		return "规则已验证 v" + strconv.FormatInt(active.Descriptor.Version, 10)
	}
	return "使用内置大陆分流规则"
}
func (r *ResourceCoordinator) Restore() error {
	r.opMu.Lock()
	defer r.opMu.Unlock()
	err := func() error {
		record, err := r.store.Load()
		if err != nil || record == nil {
			return err
		}
		signed, err := VerifyEnvelope(record.PolicyEnvelope, r.build.PolicyKeys, "v2board-client-policy-v1")
		if err != nil {
			return err
		}
		var historical Policy
		if err = DecodeStrict(signed.Payload, &historical, 262144); err != nil {
			return err
		}
		from, _ := signedTime(historical.NotBefore)
		checked, err := VerifyPolicy(record.PolicyEnvelope, r.build, nil, from)
		if err != nil {
			return err
		}
		identities := append([]ResourceIdentity{}, record.Identities...)
		seen := map[string]bool{}
		for _, identity := range identities {
			if seen[identity.ID] {
				return NewAppError("POLICY_INVALID")
			}
			seen[identity.ID] = true
		}
		var active *ActiveResource
		if descriptor := checked.Policy.Routing.Resource; descriptor != nil && record.Body != nil {
			rules, err := ValidateResource([]byte(*record.Body), *descriptor, r.build, from)
			if err != nil {
				return err
			}
			prior := false
			for _, identity := range identities {
				if identity.ID == descriptor.ID {
					if identity.SHA256 != descriptor.SHA256 {
						return NewAppError("POLICY_INVALID")
					}
					prior = true
				}
			}
			if !prior {
				if len(identities) >= 4096 {
					return NewAppError("POLICY_INVALID")
				}
				identities = append(identities, ResourceIdentity{descriptor.ID, descriptor.SHA256, descriptor.Version})
			}
			expiry, _ := signedTime(descriptor.ExpiresAt)
			if expiry > r.now() {
				active = &ActiveResource{*descriptor, rules}
			}
		}
		r.mu.Lock()
		r.active = active
		r.identities = identities
		r.mu.Unlock()
		return nil
	}()
	if err != nil {
		r.mu.Lock()
		r.failed = true
		r.mu.Unlock()
	}
	return err
}
func (r *ResourceCoordinator) Apply(ctx context.Context, envelope string) error {
	r.mu.Lock()
	if r.cancel != nil {
		r.cancel()
	}
	r.sequence++
	sequence := r.sequence
	r.pending = true
	changed := r.changed
	r.mu.Unlock()
	changed()
	r.opMu.Lock()
	r.mu.Lock()
	if sequence != r.sequence {
		r.mu.Unlock()
		r.opMu.Unlock()
		return NewAppError("CANCELLED")
	}
	operation, cancel := context.WithTimeout(ctx, 12*time.Second)
	r.cancel = cancel
	identities := append([]ResourceIdentity{}, r.identities...)
	active := r.active
	r.mu.Unlock()
	defer cancel()
	isCurrent := func() bool {
		r.mu.RLock()
		defer r.mu.RUnlock()
		return sequence == r.sequence && operation.Err() == nil
	}
	current := func() error {
		if !isCurrent() {
			return NewAppError("CANCELLED")
		}
		return nil
	}
	err := func() error {
		checked, err := VerifyPolicy(envelope, r.build, nil, r.now())
		if err != nil {
			return err
		}
		descriptor := checked.Policy.Routing.Resource
		if descriptor == nil {
			if err = r.store.Save(ResourceCache{envelope, nil, identities}, isCurrent); err != nil {
				return err
			}
			if err = current(); err != nil {
				return err
			}
			r.mu.Lock()
			if sequence != r.sequence || operation.Err() != nil {
				r.mu.Unlock()
				return NewAppError("CANCELLED")
			}
			r.active = nil
			r.failed = false
			r.mu.Unlock()
			return nil
		}
		if active != nil && reflect.DeepEqual(active.Descriptor, *descriptor) {
			r.mu.Lock()
			if sequence != r.sequence || operation.Err() != nil {
				r.mu.Unlock()
				return NewAppError("CANCELLED")
			}
			r.failed = false
			r.mu.Unlock()
			return nil
		}
		var prior, latest *ResourceIdentity
		for i := range identities {
			identity := &identities[i]
			if identity.ID == descriptor.ID {
				prior = identity
			}
			if latest == nil || identity.Version > latest.Version {
				latest = identity
			}
		}
		if prior != nil && prior.SHA256 != descriptor.SHA256 || latest != nil && (descriptor.Version < latest.Version || descriptor.Version == latest.Version && descriptor.SHA256 != latest.SHA256) || prior == nil && len(identities) >= 4096 {
			return NewAppError("POLICY_INVALID")
		}
		response, err := r.http.Request(operation, HTTPRequest{URL: descriptor.URL, MaxBytes: int(descriptor.Bytes)})
		if err != nil {
			return err
		}
		if err = RequireSuccess(response, "public"); err != nil {
			return err
		}
		if err = current(); err != nil {
			return err
		}
		rules, err := ValidateResource([]byte(response.Body), *descriptor, r.build, r.now())
		if err != nil {
			return err
		}
		next := []ResourceIdentity{}
		for _, identity := range identities {
			if identity.ID != descriptor.ID {
				next = append(next, identity)
			}
		}
		next = append(next, ResourceIdentity{descriptor.ID, descriptor.SHA256, descriptor.Version})
		if err = r.store.Save(ResourceCache{envelope, &response.Body, next}, isCurrent); err != nil {
			return err
		}
		if err = current(); err != nil {
			return err
		}
		r.mu.Lock()
		if sequence != r.sequence || operation.Err() != nil {
			r.mu.Unlock()
			return NewAppError("CANCELLED")
		}
		r.active = &ActiveResource{*descriptor, rules}
		r.identities = next
		r.failed = false
		r.mu.Unlock()
		return nil
	}()
	r.mu.Lock()
	same := sequence == r.sequence
	if same {
		r.failed = err != nil
		r.pending = false
		r.cancel = nil
	}
	changed = r.changed
	r.mu.Unlock()
	r.opMu.Unlock()
	if same {
		changed()
	}
	return err
}
func (r *ResourceCoordinator) Stop() {
	r.mu.Lock()
	r.sequence++
	if r.cancel != nil {
		r.cancel()
	}
	r.pending = false
	r.mu.Unlock()
	r.opMu.Lock()
	r.opMu.Unlock()
}
