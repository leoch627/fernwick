package core

import (
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"strconv"
	"sync"
)

type ReminderEvent struct {
	Key           string `json:"key"`
	ThresholdDays int    `json:"thresholdDays"`
	ExpiresAt     int64  `json:"expiresAt"`
}
type ReminderState struct {
	SchemaVersion int             `json:"schemaVersion"`
	Events        []ReminderEvent `json:"events"`
	// Quota holds the traffic level last announced per account (90 or 100 percent);
	// an entry goes once usage falls below 90%, after a reset or a bigger plan.
	Quota []QuotaReminder `json:"quota" default:"[]"`
}
type QuotaReminder struct {
	Key     string `json:"key"`
	Percent int    `json:"percent"`
}

func (e ReminderEvent) Validate() error {
	return invalidUnless(sha256Pattern.MatchString(e.Key) && inRange(e.ThresholdDays, 0, 30) && e.ExpiresAt >= -MaxSafeInteger && e.ExpiresAt <= MaxSafeInteger)
}
func (s ReminderState) Validate() error {
	if s.SchemaVersion != 1 || len(s.Events) > 256 || len(s.Quota) > 64 {
		return NewAppError("INVALID_INPUT")
	}
	for _, q := range s.Quota {
		if !sha256Pattern.MatchString(q.Key) || q.Percent != 90 && q.Percent != 100 {
			return NewAppError("INVALID_INPUT")
		}
	}
	for _, e := range s.Events {
		if err := e.Validate(); err != nil {
			return err
		}
	}
	return nil
}

type ExpiryReminders struct {
	mu     sync.Mutex
	tenant string
	save   func(ReminderState) error
	notify func(int64) error
	// NotifyQuota announces that the period's traffic is 90% (or 100%) used.
	NotifyQuota func(percent int) error
	state       ReminderState
}

func NewExpiryReminders(tenant string, save func(ReminderState) error, notify func(int64) error) *ExpiryReminders {
	return &ExpiryReminders{tenant: tenant, save: save, notify: notify, state: ReminderState{SchemaVersion: 1, Events: []ReminderEvent{}, Quota: []QuotaReminder{}}}
}
func (r *ExpiryReminders) Restore(value ReminderState) error {
	if err := value.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	value.Events = append([]ReminderEvent{}, value.Events...)
	value.Quota = append([]QuotaReminder{}, value.Quota...)
	r.state = value
	return nil
}
func (r *ExpiryReminders) Check(account Account, thresholds []int, now int64, current func() bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if current == nil {
		current = func() bool { return true }
	}
	if !current() || account.SessionStatus != "valid" || account.HasPlan != "yes" || account.ExpiryKind != "finite" || account.ExpiresAt == nil || account.Banned == "yes" {
		return nil
	}
	expiry := expiryMillis(account.ExpiresAt)
	remaining := expiry - now
	threshold := 31
	if remaining <= 0 {
		threshold = 0
	} else {
		for _, days := range thresholds {
			if days >= 1 && days <= 30 && remaining <= int64(days)*86400000 {
				threshold = min(threshold, days)
			}
		}
	}
	if threshold == 31 {
		return nil
	}
	raw := "[" + JSString(r.tenant) + "," + JSString(account.AccountID) + "," + strconv.FormatInt(expiry, 10) + "]"
	hash := sha256.Sum256([]byte(raw))
	key := hex.EncodeToString(hash[:])
	events := []ReminderEvent{}
	for _, event := range r.state.Events {
		if event.Key == key {
			if event.ThresholdDays <= threshold {
				return nil
			}
		} else if event.ExpiresAt > now-30*86400000 {
			events = append(events, event)
		}
	}
	events = append(events, ReminderEvent{key, threshold, expiry})
	if len(events) > 256 {
		events = events[len(events)-256:]
	}
	next := ReminderState{1, events, r.state.Quota}
	if r.save == nil {
		return NewAppError("STORAGE_FAILED")
	}
	if err := r.save(next); err != nil {
		return err
	}
	r.state = next
	if current() && r.notify != nil {
		return r.notify(remaining)
	}
	return nil
}

// CheckQuota announces once when the period's traffic passes 90% and once when it runs
// out; warn false (the operator hides traffic figures) leaves only the second.
func (r *ExpiryReminders) CheckQuota(account Account, warn bool, current func() bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if current == nil {
		current = func() bool { return true }
	}
	if !current() || account.SessionStatus != "valid" || account.HasPlan != "yes" || account.Banned == "yes" || account.QuotaKind != "finite" || account.UsedBytes == nil || account.QuotaBytes == nil {
		return nil
	}
	used, okUsed := new(big.Int).SetString(*account.UsedBytes, 10)
	quota, okQuota := new(big.Int).SetString(*account.QuotaBytes, 10)
	if !okUsed || !okQuota || quota.Sign() <= 0 {
		return nil
	}
	percent := new(big.Int).Div(new(big.Int).Mul(used, big.NewInt(100)), quota)
	level := 0
	if percent.Cmp(big.NewInt(100)) >= 0 {
		level = 100
	} else if percent.Cmp(big.NewInt(90)) >= 0 && warn {
		level = 90
	}
	hash := sha256.Sum256([]byte("[" + JSString(r.tenant) + "," + JSString(account.AccountID) + ",\"quota\"]"))
	key := hex.EncodeToString(hash[:])
	announced := 0
	quotas := []QuotaReminder{}
	for _, q := range r.state.Quota {
		if q.Key == key {
			announced = q.Percent
		} else {
			quotas = append(quotas, q)
		}
	}
	if level > 0 && announced >= level || level == 0 && announced == 0 {
		return nil
	}
	if level > 0 {
		quotas = append(quotas, QuotaReminder{key, level})
	}
	if len(quotas) > 64 {
		quotas = quotas[len(quotas)-64:]
	}
	next := ReminderState{1, r.state.Events, quotas}
	if r.save == nil {
		return NewAppError("STORAGE_FAILED")
	}
	if err := r.save(next); err != nil {
		return err
	}
	r.state = next
	if level > 0 && current() && r.NotifyQuota != nil {
		return r.NotifyQuota(level)
	}
	return nil
}
