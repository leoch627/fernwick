package core

import (
	"crypto/sha256"
	"encoding/hex"
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
}

func (e ReminderEvent) Validate() error {
	return invalidUnless(sha256Pattern.MatchString(e.Key) && inRange(e.ThresholdDays, 0, 30) && e.ExpiresAt >= -MaxSafeInteger && e.ExpiresAt <= MaxSafeInteger)
}
func (s ReminderState) Validate() error {
	if s.SchemaVersion != 1 || len(s.Events) > 256 {
		return NewAppError("INVALID_INPUT")
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
	state  ReminderState
}

func NewExpiryReminders(tenant string, save func(ReminderState) error, notify func(int64) error) *ExpiryReminders {
	return &ExpiryReminders{tenant: tenant, save: save, notify: notify, state: ReminderState{SchemaVersion: 1, Events: []ReminderEvent{}}}
}
func (r *ExpiryReminders) Restore(value ReminderState) error {
	if err := value.Validate(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	value.Events = append([]ReminderEvent{}, value.Events...)
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
	next := ReminderState{1, events}
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
