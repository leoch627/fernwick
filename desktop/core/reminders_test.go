package core

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRemindersReserveOnceAcrossConcurrentTicksAndRestart(t *testing.T) {
	_, _, account, _, _ := authFixture(t)
	var saved ReminderState
	var notices atomic.Int32
	save := func(v ReminderState) error { saved = v; return nil }
	notify := func(int64) error { notices.Add(1); return nil }
	reminders := NewExpiryReminders("tenant", save, notify)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if err := reminders.Check(account, []int{7, 3}, authTestNow, nil); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if notices.Load() != 1 {
		t.Fatal("duplicate reminders")
	}
	restarted := NewExpiryReminders("tenant", save, notify)
	if err := restarted.Restore(saved); err != nil {
		t.Fatal(err)
	}
	expiry := strings.Replace(*account.ExpiresAt, "Z", "+00:00", 1)
	account.ExpiresAt = &expiry
	if err := restarted.Check(account, []int{7, 3}, authTestNow, nil); err != nil {
		t.Fatal(err)
	}
	if notices.Load() != 1 {
		t.Fatal("timezone produced duplicate")
	}
	if err := restarted.Check(account, []int{7, 3}, authTestNow+3*86400000, nil); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Check(account, []int{7, 3}, expiryMillis(account.ExpiresAt), nil); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Check(account, []int{7, 3}, expiryMillis(account.ExpiresAt)+1000, nil); err != nil {
		t.Fatal(err)
	}
	if notices.Load() != 3 {
		t.Fatal(notices.Load())
	}
	raw, _ := EncodeJSON(saved)
	if strings.Contains(string(raw), account.AccountID) {
		t.Fatal("ledger contains account identity")
	}
}
func TestReminderFailureAndInvalidAccountsDoNotNotify(t *testing.T) {
	_, _, account, _, _ := authFixture(t)
	notices := 0
	reminders := NewExpiryReminders("tenant", func(ReminderState) error { return errors.New("disk full") }, func(int64) error { notices++; return nil })
	if err := reminders.Check(account, []int{7, 3}, authTestNow, nil); err == nil {
		t.Fatal("save failure ignored")
	}
	if err := reminders.Check(account, []int{7, 3}, authTestNow, func() bool { return false }); err != nil {
		t.Fatal(err)
	}
	if notices != 0 {
		t.Fatal("notification before reservation")
	}
	for _, change := range []func(*Account){func(a *Account) { a.Banned = "yes" }, func(a *Account) { a.SessionStatus = "invalid" }, func(a *Account) { a.ExpiryKind = "unlimited"; a.ExpiresAt = nil }} {
		a := account
		change(&a)
		if err := reminders.Check(a, []int{7, 3}, authTestNow, nil); err != nil {
			t.Fatal("invalid account reached persistence")
		}
	}
}
