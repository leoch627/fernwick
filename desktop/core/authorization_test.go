package core

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

const authTestNow int64 = 1793404800000 // 2026-10-31T00:00:00Z, as in tests/fixtures.ts.

func authPointer[T any](value T) *T { return &value }

func authFixture(t *testing.T) (BuildConfig, Session, Account, ParsedNodes, Snapshot) {
	t.Helper()
	build := BuildConfig{ProductID: "starrail-network-test", Environment: "test", AdapterID: "v2board-explicit-v1"}
	session := Session{AccountID: "alice@example.invalid", Email: "alice@example.invalid", Token: "SECRET_ACCOUNT_TOKEN", Generation: "session-1"}
	account := Account{
		AccountID: session.AccountID, Email: session.Email, PlanName: "Fixture", SessionStatus: "valid",
		ServiceAllowed: "yes", Banned: "no", HasPlan: "yes", TrafficExhausted: "no", ExpiryKind: "finite",
		ExpiresAt: authPointer(time.UnixMilli(authTestNow + 5*86400000).UTC().Format(time.RFC3339Nano)),
		QuotaKind: "finite", UsedBytes: authPointer("1024"), QuotaBytes: authPointer("1073741824"),
		ObservedAt: "2026-10-31T00:00:00.000Z", SourceEndpointID: "primary", AuthorizationEvidence: "test-contract-only",
	}
	parsed, err := ParseSubscription("vless://00000000-0000-4000-8000-000000000001@node.example.invalid:443?security=tls&type=tcp&sni=node.example.invalid#Tokyo", ParserOptions{
		Capabilities: []string{"vless-tls"}, ConfirmedTCPUDP: true, Source: "test-fixture",
	})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := CreateSnapshot(build, session, account, parsed, authTestNow, 86400, 1)
	if err != nil {
		t.Fatal(err)
	}
	return build, session, account, parsed, snapshot
}

func TestAuthorizationGate(t *testing.T) {
	tests := []struct {
		name   string
		change func(*SnapshotGateInput)
		want   ErrorCode
	}{
		{"valid cached authorization", func(*SnapshotGateInput) {}, ""},
		{"startup required", func(i *SnapshotGateInput) { i.StartupAttempted = false }, "CONTROL_UNAVAILABLE"},
		{"missing session", func(i *SnapshotGateInput) { i.Session = nil }, "AUTH_INVALID"},
		{"missing snapshot", func(i *SnapshotGateInput) { i.Snapshot = nil }, "CONTROL_UNAVAILABLE"},
		{"clock rollback", func(i *SnapshotGateInput) { i.TrustedTime = false }, "CLOCK_UNTRUSTED"},
		{"account isolation", func(i *SnapshotGateInput) { i.Snapshot.AccountID = "other" }, "CONTROL_UNAVAILABLE"},
		{"product isolation", func(i *SnapshotGateInput) { i.Snapshot.ProductID = "other" }, "CONTROL_UNAVAILABLE"},
		{"environment isolation", func(i *SnapshotGateInput) { i.Snapshot.Environment = "production" }, "CONTROL_UNAVAILABLE"},
		{"adapter isolation", func(i *SnapshotGateInput) { i.Snapshot.AdapterID = "other" }, "CONTROL_UNAVAILABLE"},
		{"session isolation", func(i *SnapshotGateInput) { i.Snapshot.SessionGeneration = "new-login" }, "CONTROL_UNAVAILABLE"},
		{"exact snapshot expiry", func(i *SnapshotGateInput) { i.Now = i.Snapshot.UsableUntil }, "SNAPSHOT_EXPIRED"},
		{"latched ban", func(i *SnapshotGateInput) { i.Restrictions["ACCOUNT_BANNED"] = true }, "ACCOUNT_BANNED"},
		{"latched auth failure", func(i *SnapshotGateInput) { i.Restrictions["AUTH_INVALID"] = true }, "AUTH_INVALID"},
		{"service evidence required", func(i *SnapshotGateInput) { i.Snapshot.Account.ServiceAllowed = "unknown" }, "NO_SERVICE"},
		{"empty subscription", func(i *SnapshotGateInput) { i.Snapshot.Nodes = []ProxyNode{} }, "NO_AUTHORIZED_NODES"},
		{"incompatible subscription", func(i *SnapshotGateInput) { i.Snapshot.Nodes[0].Compatible = false }, "NO_COMPATIBLE_NODES"},
		{"unverified udp", func(i *SnapshotGateInput) { i.Snapshot.Nodes[0].UDP = false }, "NO_COMPATIBLE_NODES"},
		{"ban precedes expiry", func(i *SnapshotGateInput) {
			i.Restrictions["ACCOUNT_BANNED"] = true
			i.Restrictions["ACCOUNT_EXPIRED"] = true
		}, "ACCOUNT_BANNED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			build, session, _, _, snapshot := authFixture(t)
			input := SnapshotGateInput{build, &session, &snapshot, true, true, authTestNow, map[ErrorCode]bool{}}
			test.change(&input)
			if got := SnapshotGate(input); got != test.want {
				t.Fatalf("gate = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSnapshotLifetimeCannotBeExtended(t *testing.T) {
	build, session, account, parsed, snapshot := authFixture(t)
	narrow := TightenSnapshot(snapshot, 3600, nil)
	if got := TightenSnapshot(narrow, 86400, nil); got.UsableUntil != authTestNow+3600000 || got.FullSyncCompletedAt != authTestNow {
		t.Fatalf("policy relaxation extended authorization: %+v", got)
	}
	renewed := account
	renewed.ExpiresAt = authPointer(time.UnixMilli(authTestNow + 90*86400000).UTC().Format(time.RFC3339Nano))
	if got := TightenSnapshot(snapshot, 86400, &renewed); got.UsableUntil != snapshot.UsableUntil {
		t.Fatal("account polling renewed the full-sync clock")
	}
	account.ExpiresAt = authPointer(time.UnixMilli(authTestNow + 30000).UTC().Format(time.RFC3339Nano))
	if got := TightenSnapshot(snapshot, 86400, &account); got.UsableUntil != authTestNow+30000 {
		t.Fatal("earlier account expiry did not tighten the snapshot")
	}
	if Restriction(account, authTestNow+30000) != "ACCOUNT_EXPIRED" {
		t.Fatal("exact account expiry did not deny")
	}
	account.ExpiresAt, account.ExpiryKind = nil, "unknown"
	unknown, err := CreateSnapshot(build, session, account, parsed, authTestNow, 86400, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got := SnapshotGate(SnapshotGateInput{build, &session, &unknown, true, true, authTestNow, nil}); got != "" {
		t.Fatalf("unknown expiry changed explicit service evidence: %q", got)
	}
	// Snapshot arrays retain the renderer/persistence wire shape even if the
	// parser reports an authoritative empty response using zero-value slices.
	empty, err := CreateSnapshot(build, session, account, ParsedNodes{AuthoritativeEmpty: true}, authTestNow, 86400, 3)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(empty)
	if err != nil || !strings.Contains(string(data), `"nodes":[]`) {
		t.Fatalf("empty nodes must marshal as an array: %s, %v", data, err)
	}
}

func TestRestrictionPriority(t *testing.T) {
	_, _, account, _, _ := authFixture(t)
	account.Banned, account.HasPlan, account.TrafficExhausted = "yes", "no", "yes"
	account.ExpiresAt = authPointer("2026-10-30T00:00:00Z")
	for _, test := range []struct {
		change func()
		want   ErrorCode
	}{
		{func() {}, "ACCOUNT_BANNED"},
		{func() { account.Banned = "no" }, "NO_SERVICE"},
		{func() { account.HasPlan = "yes" }, "ACCOUNT_EXPIRED"},
		{func() { account.ExpiresAt = authPointer("2026-11-10T00:00:00Z") }, "QUOTA_EXHAUSTED"},
		{func() { account.SessionStatus = "invalid" }, "AUTH_INVALID"},
	} {
		test.change()
		if got := Restriction(account, authTestNow); got != test.want {
			t.Fatalf("restriction = %q, want %q", got, test.want)
		}
	}
}

func TestDevelopmentBuildLoadsWithGoValidator(t *testing.T) {
	data, err := os.ReadFile("../../config/development.json")
	if err != nil {
		t.Fatal(err)
	}
	var build BuildConfig
	if err := DecodeStrict(data, &build, 262144); err != nil {
		t.Fatalf("existing build config failed Go schema: %v", err)
	}
	if _, err := ValidateBuild(build); err != nil {
		t.Fatalf("existing build config failed Go trust validator: %v", err)
	}
}
