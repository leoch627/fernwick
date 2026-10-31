package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

type testSecret struct {
	Token string `json:"token"`
}

func testKeyProvider() KeyProvider {
	return KeyProviderFunc(func(bool) ([]byte, error) { return bytes.Repeat([]byte{7}, 32), nil })
}
func TestSecureStorageEncryptedLockedAndMemoryModes(t *testing.T) {
	file := filepath.Join(t.TempDir(), "session.v2.enc")
	store := NewSecureStore[testSecret](file, testKeyProvider())
	if got, err := store.Load(); err != nil || got != nil || store.Mode() != "encrypted" {
		t.Fatalf("initial %#v %v %s", got, err, store.Mode())
	}
	value := testSecret{"SECRET_ACCOUNT_TOKEN"}
	if err := store.Save(value, nil); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(value.Token)) {
		t.Fatal("plaintext stored")
	}
	restarted := NewSecureStore[testSecret](file, testKeyProvider())
	got, err := restarted.Load()
	if err != nil || got.Token != value.Token {
		t.Fatalf("restore %v %v", got, err)
	}
	locked := NewSecureStore[testSecret](file, KeyProviderFunc(func(bool) ([]byte, error) { return nil, ErrKeyUnavailable }))
	if _, err := locked.Load(); CodeOf(err) != "STORAGE_LOCKED" || locked.Mode() != "locked" {
		t.Fatalf("missing key did not lock: %v", err)
	}
	if err := locked.Save(testSecret{"replacement"}, nil); CodeOf(err) != "STORAGE_LOCKED" {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(after, ciphertext) {
		t.Fatal("locked ciphertext changed")
	}
	corrupted := append([]byte{}, ciphertext...)
	corrupted[len(corrupted)-1] ^= 1
	if err := os.WriteFile(file, corrupted, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.Load(); CodeOf(err) != "STORAGE_LOCKED" {
		t.Fatal("tampered ciphertext accepted")
	}
	memoryPath := filepath.Join(t.TempDir(), "session.v2.enc")
	memory := NewSecureStore[testSecret](memoryPath, KeyProviderFunc(func(bool) ([]byte, error) { return nil, ErrKeyUnavailable }))
	if _, err := memory.Load(); err != nil {
		t.Fatal(err)
	}
	if err := memory.Save(value, nil); err != nil {
		t.Fatal(err)
	}
	if memory.Mode() != "memory" {
		t.Fatal(memory.Mode())
	}
	if _, err := os.Stat(memoryPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("memory mode wrote disk")
	}
}
func TestSecureStoreCancelledWriteAndClearCannotResurrectCredentials(t *testing.T) {
	file := filepath.Join(t.TempDir(), "session.v2.enc")
	store := NewSecureStore[testSecret](file, testKeyProvider())
	if _, err := store.Load(); err != nil {
		t.Fatal(err)
	}
	if err := store.Save(testSecret{"old"}, nil); err != nil {
		t.Fatal(err)
	}
	old, _ := os.ReadFile(file)
	if err := store.Save(testSecret{"new"}, func() bool { return false }); CodeOf(err) != "CANCELLED" {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(after, old) {
		t.Fatal("cancelled save overwrote")
	}
	if err := store.Clear(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("clear retained credentials")
	}
	if err := store.Save(testSecret{"stale"}, func() bool { return false }); CodeOf(err) != "CANCELLED" {
		t.Fatal(err)
	}
}
func TestJSONPersistencePreservesLoneSurrogatesAndRejectsUnknownFields(t *testing.T) {
	raw := []byte(`{"token":"\ud800<&\u2028"}`)
	var value testSecret
	if err := DecodeStrict(raw, &value, 1024); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "state.json")
	store := NewJSONStore[testSecret](file, 1024)
	if err := store.Save(value, nil); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil || got.Token != value.Token {
		t.Fatalf("surrogate changed %x %v", got.Token, err)
	}
	written, _ := os.ReadFile(file)
	if !bytes.Contains(written, []byte(`\ud800`)) {
		t.Fatal(string(written))
	}
	if err := os.WriteFile(file, []byte(`{"token":"ok","unexpected":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); CodeOf(err) != "STORAGE_FAILED" {
		t.Fatal("unknown persisted field accepted")
	}
}
func contractFixture(t *testing.T) PanelContract {
	t.Helper()
	raw, err := os.ReadFile("../../config/adapter-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract PanelContract
	if err := DecodeStrict(raw, &contract, 262144); err != nil {
		t.Fatal(err)
	}
	return contract
}
func rawAccountFixture(t *testing.T) map[string]any {
	t.Helper()
	raw := `{"email":"alice@example.invalid","banned":0,"plan_id":1,"expired_at":1793491200,"transfer_enable":"1073741824","u":"1024","d":"1024","plan":{"name":"Test"}}`
	v, err := StrictJSON([]byte(raw), 1024)
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]any)
}
func TestNormalizeAccountStrictIdentityAndBigIntegerSemantics(t *testing.T) {
	contract := contractFixture(t)
	_, session, _, _, _ := authFixture(t)
	raw := rawAccountFixture(t)
	raw["expired_at"] = nil
	account, err := NormalizeAccount(raw, contract, session, "primary", authTestNow)
	if err != nil || account.ExpiryKind != "unlimited" {
		t.Fatalf("null expiry %+v %v", account, err)
	}
	contract.NullExpiryIsUnlimited = false
	account, err = NormalizeAccount(raw, contract, session, "primary", authTestNow)
	if err != nil || account.ExpiryKind != "unknown" {
		t.Fatal(err)
	}
	raw["expired_at"] = json.Number("0")
	account, err = NormalizeAccount(raw, contract, session, "primary", authTestNow)
	if err != nil || account.ServiceAllowed != "no" {
		t.Fatal(err)
	}
	delete(raw, "expired_at")
	account, err = NormalizeAccount(raw, contract, session, "primary", authTestNow)
	if err != nil || account.ServiceAllowed != "unknown" {
		t.Fatal(err)
	}
	raw = rawAccountFixture(t)
	raw["u"] = "9007199254740993"
	raw["d"] = "2"
	raw["transfer_enable"] = "9999999999999999"
	account, err = NormalizeAccount(raw, contract, session, "primary", authTestNow)
	if err != nil || account.UsedBytes == nil || *account.UsedBytes != "9007199254740995" {
		t.Fatalf("big integer %+v %v", account, err)
	}
	raw["banned"] = "1"
	account, err = NormalizeAccount(raw, contract, session, "primary", authTestNow)
	if err != nil || account.Banned != "unknown" {
		t.Fatal("string ban coerced")
	}
	raw["banned"] = true
	account, err = NormalizeAccount(raw, contract, session, "primary", authTestNow)
	if err != nil || account.Banned != "yes" {
		t.Fatal(err)
	}
	raw["email"] = "bob@example.invalid"
	if _, err := NormalizeAccount(raw, contract, session, "primary", authTestNow); err == nil {
		t.Fatal("different account accepted")
	}
}

type transportFunc func(context.Context, HTTPRequest) (HTTPResponse, error)

func (f transportFunc) Request(ctx context.Context, r HTTPRequest) (HTTPResponse, error) {
	return f(ctx, r)
}
func TestPanelLoginNeverReplaysCredentialsAndDescriptorPreservesToken(t *testing.T) {
	f := newSignedFixture(t)
	f.build.TrustedSubscriptionOrigins = []string{"https://host.leiterup.de"}
	contract := contractFixture(t)
	calls := 0
	panel := NewV2BoardAdapter(f.build, contract, transportFunc(func(context.Context, HTTPRequest) (HTTPResponse, error) {
		calls++
		return HTTPResponse{}, errors.New("response lost")
	}))
	if _, err := panel.Login(context.Background(), "primary", "alice@example.invalid", "secret"); err == nil || calls != 1 {
		t.Fatalf("login replayed %d %v", calls, err)
	}
	panel = NewV2BoardAdapter(f.build, contract, transportFunc(func(_ context.Context, input HTTPRequest) (HTTPResponse, error) {
		if input.Headers["authorization"] != "token" {
			t.Fatal("missing auth")
		}
		return HTTPResponse{Status: 200, Body: `{"data":{"subscribe_url":"https://host.leiterup.de/api/v1/client/subscribe?token=SUB_SECRET"}}`}, nil
	}))
	descriptor, err := panel.FetchSubscriptionDescriptor(context.Background(), "primary", Session{Token: "token"})
	if err != nil || descriptor.URL != "https://host.leiterup.de/api/v1/client/subscribe?token=SUB_SECRET&flag=" {
		t.Fatalf("descriptor %+v %v", descriptor, err)
	}
}
func TestPanelDenialAndCrossReadMismatch(t *testing.T) {
	f := newSignedFixture(t)
	contract := contractFixture(t)
	_, session, _, _, _ := authFixture(t)
	var calls atomic.Int32
	raw := rawAccountFixture(t)
	raw["banned"] = true
	body, _ := EncodeJSON(map[string]any{"data": raw})
	panel := NewV2BoardAdapter(f.build, contract, transportFunc(func(context.Context, HTTPRequest) (HTTPResponse, error) {
		calls.Add(1)
		return HTTPResponse{Status: 200, Body: string(body)}, nil
	}))
	account, err := panel.FetchAccount(context.Background(), "primary", session)
	if err != nil || account.Banned != "yes" || calls.Load() != 1 {
		t.Fatalf("ban delayed %+v %v calls%d", account, err, calls.Load())
	}
	calls.Store(0)
	raw = rawAccountFixture(t)
	info, _ := EncodeJSON(map[string]any{"data": raw})
	raw["plan_id"] = "1"
	subscribe, _ := EncodeJSON(map[string]any{"data": raw})
	panel = NewV2BoardAdapter(f.build, contract, transportFunc(func(context.Context, HTTPRequest) (HTTPResponse, error) {
		selected := info
		if calls.Add(1) > 1 {
			selected = subscribe
		}
		return HTTPResponse{Status: 200, Body: string(selected)}, nil
	}))
	if _, err := panel.FetchAccount(context.Background(), "primary", session); err == nil {
		t.Fatal("strict plan equality lost")
	}
}
func TestDiagnosticsRejectsSecretLikeCodes(t *testing.T) {
	d := NewDiagnostics()
	if err := d.Record(DiagnosticInput{Stage: "sync", Code: "CONTROL_UNAVAILABLE"}); err != nil {
		t.Fatal(err)
	}
	if err := d.Record(DiagnosticInput{Stage: "sync", Code: "https://secret.invalid/token"}); err == nil {
		t.Fatal("secret code accepted")
	}
	raw, _ := EncodeJSON(d.Export("0.1.0", "linux", "x64"))
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "https://") {
		t.Fatal("sensitive diagnostics")
	}
}
