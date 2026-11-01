package core

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

type telemetryTransport struct {
	mu       sync.Mutex
	requests []HTTPRequest
	fail     map[string]bool
	reply    string
}

func (t *telemetryTransport) Request(_ context.Context, input HTTPRequest) (HTTPResponse, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.requests = append(t.requests, input)
	for prefix := range t.fail {
		if strings.HasPrefix(input.URL, prefix) {
			return HTTPResponse{}, errors.New("unreachable")
		}
	}
	return HTTPResponse{Status: 200, Body: t.reply}, nil
}

func newTestTelemetry(t *testing.T, transport Transport) (*Telemetry, telemetryFile) {
	t.Helper()
	store := telemetryFile{filepath.Join(t.TempDir(), "telemetry.json")}
	build := BuildConfig{UpdateFeedURLs: []string{"https://dl.example.com/v1/release", "https://dl.example.net/v1/release"}}
	info := func() TelemetryInfo {
		return TelemetryInfo{Email: "user@example.com", Version: "0.2.0", Platform: "win32", Arch: "x64", OS: "10.0.22631"}
	}
	return NewTelemetry(build, store.path, transport, info), store
}

func TestTelemetryQueuesPersistsAndFlushes(t *testing.T) {
	transport := &telemetryTransport{fail: map[string]bool{"https://dl.example.com": true}, reply: `{"accepted":2}`}
	telemetry, store := newTestTelemetry(t, transport)
	telemetry.Record("connect", map[string]any{"ok": false, "code": "CONNECT_TIMEOUT", "ms": int64(5230), "nodes": 12}, true)
	telemetry.Record("api", map[string]any{"host": "api.example.com", "ok": true}, false)
	telemetry.Record("bad", map[string]any{"nested": map[string]any{"x": 1}}, false)
	telemetry.Persist()
	saved, err := store.Load()
	if err != nil || saved == nil || len(saved.Events) != 2 || saved.Install == "" {
		t.Fatalf("queue not persisted: %+v %v", saved, err)
	}
	if reloaded := NewTelemetry(BuildConfig{}, store.path, transport, func() TelemetryInfo { return TelemetryInfo{} }); reloaded.Install() != saved.Install || len(reloaded.Recent(10)) != 2 {
		t.Fatal("queue not restored")
	}
	if err := telemetry.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(transport.requests) != 2 || !strings.HasPrefix(transport.requests[1].URL, "https://dl.example.net/v1/telemetry") || transport.requests[1].Method != "POST" {
		t.Fatalf("did not fall back to the second endpoint: %+v", transport.requests)
	}
	var body struct {
		Install string           `json:"install"`
		Email   string           `json:"email"`
		Events  []map[string]any `json:"events"`
	}
	if err := json.Unmarshal([]byte(transport.requests[1].Body), &body); err != nil || body.Email != "user@example.com" || body.Install != saved.Install || len(body.Events) != 2 || body.Events[0]["ms"] != float64(5230) || body.Events[0]["type"] != "connect" {
		t.Fatalf("body = %s", transport.requests[1].Body)
	}
	if saved, _ := store.Load(); len(saved.Events) != 0 || len(telemetry.Recent(10)) != 0 {
		t.Fatal("sent events stayed queued")
	}
}

func TestTelemetryKeepsEventsWhenOffline(t *testing.T) {
	transport := &telemetryTransport{fail: map[string]bool{"https://": true}}
	telemetry, _ := newTestTelemetry(t, transport)
	for i := range telemetryQueueLimit + 5 {
		telemetry.Record("api", map[string]any{"n": i}, false)
	}
	if err := telemetry.Flush(context.Background()); err == nil {
		t.Fatal("flush succeeded offline")
	}
	recent := telemetry.Recent(telemetryQueueLimit + 10)
	if len(recent) != telemetryQueueLimit || recent[0]["n"] != float64(5) {
		t.Fatalf("queue bound: %d %v", len(recent), recent[0])
	}
}

func TestTelemetryReportReturnsCode(t *testing.T) {
	transport := &telemetryTransport{reply: `{"code":"K7M3QX"}`}
	telemetry, _ := newTestTelemetry(t, transport)
	code, err := telemetry.Report(context.Background(), "连不上", []map[string]any{{"type": "connect"}}, []map[string]any{{"name": "api.example.com", "ok": false}})
	if err != nil || code != "K7M3QX" || !strings.HasSuffix(transport.requests[0].URL, "/v1/report") || !strings.Contains(transport.requests[0].Body, "连不上") {
		t.Fatal(code, err, transport.requests)
	}
	transport.reply = `{"code":"<script>"}`
	if _, err := telemetry.Report(context.Background(), "", nil, nil); err == nil {
		t.Fatal("accepted a malformed code")
	}
}

func TestTelemetryWithoutEndpointIsDisabled(t *testing.T) {
	telemetry := NewTelemetry(BuildConfig{}, filepath.Join(t.TempDir(), "telemetry.json"), &telemetryTransport{}, func() TelemetryInfo { return TelemetryInfo{} })
	var missing *Telemetry
	missing.Record("connect", map[string]any{"ok": true}, true)
	if telemetry.Enabled() || missing.Enabled() || telemetry.Flush(context.Background()) != nil {
		t.Fatal("telemetry without an endpoint")
	}
}

func TestObservedTransportReportsHostsOnly(t *testing.T) {
	transport := &telemetryTransport{fail: map[string]bool{"https://blocked.example.com": true}}
	telemetry, _ := newTestTelemetry(t, &telemetryTransport{})
	observed := NewObservedTransport(transport, telemetry)
	for range 3 {
		_, _ = observed.Request(context.Background(), HTTPRequest{URL: "https://api.example.com/api/v1/user/info?token=secret"})
	}
	_, _ = observed.Request(context.Background(), HTTPRequest{URL: "https://blocked.example.com/api/v1/client/subscribe?token=secret"})
	events := telemetry.Recent(10)
	if len(events) != 2 || events[0]["host"] != "api.example.com" || events[0]["ok"] != true || events[1]["host"] != "blocked.example.com" || events[1]["ok"] != false {
		t.Fatalf("events = %v", events)
	}
	for _, e := range events {
		for _, v := range e {
			if s, ok := v.(string); ok && strings.Contains(s, "secret") {
				t.Fatalf("leaked a URL token: %v", e)
			}
		}
	}
}

func TestReportCommandParsing(t *testing.T) {
	if cmd, err := ParseCommand([]byte(`{"type":"report","note":"打不开"}`)); err != nil || cmd.Note != "打不开" {
		t.Fatal(cmd, err)
	}
	for _, raw := range []string{`{"type":"report"}`, `{"type":"report","note":"` + strings.Repeat("x", 501) + `"}`, `{"type":"report","note":"x","extra":1}`} {
		if _, err := ParseCommand([]byte(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
}
