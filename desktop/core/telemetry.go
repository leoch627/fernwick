package core

import (
	"context"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Telemetry sends small troubleshooting events to the operator's endpoint: connection
// results and the step that failed, error codes, API host reachability, versions. It
// never records visited sites, DNS queries, traffic, tokens, subscription links or node
// credentials. Events wait in a local queue until an endpoint is reachable.

type TelemetryInfo struct {
	Email    string `json:"email"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
	OS       string `json:"os"`
}
type TelemetryQueue struct {
	Install string           `json:"install"`
	Events  []map[string]any `json:"events"`
}

const telemetryQueueLimit = 1000
const telemetryBatch = 200

var telemetryKey = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)

func (q TelemetryQueue) Validate() error {
	if !boundedText(q.Install, 0, 64) || len(q.Events) > telemetryQueueLimit {
		return NewAppError("INVALID_INPUT")
	}
	for _, e := range q.Events {
		if !validTelemetryEvent(e) {
			return NewAppError("INVALID_INPUT")
		}
	}
	return nil
}

func validTelemetryEvent(e map[string]any) bool {
	if len(e) == 0 || len(e) > 40 {
		return false
	}
	for k, v := range e {
		if !telemetryKey.MatchString(k) {
			return false
		}
		switch value := v.(type) {
		case string:
			if !utf8.ValidString(value) || len(value) > 512 {
				return false
			}
		case float64, bool, nil:
		default:
			return false
		}
	}
	return true
}

// normalizeEvent converts Go numbers to float64 so a queued event survives the JSON
// round trip unchanged, and truncates long strings.
func normalizeEvent(e map[string]any) map[string]any {
	out := make(map[string]any, len(e))
	for k, v := range e {
		switch value := v.(type) {
		case int:
			out[k] = float64(value)
		case int64:
			out[k] = float64(value)
		case string:
			for len(value) > 512 {
				_, size := utf8.DecodeLastRuneInString(value)
				value = value[:len(value)-size]
			}
			out[k] = value
		default:
			out[k] = v
		}
	}
	return out
}

// telemetryFile persists the queue with plain encoding/json: events are open-ended
// maps, which the strict store does not decode. Validate still bounds what is loaded.
type telemetryFile struct{ path string }

func (f telemetryFile) Load() (*TelemetryQueue, error) {
	raw, err := readBounded(f.path, 4<<20)
	if err != nil {
		return nil, err
	}
	var queue TelemetryQueue
	if err := json.Unmarshal(raw, &queue); err != nil || queue.Validate() != nil {
		return nil, NewAppError("STORAGE_FAILED")
	}
	return &queue, nil
}
func (f telemetryFile) Save(queue TelemetryQueue) error {
	raw, err := json.Marshal(queue)
	if err != nil {
		return err
	}
	return AtomicWrite(f.path, raw, nil)
}

type Telemetry struct {
	mu       sync.Mutex
	store    telemetryFile
	http     Transport
	urls     []string
	info     func() TelemetryInfo
	queue    TelemetryQueue
	flushing bool
	dirty    bool
	saved    time.Time
	wake     chan struct{}
}

// NewTelemetry sends to <origin>/v1/telemetry for each update endpoint origin, in order.
// Without an endpoint the queue still feeds problem reports.
func NewTelemetry(build BuildConfig, path string, http Transport, info func() TelemetryInfo) *Telemetry {
	t := &Telemetry{store: telemetryFile{path}, http: http, info: info, wake: make(chan struct{}, 1)}
	for _, raw := range build.UpdateFeedURLs {
		if u, err := url.Parse(raw); err == nil && u.Scheme == "https" {
			t.urls = append(t.urls, u.Scheme+"://"+u.Host)
		}
	}
	if saved, err := t.store.Load(); err == nil && saved != nil {
		t.queue = *saved
	}
	if t.queue.Install == "" {
		t.queue.Install = newUUID()
	}
	if t.queue.Events == nil {
		t.queue.Events = []map[string]any{}
	}
	return t
}

// Enabled reports whether an endpoint is configured to receive events and reports.
func (t *Telemetry) Enabled() bool { return t != nil && len(t.urls) > 0 }

func (t *Telemetry) Install() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.queue.Install
}

// Record queues one event. urgent asks for a prompt flush, e.g. after a failed connection.
func (t *Telemetry) Record(kind string, fields map[string]any, urgent bool) {
	if t == nil {
		return
	}
	event := normalizeEvent(fields)
	event["type"] = kind
	event["at"] = float64(time.Now().UnixMilli())
	if !validTelemetryEvent(event) {
		return
	}
	t.mu.Lock()
	t.queue.Events = append(t.queue.Events, event)
	if len(t.queue.Events) > telemetryQueueLimit {
		t.queue.Events = t.queue.Events[len(t.queue.Events)-telemetryQueueLimit:]
	}
	t.dirty = true
	due := urgent || time.Since(t.saved) > 15*time.Second
	t.mu.Unlock()
	if due {
		t.Persist()
	}
	if urgent {
		select {
		case t.wake <- struct{}{}:
		default:
		}
	}
}

// Persist writes the queue if it changed. Recording only writes every few seconds, so
// the shell calls this on exit.
func (t *Telemetry) Persist() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if !t.dirty {
		t.mu.Unlock()
		return
	}
	snapshot := TelemetryQueue{Install: t.queue.Install, Events: append([]map[string]any{}, t.queue.Events...)}
	t.dirty, t.saved = false, time.Now()
	t.mu.Unlock()
	if t.store.Save(snapshot) != nil {
		t.mu.Lock()
		t.dirty = true
		t.mu.Unlock()
	}
}

// Recent returns up to limit queued or recently sent events, oldest first, for reports.
func (t *Telemetry) Recent(limit int) []map[string]any {
	t.mu.Lock()
	defer t.mu.Unlock()
	events := t.queue.Events
	return append([]map[string]any{}, events[max(0, len(events)-limit):]...)
}

func (t *Telemetry) body(extra map[string]any) ([]byte, error) {
	info := t.info()
	value := map[string]any{"install": t.Install(), "email": info.Email, "version": info.Version, "platform": info.Platform, "arch": info.Arch, "os": info.OS}
	for k, v := range extra {
		value[k] = v
	}
	return json.Marshal(value)
}

// post tries each endpoint in order and returns the first successful response body.
func (t *Telemetry) post(ctx context.Context, path string, body []byte) (string, error) {
	err := NewAppError("CONFIGURATION_REQUIRED")
	for _, origin := range t.urls {
		var response HTTPResponse
		response, err = t.http.Request(ctx, HTTPRequest{URL: origin + path, Method: "POST", Headers: map[string]string{"content-type": "application/json"}, Body: string(body), MaxBytes: 4096})
		if err == nil && response.Status >= 200 && response.Status < 300 {
			return response.Body, nil
		}
		if err == nil {
			err = NewAppError("CONTROL_UNAVAILABLE")
		}
		if ctx.Err() != nil {
			return "", NewAppError("CANCELLED")
		}
	}
	return "", err
}

// Flush sends queued events in batches and drops what the endpoint accepted.
func (t *Telemetry) Flush(ctx context.Context) error {
	t.mu.Lock()
	if t.flushing || len(t.urls) == 0 {
		t.mu.Unlock()
		return nil
	}
	t.flushing = true
	t.mu.Unlock()
	defer func() { t.mu.Lock(); t.flushing = false; t.mu.Unlock() }()
	for {
		t.mu.Lock()
		batch := append([]map[string]any{}, t.queue.Events[:min(telemetryBatch, len(t.queue.Events))]...)
		t.mu.Unlock()
		if len(batch) == 0 {
			return nil
		}
		body, err := t.body(map[string]any{"events": batch})
		if err != nil {
			return err
		}
		if _, err = t.post(ctx, "/v1/telemetry", body); err != nil {
			return err
		}
		t.mu.Lock()
		// Events recorded while sending stay queued; only the sent prefix is removed.
		sent := 0
		for sent < len(batch) && sent < len(t.queue.Events) && t.queue.Events[sent]["at"] == batch[sent]["at"] && t.queue.Events[sent]["type"] == batch[sent]["type"] {
			sent++
		}
		t.queue.Events = append([]map[string]any{}, t.queue.Events[sent:]...)
		t.dirty = true
		t.mu.Unlock()
		t.Persist()
	}
}

// Run saves the queue every few seconds, flushes every few minutes, and flushes soon
// after an urgent event.
func (t *Telemetry) Run(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	ticks := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.Persist()
			if ticks++; ticks%12 != 0 {
				continue
			}
		case <-t.wake:
			// Let a reconnect settle so its result goes in the same batch.
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
		attempt, cancel := context.WithTimeout(ctx, 20*time.Second)
		_ = t.Flush(attempt)
		cancel()
	}
}

// Report uploads a problem report and returns the code the user gives to support.
func (t *Telemetry) Report(ctx context.Context, note string, events, checks []map[string]any) (string, error) {
	body, err := t.body(map[string]any{"note": note, "events": events, "checks": checks})
	if err != nil {
		return "", err
	}
	raw, err := t.post(ctx, "/v1/report", body)
	if err != nil {
		return "", err
	}
	var reply struct {
		Code string `json:"code"`
	}
	if json.Unmarshal([]byte(raw), &reply) != nil || len(reply.Code) != 6 || strings.ToUpper(reply.Code) != reply.Code {
		return "", NewAppError("CONTROL_UNAVAILABLE")
	}
	return reply.Code, nil
}

// ObservedTransport records each API host's failures and its first success after a
// failure, so telemetry shows which panel domain a user can reach. Only the host is
// recorded: paths and queries can carry tokens.
type ObservedTransport struct {
	inner     Transport
	telemetry *Telemetry
	mu        sync.Mutex
	healthy   map[string]bool
}

func NewObservedTransport(inner Transport, telemetry *Telemetry) *ObservedTransport {
	return &ObservedTransport{inner: inner, telemetry: telemetry, healthy: map[string]bool{}}
}

func (o *ObservedTransport) Request(ctx context.Context, input HTTPRequest) (HTTPResponse, error) {
	started := time.Now()
	response, err := o.inner.Request(ctx, input)
	u, parseErr := url.Parse(input.URL)
	if parseErr != nil || CodeOf(err) == "CANCELLED" || ctx.Err() != nil {
		return response, err
	}
	ok := err == nil && response.Status < 500
	o.mu.Lock()
	previous, seen := o.healthy[u.Host]
	o.healthy[u.Host] = ok
	o.mu.Unlock()
	if !ok || !seen || !previous {
		fields := map[string]any{"host": u.Host, "ok": ok, "ms": time.Since(started).Milliseconds()}
		if err != nil {
			fields["code"] = string(CodeOf(err))
		} else {
			fields["status"] = response.Status
		}
		o.telemetry.Record("api", fields, false)
	}
	return response, err
}
