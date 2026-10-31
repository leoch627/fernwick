package core

import (
	"regexp"
	"sync"
	"time"
)

type DiagnosticEvent struct {
	Stage      string   `json:"stage"`
	Code       string   `json:"code"`
	Generation *int64   `json:"generation,omitempty"`
	DurationMs *float64 `json:"durationMs,omitempty"`
	At         string   `json:"at"`
	ID         string   `json:"id"`
}
type DiagnosticInput struct {
	Stage      string
	Code       string
	Generation *int64
	DurationMs *float64
}

var diagnosticCode = regexp.MustCompile(`^[A-Z_]{2,64}$`)

type Diagnostics struct {
	mu     sync.Mutex
	events []DiagnosticEvent
}

func NewDiagnostics() *Diagnostics { return &Diagnostics{events: []DiagnosticEvent{}} }
func (d *Diagnostics) Record(input DiagnosticInput) error {
	if !oneOf(input.Stage, "startup", "login", "sync", "connection", "policy", "update", "storage", "lifecycle") || !diagnosticCode.MatchString(input.Code) || input.Generation != nil && *input.Generation < 0 || input.DurationMs != nil && (*input.DurationMs < 0 || *input.DurationMs > 3600000) {
		return NewAppError("INVALID_INPUT")
	}
	now := time.Now().UnixMilli()
	d.mu.Lock()
	defer d.mu.Unlock()
	events := []DiagnosticEvent{}
	for _, event := range d.events {
		at, _ := signedTime(event.At)
		if now-at < 7*86400000 {
			events = append(events, event)
		}
	}
	if len(events) > 999 {
		events = events[len(events)-999:]
	}
	events = append(events, DiagnosticEvent{input.Stage, input.Code, input.Generation, input.DurationMs, isoTime(now), newUUID()})
	d.events = events
	return nil
}
func (d *Diagnostics) Export(version, platform, arch string) any {
	d.mu.Lock()
	defer d.mu.Unlock()
	events := append([]DiagnosticEvent{}, d.events...)
	return struct {
		SchemaVersion int               `json:"schemaVersion"`
		Version       string            `json:"version"`
		Platform      string            `json:"platform"`
		Arch          string            `json:"arch"`
		CreatedAt     string            `json:"createdAt"`
		Contains      []string          `json:"contains"`
		Events        []DiagnosticEvent `json:"events"`
	}{1, version, platform, arch, isoTime(time.Now().UnixMilli()), []string{"应用版本", "平台架构", "时间和错误码", "操作耗时"}, events}
}
