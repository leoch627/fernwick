package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// Telemetry exists to troubleshoot users who say "it doesn't connect". Clients send
// connection results, error codes and API reachability; never visited sites, DNS
// queries, traffic, tokens, subscription links or node credentials. The client
// enforces that; the server only bounds and stores what arrives.

type clientInfo struct {
	Install  string `json:"install"`
	Email    string `json:"email"`
	Version  string `json:"version"`
	Platform string `json:"platform"`
	Arch     string `json:"arch"`
	OS       string `json:"os"`
}
type event map[string]any
type telemetryInput struct {
	clientInfo
	Events []event `json:"events"`
}
type reportInput struct {
	clientInfo
	Note   string  `json:"note"`
	Events []event `json:"events"`
	Checks []event `json:"checks"`
}
type storedEvent struct {
	ReceivedAt string `json:"receivedAt"`
	IP         string `json:"ip"`
	clientInfo
	Event event `json:"event"`
}
type storedReport struct {
	Code       string `json:"code"`
	ReceivedAt string `json:"receivedAt"`
	IP         string `json:"ip"`
	reportInput
}

var eventKey = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)
var reportCode = regexp.MustCompile(`^[2-9A-HJ-NP-Z]{6}$`)

const codeAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

func text(value string, limit int) bool { return utf8.ValidString(value) && len(value) <= limit }

func (c clientInfo) check() {
	check(text(c.Install, 64) && text(c.Email, 254) && text(c.Version, 64) && text(c.Platform, 16) && text(c.Arch, 16) && text(c.OS, 128), "client")
}

// checkEvents keeps events flat and small: scalar values under short keys.
func checkEvents(events []event, limit int, field string) {
	check(len(events) <= limit, field)
	for _, e := range events {
		check(len(e) > 0 && len(e) <= 40, field)
		for k, v := range e {
			check(eventKey.MatchString(k), field)
			switch value := v.(type) {
			case string:
				check(text(value, 512), field)
			case float64, bool, nil:
			default:
				check(false, field)
			}
		}
	}
}

func (s *Server) clientIP(r *http.Request) string {
	if s.trustProxy {
		if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); net.ParseIP(ip) != nil {
			return ip
		}
		if first, _, _ := strings.Cut(r.Header.Get("X-Forwarded-For"), ","); net.ParseIP(strings.TrimSpace(first)) != nil {
			return strings.TrimSpace(first)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := s.clientIP(r)
	report := r.URL.Path == "/v1/report"
	if report && !s.limits.allow("report:"+ip, 10, time.Hour) || !report && !s.limits.allow("telemetry:"+ip, 60, time.Minute) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
		return
	}
	var err error
	if report {
		err = s.storeReport(w, r, ip)
	} else {
		err = s.storeEvents(w, r, ip)
	}
	var input inputError
	if errors.As(err, &input) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": input.Error()})
	} else if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
}

var appendMu sync.Mutex

func (s *Server) storeEvents(w http.ResponseWriter, r *http.Request, ip string) error {
	var input telemetryInput
	if err := decodeBody(r, 256<<10, &input); err != nil {
		return err
	}
	if err := validate(func() { input.check(); checkEvents(input.Events, 200, "events") }); err != nil {
		return err
	}
	now := s.now().UTC()
	var lines []byte
	for _, e := range input.Events {
		line, err := json.Marshal(storedEvent{ReceivedAt: iso(now), IP: ip, clientInfo: input.clientInfo, Event: e})
		if err != nil {
			return err
		}
		lines = append(append(lines, line...), '\n')
	}
	appendMu.Lock()
	defer appendMu.Unlock()
	file, err := os.OpenFile(filepath.Join(s.data, "telemetry", now.Format("2006-01-02")+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if _, err = file.Write(lines); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]int{"accepted": len(input.Events)})
	return nil
}

func newCode() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = codeAlphabet[int(b[i])%len(codeAlphabet)]
	}
	return string(b)
}

func (s *Server) storeReport(w http.ResponseWriter, r *http.Request, ip string) error {
	var input reportInput
	if err := decodeBody(r, 2<<20, &input); err != nil {
		return err
	}
	if err := validate(func() {
		input.check()
		check(text(input.Note, 2000), "note")
		checkEvents(input.Events, 1000, "events")
		checkEvents(input.Checks, 100, "checks")
	}); err != nil {
		return err
	}
	for range 8 {
		code := newCode()
		data, err := json.MarshalIndent(storedReport{Code: code, ReceivedAt: iso(s.now()), IP: ip, reportInput: input}, "", "  ")
		if err != nil {
			return err
		}
		file, err := os.OpenFile(filepath.Join(s.data, "reports", code+".json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		if err != nil {
			return err
		}
		_, err = file.Write(data)
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		writeJSON(w, http.StatusOK, map[string]string{"code": code})
		return nil
	}
	return errors.New("no free report code")
}

// ---- admin lookup ----

func matches(c clientInfo, email, install string) bool {
	return (email == "" || strings.EqualFold(c.Email, email)) && (install == "" || c.Install == install)
}

// searchEvents returns matching events, newest first.
func (s *Server) searchEvents(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	email, install, kind := strings.TrimSpace(q.Get("email")), strings.TrimSpace(q.Get("install")), q.Get("type")
	days, limit := atoiDefault(q.Get("days"), 7, 1, 31), atoiDefault(q.Get("limit"), 500, 1, 5000)
	out := []storedEvent{}
	now := s.now().UTC()
	for d := range days {
		file, err := os.Open(filepath.Join(s.data, "telemetry", now.AddDate(0, 0, -d).Format("2006-01-02")+".jsonl"))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		day := []storedEvent{}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		for scanner.Scan() {
			var e storedEvent
			if json.Unmarshal(scanner.Bytes(), &e) == nil && matches(e.clientInfo, email, install) && (kind == "" || e.Event["type"] == kind) {
				day = append(day, e)
			}
		}
		file.Close()
		slices.Reverse(day)
		out = append(out, day...)
		if len(out) >= limit {
			break
		}
	}
	writeJSON(w, http.StatusOK, out[:min(len(out), limit)])
	return nil
}

func (s *Server) searchReports(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	email, install := strings.TrimSpace(q.Get("email")), strings.TrimSpace(q.Get("install"))
	since := s.now().AddDate(0, 0, -atoiDefault(q.Get("days"), 30, 1, 365))
	entries, err := os.ReadDir(filepath.Join(s.data, "reports"))
	if err != nil {
		return err
	}
	type summary struct {
		Code       string `json:"code"`
		ReceivedAt string `json:"receivedAt"`
		clientInfo
		Note string `json:"note"`
	}
	out := []summary{}
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil || !strings.HasSuffix(entry.Name(), ".json") || info.ModTime().Before(since) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.data, "reports", entry.Name()))
		var report storedReport
		if err != nil || json.Unmarshal(data, &report) != nil || !matches(report.clientInfo, email, install) {
			continue
		}
		out = append(out, summary{report.Code, report.ReceivedAt, report.clientInfo, report.Note})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ReceivedAt > out[j].ReceivedAt })
	writeJSON(w, http.StatusOK, out[:min(len(out), 500)])
	return nil
}

func (s *Server) report(w http.ResponseWriter, code string) error {
	code = strings.ToUpper(strings.TrimSpace(code))
	if !reportCode.MatchString(code) {
		return inputError("code")
	}
	data, err := os.ReadFile(filepath.Join(s.data, "reports", code+".json"))
	if errors.Is(err, fs.ErrNotExist) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such report"})
		return nil
	}
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, err = w.Write(data)
	return err
}

// Prune removes telemetry and reports past their retention.
func (s *Server) Prune(telemetryDays, reportDays int) {
	now := s.now().UTC()
	for dir, days := range map[string]int{"telemetry": telemetryDays, "reports": reportDays} {
		entries, _ := os.ReadDir(filepath.Join(s.data, dir))
		for _, entry := range entries {
			info, err := entry.Info()
			if err == nil && info.Mode().IsRegular() && now.Sub(info.ModTime()) > time.Duration(days)*24*time.Hour {
				_ = os.Remove(filepath.Join(s.data, dir, entry.Name()))
			}
		}
	}
}

// ---- rate limits ----

type window struct {
	start time.Time
	count int
}
type rateLimits struct {
	mu      sync.Mutex
	windows map[string]*window
}

func newRateLimits() *rateLimits { return &rateLimits{windows: map[string]*window{}} }

func (l *rateLimits) allow(key string, limit int, period time.Duration) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.windows) > 50000 {
		for k, w := range l.windows {
			if now.Sub(w.start) > time.Hour {
				delete(l.windows, k)
			}
		}
	}
	w := l.windows[key]
	if w == nil || now.Sub(w.start) >= period {
		w = &window{start: now}
		l.windows[key] = w
	}
	w.count++
	return w.count <= limit
}
