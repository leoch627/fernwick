package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Server is the update, rules, download and telemetry endpoint. Everything lives under
// one data directory:
//
//	state/{brand,release,policy}.json   signing state
//	files/releases/<version>/<file>     installers and update archives
//	files/rules/<id>/rules.json         remote rule updates
//	telemetry/<yyyy-mm-dd>.jsonl        client events, one per line
//	reports/<code>.json                 user problem reports
type Server struct {
	data string
	// origin is the API's public origin; downloads is where installers, update archives
	// and rule files are fetched from, which may be a separate domain.
	origin     string
	downloads  string
	signingKey string
	key        ed25519.PrivateKey
	trustProxy bool
	now        func() time.Time
	mu         sync.Mutex // serialises state changes; reads of single files are atomic renames
	limits     *rateLimits
}

// NewServer serves the API at origin and files at downloads; an empty downloads uses origin.
func NewServer(data, origin, downloads, signingKey string, trustProxy bool) (*Server, error) {
	key, err := parseSigningKey(signingKey)
	if err != nil {
		return nil, err
	}
	if downloads == "" {
		downloads = origin
	}
	for _, o := range []string{origin, downloads} {
		if !httpsURL(o) && !strings.HasPrefix(o, "http://127.0.0.1") && !strings.HasPrefix(o, "http://localhost") {
			return nil, errors.New("public origins must be https URLs")
		}
	}
	for _, dir := range []string{"state", "files", "telemetry", "reports"} {
		if err := os.MkdirAll(filepath.Join(data, dir), 0o750); err != nil {
			return nil, err
		}
	}
	return &Server{data: data, origin: strings.TrimRight(origin, "/"), downloads: strings.TrimRight(downloads, "/"), signingKey: signingKey, key: key, trustProxy: trustProxy, now: time.Now, limits: newRateLimits()}, nil
}

// ---- state ----

func (s *Server) load(name string, value any) (bool, error) {
	data, err := os.ReadFile(filepath.Join(s.data, "state", name))
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(data, value)
}

// writeAtomic replaces a file so readers never see a partial write.
func writeAtomic(name string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(name), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), name)
}

func (s *Server) save(name string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(s.data, "state", name), data)
}

func (s *Server) signRelease(brand Brand, state ReleaseState, now time.Time) (ReleaseState, error) {
	state.Sequence = nextSequence(state.Sequence, now)
	envelope, err := sign(s.key, purposeRelease, releasePayload(brand, state.Sequence, state.Artifacts, state.WithdrawnIDs, now))
	if err != nil {
		return state, err
	}
	state.Envelope, state.SignedAt = envelope, iso(now)
	return state, s.save("release.json", state)
}

func (s *Server) signPolicy(brand Brand, previous *PolicyState, rules *RuleResource, now time.Time) (PolicyState, error) {
	var version int64
	if previous != nil {
		version = previous.Version
	}
	version = nextSequence(version, now)
	payload, expires := policyPayload(brand, version, rules, now)
	envelope, err := sign(s.key, purposePolicy, payload)
	if err != nil {
		return PolicyState{}, err
	}
	state := PolicyState{Version: version, Rules: rules, Envelope: envelope, SignedAt: iso(now), ExpiresAt: expires}
	return state, s.save("policy.json", state)
}

// Renew keeps envelopes inside their validity windows. It runs every few hours.
func (s *Server) Renew(force bool) (release, policy bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	var brand Brand
	if ok, err := s.load("brand.json", &brand); !ok || err != nil {
		return false, false, err
	}
	var current ReleaseState
	if release, err = s.load("release.json", &current); err != nil {
		return
	}
	if release {
		if _, err = s.signRelease(brand, current, now); err != nil {
			return
		}
	}
	var previous PolicyState
	found, err := s.load("policy.json", &previous)
	if err != nil {
		return
	}
	expires, _ := time.Parse(time.RFC3339, previous.ExpiresAt)
	policy = force || !found || expires.Sub(now) < policyRenew
	if policy {
		var prior *PolicyState
		if found {
			prior = &previous
		}
		_, err = s.signPolicy(brand, prior, previous.Rules, now)
	}
	return
}

// ---- HTTP ----

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

// ServeHTTP serves both roles from one listener.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.route(w, r, true, true) }

// API serves configuration, telemetry and administration only, and answers anything
// else as an API would, so its domains do not look like a download site.
func (s *Server) API() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.route(w, r, true, false) })
}

// Downloads serves the download page and published files only.
func (s *Server) Downloads() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { s.route(w, r, false, true) })
}

func (s *Server) route(w http.ResponseWriter, r *http.Request, api, downloads bool) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	path := r.URL.Path
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	switch {
	case path == "/healthz":
		_, _ = io.WriteString(w, "ok\n")
	case api && strings.HasPrefix(path, "/admin/"):
		s.admin(w, r)
	case api && (path == "/v1/telemetry" || path == "/v1/report"):
		s.ingest(w, r)
	case api && read && (path == "/v1/release" || path == "/v1/policy"):
		var state struct {
			Envelope string `json:"envelope"`
		}
		name := strings.TrimPrefix(r.URL.Path, "/v1/") + ".json"
		if ok, err := s.load(name, &state); err != nil || !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not published"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(w, state.Envelope)
	case downloads && read && strings.HasPrefix(path, "/files/"):
		s.serveFile(w, r, strings.TrimPrefix(path, "/files/"))
	case downloads && read && (path == "/" || path == "/download"):
		var brand Brand
		var release ReleaseState
		hasBrand, _ := s.load("brand.json", &brand)
		hasRelease, _ := s.load("release.json", &release)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'")
		_, _ = io.WriteString(w, downloadPage(optional(hasBrand, &brand), optional(hasRelease, &release)))
	case !read && !api:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	case api && !downloads:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	default:
		http.NotFound(w, r)
	}
}

func optional[T any](ok bool, value *T) *T {
	if ok {
		return value
	}
	return nil
}

// serveFile serves published files with byte ranges, for resumable downloads.
func (s *Server) serveFile(w http.ResponseWriter, r *http.Request, key string) {
	// Only published files are public; state/ holds signing state.
	if !fileKey.MatchString(key) {
		http.NotFound(w, r)
		return
	}
	file, err := os.Open(filepath.Join(s.data, "files", filepath.FromSlash(key)))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	contentType := "application/octet-stream"
	if strings.HasPrefix(key, "rules/") {
		contentType = "application/json"
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("Content-Disposition", `attachment; filename="`+path.Base(key)+`"`)
	w.Header().Set("ETag", fmt.Sprintf(`"%x-%x"`, info.Size(), info.ModTime().UnixNano()))
	http.ServeContent(w, r, "", info.ModTime(), file)
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/admin/" && r.Method == http.MethodGet {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
		_, _ = io.WriteString(w, adminPage)
		return
	}
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !sameSecret(token, adminToken(s.signingKey)) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var err error
	switch {
	case r.URL.Path == "/admin/upload" && r.Method == http.MethodPost:
		err = s.upload(w, r)
	case r.URL.Path == "/admin/release" && r.Method == http.MethodPost:
		err = s.publishRelease(w, r)
	case r.URL.Path == "/admin/rules" && r.Method == http.MethodPost:
		err = s.publishRules(w, r)
	case r.URL.Path == "/admin/renew" && r.Method == http.MethodPost:
		release, policy, renewErr := s.Renew(true)
		if err = renewErr; err == nil {
			writeJSON(w, http.StatusOK, map[string]bool{"release": release, "policy": policy})
		}
	case r.URL.Path == "/admin/status" && r.Method == http.MethodGet:
		err = s.status(w)
	case r.URL.Path == "/admin/events" && r.Method == http.MethodGet:
		err = s.searchEvents(w, r)
	case r.URL.Path == "/admin/reports" && r.Method == http.MethodGet:
		err = s.searchReports(w, r)
	case strings.HasPrefix(r.URL.Path, "/admin/reports/") && r.Method == http.MethodGet:
		err = s.report(w, strings.TrimPrefix(r.URL.Path, "/admin/reports/"))
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
	var input inputError
	if errors.As(err, &input) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": input.Error()})
	} else if err != nil {
		log.Printf("admin %s: %v", r.URL.Path, err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error"})
	}
}

func decodeBody(r *http.Request, limit int64, value any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return inputError("invalid json: " + err.Error())
	}
	return nil
}

// upload stores one release or rules file. CI uploads every file before publishing.
func (s *Server) upload(w http.ResponseWriter, r *http.Request) error {
	key := r.URL.Query().Get("key")
	if !fileKey.MatchString(key) {
		return inputError("key")
	}
	target := filepath.Join(s.data, "files", filepath.FromSlash(key))
	if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".upload-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	written, err := io.Copy(tmp, http.MaxBytesReader(w, r.Body, 2147483648))
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return inputError("upload interrupted: " + err.Error())
	}
	if err = os.Chmod(tmp.Name(), 0o640); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), target); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"key": key, "bytes": written})
	return nil
}

func (s *Server) fileSize(key string) int64 {
	info, err := os.Stat(filepath.Join(s.data, "files", filepath.FromSlash(key)))
	if err != nil || !info.Mode().IsRegular() {
		return -1
	}
	return info.Size()
}

func (s *Server) publishRelease(w http.ResponseWriter, r *http.Request) error {
	var input releaseInput
	if err := decodeBody(r, 1<<20, &input); err != nil {
		return err
	}
	if err := validate(input.check); err != nil {
		return err
	}
	for _, f := range input.Files {
		if s.fileSize(f.Key) != f.Bytes {
			return inputError(f.Key + " is missing or has a different size; upload it first")
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	// Installed clients only accept their own productId/environment/channel; another brand would strand them all.
	var current Brand
	if ok, err := s.load("brand.json", &current); err != nil {
		return err
	} else if ok && (current.ProductID != input.Brand.ProductID || current.Environment != input.Brand.Environment || current.Channel != input.Brand.Channel) {
		return inputError(fmt.Sprintf("this endpoint serves %s (%s); deploy a separate endpoint for %s (%s)", current.ProductID, current.Channel, input.Brand.ProductID, input.Brand.Channel))
	}
	if err := s.save("brand.json", input.Brand); err != nil {
		return err
	}
	var previous ReleaseState
	if _, err := s.load("release.json", &previous); err != nil {
		return err
	}
	downloads := make([]Download, len(input.Files))
	for i, f := range input.Files {
		downloads[i] = Download{File: f.Key, Platform: f.Platform, Arch: f.Arch, Format: f.Format, Bytes: f.Bytes, SHA256: f.SHA256, Signed: f.SignatureIdentity != "unsigned"}
	}
	withdrawn := previous.WithdrawnIDs
	if withdrawn == nil {
		withdrawn = []string{}
	}
	release, err := s.signRelease(input.Brand, ReleaseState{Sequence: previous.Sequence, Version: input.Version, PublishedAt: iso(now), Artifacts: releaseArtifacts(s.downloads, input.Version, input.Files), Downloads: downloads, WithdrawnIDs: withdrawn}, now)
	if err != nil {
		return err
	}
	// A brand change (links, endpoints) must reach clients through a new policy.
	var policy PolicyState
	found, err := s.load("policy.json", &policy)
	if err != nil {
		return err
	}
	if _, err = s.signPolicy(input.Brand, optional(found, &policy), policy.Rules, now); err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"version": release.Version, "sequence": release.Sequence, "artifacts": len(release.Artifacts)})
	return nil
}

func (s *Server) publishRules(w http.ResponseWriter, r *http.Request) error {
	var input rulesInput
	if err := decodeBody(r, 1<<16, &input); err != nil {
		return err
	}
	if err := validate(input.check); err != nil {
		return err
	}
	if s.fileSize(input.Key) != input.Bytes {
		return inputError(input.Key + " is missing or has a different size; upload it first")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var brand Brand
	if ok, err := s.load("brand.json", &brand); err != nil {
		return err
	} else if !ok {
		return inputError("publish a release first")
	}
	var previous PolicyState
	found, err := s.load("policy.json", &previous)
	if err != nil {
		return err
	}
	var version int64
	if previous.Rules != nil {
		version = previous.Rules.Version
	}
	now := s.now()
	// The client binds a rule ID to one hash, so the ID is derived from the hash.
	rules := &RuleResource{ID: "cn-rules-" + input.SHA256[:16], Version: nextSequence(version, now), URL: s.downloads + "/files/" + input.Key, SHA256: input.SHA256, Bytes: input.Bytes}
	policy, err := s.signPolicy(brand, optional(found, &previous), rules, now)
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{"policyVersion": policy.Version, "rules": rules.ID})
	return nil
}

func (s *Server) status(w http.ResponseWriter) error {
	var brand Brand
	var release ReleaseState
	var policy PolicyState
	hasBrand, err := s.load("brand.json", &brand)
	if err != nil {
		return err
	}
	hasRelease, err := s.load("release.json", &release)
	if err != nil {
		return err
	}
	hasPolicy, err := s.load("policy.json", &policy)
	if err != nil {
		return err
	}
	out := map[string]any{"brand": optional(hasBrand, &brand), "release": nil, "policy": nil}
	if hasRelease {
		ids := []string{}
		for _, a := range release.Artifacts {
			ids = append(ids, a.ID)
		}
		out["release"] = map[string]any{"version": release.Version, "sequence": release.Sequence, "signedAt": release.SignedAt, "artifacts": ids}
	}
	if hasPolicy {
		out["policy"] = map[string]any{"version": policy.Version, "signedAt": policy.SignedAt, "expiresAt": policy.ExpiresAt, "rules": policy.Rules}
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func atoiDefault(value string, fallback, low, high int) int {
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return min(max(n, low), high)
}
