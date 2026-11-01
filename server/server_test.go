package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"work.starrail/client/desktop/core"
)

// These tests check the server against the client's own verifiers (desktop/core), so a
// payload the client would reject fails here.

const origin = "https://dl.mooncloud.net"

func keyPair(t *testing.T) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(private)
	pub, _ := x509.MarshalPKIXPublicKey(public)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}))
}

type fixture struct {
	t      *testing.T
	server *Server
	build  core.BuildConfig
	token  string
	now    time.Time
}

func newFixture(t *testing.T) *fixture {
	private, public := keyPair(t)
	server, err := NewServer(t.TempDir(), origin, private, false)
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{t: t, server: server, token: adminToken(private), now: time.Now()}
	server.now = func() time.Time { return f.now }
	raw, err := os.ReadFile("../config/development.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &f.build); err != nil {
		t.Fatal(err)
	}
	b := &f.build
	b.ProductID, b.Environment, b.Channel = "moon-cloud", "production", "stable"
	b.TrustedUpdateOrigins, b.TrustedResourceOrigins = []string{origin}, []string{origin}
	b.PolicyURLs, b.UpdateFeedURLs = []string{origin + "/v1/policy"}, []string{origin + "/v1/release"}
	b.PolicyKeys, b.UpdateKeys = map[string]string{keyID: public}, map[string]string{keyID: public}
	site := "https://www.mooncloud.net/"
	b.Links = core.BuildLinks{Website: &site, Renew: &site, Help: &site}
	b.TrustedWebOrigins = append(b.TrustedWebOrigins, "https://www.mooncloud.net", origin)
	return f
}

func (f *fixture) call(method, path, token string, body []byte) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	f.server.ServeHTTP(recorder, request)
	return recorder
}

var installer = func() []byte {
	b := make([]byte, 4096)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}()

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func file(key, platform, arch, format string) PublishedFile {
	minimum := map[string]string{"linux": "24.04", "win32": "10.0.22000", "darwin": "14.0"}[platform]
	return PublishedFile{Key: key, Platform: platform, Arch: arch, Format: format, Bytes: int64(len(installer)), SHA256: digest(installer), UnpackedBytes: 10000, MinimumOS: minimum, CoreVersion: "26.10.31", CoreSHA256: strings.Repeat("c", 64), SignatureIdentity: "unsigned"}
}

var files = []PublishedFile{
	file("releases/0.2.0/app-linux-amd64.deb", "linux", "x64", "deb"),
	file("releases/0.2.0/app-win-x64.exe", "win32", "x64", "nsis"),
	file("releases/0.2.0/app-mac-arm64.dmg", "darwin", "arm64", "dmg"),
	file("releases/0.2.0/app-mac-arm64.zip", "darwin", "arm64", "zip"),
}

func (f *fixture) brand() Brand {
	ids := []string{}
	for _, e := range f.build.APIEndpoints {
		ids = append(ids, e.ID)
	}
	return Brand{ProductID: f.build.ProductID, Name: "月云 & <Co>", Environment: f.build.Environment, Channel: f.build.Channel, EndpointIDs: ids, Links: Links{*f.build.Links.Website, *f.build.Links.Renew, *f.build.Links.Help}}
}

func (f *fixture) upload(key string, data []byte) {
	if r := f.call("POST", "/admin/upload?key="+key, f.token, data); r.Code != 200 {
		f.t.Fatalf("upload %s: %d %s", key, r.Code, r.Body)
	}
}

func (f *fixture) publish(input releaseInput) *httptest.ResponseRecorder {
	body, _ := json.Marshal(input)
	return f.call("POST", "/admin/release", f.token, body)
}

func (f *fixture) published() *fixture {
	for _, file := range files {
		f.upload(file.Key, installer)
	}
	if r := f.publish(releaseInput{Brand: f.brand(), Version: "0.2.0", Files: files}); r.Code != 200 {
		f.t.Fatalf("publish: %d %s", r.Code, r.Body)
	}
	return f
}

func TestPublishedReleaseIsAcceptedByTheClient(t *testing.T) {
	f := newFixture(t)
	if r := f.call("GET", "/v1/release", "", nil); r.Code != 404 {
		t.Fatalf("unpublished release: %d", r.Code)
	}
	f.published()
	verified, err := core.VerifyRelease(f.call("GET", "/v1/release", "", nil).Body.String(), f.build, nil, f.now.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for _, a := range verified.Index.Artifacts {
		ids = append(ids, a.ID)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{"darwin-arm64-zip-0.2.0", "linux-x64-deb-0.2.0", "win32-x64-nsis-0.2.0"}) {
		t.Fatal(ids)
	}
	linux := core.SelectUpdate(verified.Index, core.UpdateTarget{Platform: "linux", Arch: "x64", Version: "0.1.0", OSCompatible: func(string) bool { return true }})
	if linux == nil || linux.URL != origin+"/files/releases/0.2.0/app-linux-amd64.deb" {
		t.Fatal(linux)
	}
	if core.SelectUpdate(verified.Index, core.UpdateTarget{Platform: "linux", Arch: "x64", Version: "0.2.0", OSCompatible: func(string) bool { return true }}) != nil {
		t.Fatal("offered the installed version")
	}
}

func TestPolicyIsAcceptedAndCarriesRuleUpdates(t *testing.T) {
	f := newFixture(t)
	rulesRequest := func(key string, data []byte) []byte {
		body, _ := json.Marshal(rulesInput{Key: key, SHA256: digest(data), Bytes: int64(len(data))})
		return body
	}
	if r := f.call("POST", "/admin/rules", f.token, rulesRequest("rules/x/rules.json", []byte("x"))); r.Code != 400 {
		t.Fatalf("rules before upload and release: %d", r.Code)
	}
	f.published()
	first, err := core.VerifyPolicy(f.call("GET", "/v1/policy", "", nil).Body.String(), f.build, nil, f.now.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if first.Policy.Routing.Resource != nil || first.Policy.Links.Website != *f.build.Links.Website || first.Policy.Refresh.MaxSnapshotAgeSec != maxSnapshotAgeSec {
		t.Fatalf("%+v", first.Policy)
	}
	rules, _ := json.Marshal(core.Rules{SchemaVersion: 2, Sections: []core.RuleSection{{Target: "direct", Domains: []string{"domain:cn"}, IPs: []string{"1.0.1.0/24"}}}})
	f.upload("rules/20261101/rules.json", rules)
	if r := f.call("POST", "/admin/rules", f.token, rulesRequest("rules/20261101/rules.json", rules)); r.Code != 200 {
		t.Fatalf("rules: %d %s", r.Code, r.Body)
	}
	f.now = f.now.Add(time.Second)
	second, err := core.VerifyPolicy(f.call("GET", "/v1/policy", "", nil).Body.String(), f.build, &first.Watermark, f.now.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	resource := second.Policy.Routing.Resource
	if resource == nil || resource.URL != origin+"/files/rules/20261101/rules.json" {
		t.Fatal(resource)
	}
	served := f.call("GET", "/files/rules/20261101/rules.json", "", nil).Body.Bytes()
	decoded, err := core.ValidateResource(served, *resource, f.build, f.now.UnixMilli())
	if err != nil || decoded.Sections[0].Domains[0] != "domain:cn" {
		t.Fatal(decoded, err)
	}
}

func TestRenewalProducesNewerEnvelopes(t *testing.T) {
	f := newFixture(t).published()
	before, err := core.VerifyRelease(f.call("GET", "/v1/release", "", nil).Body.String(), f.build, nil, f.now.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(6 * time.Hour)
	if _, policy, err := f.server.Renew(false); err != nil || policy {
		t.Fatalf("a fresh policy was re-signed (%v, %v)", policy, err)
	}
	after, err := core.VerifyRelease(f.call("GET", "/v1/release", "", nil).Body.String(), f.build, &before.Watermark, f.now.UnixMilli())
	if err != nil || after.Watermark.Version <= before.Watermark.Version {
		t.Fatal(after.Watermark, err)
	}
	f.now = f.now.Add(25 * time.Hour)
	if _, policy, err := f.server.Renew(false); err != nil || !policy {
		t.Fatalf("an ageing policy was not re-signed (%v, %v)", policy, err)
	}
}

func TestAdminTokenAndPublishingChecks(t *testing.T) {
	f := newFixture(t)
	if adminToken(strings.ReplaceAll(f.server.signingKey, "\n", "\r\n")) != f.token || len(f.token) != 64 {
		t.Fatal("token depends on PEM line endings")
	}
	other, _ := keyPair(t)
	for _, token := range []string{"", "wrong", adminToken(other)} {
		if r := f.call("GET", "/admin/status", token, nil); r.Code != 401 {
			t.Fatalf("status with %q: %d", token, r.Code)
		}
	}
	if r := f.call("GET", "/admin/status", f.token, nil); r.Code != 200 {
		t.Fatal(r.Code)
	}
	if r := f.publish(releaseInput{Brand: f.brand(), Version: "0.2.0", Files: files}); r.Code != 400 || !strings.Contains(r.Body.String(), "upload it first") {
		t.Fatalf("published without files: %d %s", r.Code, r.Body)
	}
	for _, file := range files {
		f.upload(file.Key, installer)
	}
	insecure := f.brand()
	insecure.Links.Website = "http://insecure.net"
	state := files[0]
	state.Key = "state/release.json"
	dmg := files[0]
	dmg.Format = "dmg"
	for _, input := range []releaseInput{
		{Brand: f.brand(), Version: "latest", Files: files},
		{Brand: f.brand(), Version: "0.2.0", Files: []PublishedFile{state}},
		{Brand: f.brand(), Version: "0.2.0", Files: []PublishedFile{dmg}},
		{Brand: f.brand(), Version: "0.2.0", Files: []PublishedFile{files[0], files[0]}},
		{Brand: insecure, Version: "0.2.0", Files: files},
	} {
		if r := f.publish(input); r.Code != 400 {
			t.Errorf("accepted %+v: %d", input, r.Code)
		}
	}
	for _, key := range []string{"state/brand.json", "../escape/x", "releases/../../x"} {
		if r := f.call("POST", "/admin/upload?key="+key, f.token, []byte("x")); r.Code != 400 {
			t.Errorf("upload to %s: %d", key, r.Code)
		}
	}
}

func TestEndpointKeepsServingItsBrand(t *testing.T) {
	f := newFixture(t).published()
	renamed := f.brand()
	renamed.Name = "月云"
	if r := f.publish(releaseInput{Brand: renamed, Version: "0.2.0", Files: files}); r.Code != 200 {
		t.Fatal(r.Code)
	}
	other := f.brand()
	other.ProductID = "other-cloud"
	if r := f.publish(releaseInput{Brand: other, Version: "0.2.0", Files: files}); r.Code != 400 || !strings.Contains(r.Body.String(), "separate endpoint") {
		t.Fatal(r.Code, r.Body)
	}
}

func TestFilesAreResumableAndStateIsPrivate(t *testing.T) {
	f := newFixture(t).published()
	full := f.call("GET", "/files/releases/0.2.0/app-linux-amd64.deb", "", nil)
	if full.Code != 200 || !bytes.Equal(full.Body.Bytes(), installer) || full.Header().Get("ETag") == "" {
		t.Fatal(full.Code)
	}
	request := httptest.NewRequest("GET", "/files/releases/0.2.0/app-linux-amd64.deb", nil)
	request.Header.Set("Range", "bytes=100-199")
	request.Header.Set("If-Range", full.Header().Get("ETag"))
	partial := httptest.NewRecorder()
	f.server.ServeHTTP(partial, request)
	if partial.Code != 206 || !bytes.Equal(partial.Body.Bytes(), installer[100:200]) {
		t.Fatal(partial.Code, partial.Header())
	}
	for _, path := range []string{"/files/state/brand.json", "/files/releases/0.2.0/../../state/release.json", "/state/policy.json"} {
		if r := f.call("GET", path, "", nil); r.Code != 404 {
			t.Errorf("%s: %d", path, r.Code)
		}
	}
}

func TestDownloadPageEscapesAndRecommends(t *testing.T) {
	f := newFixture(t)
	if page := f.call("GET", "/", "", nil).Body.String(); !strings.Contains(page, "暂无可下载的版本") {
		t.Fatal(page)
	}
	f.published()
	page := f.call("GET", "/", "", nil).Body.String()
	if !strings.Contains(page, "月云 &amp; &lt;Co&gt;") || strings.Contains(page, "<Co>") || !strings.Contains(page, "/files/releases/0.2.0/app-win-x64.exe") || !strings.Contains(page, "仍要打开") {
		t.Fatal(page)
	}
	if strings.Contains(page, "app-mac-arm64.zip") {
		t.Fatal("update archive listed on the download page")
	}
}

func TestTelemetryIsStoredAndSearchable(t *testing.T) {
	f := newFixture(t)
	body := `{"install":"i-1","email":"User@Example.com","version":"0.2.0","platform":"win32","arch":"x64","os":"10.0.22631","events":[{"type":"connect","at":1,"result":"failed","code":"CONNECT_TIMEOUT","stage":"probe","ms":5230,"tcp":false},{"type":"api","at":2,"host":"api.example.com","error":"timeout"}]}`
	if r := f.call("POST", "/v1/telemetry", "", []byte(body)); r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	other := strings.ReplaceAll(strings.ReplaceAll(body, "User@Example.com", "other@example.com"), "i-1", "i-2")
	f.call("POST", "/v1/telemetry", "", []byte(other))
	var events []storedEvent
	r := f.call("GET", "/admin/events?email=user@example.com", f.token, nil)
	if err := json.Unmarshal(r.Body.Bytes(), &events); err != nil || len(events) != 2 || events[0].Event["type"] != "api" || events[1].Event["code"] != "CONNECT_TIMEOUT" || events[0].IP == "" {
		t.Fatal(r.Body)
	}
	if r := f.call("GET", "/admin/events?email=user@example.com", "", nil); r.Code != 401 {
		t.Fatal("telemetry readable without the admin token")
	}
	for _, bad := range []string{
		`{"events":[{"type":"x","nested":{"a":1}}]}`,
		`{"events":[{"bad key":1}]}`,
		`{"email":"` + strings.Repeat("a", 300) + `","events":[]}`,
		`{"unknown":1,"events":[]}`,
		`not json`,
	} {
		if r := f.call("POST", "/v1/telemetry", "", []byte(bad)); r.Code != 400 {
			t.Errorf("accepted %s: %d", bad, r.Code)
		}
	}
	if r := f.call("GET", "/v1/telemetry", "", nil); r.Code != 405 {
		t.Fatal(r.Code)
	}
}

func TestReportsGetACodeAndAreSearchable(t *testing.T) {
	f := newFixture(t)
	body := `{"install":"i-1","email":"user@example.com","version":"0.2.0","platform":"darwin","arch":"arm64","os":"15.1","note":"连不上","events":[{"type":"connect","at":1,"code":"CONNECT_TIMEOUT"}],"checks":[{"name":"api.example.com","ok":false,"error":"dns"}]}`
	r := f.call("POST", "/v1/report", "", []byte(body))
	var created struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(r.Body.Bytes(), &created) != nil || !reportCode.MatchString(created.Code) {
		t.Fatal(r.Code, r.Body)
	}
	var report storedReport
	if err := json.Unmarshal(f.call("GET", "/admin/reports/"+strings.ToLower(created.Code), f.token, nil).Body.Bytes(), &report); err != nil || report.Note != "连不上" || report.Checks[0]["error"] != "dns" {
		t.Fatal(report, err)
	}
	list := f.call("GET", "/admin/reports?email=USER@example.com", f.token, nil).Body.String()
	if !strings.Contains(list, created.Code) {
		t.Fatal(list)
	}
	if r := f.call("GET", "/admin/reports/../state", f.token, nil); r.Code != 400 {
		t.Fatal(r.Code)
	}
}

func TestIngestIsRateLimited(t *testing.T) {
	f := newFixture(t)
	body := []byte(`{"events":[]}`)
	codes := map[int]int{}
	for range 70 {
		codes[f.call("POST", "/v1/telemetry", "", body).Code]++
	}
	if codes[200] != 60 || codes[429] != 10 {
		t.Fatal(codes)
	}
}

func TestPruneRemovesOldData(t *testing.T) {
	f := newFixture(t)
	old := filepath.Join(f.server.data, "telemetry", "2020-01-01.jsonl")
	fresh := filepath.Join(f.server.data, "reports", "ABCDEF.json")
	for _, name := range []string{old, fresh} {
		if err := os.WriteFile(name, []byte("{}"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	past := time.Now().Add(-40 * 24 * time.Hour)
	_ = os.Chtimes(old, past, past)
	f.server.Prune(30, 90)
	if _, err := os.Stat(old); err == nil {
		t.Error("old telemetry kept")
	}
	if _, err := os.Stat(fresh); err != nil {
		t.Error("recent report removed")
	}
}
