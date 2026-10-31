package core

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var downloadTestBody = []byte("signed installer fixture content")

type testDownloadTransport func(context.Context, string, int64, *string) (DownloadResponse, error)

func (f testDownloadTransport) Open(ctx context.Context, url string, offset int64, etag *string) (DownloadResponse, error) {
	return f(ctx, url, offset, etag)
}
func downloadTestArtifact() Artifact {
	sum := sha256.Sum256(downloadTestBody)
	return Artifact{ID: "linux-0.2.0", Version: "0.2.0", Platform: "linux", Arch: "x64", Format: "deb", MinimumOS: "24.04", URL: "https://updates.example.invalid/app.deb", Bytes: int64(len(downloadTestBody)), SHA256: hex.EncodeToString(sum[:]), UnpackedBytes: 1024, BackupBytes: 1024, CoreVersion: "26.10.29", CoreSHA256: strings.Repeat("a", 64), HelperProtocol: 1, SignatureIdentity: "fixture"}
}
func downloadTestResponse(data []byte, status int, headers map[string]string) DownloadResponse {
	if headers == nil {
		headers = map[string]string{}
	}
	headers["content-length"] = strconv.Itoa(len(data))
	return DownloadResponse{Status: status, Headers: headers, Body: io.NopCloser(bytes.NewReader(data))}
}
func downloadTestSetup(t *testing.T, transport DownloadTransport) *ArtifactDownload {
	t.Helper()
	d := NewArtifactDownload(t.TempDir(), BuildConfig{TrustedUpdateOrigins: []string{"https://updates.example.invalid"}})
	d.transport = transport
	d.freeBytes = func(string) (uint64, error) { return 1000000000000, nil }
	artifact := downloadTestArtifact()
	if err := d.Select(&artifact); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Pause() })
	return d
}

type interruptedDownloadBody struct {
	ctx     context.Context
	data    []byte
	once    sync.Once
	partial chan struct{}
	wait    bool
}

func (b *interruptedDownloadBody) Read(p []byte) (int, error) {
	if len(b.data) > 0 {
		n := copy(p, b.data)
		b.data = b.data[n:]
		return n, nil
	}
	if b.partial != nil {
		b.once.Do(func() { close(b.partial) })
	}
	if b.wait {
		<-b.ctx.Done()
		return 0, b.ctx.Err()
	}
	return 0, errors.New("connection reset")
}
func (*interruptedDownloadBody) Close() error { return nil }

func TestDownloadExactHashAndReverify(t *testing.T) {
	d := downloadTestSetup(t, testDownloadTransport(func(context.Context, string, int64, *string) (DownloadResponse, error) {
		return downloadTestResponse(downloadTestBody, 200, nil), nil
	}))
	if err := d.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if v := d.View(); v.Status != "ready" || v.Received != int64(len(downloadTestBody)) {
		t.Fatal(v)
	}
	artifact := downloadTestArtifact()
	path, err := d.VerifiedPath(artifact)
	if err != nil {
		t.Fatal(err)
	}
	actual, _ := os.ReadFile(path)
	if !bytes.Equal(actual, downloadTestBody) {
		t.Fatal(string(actual))
	}
	if err = os.WriteFile(path, make([]byte, len(downloadTestBody)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = d.VerifiedPath(artifact); CodeOf(err) != "UPDATE_VERIFY_FAILED" {
		t.Fatal(err)
	}
}
func TestDownloadPauseRestartRangeAndETag(t *testing.T) {
	partial := make(chan struct{})
	var calls atomic.Int32
	offsets := make(chan int64, 2)
	transport := testDownloadTransport(func(ctx context.Context, _ string, offset int64, etag *string) (DownloadResponse, error) {
		offsets <- offset
		if calls.Add(1) == 1 {
			return DownloadResponse{Status: 200, Headers: map[string]string{"etag": "\"v1\"", "content-length": strconv.Itoa(len(downloadTestBody))}, Body: &interruptedDownloadBody{ctx: ctx, data: downloadTestBody[:8], partial: partial, wait: true}}, nil
		}
		if etag == nil || *etag != "\"v1\"" {
			t.Error("lost strong ETag")
		}
		return downloadTestResponse(downloadTestBody[offset:], 206, map[string]string{"content-range": fmt.Sprintf("bytes %d-%d/%d", offset, len(downloadTestBody)-1, len(downloadTestBody))}), nil
	})
	d := downloadTestSetup(t, transport)
	done := make(chan error, 1)
	go func() { done <- d.Start(context.Background()) }()
	<-partial
	if err := d.Pause(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if d.View().Status != "paused" {
		t.Fatal(d.View())
	}
	fresh := NewArtifactDownload(d.directory, d.build)
	fresh.transport = transport
	fresh.freeBytes = d.freeBytes
	artifact := downloadTestArtifact()
	if err := fresh.Select(&artifact); err != nil {
		t.Fatal(err)
	}
	if fresh.View().Received != 8 {
		t.Fatal(fresh.View())
	}
	if err := fresh.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fresh.View().Status != "ready" || <-offsets != 0 || <-offsets != 8 {
		t.Fatal(fresh.View())
	}
}
func TestDownloadRange200RestartsAndBad206Fails(t *testing.T) {
	for _, badRange := range []bool{false, true} {
		t.Run(strconv.FormatBool(badRange), func(t *testing.T) {
			calls := 0
			d := downloadTestSetup(t, testDownloadTransport(func(ctx context.Context, _ string, offset int64, _ *string) (DownloadResponse, error) {
				calls++
				if calls == 1 {
					return DownloadResponse{Status: 200, Headers: map[string]string{"content-length": strconv.Itoa(len(downloadTestBody))}, Body: &interruptedDownloadBody{data: downloadTestBody[:8]}}, nil
				}
				if badRange {
					return downloadTestResponse(downloadTestBody[8:], 206, map[string]string{"content-range": fmt.Sprintf("bytes 9-%d/%d", len(downloadTestBody)-1, len(downloadTestBody))}), nil
				}
				return downloadTestResponse(downloadTestBody, 200, nil), nil
			}))
			_ = d.Start(context.Background())
			if d.View().Status != "failed" {
				t.Fatal(d.View())
			}
			_ = d.Start(context.Background())
			want := "ready"
			if badRange {
				want = "failed"
			}
			if d.View().Status != want {
				t.Fatal(d.View())
			}
		})
	}
}
func TestDownloadRejectsHTTPErrorAndCompression(t *testing.T) {
	for _, status := range []int{302, 404, 500} {
		d := downloadTestSetup(t, testDownloadTransport(func(context.Context, string, int64, *string) (DownloadResponse, error) {
			return downloadTestResponse(downloadTestBody, status, map[string]string{"location": "https://elsewhere.invalid"}), nil
		}))
		_ = d.Start(context.Background())
		if d.View().Status != "failed" {
			t.Fatal(d.View())
		}
	}
	d := downloadTestSetup(t, testDownloadTransport(func(context.Context, string, int64, *string) (DownloadResponse, error) {
		return downloadTestResponse(downloadTestBody, 200, map[string]string{"content-encoding": "gzip"}), nil
	}))
	_ = d.Start(context.Background())
	if d.View().Status != "failed" {
		t.Fatal(d.View())
	}
}
func TestDownloadRemovesWrongHashAndExcessBytes(t *testing.T) {
	for _, body := range [][]byte{make([]byte, len(downloadTestBody)), append(append([]byte{}, downloadTestBody...), 'x')} {
		d := downloadTestSetup(t, testDownloadTransport(func(context.Context, string, int64, *string) (DownloadResponse, error) {
			return DownloadResponse{Status: 200, Headers: map[string]string{}, Body: io.NopCloser(bytes.NewReader(body))}, nil
		}))
		_ = d.Start(context.Background())
		if d.View().Status != "failed" {
			t.Fatal(d.View())
		}
		for _, name := range []string{"pending.bin", "pending.part"} {
			if _, err := os.Lstat(filepath.Join(d.directory, name)); !os.IsNotExist(err) {
				t.Fatalf("invalid artifact retained: %s %v", name, err)
			}
		}
	}
}
func TestDownloadWithdrawalDiskAndOriginGates(t *testing.T) {
	var calls atomic.Int32
	d := downloadTestSetup(t, testDownloadTransport(func(context.Context, string, int64, *string) (DownloadResponse, error) {
		calls.Add(1)
		return downloadTestResponse(downloadTestBody, 200, nil), nil
	}))
	d.freeBytes = func(string) (uint64, error) { return 10, nil }
	_ = d.Start(context.Background())
	if calls.Load() != 0 || d.View().Status != "failed" {
		t.Fatal(d.View())
	}
	evil := downloadTestArtifact()
	evil.URL = "https://evil.invalid/file"
	if err := d.Select(&evil); err == nil {
		t.Fatal("untrusted origin accepted")
	}
	d.freeBytes = func(string) (uint64, error) { return 1000000000000, nil }
	_ = d.Start(context.Background())
	if err := d.Select(nil); err != nil {
		t.Fatal(err)
	}
	if d.View().Status != "idle" {
		t.Fatal(d.View())
	}
	if _, err := os.Stat(filepath.Join(d.directory, "pending.bin")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
func TestDownloadPrunesExpiredFilesAndView(t *testing.T) {
	d := downloadTestSetup(t, testDownloadTransport(func(context.Context, string, int64, *string) (DownloadResponse, error) {
		return downloadTestResponse(downloadTestBody, 200, nil), nil
	}))
	now := time.Now().UnixMilli()
	d.now = func() int64 { return now }
	_ = d.Start(context.Background())
	now += downloadMaxAge + 1
	if err := d.Prune(); err != nil {
		t.Fatal(err)
	}
	if v := d.View(); v.Received != 0 || v.Status != "available" {
		t.Fatal(v)
	}
	if _, err := os.Stat(filepath.Join(d.directory, "pending.bin")); !os.IsNotExist(err) {
		t.Fatal(err)
	}
}
func TestDownloadSymlinkAndHardlinkCannotOverwrite(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test requires symlink privileges")
	}
	for _, hard := range []bool{false, true} {
		d := downloadTestSetup(t, testDownloadTransport(func(context.Context, string, int64, *string) (DownloadResponse, error) {
			return downloadTestResponse(downloadTestBody, 200, nil), nil
		}))
		artifact := downloadTestArtifact()
		record := DownloadRecord{SchemaVersion: 1, Artifact: artifact, CreatedAt: time.Now().UnixMilli()}
		if err := NewJSONStore[DownloadRecord](d.path("pending.json"), 32768).Save(record, nil); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(d.path("pending.part"), downloadTestBody[:2], 0600); err != nil {
			t.Fatal(err)
		}
		d.initialized = false
		if err := d.Select(&artifact); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(d.path("pending.part")); err != nil {
			t.Fatal(err)
		}
		outside := d.path("outside")
		if err := os.WriteFile(outside, []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
		var err error
		if hard {
			err = os.Link(outside, d.path("pending.part"))
		} else {
			err = os.Symlink(outside, d.path("pending.part"))
		}
		if err != nil {
			t.Fatal(err)
		}
		_ = d.Start(context.Background())
		raw, _ := os.ReadFile(outside)
		if string(raw) != "keep" || d.View().Status != "failed" {
			t.Fatal(string(raw), d.View())
		}
	}
}
func TestDownloadPauseSupersedesQueuedStart(t *testing.T) {
	var calls atomic.Int32
	d := downloadTestSetup(t, testDownloadTransport(func(context.Context, string, int64, *string) (DownloadResponse, error) {
		calls.Add(1)
		return downloadTestResponse(downloadTestBody, 200, nil), nil
	}))
	d.op.Lock()
	done := make(chan error, 1)
	go func() { done <- d.Start(context.Background()) }()
	deadline := time.Now().Add(time.Second)
	for {
		d.mu.Lock()
		intent := d.intent
		d.mu.Unlock()
		if intent > 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("start did not queue")
		}
		time.Sleep(time.Millisecond)
	}
	_ = d.Pause()
	d.op.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("paused queued request ran")
	}
}
func TestDownloadWithdrawalDuringSpaceCheck(t *testing.T) {
	var calls atomic.Int32
	d := downloadTestSetup(t, testDownloadTransport(func(context.Context, string, int64, *string) (DownloadResponse, error) {
		calls.Add(1)
		return downloadTestResponse(downloadTestBody, 200, nil), nil
	}))
	entered, release := make(chan struct{}), make(chan struct{})
	d.freeBytes = func(string) (uint64, error) { close(entered); <-release; return 1000000000000, nil }
	running := make(chan error, 1)
	go func() { running <- d.Start(context.Background()) }()
	<-entered
	withdrawn := make(chan error, 1)
	go func() { withdrawn <- d.Select(nil) }()
	d.mu.Lock()
	if d.cancel != nil {
		d.cancel()
	}
	d.mu.Unlock()
	close(release)
	if err := <-running; err != nil {
		t.Fatal(err)
	}
	if err := <-withdrawn; err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 || d.View().Status != "idle" {
		t.Fatal(d.View())
	}
}

func TestDownloadSmoke(t *testing.T) {
	if os.Getenv("STARRAIL_DOWNLOAD_SMOKE") != "1" {
		t.Skip("set STARRAIL_DOWNLOAD_SMOKE=1 for real loopback HTTPS streaming")
	}
	body := bytes.Repeat([]byte{'A'}, 512*1024)
	var requestsMu sync.Mutex
	requests := []http.Header{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/artifact", 302)
			return
		}
		requestsMu.Lock()
		requests = append(requests, r.Header.Clone())
		count := len(requests)
		requestsMu.Unlock()
		offset := 0
		if header := r.Header.Get("Range"); header != "" {
			_, _ = fmt.Sscanf(header, "bytes=%d-", &offset)
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(body)-offset))
		w.Header().Set("ETag", "\"fixture-v1\"")
		if offset > 0 {
			w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", offset, len(body)-1, len(body)))
			w.WriteHeader(206)
		}
		if count == 1 {
			_, _ = w.Write(body[:65536])
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		_, _ = w.Write(body[offset:])
	}))
	defer server.Close()
	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	d := NewArtifactDownload(t.TempDir(), BuildConfig{TrustedUpdateOrigins: []string{server.URL}})
	d.transport = HTTPSDownloadTransport{roots: roots}
	d.freeBytes = func(string) (uint64, error) { return 1000000000000, nil }
	artifact := downloadTestArtifact()
	artifact.URL = server.URL + "/artifact"
	artifact.Bytes = int64(len(body))
	sum := sha256.Sum256(body)
	artifact.SHA256 = hex.EncodeToString(sum[:])
	if err := d.Select(&artifact); err != nil {
		t.Fatal(err)
	}
	partial := make(chan struct{})
	var once sync.Once
	d.OnChange(func() {
		if d.View().Received >= 65536 {
			once.Do(func() { close(partial) })
		}
	})
	running := make(chan error, 1)
	go func() { running <- d.Start(context.Background()) }()
	select {
	case <-partial:
	case <-time.After(5 * time.Second):
		t.Fatal("stream never progressed")
	}
	_ = d.Pause()
	<-running
	if d.View().Status != "paused" {
		t.Fatal(d.View())
	}
	_ = d.Start(context.Background())
	if d.View().Status != "ready" {
		t.Fatal(d.View())
	}
	requestsMu.Lock()
	recorded := append([]http.Header{}, requests...)
	requestsMu.Unlock()
	if len(recorded) != 2 || recorded[1].Get("Range") != "bytes=65536-" || recorded[1].Get("If-Range") != "\"fixture-v1\"" {
		t.Fatal(recorded)
	}
	for _, headers := range recorded {
		if headers.Get("Authorization") != "" || headers.Get("Cookie") != "" {
			t.Fatal("account credentials leaked")
		}
	}
	path, err := d.VerifiedPath(artifact)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(path)
	if !bytes.Equal(got, body) {
		t.Fatal("wrong bytes")
	}
	response, err := (HTTPSDownloadTransport{roots: roots}).Open(context.Background(), server.URL+"/redirect", 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.Status != 302 {
		t.Fatal("redirect followed")
	}
	if response, err := (HTTPSDownloadTransport{}).Open(context.Background(), server.URL+"/artifact", 0, nil); err == nil {
		response.Body.Close()
		t.Fatal("untrusted TLS accepted")
	}
}
