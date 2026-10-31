package core

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"sync"
	"time"
)

type DownloadView struct {
	Status   string  `json:"status"`
	Version  *string `json:"version"`
	Received int64   `json:"received"`
	Total    int64   `json:"total"`
	Error    *string `json:"error"`
}
type DownloadResponse struct {
	Status  int
	Headers map[string]string
	Body    io.ReadCloser
}
type DownloadTransport interface {
	Open(context.Context, string, int64, *string) (DownloadResponse, error)
}
type HTTPSDownloadTransport struct{ roots *x509.CertPool }
type deadlineConn struct{ net.Conn }

func (c deadlineConn) Read(p []byte) (int, error) {
	_ = c.Conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	return c.Conn.Read(p)
}
func (c deadlineConn) Write(p []byte) (int, error) {
	_ = c.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	return c.Conn.Write(p)
}

type downloadBody struct {
	io.ReadCloser
	transport *http.Transport
}

func (b downloadBody) Close() error {
	err := b.ReadCloser.Close()
	b.transport.CloseIdleConnections()
	return err
}
func (transportOptions HTTPSDownloadTransport) Open(ctx context.Context, raw string, offset int64, etag *string) (DownloadResponse, error) {
	if _, err := HTTPSURL(raw); err != nil {
		return DownloadResponse{}, err
	}
	dialer := net.Dialer{Timeout: 15 * time.Second}
	transport := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: transportOptions.roots}, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 15 * time.Second, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := dialer.DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		return deadlineConn{conn}, nil
	}}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, raw, nil)
	if err != nil {
		return DownloadResponse{}, NewAppError("UPDATE_DOWNLOAD_FAILED")
	}
	req.Header.Set("User-Agent", "v2board-client-updater/0.1")
	req.Header.Set("Accept-Encoding", "identity")
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
		if etag != nil {
			req.Header.Set("If-Range", *etag)
		}
	}
	response, err := client.Do(req)
	if err != nil {
		transport.CloseIdleConnections()
		if ctx.Err() != nil {
			return DownloadResponse{}, NewAppError("CANCELLED")
		}
		return DownloadResponse{}, NewAppError("UPDATE_DOWNLOAD_FAILED")
	}
	headers := map[string]string{}
	for key := range response.Header {
		headers[http.CanonicalHeaderKey(key)] = response.Header.Get(key)
	}
	return DownloadResponse{response.StatusCode, headers, downloadBody{response.Body, transport}}, nil
}

type DownloadRecord struct {
	SchemaVersion int      `json:"schemaVersion"`
	Artifact      Artifact `json:"artifact"`
	CreatedAt     int64    `json:"createdAt"`
	ETag          *string  `json:"etag,nullable"`
	Complete      bool     `json:"complete"`
}

func (r DownloadRecord) Validate() error {
	if r.SchemaVersion != 1 || r.CreatedAt < 0 || r.CreatedAt > MaxSafeInteger || r.ETag != nil && !boundedText(*r.ETag, 0, 512) {
		return NewAppError("INVALID_INPUT")
	}
	return r.Artifact.Validate()
}

const downloadMaxAge int64 = 7 * 86400000

var downloadETag = regexp.MustCompile(`^"[^"\r\n]{1,500}"$`)
var contentRange = regexp.MustCompile(`^bytes ([0-9]+)-([0-9]+)/([0-9]+)$`)

type ArtifactDownload struct {
	op          sync.Mutex
	mu          sync.Mutex
	directory   string
	build       BuildConfig
	transport   DownloadTransport
	now         func() int64
	freeBytes   func(string) (uint64, error)
	changed     func()
	artifact    *Artifact
	record      *DownloadRecord
	state       DownloadView
	running     chan struct{}
	cancel      context.CancelFunc
	stopped     bool
	initialized bool
	intent      uint64
}

func NewArtifactDownload(directory string, build BuildConfig) *ArtifactDownload {
	return &ArtifactDownload{directory: directory, build: build, transport: HTTPSDownloadTransport{}, now: func() int64 { return time.Now().UnixMilli() }, freeBytes: diskFreeBytes, state: DownloadView{Status: "idle"}}
}
func (d *ArtifactDownload) OnChange(fn func()) { d.mu.Lock(); d.changed = fn; d.mu.Unlock() }
func (d *ArtifactDownload) View() DownloadView {
	d.mu.Lock()
	defer d.mu.Unlock()
	value := d.state
	if value.Version != nil {
		s := *value.Version
		value.Version = &s
	}
	if value.Error != nil {
		s := *value.Error
		value.Error = &s
	}
	return value
}
func (d *ArtifactDownload) set(fn func(*DownloadView)) {
	d.mu.Lock()
	fn(&d.state)
	changed := d.changed
	d.mu.Unlock()
	if changed != nil {
		changed()
	}
}
func (d *ArtifactDownload) path(name string) string { return filepath.Join(d.directory, name) }
func (d *ArtifactDownload) remove() error {
	for _, name := range []string{"pending.part", "pending.bin", "pending.json"} {
		if err := os.Remove(d.path(name)); err != nil && !os.IsNotExist(err) {
			return NewAppError("STORAGE_FAILED")
		}
	}
	d.mu.Lock()
	d.record = nil
	d.mu.Unlock()
	return nil
}
func (d *ArtifactDownload) Pause() error {
	d.mu.Lock()
	d.intent++
	d.stopped = true
	cancel, done := d.cancel, d.running
	if cancel != nil {
		cancel()
	}
	d.mu.Unlock()
	if done != nil {
		<-done
	}
	return nil
}
func (d *ArtifactDownload) Select(input *Artifact) error {
	var artifact *Artifact
	if input != nil {
		copy := *input
		artifact = &copy
		if err := artifact.Validate(); err != nil {
			return err
		}
		if _, err := TrustedURL(artifact.URL, d.build.TrustedUpdateOrigins); err != nil {
			return err
		}
	}
	d.op.Lock()
	defer d.op.Unlock()
	d.mu.Lock()
	same := d.initialized && reflect.DeepEqual(d.artifact, artifact) && (d.record == nil || d.now()-d.record.CreatedAt <= downloadMaxAge)
	d.mu.Unlock()
	if same {
		return nil
	}
	_ = d.Pause()
	if err := os.MkdirAll(d.directory, 0700); err != nil {
		return NewAppError("STORAGE_FAILED")
	}
	if info, err := os.Lstat(d.directory); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return NewAppError("STORAGE_FAILED")
	}
	d.mu.Lock()
	d.artifact = artifact
	d.initialized = true
	d.stopped = false
	d.mu.Unlock()
	d.resetAvailable()
	record, err := NewJSONStore[DownloadRecord](d.path("pending.json"), 32768).Load()
	if err != nil || record == nil || artifact == nil || !reflect.DeepEqual(record.Artifact, *artifact) || record.CreatedAt > d.now()+120000 || d.now()-record.CreatedAt > downloadMaxAge {
		return d.remove()
	}
	path := d.path("pending.part")
	if record.Complete {
		path = d.path("pending.bin")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > artifact.Bytes || !singleLink(info) || !safeDownloadSlot(path) {
		return d.remove()
	}
	if record.Complete {
		if err := VerifyArtifact(path, *artifact); err != nil {
			return d.remove()
		}
	}
	d.mu.Lock()
	d.record = record
	d.mu.Unlock()
	d.set(func(v *DownloadView) {
		v.Received = info.Size()
		v.Status = "paused"
		if record.Complete {
			v.Status = "ready"
		}
	})
	return nil
}
func (d *ArtifactDownload) resetAvailable() {
	d.mu.Lock()
	a := d.artifact
	d.mu.Unlock()
	d.set(func(v *DownloadView) {
		*v = DownloadView{Status: "idle"}
		if a != nil {
			version := a.Version
			v.Status = "available"
			v.Version = &version
			v.Total = a.Bytes
		}
	})
}
func (d *ArtifactDownload) Start(parent context.Context) error {
	if parent == nil {
		parent = context.Background()
	}
	d.mu.Lock()
	d.intent++
	intent := d.intent
	d.mu.Unlock()
	d.op.Lock()
	d.mu.Lock()
	if intent != d.intent {
		d.mu.Unlock()
		d.op.Unlock()
		return nil
	}
	if d.running != nil {
		done := d.running
		d.mu.Unlock()
		d.op.Unlock()
		select {
		case <-done:
			return nil
		case <-parent.Done():
			return NewAppError("CANCELLED")
		}
	}
	if d.artifact == nil {
		d.mu.Unlock()
		d.op.Unlock()
		return NewAppError("UPDATE_VERIFY_FAILED")
	}
	if d.state.Status == "ready" {
		d.mu.Unlock()
		d.op.Unlock()
		return nil
	}
	a := *d.artifact
	ctx, cancel := context.WithTimeout(parent, 30*time.Minute)
	d.cancel = cancel
	d.stopped = false
	done := make(chan struct{})
	d.running = done
	d.mu.Unlock()
	d.op.Unlock()
	err := d.transfer(ctx, a)
	if err != nil {
		if CodeOf(err) == "UPDATE_VERIFY_FAILED" {
			_ = d.remove()
			d.set(func(v *DownloadView) { v.Received = 0 })
		}
		d.mu.Lock()
		stopped := d.stopped
		d.mu.Unlock()
		d.set(func(v *DownloadView) {
			if stopped {
				v.Status = "paused"
				v.Error = nil
			} else {
				v.Status = "failed"
				message := "更新下载或校验失败，可重试"
				v.Error = &message
			}
		})
	}
	cancel()
	d.mu.Lock()
	d.running = nil
	d.cancel = nil
	close(done)
	d.mu.Unlock()
	return nil
}
func (d *ArtifactDownload) saveRecord(ctx context.Context) error {
	d.mu.Lock()
	record := *d.record
	d.mu.Unlock()
	return NewJSONStore[DownloadRecord](d.path("pending.json"), 32768).Save(record, func() bool { return ctx.Err() == nil })
}
func (d *ArtifactDownload) transfer(ctx context.Context, artifact Artifact) error {
	if err := os.MkdirAll(d.directory, 0700); err != nil {
		return NewAppError("UPDATE_DOWNLOAD_FAILED")
	}
	if info, err := os.Lstat(d.directory); err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return NewAppError("UPDATE_DOWNLOAD_FAILED")
	}
	free, err := d.freeBytes(d.directory)
	if err != nil || free < uint64(RequiredDiskBytes(artifact)) {
		return NewAppError("UPDATE_DOWNLOAD_FAILED")
	}
	if ctx.Err() != nil {
		return NewAppError("CANCELLED")
	}
	d.mu.Lock()
	expired := d.record == nil || d.now()-d.record.CreatedAt > downloadMaxAge
	d.mu.Unlock()
	if expired {
		if err := d.remove(); err != nil {
			return err
		}
		d.mu.Lock()
		d.record = &DownloadRecord{SchemaVersion: 1, Artifact: artifact, CreatedAt: d.now()}
		d.mu.Unlock()
	}
	if err := d.saveRecord(ctx); err != nil {
		return err
	}
	file, err := openDownloadFile(d.path("pending.part"))
	if err != nil {
		return NewAppError("UPDATE_VERIFY_FAILED")
	}
	defer func() {
		if file != nil {
			_ = file.Close()
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !singleLink(info) || info.Size() > artifact.Bytes {
		return NewAppError("UPDATE_VERIFY_FAILED")
	}
	offset := info.Size()
	d.set(func(v *DownloadView) { v.Status = "downloading"; v.Received = offset; v.Error = nil })
	if offset < artifact.Bytes {
		d.mu.Lock()
		etag := d.record.ETag
		d.mu.Unlock()
		raw, err := TrustedURL(artifact.URL, d.build.TrustedUpdateOrigins)
		if err != nil {
			return err
		}
		response, err := d.transport.Open(ctx, raw, offset, etag)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		header := func(name string) string {
			value := response.Headers[http.CanonicalHeaderKey(name)]
			if value == "" {
				value = response.Headers[name]
			}
			return value
		}
		if encoding := header("content-encoding"); encoding != "" && encoding != "identity" {
			return NewAppError("UPDATE_DOWNLOAD_FAILED")
		}
		if response.Status == 200 {
			if offset > 0 {
				if err := file.Truncate(0); err != nil {
					return err
				}
			}
			offset = 0
		} else if response.Status == 206 && offset > 0 {
			m := contentRange.FindStringSubmatch(header("content-range"))
			if m == nil {
				return NewAppError("UPDATE_DOWNLOAD_FAILED")
			}
			start, _ := strconv.ParseInt(m[1], 10, 64)
			end, _ := strconv.ParseInt(m[2], 10, 64)
			total, _ := strconv.ParseInt(m[3], 10, 64)
			if start != offset || end != artifact.Bytes-1 || total != artifact.Bytes {
				return NewAppError("UPDATE_DOWNLOAD_FAILED")
			}
		} else {
			return NewAppError("UPDATE_DOWNLOAD_FAILED")
		}
		if length := header("content-length"); length != "" {
			n, err := strconv.ParseInt(length, 10, 64)
			if err != nil || n != artifact.Bytes-offset {
				return NewAppError("UPDATE_DOWNLOAD_FAILED")
			}
		}
		tag := header("etag")
		d.mu.Lock()
		d.record.ETag = nil
		if downloadETag.MatchString(tag) {
			d.record.ETag = &tag
		}
		d.mu.Unlock()
		if err := d.saveRecord(ctx); err != nil {
			return err
		}
		buffer := make([]byte, 64*1024)
		for {
			n, readErr := response.Body.Read(buffer)
			if ctx.Err() != nil {
				return NewAppError("CANCELLED")
			}
			if n > 0 {
				if offset+int64(n) > artifact.Bytes {
					return NewAppError("UPDATE_VERIFY_FAILED")
				}
				written, err := file.WriteAt(buffer[:n], offset)
				if err != nil || written != n {
					return NewAppError("UPDATE_DOWNLOAD_FAILED")
				}
				offset += int64(n)
				d.set(func(v *DownloadView) { v.Received = offset })
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return NewAppError("UPDATE_DOWNLOAD_FAILED")
			}
		}
	}
	if ctx.Err() != nil {
		return NewAppError("CANCELLED")
	}
	if offset != artifact.Bytes {
		return NewAppError("UPDATE_DOWNLOAD_FAILED")
	}
	if err := file.Sync(); err != nil {
		return err
	}
	d.set(func(v *DownloadView) { v.Status = "verifying" })
	if err := file.Close(); err != nil {
		return err
	}
	file = nil
	if err := VerifyArtifact(d.path("pending.part"), artifact); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return NewAppError("CANCELLED")
	}
	if err := os.Rename(d.path("pending.part"), d.path("pending.bin")); err != nil {
		return err
	}
	d.mu.Lock()
	d.record.Complete = true
	d.mu.Unlock()
	if err := d.saveRecord(ctx); err != nil {
		return err
	}
	d.set(func(v *DownloadView) { v.Status = "ready"; v.Received = artifact.Bytes; v.Error = nil })
	return nil
}
func (d *ArtifactDownload) Cancel() error {
	d.op.Lock()
	defer d.op.Unlock()
	_ = d.Pause()
	err := d.remove()
	d.resetAvailable()
	return err
}
func (d *ArtifactDownload) Prune() error {
	d.op.Lock()
	defer d.op.Unlock()
	d.mu.Lock()
	running := d.running != nil
	expired := d.record != nil && d.now()-d.record.CreatedAt > downloadMaxAge
	d.mu.Unlock()
	if running && !expired {
		return nil
	}
	record, err := NewJSONStore[DownloadRecord](d.path("pending.json"), 32768).Load()
	if err != nil || record == nil || expired || record.CreatedAt > d.now()+120000 || d.now()-record.CreatedAt > downloadMaxAge {
		_ = d.Pause()
		err := d.remove()
		d.resetAvailable()
		return err
	}
	return nil
}
func (d *ArtifactDownload) VerifiedPath(artifact Artifact) (string, error) {
	d.op.Lock()
	defer d.op.Unlock()
	d.mu.Lock()
	valid := d.state.Status == "ready" && d.artifact != nil && d.artifact.ID == artifact.ID && d.artifact.SHA256 == artifact.SHA256 && d.record != nil && d.now()-d.record.CreatedAt <= downloadMaxAge
	d.mu.Unlock()
	if !valid {
		return "", NewAppError("UPDATE_VERIFY_FAILED")
	}
	path := d.path("pending.bin")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || !singleLink(info) || !safeDownloadSlot(path) {
		return "", NewAppError("UPDATE_VERIFY_FAILED")
	}
	if err := VerifyArtifact(path, artifact); err != nil {
		return "", err
	}
	return path, nil
}
