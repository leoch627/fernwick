package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

func itoa(v int) string { return strconv.Itoa(v) }
func nonce() string {
	b := make([]byte, 24)
	if _, e := rand.Read(b); e != nil {
		panic("random source unavailable")
	}
	return hex.EncodeToString(b)
}
func digestFile(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Size() > 2*1024*1024*1024 {
		return "", failure("INVALID_INPUT")
	}
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func strictJSON(data []byte, target any) error {
	if len(data) > maxMessage || !utf8.Valid(data) {
		return failure("INVALID_INPUT")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 24 {
			return failure("INVALID_INPUT")
		}
		t, e := d.Token()
		if e != nil {
			return e
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				seen := map[string]bool{}
				for d.More() {
					key, e := d.Token()
					if e != nil {
						return e
					}
					k, ok := key.(string)
					if !ok || seen[k] {
						return failure("INVALID_INPUT")
					}
					seen[k] = true
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
				_, e = d.Token()
				return e
			case '[':
				for d.More() {
					if e = walk(depth + 1); e != nil {
						return e
					}
				}
				_, e = d.Token()
				return e
			default:
				return failure("INVALID_INPUT")
			}
		}
		return nil
	}
	if e := walk(0); e != nil {
		return failure("INVALID_INPUT")
	}
	if _, e := d.Token(); e != io.EOF {
		return failure("INVALID_INPUT")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if e := d.Decode(target); e != nil {
		return failure("INVALID_INPUT")
	}
	return nil
}
func atomicJSON(path string, value any) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	tmp := path + "." + nonce() + ".tmp"
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		return e
	}
	defer os.Remove(tmp)
	data := jsonBytes(value)
	if _, e = f.Write(data); e == nil {
		e = f.Sync()
	}
	if closeErr := f.Close(); e == nil {
		e = closeErr
	}
	if e != nil {
		return e
	}
	if e = replaceFile(tmp, path); e != nil {
		return e
	}
	return syncDirectory(filepath.Dir(path))
}
func readJSON(path string, target any) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, maxMessage+1))
	if e != nil {
		return e
	}
	return strictJSON(b, target)
}
func copyFile(source, destination string, mode os.FileMode) error {
	from, e := os.Open(source)
	if e != nil {
		return e
	}
	defer from.Close()
	if e = os.MkdirAll(filepath.Dir(destination), 0755); e != nil {
		return e
	}
	tmp := destination + "." + nonce() + ".tmp"
	to, e := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	defer os.Remove(tmp)
	_, e = io.Copy(to, from)
	if e == nil {
		e = to.Sync()
	}
	if ce := to.Close(); e == nil {
		e = ce
	}
	if e != nil {
		return e
	}
	return replaceFile(tmp, destination)
}

// run runs a system tool. The caller's context bounds it; ten seconds is only a ceiling
// for a tool that hangs, as a cold system (Windows' first PowerShell or a busy configd)
// can take several seconds for what normally takes a fraction of one.
func run(ctx context.Context, program string, input []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, program, args...)
	command.Stdin = bytes.NewReader(input)
	command.Env = safeEnvironment()
	command.WaitDelay = 200 * time.Millisecond
	configureChild(command)
	var output, diagnostics limitedBuffer
	command.Stdout = &output
	command.Stderr = &diagnostics
	e := command.Run()
	if e != nil {
		logEvent("%s %s: %v: %s", filepath.Base(program), clip(strings.Join(args, " "), 160), e, clip(strings.TrimSpace(diagnostics.String()), 400))
		return nil, failure("NETWORK_RECOVERY_REQUIRED")
	}
	return output.Bytes(), nil
}
func clip(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

// The service's own log, for whoever has to find out why a connection failed on a real
// machine. It records failed steps and system tools, never nodes, credentials or
// traffic, and keeps the previous file when it grows past 512 KB.
var eventLog sync.Mutex

func logEvent(format string, values ...any) {
	eventLog.Lock()
	defer eventLog.Unlock()
	path := filepath.Join(stateRoot(), "helper.log")
	if info, e := os.Stat(path); e == nil && info.Size() > 512*1024 {
		_ = os.Rename(path, path+".1")
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return
	}
	defer f.Close()
	_, _ = fmt.Fprintf(f, "%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, values...))
}

// coreLog collects what the core prints (its version, and why it did not start) in
// core.log, replaced at every start and capped at 256 KB.
func coreLog() io.WriteCloser {
	f, e := os.OpenFile(filepath.Join(stateRoot(), "core.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return nopWriteCloser{}
	}
	return &cappedFile{file: f, left: 256 * 1024}
}

type nopWriteCloser struct{}

func (nopWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopWriteCloser) Close() error                { return nil }

type cappedFile struct {
	mu   sync.Mutex
	file *os.File
	left int
}

func (c *cappedFile) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file != nil && c.left > 0 {
		chunk := p[:min(len(p), c.left)]
		written, _ := c.file.Write(chunk)
		c.left -= written
	}
	return len(p), nil
}
func (c *cappedFile) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.file == nil {
		return nil
	}
	e := c.file.Close()
	c.file = nil
	return e
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > 1024*1024 {
		return 0, failure("INVALID_INPUT")
	}
	return b.Buffer.Write(p)
}
func checkCore() error {
	if installed.CorePath == "" || installed.CoreSHA256 != build.CoreHashes[targetID()] {
		return failure("COMPONENTS_UNAVAILABLE")
	}
	if e := protectedFile(installed.CorePath); e != nil {
		return e
	}
	sum, e := digestFile(installed.CorePath)
	if e != nil || sum != installed.CoreSHA256 {
		return failure("COMPONENTS_UNAVAILABLE")
	}
	return nil
}

var peerCache = struct {
	sync.Mutex
	app os.FileInfo
}{}

func verifyPeer(p Peer) error {
	if p.PID <= 0 || p.User == "" || !samePath(p.Executable, installed.AppExecutable) {
		return failure("PERMISSION_REQUIRED")
	}
	args := strings.ToLower(p.Arguments)
	for _, bad := range []string{"--type=", "--inspect", "--remote-debugging", "--require", "--eval", "--js-flags", "--app=", "electron_run_as_node"} {
		if strings.Contains(args, bad) {
			return failure("PERMISSION_REQUIRED")
		}
	}
	if !validAppArguments(p.Arguments, installed.AppExecutable) {
		return failure("PERMISSION_REQUIRED")
	}
	peerCache.Lock()
	defer peerCache.Unlock()
	appInfo, e := os.Stat(installed.AppExecutable)
	if e != nil {
		return failure("PERMISSION_REQUIRED")
	}
	unchanged := func(before, after os.FileInfo) bool {
		return before != nil && os.SameFile(before, after) && before.Size() == after.Size() && before.ModTime() == after.ModTime() && before.Mode() == after.Mode()
	}
	if unchanged(peerCache.app, appInfo) {
		return nil
	}
	if e := protectedFile(installed.AppExecutable); e != nil {
		return e
	}
	value, e := digestFile(installed.AppExecutable)
	if e != nil || value != installed.AppSHA256 {
		return failure("PERMISSION_REQUIRED")
	}
	peerCache.app = appInfo
	return nil
}
func writeJournal(j *Journal) error {
	if j == nil {
		return nil
	}
	return atomicJSON(filepath.Join(stateRoot(), "network.json"), j)
}
func loadJournal() (*Journal, error) {
	return readJournal(filepath.Join(stateRoot(), "network.json"))
}
func readJournal(path string) (*Journal, error) {
	var j Journal
	e := readJSON(path, &j)
	if os.IsNotExist(e) {
		return nil, nil
	}
	if e != nil {
		return nil, e
	}
	if j.SchemaVersion != 1 || len(j.ID) != 48 || !regexpHex(j.ID) || j.Tun != tunName() || !samePath(j.CorePath, installed.CorePath) {
		return nil, failure("NETWORK_RECOVERY_REQUIRED")
	}
	return &j, nil
}
func regexpHex(s string) bool { _, e := hex.DecodeString(s); return e == nil }
func cleanError(e error) string {
	if e == nil {
		return ""
	}
	for _, v := range []string{"CANCELLED", "INVALID_INPUT", "NO_COMPATIBLE_NODES", "PERMISSION_REQUIRED", "NETWORK_CONFLICT", "COMPONENTS_UNAVAILABLE", "CONNECT_TIMEOUT", "NETWORK_RECOVERY_REQUIRED", "UPDATE_VERIFY_FAILED", "UPDATE_DOWNLOAD_FAILED", "STORAGE_FAILED", "CONTROL_UNAVAILABLE"} {
		if e.Error() == v {
			return v
		}
	}
	return "COMPONENTS_UNAVAILABLE"
}
func applicationResources(appRoot string) string {
	if targetOS() == "darwin" {
		return filepath.Join(appRoot, "Contents", "Resources")
	}
	return filepath.Join(appRoot, "resources")
}
func ensureSameInstallation() error {
	if installed.ProductID != build.ProductID || installed.BuildID != build.BuildID {
		return failure("COMPONENTS_UNAVAILABLE")
	}
	return checkCore()
}
func logCode(code string) {
	fmt.Fprintln(os.Stderr, serviceID()+"-helper:", cleanError(failure(code)))
	logEvent("%s", cleanError(failure(code)))
}
