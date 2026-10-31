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
func run(ctx context.Context, program string, input []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, program, args...)
	command.Stdin = bytes.NewReader(input)
	command.Env = safeEnvironment()
	command.WaitDelay = 200 * time.Millisecond
	configureChild(command)
	var output limitedBuffer
	command.Stdout = &output
	command.Stderr = io.Discard
	e := command.Run()
	if e != nil {
		return nil, failure("NETWORK_RECOVERY_REQUIRED")
	}
	return output.Bytes(), nil
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
	app, archive os.FileInfo
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
	archiveInfo, e := os.Stat(installed.AppArchive)
	if e != nil {
		return failure("PERMISSION_REQUIRED")
	}
	unchanged := func(before, after os.FileInfo) bool {
		return before != nil && os.SameFile(before, after) && before.Size() == after.Size() && before.ModTime() == after.ModTime() && before.Mode() == after.Mode()
	}
	if unchanged(peerCache.app, appInfo) && unchanged(peerCache.archive, archiveInfo) {
		return nil
	}
	for path, hash := range map[string]string{installed.AppExecutable: installed.AppSHA256, installed.AppArchive: installed.ArchiveSHA256} {
		if e := protectedFile(path); e != nil {
			return e
		}
		value, e := digestFile(path)
		if e != nil || value != hash {
			return failure("PERMISSION_REQUIRED")
		}
	}
	peerCache.app = appInfo
	peerCache.archive = archiveInfo
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
func logCode(code string) { fmt.Fprintln(os.Stderr, serviceID()+"-helper:", cleanError(failure(code))) }
