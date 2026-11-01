package core

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf16"
)

type fakeUpdateService struct {
	verified  bool
	installed atomic.Int32
}

func (s *fakeUpdateService) Verified() bool { return s.verified }
func (s *fakeUpdateService) Install(context.Context, Artifact, string, string) error {
	s.installed.Add(1)
	return nil
}

type spawned struct {
	name      string
	args, env []string
}

func testUpdater(t *testing.T, platform string) (*SelfUpdater, *[]string, *[]spawned, *atomic.Int32) {
	commands, children := []string{}, []spawned{}
	quits := &atomic.Int32{}
	u := &SelfUpdater{Platform: platform, Packaged: true, Work: t.TempDir(), Package: "starrail", UninstallKey: "app.starrail", Quit: func() { quits.Add(1) }}
	switch platform {
	case "darwin":
		u.AppRoot, u.Executable = "/Applications/StarRail.app", "/Applications/StarRail.app/Contents/MacOS/StarRail"
	case "linux":
		u.AppRoot, u.Executable = "/opt/StarRail", "/opt/StarRail/starrail"
	default:
		u.AppRoot, u.Executable = `C:\Program Files\StarRail`, `C:\Program Files\StarRail\StarRail.exe`
	}
	u.run = func(_ context.Context, name string, args ...string) error {
		commands = append(commands, strings.Join(append([]string{name}, args...), " "))
		return nil
	}
	u.spawn = func(name string, args, env []string) error {
		children = append(children, spawned{name, args, env})
		return nil
	}
	return u, &commands, &children, quits
}

func waitQuit(t *testing.T, quits *atomic.Int32, want int32) {
	t.Helper()
	for i := 0; i < 1000 && quits.Load() != want; i++ {
		time.Sleep(time.Millisecond)
	}
	if quits.Load() != want {
		t.Fatalf("quit %d times, want %d", quits.Load(), want)
	}
}

func TestSelfUpdaterAvailability(t *testing.T) {
	for _, test := range []struct {
		platform, root, executable string
		packaged, want             bool
	}{
		{"darwin", "/Applications/StarRail.app", "/Applications/StarRail.app/Contents/MacOS/StarRail", true, true},
		{"darwin", "/Volumes/StarRail/StarRail.app", "/Volumes/StarRail/StarRail.app/Contents/MacOS/StarRail", true, false},
		{"darwin", "/Users/me/Downloads/StarRail.app", "/Users/me/Downloads/StarRail.app/Contents/MacOS/StarRail", true, false},
		{"win32", `C:\Program Files\StarRail`, `C:\Program Files\StarRail\StarRail.exe`, true, true},
		{"linux", "/opt/StarRail", "/opt/StarRail/starrail", true, true},
		{"linux", "/home/me/src", "/home/me/src/starrail", true, false},
		{"linux", "/opt/StarRail", "/opt/StarRail/starrail", false, false},
	} {
		u := &SelfUpdater{Platform: test.platform, Packaged: test.packaged, AppRoot: test.root, Executable: test.executable, Package: "starrail", UninstallKey: "app.starrail", Quit: func() {}}
		if got := u.Available(); got != test.want {
			t.Errorf("%s %s: available = %v", test.platform, test.root, got)
		}
	}
	var missing *SelfUpdater
	if missing.Available() {
		t.Error("nil updater is available")
	}
}

// With the network service running, it installs without a prompt and the watcher
// waits for the new version before starting it.
func TestSelfUpdaterPrefersTheNetworkService(t *testing.T) {
	for _, platform := range []string{"darwin", "linux", "win32"} {
		u, commands, children, quits := testUpdater(t, platform)
		service := &fakeUpdateService{verified: true}
		u.Service = service
		if err := u.Install(context.Background(), Artifact{Version: "9.0.0"}, "/fixture/update", "envelope"); err != nil {
			t.Fatal(err)
		}
		waitQuit(t, quits, 1)
		if service.installed.Load() != 1 || len(*commands) != 0 || len(*children) != 1 {
			t.Fatalf("%s: service %d, commands %v, children %v", platform, service.installed.Load(), *commands, *children)
		}
		child := (*children)[0]
		joined := strings.Join(append(child.args, child.env...), " ")
		if !strings.Contains(joined, "9.0.0") {
			t.Fatalf("%s: watcher does not wait for the new version: %v", platform, child)
		}
		if platform == "win32" && (!strings.HasSuffix(child.name, "powershell.exe") || !strings.Contains(decodePowerShell(t, child.args), "DisplayVersion")) {
			t.Fatalf("windows watcher: %v", child)
		}
	}
}

func TestSelfUpdaterLinuxWithoutServiceAsksOnce(t *testing.T) {
	u, commands, children, quits := testUpdater(t, "linux")
	if err := u.Install(context.Background(), Artifact{Version: "9.0.0"}, "/fixture/update.deb", ""); err != nil {
		t.Fatal(err)
	}
	waitQuit(t, quits, 1)
	if len(*commands) != 1 || (*commands)[0] != "/usr/bin/pkexec /usr/bin/dpkg --install /fixture/update.deb" || len(*children) != 1 {
		t.Fatalf("commands %v children %v", *commands, *children)
	}
	// Cancelling the authorization keeps the app running.
	u, _, children, quits = testUpdater(t, "linux")
	u.run = func(context.Context, string, ...string) error { return errors.New("dismissed") }
	if err := u.Install(context.Background(), Artifact{Version: "9.0.0"}, "/fixture/update.deb", ""); CodeOf(err) != "PERMISSION_REQUIRED" || len(*children) != 0 || quits.Load() != 0 {
		t.Fatalf("err %v children %v quits %d", err, *children, quits.Load())
	}
}

// Without the service, Windows quits first: the elevated installer replaces this
// executable, then the watcher starts the new one.
func TestSelfUpdaterWindowsRunsTheInstallerElevated(t *testing.T) {
	u, commands, children, quits := testUpdater(t, "win32")
	body := []byte("MZ installer fixture")
	sum := sha256.Sum256(body)
	source := filepath.Join(t.TempDir(), "pending.bin")
	if err := os.WriteFile(source, body, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(u.Work, "starrail-8.0.0-windows-x64.exe"), []byte("stale"), 0600); err != nil {
		t.Fatal(err)
	}
	artifact := Artifact{Version: "9.0.0", URL: "https://host.example/releases/9.0.0/starrail-9.0.0-windows-x64.exe", Bytes: int64(len(body)), SHA256: hex.EncodeToString(sum[:])}
	if err := u.Install(context.Background(), artifact, source, ""); err != nil {
		t.Fatal(err)
	}
	waitQuit(t, quits, 1)
	setup := filepath.Join(u.Work, "starrail-9.0.0-windows-x64.exe")
	if data, err := os.ReadFile(setup); err != nil || string(data) != string(body) {
		t.Fatal("installer was not staged as an .exe")
	}
	if _, err := os.Stat(filepath.Join(u.Work, "starrail-8.0.0-windows-x64.exe")); !os.IsNotExist(err) {
		t.Fatal("stale installer left behind")
	}
	if len(*commands) != 0 || len(*children) != 1 {
		t.Fatalf("commands %v children %v", *commands, *children)
	}
	script := decodePowerShell(t, (*children)[0].args)
	if !strings.Contains(script, "-Verb RunAs") || !strings.Contains(script, "'/S /D=' + $env:STARRAIL_DIR") {
		t.Fatalf("script: %s", script)
	}
	env := strings.Join((*children)[0].env, "\n")
	for _, want := range []string{"STARRAIL_SETUP=" + setup, `STARRAIL_DIR=C:\Program Files\StarRail`, `STARRAIL_APP=C:\Program Files\StarRail\StarRail.exe`} {
		if !strings.Contains(env, want) {
			t.Fatalf("missing %q in %s", want, env)
		}
	}
	// A file that does not match the signed hash is never run.
	u, _, children, _ = testUpdater(t, "win32")
	artifact.SHA256 = strings.Repeat("0", 64)
	if err := u.Install(context.Background(), artifact, source, ""); CodeOf(err) != "UPDATE_VERIFY_FAILED" || len(*children) != 0 {
		t.Fatalf("unverified installer: %v", err)
	}
}

func TestSelfUpdaterReplacesAUserOwnedBundle(t *testing.T) {
	u, commands, _, _ := testUpdater(t, "darwin")
	applications := t.TempDir()
	u.AppRoot = filepath.Join(applications, "StarRail.app")
	if err := os.MkdirAll(filepath.Join(u.AppRoot, "Contents"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(u.AppRoot, "Contents", "version"), []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	u.owned = func(string) bool { return true }
	u.run = func(_ context.Context, name string, args ...string) error {
		*commands = append(*commands, name)
		if name == "/usr/bin/ditto" && args[0] == "-x" {
			app := filepath.Join(args[3], "StarRail.app", "Contents")
			if err := os.MkdirAll(app, 0755); err != nil {
				return err
			}
			return os.WriteFile(filepath.Join(app, "version"), []byte("new"), 0644)
		}
		return nil
	}
	if err := u.replaceBundle(context.Background(), "/fixture/update.zip"); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(u.AppRoot, "Contents", "version")); string(data) != "new" {
		t.Fatal("bundle not replaced")
	}
	entries, _ := os.ReadDir(applications)
	if len(entries) != 1 || strings.Join(*commands, " ") != "/usr/bin/ditto /usr/bin/codesign" {
		t.Fatalf("left %v, ran %v", entries, *commands)
	}
	// A root-owned bundle takes one administrator prompt.
	*commands = nil
	u.owned = func(string) bool { return false }
	if err := u.replaceBundle(context.Background(), "/fixture/update.zip"); err != nil || strings.Join(*commands, " ") != "/usr/bin/ditto /usr/bin/codesign /usr/bin/osascript" {
		t.Fatalf("err %v ran %v", err, *commands)
	}
}

// Paths reach sh as single arguments whatever quotes they contain.
func TestAdminShellQuotesEveryArgument(t *testing.T) {
	apple := adminShell(`printf '%s\n' "$1" "$2"`, `/Applications/It's "Mine".app`, `C:\odd\path`)
	prefix, suffix := `do shell script "`, `" with administrator privileges`
	if !strings.HasPrefix(apple, prefix) || !strings.HasSuffix(apple, suffix) {
		t.Fatal(apple)
	}
	command := strings.NewReplacer(`\\`, `\`, `\"`, `"`).Replace(strings.TrimSuffix(strings.TrimPrefix(apple, prefix), suffix))
	out, err := exec.Command("/bin/sh", "-c", command).Output()
	if err != nil || string(out) != "/Applications/It's \"Mine\".app\nC:\\odd\\path\n" {
		t.Fatalf("%q %v", out, err)
	}
}

func TestUpdateShellScriptsParse(t *testing.T) {
	for name, script := range map[string]string{"mac relaunch": macRelaunch, "linux relaunch": linuxRelaunch, "mac swap": macSwapScript} {
		if out, err := exec.Command("/bin/sh", "-n", "-c", script).CombinedOutput(); err != nil {
			t.Errorf("%s: %v %s", name, err, out)
		}
	}
}

func decodePowerShell(t *testing.T, args []string) string {
	t.Helper()
	for i, arg := range args {
		if arg == "-EncodedCommand" && i+1 < len(args) {
			raw, err := base64.StdEncoding.DecodeString(args[i+1])
			if err != nil || len(raw)%2 != 0 {
				t.Fatal("bad encoding")
			}
			units := make([]uint16, len(raw)/2)
			for j := range units {
				units[j] = uint16(raw[2*j]) | uint16(raw[2*j+1])<<8
			}
			return string(utf16.Decode(units))
		}
	}
	t.Fatalf("no encoded command in %v", args)
	return ""
}

// The Linux watcher really waits for dpkg to report the new version, then starts the
// app with --updated (the only extra argument the network service accepts).
func TestLinuxRelaunchStartsTheNewVersion(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no POSIX shell")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "started")
	if err := os.WriteFile(filepath.Join(dir, "dpkg-query"), []byte("#!/bin/sh\necho 9.0.0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(dir, "app")
	if err := os.WriteFile(app, []byte("#!/bin/sh\necho \"$@\" > \""+marker+"\"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sh", "-c", linuxRelaunch, "sh", "2147483646", "9.0.0", app, "starrail")
	cmd.Env = append(os.Environ(), "PATH="+dir+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if data, err := os.ReadFile(marker); err != nil || strings.TrimSpace(string(data)) != "--updated" {
		t.Fatalf("app started with %q (%v)", data, err)
	}
}
