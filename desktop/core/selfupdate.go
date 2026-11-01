package core

import (
	"context"
	"encoding/base64"
	"net/url"
	"os"
	"os/exec"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// UpdateService is the network service's privileged installer (NativeDriver).
type UpdateService interface {
	Verified() bool
	Install(ctx context.Context, artifact Artifact, path, envelope string) error
}

// SelfUpdater installs a downloaded, verified update and starts the new version, so
// users never return to the download page.
//
// The network service installs it without a prompt whenever it is running: Windows and
// Linux install the service with the app, macOS once TUN mode has been used (and then
// the bundle is root-owned, which only the service can replace). Without the service,
// macOS replaces the bundle as the user, and otherwise asks for one system
// authorization: macOS for a bundle the user does not own, Windows for the installer,
// Linux for dpkg.
type SelfUpdater struct {
	Service  UpdateService
	Platform string // win32, darwin or linux
	Packaged bool
	// AppRoot is the .app bundle on macOS and the installation directory elsewhere;
	// Executable is the running application.
	AppRoot, Executable string
	// Package is the Linux package name; UninstallKey the Windows uninstall entry the
	// installer writes last, which marks a finished installation.
	Package, UninstallKey string
	// Work is a private directory for staging (the download directory).
	Work string
	Quit func()

	run   func(ctx context.Context, name string, args ...string) error
	spawn func(name string, args, env []string) error
	owned func(root string) bool
}

// Available reports whether this installation can update itself. A development build,
// or an app run from the disk image or Downloads, is sent to the download page.
func (u *SelfUpdater) Available() bool {
	if u == nil || !u.Packaged || u.AppRoot == "" || u.Executable == "" || u.Quit == nil {
		return false
	}
	switch u.Platform {
	case "darwin":
		return strings.HasPrefix(u.AppRoot, "/Applications/") && strings.HasSuffix(u.AppRoot, ".app")
	case "win32":
		return u.UninstallKey != ""
	case "linux":
		return strings.HasPrefix(u.Executable, "/opt/") && u.Package != ""
	}
	return false
}

func (u *SelfUpdater) command(ctx context.Context, name string, args ...string) error {
	if u.run != nil {
		return u.run(ctx, name, args...)
	}
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = time.Second
	return cmd.Run()
}

func (u *SelfUpdater) detached(name string, args, env []string) error {
	if u.spawn != nil {
		return u.spawn(name, args, env)
	}
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), env...)
	detachProcess(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}

// Install applies the update at path (already checked against artifact) and quits; a
// detached watcher starts the new version once the installation has finished.
func (u *SelfUpdater) Install(ctx context.Context, artifact Artifact, path, envelope string) error {
	if !u.Available() {
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	pid := strconv.Itoa(os.Getpid())
	var name string
	var args, env []string
	switch {
	case u.Service != nil && u.Service.Verified():
		if err := u.Service.Install(ctx, artifact, path, envelope); err != nil {
			return err
		}
		name, args, env = u.relaunch(pid, artifact.Version)
	case u.Platform == "darwin":
		if err := u.replaceBundle(ctx, path); err != nil {
			return err
		}
		name, args, env = u.relaunch(pid, artifact.Version)
	case u.Platform == "linux":
		if err := u.command(ctx, "/usr/bin/pkexec", "/usr/bin/dpkg", "--install", path); err != nil {
			return NewAppError("PERMISSION_REQUIRED")
		}
		name, args, env = u.relaunch(pid, artifact.Version)
	case u.Platform == "win32":
		// The installer replaces this executable, so it runs after the app has quit.
		setup, err := u.stageInstaller(path, artifact)
		if err != nil {
			return err
		}
		name, args, env = windowsScript(windowsElevatedInstall, map[string]string{"STARRAIL_PID": pid, "STARRAIL_SETUP": setup, "STARRAIL_DIR": u.AppRoot, "STARRAIL_APP": u.Executable})
	default:
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	// The update is in place (or is installed once the app quits); failing to start the
	// new version only means the user opens it.
	_ = u.detached(name, args, env)
	go u.Quit()
	return nil
}

var installerName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,160}\.exe$`)

// stageInstaller copies the verified installer to an .exe the shell can elevate, under
// its published name (Windows treats names containing "setup" or "update" specially).
func (u *SelfUpdater) stageInstaller(path string, artifact Artifact) (string, error) {
	old, _ := filepath.Glob(filepath.Join(u.Work, "*.exe"))
	for _, name := range old {
		_ = os.Remove(name)
	}
	name := "release-" + artifact.Version + ".exe"
	if parsed, err := url.Parse(artifact.URL); err == nil && installerName.MatchString(pathpkg.Base(parsed.Path)) {
		name = pathpkg.Base(parsed.Path)
	}
	setup := filepath.Join(u.Work, name)
	data, err := os.ReadFile(path)
	if err != nil || AtomicWrite(setup, data, nil) != nil {
		return "", NewAppError("STORAGE_FAILED")
	}
	if err := VerifyArtifact(setup, artifact); err != nil {
		_ = os.Remove(setup)
		return "", err
	}
	return setup, nil
}

// replaceBundle swaps the .app for the verified archive's copy: as the user when the
// bundle is theirs, else with one administrator prompt.
func (u *SelfUpdater) replaceBundle(ctx context.Context, archive string) error {
	stage := filepath.Join(u.Work, "stage")
	_ = os.RemoveAll(stage)
	if err := os.MkdirAll(stage, 0700); err != nil {
		return NewAppError("STORAGE_FAILED")
	}
	defer os.RemoveAll(stage)
	app := filepath.Join(stage, filepath.Base(u.AppRoot))
	if err := u.command(ctx, "/usr/bin/ditto", "-x", "-k", archive, stage); err != nil {
		return NewAppError("UPDATE_VERIFY_FAILED")
	}
	if info, err := os.Lstat(app); err != nil || !info.IsDir() {
		return NewAppError("UPDATE_VERIFY_FAILED")
	}
	// Ad-hoc signatures verify as well; a damaged copy would not launch.
	if err := u.command(ctx, "/usr/bin/codesign", "--verify", "--deep", "--strict", app); err != nil {
		return NewAppError("UPDATE_VERIFY_FAILED")
	}
	old := filepath.Join(filepath.Dir(u.AppRoot), "."+filepath.Base(u.AppRoot)+".update-old")
	owned := u.owned
	if owned == nil {
		owned = ownedByUser
	}
	if owned(u.AppRoot) {
		_ = os.RemoveAll(old)
		if err := os.Rename(u.AppRoot, old); err == nil {
			if err := os.Rename(app, u.AppRoot); err != nil {
				if err := u.command(ctx, "/usr/bin/ditto", app, u.AppRoot); err != nil {
					_ = os.RemoveAll(u.AppRoot)
					_ = os.Rename(old, u.AppRoot)
					return NewAppError("STORAGE_FAILED")
				}
			}
			_ = os.RemoveAll(old)
			return nil
		}
	}
	// A root-owned bundle (left by the network service) or a standard account.
	if err := u.command(ctx, "/usr/bin/osascript", "-e", adminShell(macSwapScript, u.AppRoot, app, old)); err != nil {
		return NewAppError("PERMISSION_REQUIRED")
	}
	return nil
}

const macSwapScript = `set -e
rm -rf "$3"
mv "$1" "$3"
if ! /usr/bin/ditto "$2" "$1"; then rm -rf "$1"; mv "$3" "$1"; exit 1; fi
rm -rf "$3"`

// adminShell runs script with arguments $1.. under "do shell script ... with
// administrator privileges". Every value is single-quoted for sh, then escaped for
// the AppleScript string.
func adminShell(script string, args ...string) string {
	quote := func(v string) string { return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" }
	command := "/bin/sh -c " + quote(script) + " sh"
	for _, arg := range args {
		command += " " + quote(arg)
	}
	apple := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(command)
	return `do shell script "` + apple + `" with administrator privileges`
}

// relaunch builds the detached watcher that waits for this process to exit and for the
// new version to be installed, then starts it. It gives up waiting after five minutes
// and starts whatever is installed, so a failed update leaves a running app.
func (u *SelfUpdater) relaunch(pid, version string) (string, []string, []string) {
	switch u.Platform {
	case "darwin":
		return "/bin/sh", []string{"-c", macRelaunch, "sh", pid, version, u.AppRoot}, nil
	case "linux":
		return "/bin/sh", []string{"-c", linuxRelaunch, "sh", pid, version, u.Executable, u.Package}, nil
	}
	return windowsScript(windowsRelaunch, map[string]string{"STARRAIL_PID": pid, "STARRAIL_VERSION": version, "STARRAIL_KEY": u.UninstallKey, "STARRAIL_APP": u.Executable})
}

const macRelaunch = `while kill -0 "$1" 2>/dev/null; do sleep 0.2; done
i=0
while [ $i -lt 600 ]; do
  [ "$(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "$3/Contents/Info.plist" 2>/dev/null)" = "$2" ] && break
  sleep 0.5; i=$((i+1))
done
sleep 1
exec /usr/bin/open "$3" --args --updated`

const linuxRelaunch = `while kill -0 "$1" 2>/dev/null; do sleep 0.2; done
i=0
while [ $i -lt 600 ]; do
  [ "$(dpkg-query -W -f='${Version}' "$4" 2>/dev/null)" = "$2" ] && break
  sleep 0.5; i=$((i+1))
done
sleep 1
exec "$3" --updated >/dev/null 2>&1`

// The network service runs the installer; DisplayVersion is written after it has
// reinstalled the service, so the new version starts with the service ready.
const windowsRelaunch = `$ErrorActionPreference = 'SilentlyContinue'
Wait-Process -Id ([int]$env:STARRAIL_PID) -Timeout 60
$key = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\' + $env:STARRAIL_KEY
for ($i = 0; $i -lt 600; $i++) {
  if ((Get-ItemProperty -LiteralPath $key).DisplayVersion -eq $env:STARRAIL_VERSION) { break }
  Start-Sleep -Milliseconds 500
}
Start-Sleep -Seconds 1
Start-Process -FilePath $env:STARRAIL_APP -ArgumentList '--updated'`

// Without the network service: one UAC prompt for the installer, which also repairs
// the service. NSIS takes /D= unquoted as its last argument.
const windowsElevatedInstall = `$ErrorActionPreference = 'SilentlyContinue'
Wait-Process -Id ([int]$env:STARRAIL_PID) -Timeout 60
try { Start-Process -FilePath $env:STARRAIL_SETUP -ArgumentList ('/S /D=' + $env:STARRAIL_DIR) -Verb RunAs -Wait -ErrorAction Stop } catch {}
Remove-Item -LiteralPath $env:STARRAIL_SETUP -Force
Start-Process -FilePath $env:STARRAIL_APP -ArgumentList '--updated'`

// windowsScript runs a PowerShell script with its inputs in the environment; the
// script travels base64 encoded, so no value is ever parsed as code.
func windowsScript(script string, values map[string]string) (string, []string, []string) {
	encoded := utf16.Encode([]rune(script))
	raw := make([]byte, 0, len(encoded)*2)
	for _, unit := range encoded {
		raw = append(raw, byte(unit), byte(unit>>8))
	}
	env := make([]string, 0, len(values))
	for _, key := range []string{"STARRAIL_PID", "STARRAIL_VERSION", "STARRAIL_KEY", "STARRAIL_SETUP", "STARRAIL_DIR", "STARRAIL_APP"} {
		if value, ok := values[key]; ok {
			env = append(env, key+"="+value)
		}
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	shell := filepath.Join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	return shell, []string{"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw)}, env
}
