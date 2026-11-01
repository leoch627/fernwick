//go:build linux || darwin

package main

import (
	"context"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

func targetOS() string { return runtime.GOOS }
func targetID() string {
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x64"
	}
	return runtime.GOOS + "-" + arch
}
func safeEnvironment() []string {
	return []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", "XRAY_LOCATION_ASSET=" + filepath.Dir(installed.CorePath)}
}
func samePath(a, b string) bool { return filepath.Clean(a) == filepath.Clean(b) }
func protectedFile(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		stat, e := os.Lstat(current)
		if e == nil && runtime.GOOS == "darwin" && current == "/Applications" {
			owner, ok := stat.Sys().(*syscall.Stat_t)
			if ok && owner.Uid == 0 && stat.Mode().Perm()&0002 == 0 {
				return nil
			}
		}
		if e != nil || stat.Mode()&os.ModeSymlink != 0 || stat.Mode().Perm()&0022 != 0 {
			return failure("PERMISSION_REQUIRED")
		}
		owner, ok := stat.Sys().(*syscall.Stat_t)
		if !ok || owner.Uid != 0 {
			return failure("PERMISSION_REQUIRED")
		}
		if current == "/" {
			return nil
		}
	}
}
func replaceFile(from, to string) error { return os.Rename(from, to) }
func syncDirectory(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func machineLock() (io.Closer, error) {
	if e := os.MkdirAll(stateRoot(), 0700); e != nil {
		return nil, e
	}
	file, e := os.OpenFile(filepath.Join(stateRoot(), "machine.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		file.Close()
		return nil, failure("NETWORK_CONFLICT")
	}
	return file, nil
}

// prepareSocketDir creates the socket's directory readable by everyone. The service
// runs with umask 077, so MkdirAll alone leaves it 0700 and the app, running as the
// user, cannot reach the socket however open the socket itself is.
func prepareSocketDir(dir string) error {
	if e := os.MkdirAll(dir, 0755); e != nil {
		return e
	}
	if info, e := os.Lstat(dir); e != nil || !info.IsDir() {
		return failure("PERMISSION_REQUIRED")
	}
	return os.Chmod(dir, 0755)
}
func listenIPC() (net.Listener, error) {
	path := socketPath()
	if e := prepareSocketDir(filepath.Dir(path)); e != nil {
		return nil, e
	}
	if value, e := os.Lstat(path); e == nil {
		if value.Mode()&os.ModeSocket == 0 {
			return nil, failure("PERMISSION_REQUIRED")
		}
		if e = os.Remove(path); e != nil {
			return nil, e
		}
	}
	listener, e := net.Listen("unix", path)
	if e != nil {
		return nil, e
	}
	if e = os.Chmod(path, 0666); e != nil {
		listener.Close()
		return nil, e
	}
	return listener, nil
}
func terminateChild(command *exec.Cmd) error {
	if command.Process == nil {
		return nil
	}
	return unix.Kill(-command.Process.Pid, unix.SIGTERM)
}
func attachCore(*exec.Cmd) error { return nil }
func terminateOrphan(j *Journal) error {
	birth, e := processBirth(j.CorePID)
	if e != nil || birth != j.CoreBirth {
		return nil
	}
	path, _, e := processIdentity(j.CorePID)
	if e != nil || !samePath(path, j.CorePath) {
		return failure("NETWORK_RECOVERY_REQUIRED")
	}
	return unix.Kill(j.CorePID, unix.SIGKILL)
}
func requireAdministrator() error {
	if os.Geteuid() != 0 {
		return failure("PERMISSION_REQUIRED")
	}
	return nil
}
func validAppArguments(args, path string) bool {
	var rest []string
	if strings.ContainsRune(args, '\x00') {
		parts := strings.Split(strings.TrimRight(args, "\x00"), "\x00")
		if len(parts) == 0 || !samePath(parts[0], path) {
			return false
		}
		rest = parts[1:]
	} else {
		if !strings.HasPrefix(args, path) {
			return false
		}
		rest = strings.Fields(strings.TrimPrefix(args, path))
	}
	for _, arg := range rest {
		if !contains([]string{"--hidden", "--autostart", "--updated"}, arg) && !strings.HasPrefix(arg, "-psn_") {
			return false
		}
	}
	return true
}
func runService() error { ctx, cancel := signalContext(); defer cancel(); return serve(ctx) }
func startDetached(path string, args ...string) error {
	command := exec.Command(path, args...)
	command.Env = safeEnvironment()
	command.Stdin = nil
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if e := command.Start(); e != nil {
		return e
	}
	return command.Process.Release()
}
func stopInstalledService() error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return platformStopService(ctx)
}
func secureInstallationDirectories() error { return nil }
func availableSpace() (uint64, error) {
	var stat unix.Statfs_t
	e := unix.Statfs(stateRoot(), &stat)
	return uint64(stat.Bavail) * uint64(stat.Bsize), e
}
func removeHelperInstallation() error { return os.RemoveAll(helperRoot()) }
func openDownload(path string) (*os.File, error) {
	fd, e := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	return os.NewFile(uintptr(fd), path), nil
}
