//go:build !windows

package core

import (
	"context"
	"net"
	"os"
	"os/exec"
	"syscall"
)

func dialNative(ctx context.Context, path string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}
func checkNativeSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	return nil
}
func readNativeIdentity(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 || info.Size() > 8192 {
		return nil, NewAppError("COMPONENTS_UNAVAILABLE")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return nil, NewAppError("COMPONENTS_UNAVAILABLE")
	}
	return os.ReadFile(path)
}
func configureNativeChild(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func terminateNativeChild(cmd *exec.Cmd, hard bool) error {
	signal := syscall.SIGTERM
	if hard {
		signal = syscall.SIGKILL
	}
	return syscall.Kill(-cmd.Process.Pid, signal)
}
