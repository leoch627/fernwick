//go:build windows

package core

import (
	"context"
	"github.com/Microsoft/go-winio"
	"net"
	"os"
	"os/exec"
	"syscall"
)

func dialNative(ctx context.Context, path string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, path)
}
func checkNativeSocket(string) error { return nil }
func readNativeIdentity(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 8192 {
		return nil, NewAppError("COMPONENTS_UNAVAILABLE")
	}
	return os.ReadFile(path)
}
func configureNativeChild(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}
func terminateNativeChild(cmd *exec.Cmd, _ bool) error { return cmd.Process.Kill() }
