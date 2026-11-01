//go:build !windows

package core

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// detachProcess starts the watcher in its own session so it outlives the app.
func detachProcess(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

// ownedByUser reports whether the user owns the bundle and everything in it, so it can
// be replaced without an administrator. The network service makes it root's.
func ownedByUser(root string) bool {
	uid := uint32(os.Getuid())
	owned := true
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uid {
			owned = false
			return filepath.SkipAll
		}
		return nil
	})
	return err == nil && owned
}
