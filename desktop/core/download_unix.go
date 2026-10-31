//go:build !windows

package core

import (
	"os"
	"syscall"
)

func diskFreeBytes(path string) (uint64, error) {
	var s syscall.Statfs_t
	err := syscall.Statfs(path, &s)
	return uint64(s.Bavail) * uint64(s.Bsize), err
}
func singleLink(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Nlink == 1
}
func openDownloadFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
}
func safeDownloadSlot(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && singleLink(info)
}
