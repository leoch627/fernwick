//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSocketDirReachableUnderServiceUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := filepath.Join(t.TempDir(), "service")
	for range 2 { // fresh and already existing with the wrong mode
		if e := prepareSocketDir(dir); e != nil {
			t.Fatal(e)
		}
		info, e := os.Stat(dir)
		if e != nil || info.Mode().Perm() != 0o755 {
			t.Fatalf("socket directory mode %v (%v)", info.Mode().Perm(), e)
		}
		_ = os.Chmod(dir, 0o700)
	}
	link := filepath.Join(t.TempDir(), "link")
	if e := os.Symlink(t.TempDir(), link); e != nil {
		t.Fatal(e)
	}
	if prepareSocketDir(link) == nil {
		t.Fatal("followed a symlinked socket directory")
	}
}
