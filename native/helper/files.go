package main

import (
	"archive/zip"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func longRun(ctx context.Context, program, directory string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, program, args...)
	c.Env = safeEnvironment()
	c.Dir = directory
	c.Stdout = io.Discard
	c.Stderr = io.Discard
	configureChild(c)
	if e := c.Run(); e != nil {
		return failure("UPDATE_VERIFY_FAILED")
	}
	return nil
}
func combined(ctx context.Context, program string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, program, args...)
	c.Env = safeEnvironment()
	return c.CombinedOutput()
}
func copyTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, item os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		relative, e := filepath.Rel(source, path)
		if e != nil {
			return e
		}
		target := filepath.Join(destination, relative)
		info, e := item.Info()
		if e != nil {
			return e
		}
		if item.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if item.Type()&os.ModeSymlink != 0 {
			link, e := os.Readlink(path)
			if e != nil {
				return e
			}
			_ = os.Remove(target)
			return os.Symlink(link, target)
		}
		if !info.Mode().IsRegular() {
			return failure("UPDATE_VERIFY_FAILED")
		}
		return copyFile(path, target, info.Mode().Perm())
	})
}
func extractAppZIP(path, destination string, limit int64) error {
	reader, e := zip.OpenReader(path)
	if e != nil {
		return e
	}
	defer reader.Close()
	if len(reader.File) > 100000 {
		return failure("UPDATE_VERIFY_FAILED")
	}
	if e = os.MkdirAll(destination, 0700); e != nil {
		return e
	}
	total := uint64(0)
	seen := map[string]bool{}
	symlinks := map[string]string{}
	for _, entry := range reader.File {
		name := filepath.FromSlash(entry.Name)
		clean := filepath.Clean(name)
		if filepath.IsAbs(name) || clean == ".." || strings.HasPrefix(clean, ".."+string(os.PathSeparator)) || seen[clean] || strings.ContainsAny(name, "\x00\\") {
			return failure("UPDATE_VERIFY_FAILED")
		}
		seen[clean] = true
		total += entry.UncompressedSize64
		if total > uint64(limit) || total > 4*1024*1024*1024 {
			return failure("UPDATE_VERIFY_FAILED")
		}
		target := filepath.Join(destination, clean)
		if entry.FileInfo().IsDir() {
			if e = os.MkdirAll(target, 0755); e != nil {
				return e
			}
			continue
		}
		if e = os.MkdirAll(filepath.Dir(target), 0755); e != nil {
			return e
		}
		input, e := entry.Open()
		if e != nil {
			return e
		}
		if entry.Mode()&os.ModeSymlink != 0 {
			b, e := io.ReadAll(io.LimitReader(input, 4097))
			input.Close()
			if e != nil || len(b) > 4096 {
				return failure("UPDATE_VERIFY_FAILED")
			}
			link := string(b)
			resolved := filepath.Clean(filepath.Join(filepath.Dir(target), link))
			if filepath.IsAbs(link) || !strings.HasPrefix(resolved, destination+string(os.PathSeparator)) {
				return failure("UPDATE_VERIFY_FAILED")
			}
			symlinks[target] = link
			continue
		}
		if !entry.Mode().IsRegular() {
			input.Close()
			return failure("UPDATE_VERIFY_FAILED")
		}
		mode := os.FileMode(0644)
		if entry.Mode()&0111 != 0 {
			mode = 0755
		}
		output, e := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if e != nil {
			input.Close()
			return e
		}
		_, e = io.Copy(output, io.LimitReader(input, int64(entry.UncompressedSize64)+1))
		input.Close()
		output.Close()
		if e != nil {
			return e
		}
	}
	// Create links last, after all regular files, so ZIP paths never traverse archive-created symlinks.
	for path, link := range symlinks {
		if e = os.Symlink(link, path); e != nil {
			return e
		}
	}
	return nil
}
