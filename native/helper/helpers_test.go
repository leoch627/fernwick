package main

import (
	"os"
	"path/filepath"
	"testing"
)

// withBuild and withInstalled swap the package-level configuration for one test.
func withBuild(t *testing.T, value Build) {
	t.Helper()
	previous := build
	build = value
	t.Cleanup(func() { build = previous })
}
func withInstalled(t *testing.T, value Installation) {
	t.Helper()
	previous := installed
	installed = value
	t.Cleanup(func() { installed = previous })
}
func errorCode(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if e := os.WriteFile(path, []byte(content), 0755); e != nil {
		t.Fatal(e)
	}
	return path
}
