//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

func validatePlatformUpdate(ctx context.Context, path string, a Artifact) error {
	data, e := run(ctx, "/usr/bin/dpkg-deb", nil, "--field", path, "Package", "Version", "Architecture")
	if e != nil {
		return failure("UPDATE_VERIFY_FAILED")
	}
	values := string(data)
	if !strings.Contains(values, "Package: "+build.AppExecutableName+"\n") || !strings.Contains(values, "Version: "+a.Version+"\n") || !strings.Contains(values, "Architecture: amd64") {
		return failure("UPDATE_VERIFY_FAILED")
	}
	return nil
}
func launchUpdateWorker(ctx context.Context, worker, id string) error {
	_, e := run(ctx, fixedTool("systemd-run"), nil, "--unit=starrail-update-"+id, "--collect", "--service-type=exec", worker, "update-worker", id)
	return e
}
func installPlatformUpdate(ctx context.Context, job UpdateJob) error {
	backup := filepath.Join(stateRoot(), "backup")
	if e := os.RemoveAll(backup); e != nil {
		return e
	}
	if e := os.MkdirAll(backup, 0700); e != nil {
		return e
	}
	if e := longRun(ctx, "/usr/bin/dpkg-repack", backup, build.AppExecutableName); e != nil {
		return e
	}
	files, e := filepath.Glob(filepath.Join(backup, build.AppExecutableName+"_*.deb"))
	if e != nil || len(files) != 1 {
		return failure("UPDATE_VERIFY_FAILED")
	}
	if e = markUpdateApplying(job); e != nil {
		return e
	}
	if e = longRun(ctx, "/usr/bin/dpkg", "", "--install", job.Path); e != nil {
		if restore := longRun(ctx, "/usr/bin/dpkg", "", "--install", files[0]); restore != nil {
			return failure("NETWORK_RECOVERY_REQUIRED")
		}
		return e
	}
	return nil
}
func launchRecoveryWorker(ctx context.Context, worker, id string) error {
	_, e := run(ctx, fixedTool("systemd-run"), nil, "--unit=starrail-recovery-"+id, "--collect", "--service-type=exec", worker, "update-recover", id)
	return e
}
func restorePlatformBackup(ctx context.Context) error {
	files, e := filepath.Glob(filepath.Join(stateRoot(), "backup", build.AppExecutableName+"_*.deb"))
	if e != nil || len(files) != 1 {
		return failure("UPDATE_VERIFY_FAILED")
	}
	return longRun(ctx, "/usr/bin/dpkg", "", "--install", files[0])
}
