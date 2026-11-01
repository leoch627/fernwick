//go:build darwin

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

func secureMacApplication(root string) error {
	return filepath.WalkDir(root, func(path string, item os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		info, e := item.Info()
		if e != nil {
			return e
		}
		if item.Type()&os.ModeSymlink != 0 {
			resolved, e := filepath.EvalSymlinks(path)
			if e != nil || !strings.HasPrefix(resolved, root+string(os.PathSeparator)) {
				return failure("PERMISSION_REQUIRED")
			}
			return os.Lchown(path, 0, 0)
		}
		if e = os.Chown(path, 0, 0); e != nil {
			return e
		}
		mode := os.FileMode(0644)
		if info.IsDir() || info.Mode()&0111 != 0 {
			mode = 0755
		}
		return os.Chmod(path, mode)
	})
}
func validatePlatformUpdate(ctx context.Context, path string, a Artifact) error {
	// Extract only validated ZIP entries to a root-owned staging tree; symlinks stay inside the .app.
	staged := path + ".unpacked"
	_ = os.RemoveAll(staged)
	if e := extractAppZIP(path, staged, a.UnpackedBytes); e != nil {
		return e
	}
	app := filepath.Join(staged, filepath.Base(installed.AppRoot))
	if _, e := os.Stat(app); e != nil {
		return failure("UPDATE_VERIFY_FAILED")
	}
	// Ad-hoc signed bundles verify too; this catches a damaged extraction before the swap.
	if e := longRun(ctx, "/usr/bin/codesign", "", "--verify", "--deep", "--strict", app); e != nil {
		return failure("UPDATE_VERIFY_FAILED")
	}
	// Unsigned (ad-hoc) builds are trusted through the signed release index, which pinned
	// the archive's SHA-256; there is no Team ID or notarization to check.
	if unsignedUpdate(a) {
		return nil
	}
	out, e := combined(ctx, "/usr/bin/codesign", "-dv", "--verbose=4", app)
	if e != nil || !strings.Contains(string(out), "TeamIdentifier="+a.SignatureIdentity+"\n") {
		return failure("UPDATE_VERIFY_FAILED")
	}
	if e := longRun(ctx, "/usr/sbin/spctl", "", "--assess", "--type", "execute", app); e != nil {
		return failure("UPDATE_VERIFY_FAILED")
	}
	return nil
}
func launchUpdateWorker(ctx context.Context, worker, id string) error {
	_, e := run(ctx, "/bin/launchctl", nil, "submit", "-l", build.HelperLabel+".update."+id, "--", worker, "update-worker", id)
	return e
}
func installPlatformUpdate(ctx context.Context, job UpdateJob) error {
	backup := filepath.Join(stateRoot(), "backup", filepath.Base(installed.AppRoot))
	if e := os.MkdirAll(filepath.Dir(backup), 0700); e != nil {
		return e
	}
	if e := os.RemoveAll(backup); e != nil {
		return e
	}
	if e := longRun(ctx, "/usr/bin/ditto", "", installed.AppRoot, backup); e != nil {
		return e
	}
	if e := copyTree(helperRoot(), filepath.Join(filepath.Dir(backup), "helper")); e != nil {
		return e
	}
	if e := copyFile(filepath.Join(stateRoot(), "installation.json"), filepath.Join(filepath.Dir(backup), "installation.json"), 0600); e != nil {
		return e
	}
	staged := filepath.Join(job.Path+".unpacked", filepath.Base(installed.AppRoot))
	replacement := installed.AppRoot + ".update-new"
	_ = os.RemoveAll(replacement)
	if e := longRun(ctx, "/usr/bin/ditto", "", staged, replacement); e != nil {
		return e
	}
	if e := secureMacApplication(replacement); e != nil {
		return e
	}
	if e := markUpdateApplying(job); e != nil {
		return e
	}
	old := installed.AppRoot + ".update-old"
	_ = os.RemoveAll(old)
	if e := os.Rename(installed.AppRoot, old); e != nil {
		return e
	}
	rollback := func() {
		_ = stopInstalledService()
		_ = os.RemoveAll(installed.AppRoot)
		_ = os.Rename(old, installed.AppRoot)
		_ = copyTree(filepath.Join(filepath.Dir(backup), "helper"), helperRoot())
		_ = copyFile(filepath.Join(filepath.Dir(backup), "installation.json"), filepath.Join(stateRoot(), "installation.json"), 0600)
		_ = platformInstall(installed)
	}
	if e := os.Rename(replacement, installed.AppRoot); e != nil {
		rollback()
		return e
	}
	helper := filepath.Join(applicationResources(installed.AppRoot), "native", targetID(), "helper")
	if e := longRun(ctx, helper, "", "install", "--app", installed.AppRoot); e != nil {
		rollback()
		return e
	}
	_ = os.RemoveAll(old)
	_ = os.RemoveAll(job.Path + ".unpacked")
	return nil
}
func launchRecoveryWorker(ctx context.Context, worker, id string) error {
	_, e := run(ctx, "/bin/launchctl", nil, "submit", "-l", build.HelperLabel+".recovery."+id, "--", worker, "update-recover", id)
	return e
}
func restorePlatformBackup(ctx context.Context) error {
	backup := filepath.Join(stateRoot(), "backup")
	if !strings.HasPrefix(installed.AppRoot, "/Applications/") || !strings.HasSuffix(installed.AppRoot, ".app") {
		return failure("UPDATE_VERIFY_FAILED")
	}
	if e := os.RemoveAll(installed.AppRoot); e != nil {
		return e
	}
	if e := longRun(ctx, "/usr/bin/ditto", "", filepath.Join(backup, filepath.Base(installed.AppRoot)), installed.AppRoot); e != nil {
		return e
	}
	if e := copyTree(filepath.Join(backup, "helper"), helperRoot()); e != nil {
		return e
	}
	return copyFile(filepath.Join(backup, "installation.json"), filepath.Join(stateRoot(), "installation.json"), 0600)
}
