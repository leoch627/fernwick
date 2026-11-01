//go:build windows

package main

import (
	"context"
	"golang.org/x/sys/windows"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

func secureMacApplication(string) error { return nil }
func availableSpace() (uint64, error) {
	path, e := windows.UTF16PtrFromString(stateRoot())
	if e != nil {
		return 0, e
	}
	var available, total, free uint64
	e = windows.GetDiskFreeSpaceEx(path, &available, &total, &free)
	return available, e
}
func removeHelperInstallation() error {
	var paths []string
	if e := filepath.WalkDir(helperRoot(), func(path string, _ os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		paths = append(paths, path)
		return nil
	}); e != nil {
		return e
	}
	for i := len(paths) - 1; i >= 0; i-- {
		if e := os.Remove(paths[i]); e != nil && !os.IsNotExist(e) {
			name, e := windows.UTF16PtrFromString(paths[i])
			if e != nil {
				return e
			}
			if e = windows.MoveFileEx(name, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT); e != nil {
				return e
			}
		}
	}
	return nil
}
func secureInstallationDirectories() error {
	if e := protectDirectory(helperRoot()); e != nil {
		return e
	}
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if e != nil {
		return e
	}
	acl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(stateRoot(), windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil)
}
func openDownload(path string) (*os.File, error) {
	name, e := windows.UTF16PtrFromString(path)
	if e != nil {
		return nil, e
	}
	h, e := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if e != nil {
		return nil, e
	}
	var info windows.ByHandleFileInformation
	if e = windows.GetFileInformationByHandle(h, &info); e != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.NumberOfLinks != 1 {
		windows.CloseHandle(h)
		return nil, failure("UPDATE_VERIFY_FAILED")
	}
	return os.NewFile(uintptr(h), path), nil
}
func validatePlatformUpdate(ctx context.Context, path string, a Artifact) error {
	// An unsigned installer is trusted through the signed release index alone: its
	// SHA-256 was checked against the index before this call. A signed one must also
	// carry the certificate the index names.
	if unsignedUpdate(a) {
		return nil
	}
	_, e := powershell(ctx, `$s=Get-AuthenticodeSignature -LiteralPath $v.path; if($s.Status -ne 'Valid' -or $s.SignerCertificate.Subject -ne $v.identity){throw 'signature'}`, object{"path": path, "identity": a.SignatureIdentity})
	if e != nil {
		return failure("UPDATE_VERIFY_FAILED")
	}
	return nil
}
func launchUpdateWorker(_ context.Context, worker, id string) error {
	return startDetached(worker, "update-worker", id)
}
func installPlatformUpdate(ctx context.Context, job UpdateJob) error {
	backup := filepath.Join(stateRoot(), "backup")
	_ = os.RemoveAll(backup)
	if e := os.MkdirAll(backup, 0700); e != nil {
		return e
	}
	if e := copyTree(installed.AppRoot, filepath.Join(backup, "app")); e != nil {
		return e
	}
	if e := copyTree(helperRoot(), filepath.Join(backup, "helper")); e != nil {
		return e
	}
	if e := copyFile(filepath.Join(stateRoot(), "installation.json"), filepath.Join(backup, "installation.json"), 0600); e != nil {
		return e
	}
	// NSIS treats /D= as a final argument; no shell or user-supplied command line is used.
	if e := markUpdateApplying(job); e != nil {
		return e
	}
	if e := runInstaller(ctx, job.Path, "/S", "/D="+installed.AppRoot); e != nil {
		_ = stopInstalledService()
		_ = copyTree(filepath.Join(backup, "app"), installed.AppRoot)
		_ = copyTree(filepath.Join(backup, "helper"), helperRoot())
		_ = copyFile(filepath.Join(backup, "installation.json"), filepath.Join(stateRoot(), "installation.json"), 0600)
		_ = platformInstall(installed)
		return e
	}
	return nil
}
func launchRecoveryWorker(_ context.Context, worker, id string) error {
	return startDetached(worker, "update-recover", id)
}
func restorePlatformBackup(context.Context) error {
	backup := filepath.Join(stateRoot(), "backup")
	if e := copyTree(filepath.Join(backup, "app"), installed.AppRoot); e != nil {
		return e
	}
	if e := copyTree(filepath.Join(backup, "helper"), helperRoot()); e != nil {
		return e
	}
	return copyFile(filepath.Join(backup, "installation.json"), filepath.Join(stateRoot(), "installation.json"), 0600)
}

// runInstaller runs the verified installer with the system's environment variables. The
// installer finds the Start menu and the desktop through %ProgramData% and %PUBLIC%,
// which the minimal environment of the network tools lacks: without them it created no
// shortcuts on an in-app update.
func runInstaller(ctx context.Context, path string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	c := exec.CommandContext(ctx, path, args...)
	environment, e := windows.Token(0).Environ(false)
	if e != nil {
		environment = safeEnvironment()
	}
	c.Env = environment
	c.Dir = filepath.Dir(path)
	c.Stdout = io.Discard
	c.Stderr = io.Discard
	configureChild(c)
	if e := c.Run(); e != nil {
		logEvent("update: the installer failed: %v", e)
		return failure("UPDATE_VERIFY_FAILED")
	}
	return nil
}
