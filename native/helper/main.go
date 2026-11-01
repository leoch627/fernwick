package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

//go:embed build.json
var buildJSON []byte

func loadInstallation() error {
	if e := protectedFile(filepath.Join(stateRoot(), "installation.json")); e != nil {
		return e
	}
	if e := readJSON(filepath.Join(stateRoot(), "installation.json"), &installed); e != nil {
		return e
	}
	if installed.ProductID != build.ProductID || !samePath(installed.HelperPath, helperExecutable()) || !samePath(installed.CorePath, coreExecutable()) {
		return failure("COMPONENTS_UNAVAILABLE")
	}
	return nil
}
func helperExecutable() string {
	name := "helper"
	if targetOS() == "windows" {
		name += ".exe"
	}
	return filepath.Join(helperRoot(), name)
}
func coreExecutable() string {
	name := "xray"
	if targetOS() == "windows" {
		name += ".exe"
	}
	return filepath.Join(helperRoot(), name)
}
func expectedAppExecutable(root string) string {
	if targetOS() == "darwin" {
		return filepath.Join(root, "Contents", "MacOS", build.AppExecutableName)
	}
	return filepath.Join(root, build.AppExecutableName)
}
func installApplication(root string) error {
	if !filepath.IsAbs(root) || strings.ContainsAny(root, "\r\n\x00") {
		return failure("INVALID_INPUT")
	}
	resolved, e := filepath.EvalSymlinks(root)
	if e != nil || !samePath(root, resolved) {
		return failure("INVALID_INPUT")
	}
	app := expectedAppExecutable(root)
	source := filepath.Join(applicationResources(root), "native", targetID())
	self, e := os.Executable()
	if e != nil {
		return e
	}
	if targetOS() == "darwin" {
		if !strings.HasPrefix(root, "/Applications/") || !strings.HasSuffix(root, ".app") {
			return failure("PERMISSION_REQUIRED")
		}
		if e = secureMacApplication(root); e != nil {
			return e
		}
	}
	for _, path := range []string{app, self, filepath.Join(source, filepath.Base(coreExecutable()))} {
		if e = protectedFile(path); e != nil {
			return e
		}
	}
	coreHash, e := digestFile(filepath.Join(source, filepath.Base(coreExecutable())))
	if e != nil || coreHash != build.CoreHashes[targetID()] {
		return failure("COMPONENTS_UNAVAILABLE")
	}
	if oldErr := loadInstallation(); oldErr == nil {
		if e = stopInstalledService(); e != nil {
			return e
		}
		if e = recoverAlone(); e != nil {
			return e
		}
	}
	if e = os.MkdirAll(helperRoot(), 0755); e != nil {
		return e
	}
	if e = os.MkdirAll(stateRoot(), 0700); e != nil {
		return e
	}
	if e = secureInstallationDirectories(); e != nil {
		return e
	}
	if e = ensureServerIdentity(); e != nil {
		return e
	}
	if !samePath(self, helperExecutable()) {
		if e = copyFile(self, helperExecutable(), 0755); e != nil {
			return e
		}
	}
	if e = copyFile(filepath.Join(source, filepath.Base(coreExecutable())), coreExecutable(), 0755); e != nil {
		return e
	}
	if targetOS() == "windows" {
		path := filepath.Join(source, "wintun.dll")
		sum, e := digestFile(path)
		if e != nil || sum != build.NativeHashes["wintun.dll"] {
			return failure("COMPONENTS_UNAVAILABLE")
		}
		if e = copyFile(path, filepath.Join(helperRoot(), "wintun.dll"), 0644); e != nil {
			return e
		}
	}
	appHash, e := digestFile(app)
	if e != nil {
		return e
	}
	installed = Installation{ProductID: build.ProductID, AppExecutable: app, AppRoot: root, AppSHA256: appHash, CorePath: coreExecutable(), CoreSHA256: coreHash, HelperPath: helperExecutable(), BuildID: build.BuildID}
	if e = atomicJSON(filepath.Join(stateRoot(), "installation.json"), installed); e != nil {
		return e
	}
	return platformInstall(installed)
}
func recoverAlone() error {
	lock, e := machineLock()
	if e != nil {
		return e
	}
	defer lock.Close()
	journal, e := loadJournal()
	if e != nil {
		return e
	}
	s := &service{journal: journal, state: "Disconnected"}
	return s.cleanup()
}
func main() {
	if strictJSON(buildJSON, &build) != nil || len(build.BuildID) != 64 || !validIdentity(build) {
		os.Exit(1)
	}
	if name := build.AppExecutableNames[targetID()]; name != "" {
		build.AppExecutableName = name
	}
	args := os.Args[1:]
	if (len(args) == 2 || len(args) == 3) && args[0] == "probe-core" {
		if len(args) == 3 && args[2] != "--check" {
			os.Exit(1)
		}
		if e := probeWorker(args[1], len(args) == 3); e != nil {
			os.Exit(1)
		}
		return
	}
	if (len(args) == 2 || len(args) == 3) && args[0] == "proxy-core" {
		if len(args) == 3 && args[2] != "--check" {
			os.Exit(1)
		}
		if e := proxyWorker(args[1], len(args) == 3); e != nil {
			os.Exit(1)
		}
		return
	}
	if len(args) == 1 && args[0] == "version" {
		fmt.Printf("%s helper %s protocol %d build %s\n", build.DisplayName, build.Version, protocolVersion, build.BuildID)
		return
	}
	if e := requireAdministrator(); e != nil {
		logCode(cleanError(e))
		os.Exit(1)
	}
	var e error
	switch {
	case len(args) == 3 && args[0] == "install" && args[1] == "--app":
		e = installApplication(args[2])
	case len(args) == 1 && args[0] == "serve":
		pending, recoveryErr := interruptedUpdate()
		if pending || recoveryErr != nil {
			if recoveryErr != nil {
				logCode(cleanError(recoveryErr))
			}
			os.Exit(1)
		}
		e = loadInstallation()
		if e == nil {
			e = ensureSameInstallation()
		}
		if e == nil {
			e = runService()
		}
	case len(args) == 1 && args[0] == "recover":
		e = loadInstallation()
		if e == nil {
			e = recoverAlone()
		}
	case len(args) == 1 && args[0] == "repair":
		e = loadInstallation()
		if e == nil {
			e = stopInstalledService()
		}
		if e == nil {
			e = recoverAlone()
		}
		if e == nil {
			e = platformInstall(installed)
		}
	case len(args) == 1 && args[0] == "uninstall":
		e = loadInstallation()
		if e == nil {
			e = stopInstalledService()
		}
		if e == nil {
			e = recoverAlone()
		}
		if e == nil {
			e = platformUninstall()
		}
		if e == nil {
			_ = os.Remove(filepath.Join(stateRoot(), "installation.json"))
			e = removeHelperInstallation()
		}
	case len(args) == 2 && args[0] == "update-worker":
		e = loadInstallation()
		if e == nil {
			e = applyUpdate(context.Background(), args[1])
		}
	case len(args) == 2 && args[0] == "update-recover":
		e = recoverInterruptedUpdate(args[1])
	default:
		e = failure("INVALID_INPUT")
	}
	if e != nil {
		logCode(cleanError(e))
		os.Exit(1)
	}
}
