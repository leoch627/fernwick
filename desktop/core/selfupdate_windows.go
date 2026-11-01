package core

import (
	"os/exec"
	"syscall"
)

// detachProcess starts the watcher without a console window, outside the app's
// process group, so closing the app does not end it.
func detachProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: 0x08000000 | 0x00000200} // CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP
}

func ownedByUser(string) bool { return false }
