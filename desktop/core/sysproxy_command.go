//go:build !windows

package core

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// systemCommand runs a short settings command and returns its trimmed output.
func systemCommand(ctx context.Context, program string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, program, args...)
	command.WaitDelay = time.Second
	out, err := command.CombinedOutput()
	if err != nil {
		return "", NewAppError("SYSTEM_PROXY_FAILED")
	}
	return strings.TrimSpace(string(out)), nil
}
