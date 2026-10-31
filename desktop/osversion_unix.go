//go:build !windows

package main

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func systemVersion() (string, bool) {
	if runtime.GOOS == "darwin" {
		out, err := exec.Command("/usr/sbin/sysctl", "-n", "kern.osproductversion").Output()
		return strings.TrimSpace(string(out)), err == nil
	}
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return "", false
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[key] = strings.Trim(value, "\"")
		}
	}
	return values["VERSION_ID"], values["ID"] == "ubuntu"
}
