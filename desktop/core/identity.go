package core

import (
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

var productIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)
var appIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)+$`)
var unsafeDisplayNamePattern = regexp.MustCompile("[\\x00-\\x1f\"'`$\\\\<>&/:*?|]")

func ValidProductID(value string) bool { return productIDPattern.MatchString(value) }
func ValidAppID(value string) bool     { return len(value) <= 120 && appIDPattern.MatchString(value) }
func ValidDisplayName(value string) bool {
	return jsUTF16Length(value) >= 1 && jsUTF16Length(value) <= 64 && !unsafeDisplayNamePattern.MatchString(value)
}

func platformName(platform []string) string {
	if len(platform) > 0 {
		return platform[0]
	}
	if runtime.GOOS == "windows" {
		return "win32"
	}
	return runtime.GOOS
}
func TUNName(platform string) string {
	switch platform {
	case "darwin":
		return "utun50"
	case "win32", "windows":
		return "ProxyTun"
	case "linux":
		return "vbtun0"
	}
	return ""
}
func HelperLabel(build BuildConfig) string { return build.AppID + ".helper" }
func HelperSocket(build BuildConfig, platform ...string) string {
	switch platformName(platform) {
	case "win32", "windows":
		return `\\.\pipe\` + build.ProductID + ".helper.v1"
	case "darwin":
		return "/var/run/" + build.ProductID + "/helper.sock"
	default:
		return "/run/" + build.ProductID + "/helper.sock"
	}
}
func HelperRoot(build BuildConfig, appRoot string, platform ...string) string {
	switch platformName(platform) {
	case "win32", "windows":
		// Respect Windows separators even when validating packages on another OS.
		if strings.Contains(appRoot, `\`) {
			root := strings.TrimRight(appRoot, `\/`)
			index := strings.LastIndexAny(root, `\/`)
			if index >= 0 {
				return root[:index] + `\` + build.ProductID + "-service"
			}
			return build.ProductID + "-service"
		}
		return filepath.Join(filepath.Dir(appRoot), build.ProductID+"-service")
	case "darwin":
		return "/Library/PrivilegedHelperTools/" + HelperLabel(build)
	default:
		return "/usr/lib/" + build.ProductID
	}
}
