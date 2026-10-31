package main

import (
	"fmt"
	"golang.org/x/sys/windows"
)

func systemVersion() (string, bool) {
	version := windows.RtlGetVersion()
	return fmt.Sprintf("%d.%d.%d", version.MajorVersion, version.MinorVersion, version.BuildNumber), true
}
