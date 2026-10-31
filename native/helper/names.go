package main

import (
	"regexp"
	"strings"
)

// System identifiers derive from the build so a rebranded client gets its own paths and services.
// The product ID is the stable slug; the display name is free to change between releases.
var productPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{1,38}[a-z0-9]$`)
var labelIDPattern = regexp.MustCompile(`^[a-z][a-z0-9-]*(?:\.[a-z0-9-]+)+$`)

func validIdentity(b Build) bool {
	return productPattern.MatchString(b.ProductID) && labelIDPattern.MatchString(b.HelperLabel) && len(b.HelperLabel) <= 128 &&
		b.DisplayName != "" && len(b.DisplayName) <= 128 && !strings.ContainsAny(b.DisplayName, "\x00\r\n\"'`$\\<>&")
}
func serviceID() string { return build.ProductID }

// ruleTag is the product ID reduced to [a-z0-9] for firewall tables, pf anchors and rule groups.
func ruleTag() string { return strings.ReplaceAll(build.ProductID, "-", "") }
