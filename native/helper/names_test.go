package main

import (
	"strings"
	"testing"
)

func TestValidIdentity(t *testing.T) {
	good := Build{ProductID: "starrail-network", HelperLabel: "work.starrail.client.helper", DisplayName: "星轨加速"}
	if !validIdentity(good) {
		t.Fatal("valid identity rejected")
	}
	cases := map[string]func(*Build){
		"uppercase id":       func(b *Build) { b.ProductID = "StarRail" },
		"path in id":         func(b *Build) { b.ProductID = "../etc" },
		"trailing hyphen":    func(b *Build) { b.ProductID = "starrail-" },
		"short id":           func(b *Build) { b.ProductID = "s" },
		"long id":            func(b *Build) { b.ProductID = "s" + strings.Repeat("a", 40) },
		"label without dots": func(b *Build) { b.HelperLabel = "helper" },
		"label with slash":   func(b *Build) { b.HelperLabel = "work.starrail/helper" },
		"empty name":         func(b *Build) { b.DisplayName = "" },
		"name breaks plist":  func(b *Build) { b.DisplayName = "a</string>" },
		"name breaks unit":   func(b *Build) { b.DisplayName = "a\nExecStart=/bin/sh" },
		"name breaks shell":  func(b *Build) { b.DisplayName = "a'; rm -rf /" },
	}
	for name, mutate := range cases {
		b := good
		mutate(&b)
		if validIdentity(b) {
			t.Errorf("%s: accepted %+v", name, b)
		}
	}
}

func TestDerivedNames(t *testing.T) {
	withBuild(t, Build{ProductID: "star-rail-2", HelperLabel: "work.starrail.client.helper", DisplayName: "StarRail"})
	if ruleTag() != "starrail2" || serviceID() != "star-rail-2" {
		t.Fatalf("ruleTag=%q serviceID=%q", ruleTag(), serviceID())
	}
	for _, path := range []string{stateRoot(), helperRoot(), socketPath()} {
		if !strings.Contains(path, "star-rail-2") && !strings.Contains(path, "work.starrail.client.helper") {
			t.Errorf("path %q is not derived from the build", path)
		}
	}
}
