package core

import (
	"testing"
	"time"
)

// The window's reason reaches the view only while it is open on this platform.
func TestMaintenanceWindowAppliesToPlatformAndTime(t *testing.T) {
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC).UnixMilli()
	at := func(ms int64) string { return time.UnixMilli(ms).UTC().Format(time.RFC3339Nano) }
	policy := &Policy{Maintenance: &Maintenance{Reason: "机房迁移", StartsAt: at(now), EndsAt: at(now + 3600000), Platforms: []string{"darwin", "win32"}}}
	c := &ClientController{deps: ControllerDeps{Platform: "darwin"}}
	if m := c.maintenanceOf(policy, now); m == nil || m.Reason != "机房迁移" {
		t.Fatalf("open window not reported: %+v", m)
	}
	for name, when := range map[string]int64{"before": now - 1, "at end": now + 3600000} {
		if c.maintenanceOf(policy, when) != nil {
			t.Fatalf("window reported %s", name)
		}
	}
	other := &ClientController{deps: ControllerDeps{Platform: "linux"}}
	if other.maintenanceOf(policy, now) != nil {
		t.Fatal("window reported on a platform it does not name")
	}
	if c.maintenanceOf(nil, now) != nil || c.maintenanceOf(&Policy{}, now) != nil {
		t.Fatal("window reported without one")
	}
}
