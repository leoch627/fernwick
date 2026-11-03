package core

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// A valid signed feed must survive the service's lowercase HTTP reply, including
// when an installed service is idle or a TUN connection needs its control channel.
func TestControllerChecksSignedReleaseThroughInstalledHelper(t *testing.T) {
	for _, mode := range []string{"idle", "tun", "helper-unavailable"} {
		t.Run(mode, func(t *testing.T) {
			f, artifact, _ := updateFixture(t, "darwin", "unsigned")
			artifact.ID, artifact.Version = "darwin-x64-zip-0.2.8", "0.2.8"
			now := time.Now().UnixMilli()
			envelope := f.sign(t, ReleaseIndex{
				SchemaVersion: 1, ProductID: f.build.ProductID, Environment: f.build.Environment, Channel: f.build.Channel,
				IssuedAt: isoTime(now - 60000), ExpiresAt: isoTime(now + 3600000), ReleaseSequence: 1,
				Artifacts: []Artifact{artifact}, WithdrawnIDs: []string{},
			}, "v2board-client-release-v1", "r1")
			var helperCalls, directCalls atomic.Int32
			driver := testRPCDriver(t, nil, func(input map[string]any) nativeReply {
				helperCalls.Add(1)
				if input["action"] != "control" {
					t.Errorf("unexpected helper action: %v", input["action"])
				}
				if mode == "helper-unavailable" {
					return nativeReply{OK: false, Error: "CONTROL_UNAVAILABLE"}
				}
				return nativeReply{OK: true, HTTP: &HTTPResponse{
					Status: 200, Headers: map[string]string{"content-type": "application/json"}, Body: envelope,
				}}
			})
			driver.verified = true
			if mode != "idle" {
				driver.ticket = "connected-ticket"
			}
			transport := &HelperTransport{native: driver, direct: transportFunc(func(context.Context, HTTPRequest) (HTTPResponse, error) {
				directCalls.Add(1)
				if mode == "tun" {
					return HTTPResponse{}, NewAppError("CONTROL_UNAVAILABLE")
				}
				return HTTPResponse{Status: 200, Body: envelope}, nil
			})}
			download := &controllerDownload{}
			h := newControllerHarness(t, func(d *ControllerDeps) {
				d.Platform, d.Arch, d.Version = "darwin", "x64", "0.2.7"
				d.Build.UpdateKeys = f.build.UpdateKeys
				d.Build.UpdateFeedURLs = []string{"https://host.leiterup.de/v1/release"}
				d.Build.TrustedUpdateOrigins = []string{"https://host.leiterup.de"}
				d.OSCompatible = func(string) bool { return true }
				d.HTTP, d.Download = transport, download
			}, false)
			// Initialization also checks in the background; the explicit call waits
			// for it, and the selected artifact and store prove it actually succeeded.
			if result := commandForTest(h.controller, map[string]any{"type": "check-update"}); !result.OK {
				t.Fatalf("update check failed through %s: %+v", mode, result)
			}
			view := download.View()
			if view.Status != "available" || view.Version == nil || *view.Version != artifact.Version {
				t.Fatalf("signed update was not selected: %+v", view)
			}
			saved, err := h.controller.deps.ReleaseStore.Load()
			if err != nil || saved == nil || saved.Envelope != envelope {
				t.Fatalf("signed release was not saved: %v", err)
			}
			if mode == "idle" && (helperCalls.Load() != 0 || directCalls.Load() == 0) ||
				mode == "tun" && (helperCalls.Load() == 0 || directCalls.Load() != 0) ||
				mode == "helper-unavailable" && (helperCalls.Load() == 0 || directCalls.Load() == 0) {
				t.Fatalf("unexpected route: helper=%d direct=%d", helperCalls.Load(), directCalls.Load())
			}
		})
	}
}
