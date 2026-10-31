package core

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type controllerDownload struct {
	starts       atomic.Int32
	mu           sync.Mutex
	selected     *Artifact
	pauseEntered chan struct{}
	pauseRelease <-chan struct{}
}

func (*controllerDownload) OnChange(func()) {}
func (d *controllerDownload) View() DownloadView {
	d.mu.Lock()
	defer d.mu.Unlock()
	view := DownloadView{Status: "idle"}
	if d.selected != nil {
		version := d.selected.Version
		view.Version = &version
		view.Total = d.selected.Bytes
		view.Status = "available"
	}
	return view
}
func (*controllerDownload) Prune() error { return nil }
func (d *controllerDownload) Select(a *Artifact) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.selected = a
	return nil
}
func (d *controllerDownload) Start(context.Context) error { d.starts.Add(1); return nil }
func (d *controllerDownload) Pause() error {
	d.mu.Lock()
	entered, release := d.pauseEntered, d.pauseRelease
	d.pauseEntered = nil
	d.mu.Unlock()
	if entered != nil {
		close(entered)
	}
	if release != nil {
		<-release
	}
	return nil
}
func (*controllerDownload) Cancel() error                         { return nil }
func (*controllerDownload) VerifiedPath(Artifact) (string, error) { return "/fixture/update", nil }
func TestControllerManualAndNativeUpdateSelection(t *testing.T) {
	for _, test := range []struct {
		platform, identity string
		manual             bool
	}{{"win32", "unsigned", true}, {"darwin", "unsigned", true}, {"linux", "unsigned", false}, {"win32", "CN=Moon Cloud Ltd", false}} {
		t.Run(test.platform+test.identity, func(t *testing.T) {
			f := newSignedFixture(t)
			now := time.Now().UnixMilli()
			format, minimum := "nsis", "10.0"
			if test.platform == "linux" {
				format, minimum = "deb", "24.04"
			}
			if test.platform == "darwin" {
				format, minimum = "zip", "14.0"
			}
			artifact := Artifact{ID: test.platform + "-x64-" + format + "-9.0.0", Version: "9.0.0", Platform: test.platform, Arch: "x64", Format: format, MinimumOS: minimum, URL: "https://host.leiterup.de/releases/app", Bytes: 10, SHA256: strings.Repeat("a", 64), UnpackedBytes: 10, BackupBytes: 10, CoreVersion: "26.10.31", CoreSHA256: strings.Repeat("b", 64), HelperProtocol: 1, SignatureIdentity: test.identity}
			index := ReleaseIndex{SchemaVersion: 1, ProductID: f.build.ProductID, Environment: f.build.Environment, Channel: f.build.Channel, IssuedAt: isoTime(now - 60000), ExpiresAt: isoTime(now + 3600000), ReleaseSequence: 1, Artifacts: []Artifact{artifact}, WithdrawnIDs: []string{}}
			envelope := f.sign(t, index, "v2board-client-release-v1", "r1")
			download := &controllerDownload{}
			opened := []string{}
			h := newControllerHarness(t, func(d *ControllerDeps) {
				d.Platform = test.platform
				d.Arch = "x64"
				d.Build.UpdateKeys = f.build.UpdateKeys
				d.Build.UpdateFeedURLs = []string{"https://host.leiterup.de/v1/release"}
				d.Build.TrustedUpdateOrigins = []string{"https://host.leiterup.de"}
				d.Download = download
				d.Version = "1.0.0"
				d.OSCompatible = func(string) bool { return true }
				d.HTTP = transportFunc(func(context.Context, HTTPRequest) (HTTPResponse, error) {
					return HTTPResponse{Status: 200, Body: envelope}, nil
				})
				d.OpenExternal = func(u, hint string) (bool, error) { opened = append(opened, u); return true, nil }
			}, false)
			if result := commandForTest(h.controller, map[string]any{"type": "check-update"}); !result.OK {
				t.Fatal(result)
			}
			if h.controller.View().ManualUpdate != test.manual {
				t.Fatal("manual update classification")
			}
			if result := commandForTest(h.controller, map[string]any{"type": "download-update"}); !result.OK {
				t.Fatal(result)
			}
			if test.manual {
				if result := commandForTest(h.controller, map[string]any{"type": "install-update"}); !result.OK {
					t.Fatal(result)
				}
				if len(opened) != 2 || opened[0] != "https://host.leiterup.de/" || download.starts.Load() != 0 {
					t.Fatal("unsigned update entered native path")
				}
			} else {
				deadline := time.Now().Add(time.Second)
				for download.starts.Load() == 0 && time.Now().Before(deadline) {
					time.Sleep(time.Millisecond)
				}
				if download.starts.Load() != 1 || len(opened) != 0 {
					t.Fatal("native update did not download")
				}
			}
		})
	}
}
func TestControllerShutdownCleansNetworkBeforeWaitingForDownloads(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	download := &controllerDownload{pauseEntered: entered, pauseRelease: release}
	h := newControllerHarness(t, func(d *ControllerDeps) { d.Download = download }, true)
	before := h.driver.cleanups.Load()
	done := make(chan error, 1)
	go func() { done <- h.controller.Stop(context.Background()) }()
	<-entered
	if h.driver.cleanups.Load() != before+1 || h.controller.View().Connection != "Disconnected" {
		t.Fatal("download blocked network restoration")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
