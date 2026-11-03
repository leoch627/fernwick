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

type controllerInstaller struct {
	available bool
	installed chan Artifact
	envelope  string
}

func (i *controllerInstaller) Available() bool { return i.available }
func (i *controllerInstaller) Install(_ context.Context, a Artifact, path, envelope string) error {
	if path != "/fixture/update" {
		return NewAppError("UPDATE_VERIFY_FAILED")
	}
	i.envelope = envelope
	i.installed <- a
	return nil
}

// readyDownload finishes immediately, as a download that completes.
type readyDownload struct {
	controllerDownload
	ready atomic.Bool
}

func (d *readyDownload) Start(ctx context.Context) error {
	_ = d.controllerDownload.Start(ctx)
	d.ready.Store(true)
	return nil
}
func (d *readyDownload) View() DownloadView {
	view := d.controllerDownload.View()
	if d.ready.Load() {
		view.Status = "ready"
	}
	return view
}

// failedDownload ends the way a transfer that broke off does: Start returns and the
// status says failed.
type failedDownload struct{ controllerDownload }

func (d *failedDownload) Start(ctx context.Context) error {
	_ = d.controllerDownload.Start(ctx)
	return nil
}
func (d *failedDownload) View() DownloadView {
	view := d.controllerDownload.View()
	if d.starts.Load() > 0 {
		view.Status = "failed"
	}
	return view
}

func updateFixture(t *testing.T, platform, identity string) (signedFixture, Artifact, string) {
	f := newSignedFixture(t)
	now := time.Now().UnixMilli()
	format, minimum := "nsis", "10.0"
	if platform == "linux" {
		format, minimum = "deb", "24.04"
	}
	if platform == "darwin" {
		format, minimum = "zip", "14.0"
	}
	artifact := Artifact{ID: platform + "-x64-" + format + "-9.0.0", Version: "9.0.0", Platform: platform, Arch: "x64", Format: format, MinimumOS: minimum, URL: "https://host.leiterup.de/releases/app", Bytes: 10, SHA256: strings.Repeat("a", 64), UnpackedBytes: 10, BackupBytes: 10, CoreVersion: "26.10.31", CoreSHA256: strings.Repeat("b", 64), HelperProtocol: 1, SignatureIdentity: identity}
	index := ReleaseIndex{SchemaVersion: 1, ProductID: f.build.ProductID, Environment: f.build.Environment, Channel: f.build.Channel, IssuedAt: isoTime(now - 60000), ExpiresAt: isoTime(now + 3600000), ReleaseSequence: 1, Artifacts: []Artifact{artifact}, WithdrawnIDs: []string{}}
	return f, artifact, f.sign(t, index, "v2board-client-release-v1", "r1")
}

func updateHarness(t *testing.T, platform, envelope string, f signedFixture, download DownloadManager, installer Installer, opened *[]string) *controllerHarness {
	return newControllerHarness(t, func(d *ControllerDeps) {
		d.Platform = platform
		d.Arch = "x64"
		d.Build.UpdateKeys = f.build.UpdateKeys
		d.Build.UpdateFeedURLs = []string{"https://host.leiterup.de/v1/release"}
		d.Build.TrustedUpdateOrigins = []string{"https://host.leiterup.de"}
		d.Download = download
		d.Installer = installer
		d.Version = "1.0.0"
		d.OSCompatible = func(string) bool { return true }
		d.HTTP = transportFunc(func(context.Context, HTTPRequest) (HTTPResponse, error) {
			return HTTPResponse{Status: 200, Body: envelope}, nil
		})
		d.OpenExternal = func(u, hint string) (bool, error) { *opened = append(*opened, u); return true, nil }
	}, false)
}

// Unsigned Windows and macOS builds update in place like Linux; only an installation
// that cannot update itself is sent to the download page.
func TestControllerManualAndInAppUpdateSelection(t *testing.T) {
	for _, test := range []struct {
		platform, identity string
		available          bool
	}{{"win32", "unsigned", true}, {"darwin", "unsigned", true}, {"linux", "unsigned", true}, {"win32", "CN=Moon Cloud Ltd", true}, {"darwin", "unsigned", false}} {
		t.Run(test.platform+test.identity, func(t *testing.T) {
			f, _, envelope := updateFixture(t, test.platform, test.identity)
			download := &controllerDownload{}
			opened := []string{}
			h := updateHarness(t, test.platform, envelope, f, download, &controllerInstaller{available: test.available, installed: make(chan Artifact, 1)}, &opened)
			if result := commandForTest(h.controller, map[string]any{"type": "check-update"}); !result.OK {
				t.Fatal(result)
			}
			if h.controller.View().ManualUpdate == test.available {
				t.Fatal("manual update classification")
			}
			if result := commandForTest(h.controller, map[string]any{"type": "download-update"}); !result.OK {
				t.Fatal(result)
			}
			if !test.available {
				if result := commandForTest(h.controller, map[string]any{"type": "install-update"}); !result.OK {
					t.Fatal(result)
				}
				if len(opened) != 2 || opened[0] != "https://host.leiterup.de/" || download.starts.Load() != 0 {
					t.Fatal("a manual update entered the in-app path")
				}
				return
			}
			deadline := time.Now().Add(time.Second)
			for download.starts.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if download.starts.Load() != 1 || len(opened) != 0 {
				t.Fatal("in-app update did not download")
			}
		})
	}
}

// One click updates: install-update downloads first, then installs the same artifact
// with the signed index it was verified against.
func TestControllerInstallUpdateDownloadsThenInstalls(t *testing.T) {
	f, artifact, envelope := updateFixture(t, "win32", "unsigned")
	download := &readyDownload{}
	installer := &controllerInstaller{available: true, installed: make(chan Artifact, 1)}
	opened := []string{}
	h := updateHarness(t, "win32", envelope, f, download, installer, &opened)
	if result := commandForTest(h.controller, map[string]any{"type": "check-update"}); !result.OK {
		t.Fatal(result)
	}
	if result := commandForTest(h.controller, map[string]any{"type": "install-update"}); !result.OK {
		t.Fatal(result)
	}
	select {
	case got := <-installer.installed:
		if got.ID != artifact.ID || got.SHA256 != artifact.SHA256 || installer.envelope != envelope {
			t.Fatalf("installed %v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("update was downloaded but not installed")
	}
	if download.starts.Load() != 1 || !h.controller.View().Installing || len(opened) != 0 {
		t.Fatal("install state")
	}
	// A second click while installing does nothing.
	if result := commandForTest(h.controller, map[string]any{"type": "install-update"}); !result.OK || len(installer.installed) != 0 {
		t.Fatal("installed twice")
	}
}

func TestControllerReportsAFailedUpdateDownload(t *testing.T) {
	f, _, envelope := updateFixture(t, "win32", "unsigned")
	download := &failedDownload{}
	installer := &controllerInstaller{available: true, installed: make(chan Artifact, 1)}
	opened := []string{}
	h := updateHarness(t, "win32", envelope, f, download, installer, &opened)
	if result := commandForTest(h.controller, map[string]any{"type": "check-update"}); !result.OK {
		t.Fatal(result)
	}
	if result := commandForTest(h.controller, map[string]any{"type": "install-update"}); !result.OK {
		t.Fatal(result)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		view := h.controller.View()
		if view.UpdateError != nil && *view.UpdateError == "UPDATE_DOWNLOAD_FAILED" && !view.Installing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a failed download went unreported: error=%v installing=%v", view.UpdateError, view.Installing)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(installer.installed) != 0 {
		t.Fatal("a failed download was installed")
	}
}

// Update checks are mandatory: one runs at start without any user action, and a
// manual check still works afterwards.
func TestControllerChecksForUpdatesWithoutBeingAsked(t *testing.T) {
	f, _, envelope := updateFixture(t, "linux", "unsigned")
	var requests atomic.Int32
	h := newControllerHarness(t, func(d *ControllerDeps) {
		d.Platform = "linux"
		d.Arch = "x64"
		d.Build.UpdateKeys = f.build.UpdateKeys
		d.Build.UpdateFeedURLs = []string{"https://host.leiterup.de/v1/release"}
		d.Build.TrustedUpdateOrigins = []string{"https://host.leiterup.de"}
		d.Version = "1.0.0"
		d.OSCompatible = func(string) bool { return true }
		d.HTTP = transportFunc(func(_ context.Context, r HTTPRequest) (HTTPResponse, error) {
			if strings.HasSuffix(r.URL, "/v1/release") {
				requests.Add(1)
			}
			return HTTPResponse{Status: 200, Body: envelope}, nil
		})
	}, false)
	deadline := time.Now().Add(3 * time.Second)
	for (requests.Load() == 0 || h.controller.View().Update == "正在检查更新") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if requests.Load() == 0 || !strings.HasPrefix(h.controller.View().Update, "发现新版本 9.0.0") {
		t.Fatalf("no automatic check: %d requests, %q", requests.Load(), h.controller.View().Update)
	}
	before := requests.Load()
	if result := commandForTest(h.controller, map[string]any{"type": "check-update"}); !result.OK || requests.Load() != before+1 {
		t.Fatal("manual check")
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
