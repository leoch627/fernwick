package core

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type failingReleaseStore struct {
	ValueStore[PolicyRecord]
	fail *atomic.Bool
}

func (s failingReleaseStore) Save(p PolicyRecord, current func() bool) error {
	if s.fail.Load() {
		return NewAppError("STORAGE_FAILED")
	}
	return s.ValueStore.Save(p, current)
}

func TestUpdateCheckFailuresHaveSpecificReasonsAndOneBrowserFallback(t *testing.T) {
	for _, stage := range []struct {
		name string
		code ErrorCode
	}{{"network", "UPDATE_CHECK_FAILED"}, {"signature", "UPDATE_VERIFY_FAILED"}, {"storage", "UPDATE_STORAGE_FAILED"}} {
		t.Run(stage.name, func(t *testing.T) {
			f, _, envelope := updateFixture(t, "win32", "unsigned")
			var fail, saveFail atomic.Bool
			var opened atomic.Int32
			h := newControllerHarness(t, func(d *ControllerDeps) {
				d.Build.UpdateKeys = f.build.UpdateKeys
				d.Build.UpdateFeedURLs = []string{"https://host.leiterup.de/v1/release"}
				d.Build.TrustedUpdateOrigins = []string{"https://host.leiterup.de"}
				d.Build.TrustedWebOrigins = []string{"https://host.leiterup.de"}
				d.ReleaseStore = failingReleaseStore{d.ReleaseStore, &saveFail}
				d.HTTP = transportFunc(func(context.Context, HTTPRequest) (HTTPResponse, error) {
					if fail.Load() && stage.name == "network" {
						return HTTPResponse{}, NewAppError("CONTROL_UNAVAILABLE")
					}
					if fail.Load() && stage.name == "signature" {
						return HTTPResponse{Status: 200, Body: "untrusted release"}, nil
					}
					return HTTPResponse{Status: 200, Body: envelope}, nil
				})
				d.OpenExternal = func(target, hint string) (bool, error) {
					if target != "https://host.leiterup.de/" || hint != "" {
						t.Errorf("unsafe recovery target %q", target)
					}
					opened.Add(1)
					return true, nil
				}
			}, false)
			c := h.controller
			if err := c.checkUpdate(context.Background()); err != nil {
				t.Fatal(err)
			}
			fail.Store(true)
			saveFail.Store(stage.name == "storage")
			// A passive periodic check records the reason without interrupting the user.
			if err := c.checkUpdate(context.Background()); CodeOf(err) != stage.code || opened.Load() != 0 {
				t.Fatalf("passive check: %v", err)
			}
			for range 2 {
				r := commandForTest(c, map[string]any{"type": "check-update"})
				if r.OK || r.Error != stage.code || r.State.UpdateError == nil || *r.State.UpdateError != stage.code || r.State.Error != nil {
					t.Fatalf("wrong failure: %+v", r)
				}
			}
			if opened.Load() != 1 {
				t.Fatal("repeated automatic browser openings")
			}
			if r := commandForTest(c, map[string]any{"type": "open-download-page"}); !r.OK || opened.Load() != 2 {
				t.Fatal("manual recovery should remain available")
			}
		})
	}
}

type rejectedInstaller struct{ code ErrorCode }

func (rejectedInstaller) Available() bool { return true }
func (i rejectedInstaller) Install(context.Context, Artifact, string, string) error {
	return NewAppError(i.code)
}

func TestUpdateInstallationFailureAndCancellation(t *testing.T) {
	for _, code := range []ErrorCode{"PERMISSION_REQUIRED", "UPDATE_VERIFY_FAILED", "CANCELLED"} {
		t.Run(string(code), func(t *testing.T) {
			f, _, envelope := updateFixture(t, "win32", "unsigned")
			download := &readyDownload{}
			download.ready.Store(true)
			opened := []string{}
			h := updateHarness(t, "win32", envelope, f, download, rejectedInstaller{code}, &opened)
			if err := h.controller.checkUpdate(context.Background()); err != nil {
				t.Fatal(err)
			}
			r := commandForTest(h.controller, map[string]any{"type": "install-update"})
			if r.OK || r.State.Installing {
				t.Fatal("failed update left installing")
			}
			if code == "CANCELLED" {
				if len(opened) != 0 || r.State.UpdateError != nil {
					t.Fatal("cancellation treated as failure")
				}
			} else if len(opened) != 1 || r.State.UpdateError == nil || *r.State.UpdateError != updateFailureCode(NewAppError(code)) {
				t.Fatalf("no install recovery: %+v", r)
			}
		})
	}
}

func TestDownloadFailureOpensManualPageWithoutConnectionError(t *testing.T) {
	f, _, envelope := updateFixture(t, "win32", "unsigned")
	var opened atomic.Int32
	h := newControllerHarness(t, func(d *ControllerDeps) {
		d.Platform, d.Arch, d.Version = "win32", "x64", "1.0.0"
		d.Build.UpdateKeys = f.build.UpdateKeys
		d.Build.UpdateFeedURLs = []string{"https://host.leiterup.de/v1/release"}
		d.Build.TrustedUpdateOrigins = []string{"https://host.leiterup.de"}
		d.Build.TrustedWebOrigins = []string{"https://host.leiterup.de"}
		d.OSCompatible = func(string) bool { return true }
		d.HTTP = transportFunc(func(context.Context, HTTPRequest) (HTTPResponse, error) {
			return HTTPResponse{Status: 200, Body: envelope}, nil
		})
		d.Download = &failedDownload{}
		d.Installer = rejectedInstaller{"UPDATE_INSTALL_FAILED"}
		d.OpenExternal = func(string, string) (bool, error) { opened.Add(1); return true, nil }
	}, false)
	if err := h.controller.checkUpdate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := commandForTest(h.controller, map[string]any{"type": "install-update"}); !r.OK {
		t.Fatal(r)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		v := h.controller.View()
		if strings.Contains(v.Update, "已打开手动下载页") {
			if v.Error != nil || v.UpdateError == nil || *v.UpdateError != "UPDATE_DOWNLOAD_FAILED" || v.Installing || opened.Load() != 1 {
				t.Fatalf("bad recovery: %+v", v)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no recovery: %+v", v)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestFallbackDoesNotClaimBrowserOpenedOrUseUntrustedOrigin(t *testing.T) {
	for _, trusted := range []bool{true, false} {
		var attempts atomic.Int32
		h := newControllerHarness(t, func(d *ControllerDeps) {
			d.Build.TrustedUpdateOrigins = []string{"https://host.leiterup.de"}
			d.Build.TrustedWebOrigins = []string{}
			if trusted {
				d.Build.TrustedWebOrigins = []string{"https://host.leiterup.de"}
			}
			d.OpenExternal = func(string, string) (bool, error) { attempts.Add(1); return false, nil }
		}, false)
		h.controller.updateFailed(NewAppError("UPDATE_DOWNLOAD_FAILED"))
		h.controller.updateFailed(NewAppError("UPDATE_DOWNLOAD_FAILED"))
		v := h.controller.View()
		if strings.Contains(v.Update, "已打开") || !strings.Contains(v.Update, "未能打开") {
			t.Fatal(v.Update)
		}
		want := int32(0)
		if trusted {
			want = 1
		}
		if attempts.Load() != want {
			t.Fatalf("browser attempts %d want %d", attempts.Load(), want)
		}
	}
}

func TestConcurrentUpdateFailuresOpenBrowserOnce(t *testing.T) {
	var opened atomic.Int32
	h := newControllerHarness(t, func(d *ControllerDeps) {
		d.Build.TrustedUpdateOrigins = []string{"https://host.leiterup.de"}
		d.Build.TrustedWebOrigins = []string{"https://host.leiterup.de"}
		d.OpenExternal = func(string, string) (bool, error) { opened.Add(1); time.Sleep(10 * time.Millisecond); return true, nil }
	}, false)
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() { h.controller.updateFailed(NewAppError("UPDATE_DOWNLOAD_FAILED")) })
	}
	wg.Wait()
	status := h.controller.View().Update
	if opened.Load() != 1 || strings.Count(status, "已打开手动下载页") > 1 || strings.Contains(status, "未能打开") {
		t.Fatal(opened.Load(), status)
	}
}

// After the page opened once, a later failure reports itself without claiming the
// browser opened again.
func TestLaterUpdateFailureDoesNotClaimPageOpenedAgain(t *testing.T) {
	var opened atomic.Int32
	h := newControllerHarness(t, func(d *ControllerDeps) {
		d.Build.TrustedUpdateOrigins = []string{"https://host.leiterup.de"}
		d.Build.TrustedWebOrigins = []string{"https://host.leiterup.de"}
		d.OpenExternal = func(string, string) (bool, error) { opened.Add(1); return true, nil }
	}, false)
	h.controller.updateFailed(NewAppError("UPDATE_DOWNLOAD_FAILED"))
	if status := h.controller.View().Update; !strings.Contains(status, "已打开手动下载页") {
		t.Fatal(status)
	}
	h.controller.updateFailed(NewAppError("UPDATE_CHECK_FAILED"))
	if status := h.controller.View().Update; opened.Load() != 1 || status != Messages["UPDATE_CHECK_FAILED"] {
		t.Fatal(opened.Load(), status)
	}
}
