package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type sessionUpgradePanel struct {
	lifecyclePanel
	logins atomic.Int32
}

func (p *sessionUpgradePanel) Login(ctx context.Context, endpoint, email, password string) (Session, error) {
	p.logins.Add(1)
	return p.DemoPanel.Login(ctx, endpoint, email, password)
}

func startSessionUpgradeController(t *testing.T, dir, version string, panel *sessionUpgradePanel, change func(*ControllerDeps)) (*ClientController, func()) {
	t.Helper()
	raw, err := os.ReadFile("../../config/development.json")
	if err != nil {
		t.Fatal(err)
	}
	var build BuildConfig
	if err := DecodeStrict(raw, &build, 262144); err != nil {
		t.Fatal(err)
	}
	build.NodeCapabilitiesConfirmed = true
	build.PolicyURLs, build.UpdateFeedURLs = []string{}, []string{}
	deps := ControllerDeps{
		Build: build, Version: version, Panel: panel, NetworkDriver: &lifecycleDriver{},
		Secure:       NewSecureStore[Persisted](filepath.Join(dir, "session.v2.enc"), testKeyProvider()),
		Preferences:  NewJSONStore[Preferences](filepath.Join(dir, "preferences.json"), 131072),
		PolicyStore:  NewJSONStore[PolicyRecord](filepath.Join(dir, "policy.json"), 0),
		ReleaseStore: NewJSONStore[PolicyRecord](filepath.Join(dir, "release-index.json"), 0),
		HTTP: transportFunc(func(context.Context, HTTPRequest) (HTTPResponse, error) {
			return HTTPResponse{}, errors.New("no live network in upgrade tests")
		}),
		Parse: func(_ context.Context, raw string, desc SubscriptionDescriptor) (ParsedNodes, error) {
			return ParseSubscription(raw, ParserOptions{Capabilities: build.ProtocolCapabilities, ConfirmedTCPUDP: true, Source: "fixture", AuthoritativeEmpty: desc.AuthoritativeEmpty})
		},
	}
	if change != nil {
		change(&deps)
	}
	c := NewClientController(deps)
	var once sync.Once
	stop := func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := c.Stop(ctx); err != nil {
				t.Error(err)
			}
		})
	}
	t.Cleanup(stop)
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	return c, stop
}

func writeLegacySessionFixture(t *testing.T, dir string) []byte {
	t.Helper()
	// Produced by the v0.2.7 SecureStore with synthetic credentials and the test
	// key (32 bytes of 0x07). Keep this fixture independent of the current writer.
	encoded, err := os.ReadFile("testdata/session-v0.2.7.base64")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "session.v2.enc"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestControllerUpgradeRetainsLoginAndPreferences(t *testing.T) {
	for _, offline := range []bool{false, true} {
		name := "online"
		if offline {
			name = "offline"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeLegacySessionFixture(t, dir)
			panel := &sessionUpgradePanel{}
			if offline {
				panel.err = NewAppError("CONTROL_UNAVAILABLE")
			}
			for _, version := range []string{"0.2.8", "0.2.9", "0.3.0"} {
				c, stop := startSessionUpgradeController(t, dir, version, panel, nil)
				session := c.sessionCopy()
				if session == nil || session.AccountID != "upgrade-fixture" || session.Email != "test@example.invalid" || session.Token != "fixture-only-upgrade-token" || session.Generation != "fixture-login-before-upgrade" {
					t.Fatal("upgrade lost or replaced the saved session")
				}
				view := c.View()
				if !view.LoggedIn || view.Version != version || view.Storage != "encrypted" || panel.logins.Load() != 0 {
					t.Fatal("upgrade required a new login or lost encryption")
				}
				if version == "0.2.8" {
					if err := c.updatePreferences(func(p *Preferences) error {
						p.Theme = "dark"
						p.FavoriteNodeIDs = []string{strings.Repeat("a", 64)}
						p.RecentNodeIDs = []string{strings.Repeat("b", 64)}
						return nil
					}); err != nil {
						t.Fatal(err)
					}
				} else if view.Preferences.Theme != "dark" || len(view.Preferences.FavoriteNodeIDs) != 1 || len(view.Preferences.RecentNodeIDs) != 1 {
					t.Fatal("upgrade lost saved preferences")
				}
				stop()
				ciphertext, err := os.ReadFile(filepath.Join(dir, "session.v2.enc"))
				if err != nil || bytes.Contains(ciphertext, []byte(session.Token)) {
					t.Fatal("session missing or stored as plaintext", err)
				}
			}
		})
	}
}

func TestControllerUpgradeKeepsLoginAfterOfflineShutdown(t *testing.T) {
	dir := t.TempDir()
	panel := &sessionUpgradePanel{}
	c, stop := startSessionUpgradeController(t, dir, "0.2.8", panel, nil)
	if result := commandForTest(c, map[string]any{"type": "login", "email": "test@example.invalid", "password": "fixture-only"}); !result.OK {
		t.Fatal("fixture login failed", result.Error)
	}
	session := c.sessionCopy()
	stop()
	panel.mu.Lock()
	panel.err = NewAppError("CONTROL_UNAVAILABLE")
	panel.mu.Unlock()
	upgraded, stopUpgrade := startSessionUpgradeController(t, dir, "0.2.9", panel, nil)
	if restored := upgraded.sessionCopy(); restored == nil || *restored != *session || !upgraded.View().LoggedIn || panel.logins.Load() != 1 || upgraded.View().Sync != "UsingValidCache" {
		t.Fatal("offline restart lost the saved login or cache")
	}
	stopUpgrade()
}

func TestControllerUpgradeDoesNotRestoreLogoutOrRevokedSession(t *testing.T) {
	for _, kind := range []string{"logout", "revoked"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			writeLegacySessionFixture(t, dir)
			panel := &sessionUpgradePanel{}
			if kind == "revoked" {
				panel.err = NewAppError("AUTH_INVALID")
			}
			c, stop := startSessionUpgradeController(t, dir, "0.2.9", panel, nil)
			if kind == "logout" {
				if result := commandForTest(c, map[string]any{"type": "logout"}); !result.OK {
					t.Fatal(result.Error)
				}
			}
			if c.View().LoggedIn {
				t.Fatal("invalidated session still logged in")
			}
			stop()
			if _, err := os.Stat(filepath.Join(dir, "session.v2.enc")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalidated credentials remained on disk", err)
			}
			panel.mu.Lock()
			panel.err = nil
			panel.mu.Unlock()
			restarted, _ := startSessionUpgradeController(t, dir, "0.3.0", panel, nil)
			if restarted.View().LoggedIn || panel.logins.Load() != 0 {
				t.Fatal("later upgrade resurrected an invalidated login")
			}
		})
	}
}

func TestControllerUpgradeDoesNotImportAnotherProductOrEnvironment(t *testing.T) {
	for _, mismatch := range []string{"product", "environment"} {
		t.Run(mismatch, func(t *testing.T) {
			dir := t.TempDir()
			before := writeLegacySessionFixture(t, dir)
			panel := &sessionUpgradePanel{}
			c, stop := startSessionUpgradeController(t, dir, "0.2.9", panel, func(d *ControllerDeps) {
				if mismatch == "product" {
					d.Build.ProductID = "different-product"
				} else {
					d.Build.Environment = "production"
				}
			})
			if c.View().LoggedIn {
				t.Fatal("upgrade imported an unrelated login")
			}
			stop()
			after, err := os.ReadFile(filepath.Join(dir, "session.v2.enc"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("unrelated saved session was erased", err)
			}
		})
	}
}
