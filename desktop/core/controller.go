package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

type ValueStore[T any] interface {
	Load() (*T, error)
	Save(T, func() bool) error
}
type SessionStore interface {
	ValueStore[Persisted]
	Mode() string
	Clear() error
}
type DownloadManager interface {
	OnChange(func())
	View() DownloadView
	Prune() error
	Select(*Artifact) error
	Start(context.Context) error
	Pause() error
	Cancel() error
	VerifiedPath(Artifact) (string, error)
}

// Installer applies a verified update in place (SelfUpdater). Available is false where
// the installation cannot update itself; the user is then sent to the download page.
type Installer interface {
	Available() bool
	Install(context.Context, Artifact, string, string) error
}
type ControllerDeps struct {
	Build             BuildConfig
	Version           string
	Platform          string
	Arch              string
	Panel             Panel
	Secure            SessionStore
	Preferences       ValueStore[Preferences]
	PolicyStore       ValueStore[PolicyRecord]
	ReleaseStore      ValueStore[PolicyRecord]
	HTTP              Transport
	Parse             func(context.Context, string, SubscriptionDescriptor) (ParsedNodes, error)
	Probe             ProbeFunc
	Demo              bool
	NetworkDriver     NetworkDriver
	Download          DownloadManager
	Resources         *ResourceCoordinator
	Reminders         *ExpiryReminders
	Installer         Installer
	OpenExternal      func(string, string) (bool, error)
	ExportDiagnostics func(any) error
	LaunchAtLogin     func(bool) error
	OSCompatible      func(string) bool
	// Telemetry reports to the operator's endpoint; nil disables it. SelfCheck runs the
	// network checks attached to a problem report.
	Telemetry *Telemetry
	SelfCheck func(context.Context, []ProxyNode) []map[string]any
}
type savedProbe struct {
	fingerprint string
	latency     *float64
	state       string
}
type suspendIntent struct {
	intent         bool
	generation     uint64
	userGeneration uint64
	session        string
}
type controllerFuture struct {
	done chan struct{}
	err  error
}

// Controller state is protected by mu. Blocking work never holds mu. Each result
// is checked against the session/network generation before it becomes visible.
type ClientController struct {
	mu                                                                    sync.Mutex
	deps                                                                  ControllerDeps
	session                                                               *Session
	snapshot                                                              *Snapshot
	account                                                               *Account
	restrictions                                                          map[ErrorCode]bool
	preferences                                                           Preferences
	startupAttempted                                                      bool
	syncStatus                                                            string
	failure                                                               ErrorCode
	clock                                                                 *ConservativeClock
	pool                                                                  *EndpointPool
	syncer                                                                *SyncCoordinator
	network                                                               *NetworkController
	policy                                                                *PolicyService
	publicCtx                                                             context.Context
	cancelPublic                                                          context.CancelFunc
	loginCancel                                                           context.CancelFunc
	loginGeneration                                                       uint64
	probeCancel                                                           context.CancelFunc
	probeGeneration                                                       uint64
	nextFull, nextAccount, nextPolicy, nextUpdate, nextPersist, nextPrune time.Time
	lastManual, lastProbeBatch, renewalRefresh                            time.Time
	renewalUntil                                                          int64
	updateStatus                                                          string
	policyBusy, updateBusy                                                bool
	// installWhenReady: the user asked to update before the download finished;
	// installing marks the update being applied, after which the app quits.
	installWhenReady, installing bool
	updateDone                   chan struct{}
	releaseWatermark             *Watermark
	releaseIndex                 *ReleaseIndex
	updateArtifact               *Artifact
	releaseEnvelope              string
	lastPolicyVersion            int64
	installedRules               string
	recovery                     *controllerFuture
	suspended                    *suspendIntent
	actualNode                   *string
	closing                      bool
	started                      bool
	tickDone                     chan struct{}
	stopMu                       sync.Mutex
	persistMu                    sync.Mutex
	intentGeneration             uint64
	probeResults                 map[string]savedProbe
	dirty                        chan struct{}
	listeners                    map[uint64]func(AppView)
	listenerID                   uint64
	diagnosticsMu                sync.Mutex
	diagnosticEvents             []map[string]any
	report                       ReportView
}

func NewClientController(deps ControllerDeps) *ClientController {
	if deps.Version == "" {
		deps.Version = "0.1.0"
	}
	if deps.Platform == "" {
		deps.Platform = runtime.GOOS
		if deps.Platform == "windows" {
			deps.Platform = "win32"
		}
	}
	if deps.Arch == "" {
		deps.Arch = runtime.GOARCH
		if deps.Arch == "amd64" {
			deps.Arch = "x64"
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := &ClientController{deps: deps, preferences: DefaultPreferences, clock: NewConservativeClock(0), restrictions: map[ErrorCode]bool{}, syncStatus: "Idle", updateStatus: "尚未检查", report: ReportView{Status: "idle"}, publicCtx: ctx, cancelPublic: cancel, probeResults: map[string]savedProbe{}, dirty: make(chan struct{}, 1), listeners: map[uint64]func(AppView){}, diagnosticEvents: []map[string]any{}}
	c.pool = NewEndpointPool(deps.Build.APIEndpoints, c.now)
	c.policy = NewPolicyService(deps.Build, func(record PolicyRecord) error { return deps.PolicyStore.Save(record, nil) }, c.now)
	c.network = NewNetworkController(deps.NetworkDriver, c.emit)
	c.syncer = NewSyncCoordinator(deps.Build, deps.Panel, c.pool, SyncHooks{
		Session: c.sessionCopy, Policy: c.policy.Active, Now: c.now, Snapshot: c.snapshotCopy,
		AccountCurrent: func(generation string, a Account) bool {
			c.mu.Lock()
			if c.closing || c.session == nil || c.session.Generation != generation {
				c.mu.Unlock()
				return false
			}
			c.account = &a
			if c.snapshot != nil {
				s := TightenSnapshot(*c.snapshot, c.maxAge(), &a)
				c.snapshot = &s
			}
			c.mu.Unlock()
			c.emit()
			go func() {
				if e := c.persist(); e != nil {
					c.fail("STORAGE_FAILED")
				}
			}()
			return true
		},
		RestrictCurrent: c.restrictCurrent, Commit: c.commitSnapshot, DoneCurrent: c.syncDoneCurrent, Parse: deps.Parse,
	})
	if deps.Download != nil {
		deps.Download.OnChange(c.emit)
	}
	if deps.Resources != nil {
		deps.Resources.OnChange(c.emit)
	}
	go c.publish()
	return c
}
func (c *ClientController) now() int64 { return c.clock.Now() }

// SessionEmail is the signed-in account, for telemetry; empty when signed out.
func (c *ClientController) SessionEmail() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil {
		return ""
	}
	return c.session.Email
}
func (c *ClientController) maxAge() int {
	if p := c.policy.Active(); p != nil {
		return p.Refresh.MaxSnapshotAgeSec
	}
	return MaxSnapshotAgeSec
}
func (c *ClientController) sessionCopy() *Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil {
		return nil
	}
	s := *c.session
	return &s
}
func (c *ClientController) snapshotCopy() *Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.snapshot == nil {
		return nil
	}
	s := *c.snapshot
	s.Nodes = append([]ProxyNode{}, s.Nodes...)
	return &s
}
func (c *ClientController) sessionCurrent(generation string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closing && c.session != nil && c.session.Generation == generation
}
func (c *ClientController) gateLocked() ErrorCode {
	now := c.clock.Now()
	return SnapshotGate(SnapshotGateInput{c.deps.Build, c.session, c.snapshot, c.startupAttempted, c.clock.Trusted(), now, c.restrictions})
}
func (c *ClientController) gate() ErrorCode { c.mu.Lock(); defer c.mu.Unlock(); return c.gateLocked() }
func (c *ClientController) emit() {
	select {
	case c.dirty <- struct{}{}:
	default:
	}
}
func (c *ClientController) publish() {
	for {
		select {
		case <-c.publicCtx.Done():
			return
		case <-c.dirty:
			c.mu.Lock()
			closing := c.closing
			listeners := make([]func(AppView), 0, len(c.listeners))
			for _, fn := range c.listeners {
				listeners = append(listeners, fn)
			}
			c.mu.Unlock()
			if closing || len(listeners) == 0 {
				continue
			}
			view := c.View()
			for _, fn := range listeners {
				fn(view)
			}
		}
	}
}
func (c *ClientController) Subscribe(fn func(AppView)) func() {
	c.mu.Lock()
	c.listenerID++
	id := c.listenerID
	c.listeners[id] = fn
	c.mu.Unlock()
	return func() { c.mu.Lock(); delete(c.listeners, id); c.mu.Unlock() }
}
func (c *ClientController) record(stage, code string) {
	c.diagnosticsMu.Lock()
	defer c.diagnosticsMu.Unlock()
	c.diagnosticEvents = append(c.diagnosticEvents, map[string]any{"at": time.Now().UTC().Format(time.RFC3339Nano), "stage": stage, "code": code})
	if len(c.diagnosticEvents) > 200 {
		c.diagnosticEvents = c.diagnosticEvents[len(c.diagnosticEvents)-200:]
	}
	c.deps.Telemetry.Record(stage, map[string]any{"code": code}, false)
}
func (c *ClientController) fail(code ErrorCode) {
	c.mu.Lock()
	if !c.closing {
		c.failure = code
	}
	c.mu.Unlock()
	c.record("lifecycle", string(code))
	c.emit()
}
func (c *ClientController) persistedLocked(snapshot *Snapshot, account *Account, restrictions map[ErrorCode]bool) *Persisted {
	if c.session == nil {
		return nil
	}
	session := *c.session
	codes := []ErrorCode{}
	for code, on := range restrictions {
		if on {
			codes = append(codes, code)
		}
	}
	sort.Slice(codes, func(i, j int) bool { return codes[i] < codes[j] })
	return &Persisted{SchemaVersion: 1, ProductID: c.deps.Build.ProductID, Environment: c.deps.Build.Environment, Session: session, Snapshot: snapshot, Account: account, Restrictions: codes, TimeUpper: c.clock.HighWater()}
}
func (c *ClientController) persist() error {
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	c.mu.Lock()
	data := c.persistedLocked(c.snapshot, c.account, c.restrictions)
	c.mu.Unlock()
	if data == nil {
		return nil
	}
	generation := data.Session.Generation
	return c.deps.Secure.Save(*data, func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.session != nil && c.session.Generation == generation
	})
}
func (c *ClientController) commitSnapshot(ctx context.Context, snapshot Snapshot) error {
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	c.mu.Lock()
	if c.closing || ctx.Err() != nil || c.session == nil || c.session.Generation != snapshot.SessionGeneration {
		c.mu.Unlock()
		return NewAppError("CANCELLED")
	}
	generation := c.session.Generation
	snapshot = TightenSnapshot(snapshot, c.maxAge(), c.account)
	data := c.persistedLocked(&snapshot, &snapshot.Account, map[ErrorCode]bool{})
	c.mu.Unlock()
	current := func() bool { return ctx.Err() == nil && c.sessionCurrent(generation) }
	if err := c.deps.Secure.Save(*data, current); err != nil {
		return err
	}
	c.mu.Lock()
	if c.closing || ctx.Err() != nil || c.session == nil || c.session.Generation != generation {
		c.mu.Unlock()
		return NewAppError("CANCELLED")
	}
	snapshot = TightenSnapshot(snapshot, c.maxAge(), c.account)
	c.snapshot = &snapshot
	c.account = &snapshot.Account
	c.restrictions = map[ErrorCode]bool{}
	c.clock.RevalidateAfterOnlineSync()
	for id, result := range c.probeResults {
		found := false
		for _, n := range snapshot.Nodes {
			if n.ID == id && n.ConnectionFingerprint == result.fingerprint {
				found = true
				break
			}
		}
		if !found {
			delete(c.probeResults, id)
		}
	}
	disconnect := false
	if c.actualNode != nil {
		disconnect = true
		for _, n := range snapshot.Nodes {
			if n.ID == *c.actualNode {
				disconnect = false
				break
			}
		}
	}
	c.mu.Unlock()
	if disconnect {
		return c.network.Disconnect(ctx)
	}
	return nil
}
func (c *ClientController) syncDone(code ErrorCode) {
	c.syncDoneCurrent("", code)
}
func (c *ClientController) syncDoneCurrent(generation string, code ErrorCode) {
	c.mu.Lock()
	if c.closing || generation != "" && (c.session == nil || c.session.Generation != generation) {
		c.mu.Unlock()
		return
	}
	c.startupAttempted = true
	c.failure = code
	gate := c.gateLocked()
	switch {
	case code != "" && gate == "":
		c.syncStatus = "UsingValidCache"
	case gate == "AUTH_INVALID":
		c.syncStatus = "NeedsLogin"
	case gate != "" && len(c.restrictions) > 0:
		c.syncStatus = "Denied"
	case gate != "":
		c.syncStatus = "Unavailable"
	default:
		c.syncStatus = "Fresh"
	}
	c.mu.Unlock()
	event := string(code)
	if event == "" {
		event = "SYNC_COMPLETE"
	}
	c.record("sync", event)
	c.emit()
}
func (c *ClientController) restrict(code ErrorCode) {
	c.restrictCurrent("", code)
}
func (c *ClientController) restrictCurrent(generation string, code ErrorCode) bool {
	c.mu.Lock()
	if c.closing || generation != "" && (c.session == nil || c.session.Generation != generation) {
		c.mu.Unlock()
		return false
	}
	if c.probeCancel != nil {
		c.probeCancel()
	}
	c.restrictions[code] = true
	c.failure = code
	if code == "AUTH_INVALID" {
		c.session = nil
		c.snapshot = nil
		c.account = nil
		c.probeResults = map[string]savedProbe{}
		c.syncStatus = "NeedsLogin"
	}
	loginGeneration := c.loginGeneration
	c.mu.Unlock()
	if code == "AUTH_INVALID" {
		c.syncer.Cancel()
		if err := c.clearSession(loginGeneration); err != nil {
			c.fail("STORAGE_FAILED")
		}
	} else {
		go func() {
			if err := c.persist(); err != nil {
				c.fail("STORAGE_FAILED")
			}
		}()
	}
	if err := c.network.Disconnect(context.Background()); err != nil {
		c.fail("NETWORK_RECOVERY_REQUIRED")
	}
	c.emit()
	return true
}

func (c *ClientController) clearSession(loginGeneration uint64) error {
	c.persistMu.Lock()
	defer c.persistMu.Unlock()
	c.mu.Lock()
	current := c.session == nil && c.loginGeneration == loginGeneration
	c.mu.Unlock()
	if !current {
		return nil
	}
	return c.deps.Secure.Clear()
}
func (c *ClientController) linkLocked(key string, p *Policy) *string {
	if p != nil {
		switch key {
		case "website":
			return &p.Links.Website
		case "renew":
			return &p.Links.Renew
		case "help":
			return &p.Links.Help
		}
	}
	switch key {
	case "website":
		return c.deps.Build.Links.Website
	case "renew":
		return c.deps.Build.Links.Renew
	case "help":
		return c.deps.Build.Links.Help
	}
	return nil
}
func (c *ClientController) manualUpdateLocked() bool {
	return c.updateArtifact != nil && (c.deps.Installer == nil || !c.deps.Installer.Available())
}
func (c *ClientController) View() AppView {
	// Service callbacks never run with their own state lock held.
	p := c.policy.Active()
	network := c.network.View()
	storage := c.deps.Secure.Mode()
	download := DownloadView{Status: "idle"}
	if c.deps.Download != nil {
		download = c.deps.Download.View()
	}
	rules := "内置规则待配置"
	if c.deps.Resources != nil {
		rules = c.deps.Resources.Status()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock.Now()
	gate := c.gateLocked()
	view := AppView{Brand: c.deps.Build.Name, Version: c.deps.Version, Environment: c.deps.Build.Environment, Demo: c.deps.Demo, LoggedIn: c.session != nil, Connection: network.State, SelectedNode: c.preferences.NodeID, ActualNode: c.actualNode, Sync: c.syncStatus, Nodes: []NodeView{}, Preferences: c.preferences, Storage: storage, HelperReady: c.network.Ready(), ProxyPort: c.network.ProxyPort(), Policy: "使用内置设置", Update: c.updateStatus, ManualUpdate: c.manualUpdateLocked(), Installing: c.installing || c.installWhenReady, PendingRenewal: c.renewalUntil > now, Download: download, Rules: rules, ShowTrafficSummary: true, Links: ViewLinks{c.linkLocked("website", p) != nil, c.linkLocked("renew", p) != nil, c.linkLocked("help", p) != nil}, Report: c.report, ReportAvailable: c.deps.Telemetry.Enabled(), Now: now}
	if c.failure != "" {
		e := c.failure
		view.Error = &e
	} else if c.session != nil && c.startupAttempted && gate != "" {
		view.Error = &gate
	}
	if a := c.account; a != nil {
		parts := strings.SplitN(a.Email, "@", 2)
		name := []rune(parts[0])
		domain := ""
		if len(parts) == 2 {
			domain = parts[1]
		}
		status := "权益待验证"
		if a.ServiceAllowed == "yes" {
			status = "套餐可用"
		}
		if denied := Restriction(*a, now); denied != "" {
			status = Messages[denied]
		}
		view.Account = &AccountView{string(name[:min(2, len(name))]) + "***@" + domain, a.PlanName, a.ExpiryKind, a.ExpiresAt, a.QuotaKind, a.UsedBytes, a.QuotaBytes, a.ObservedAt, status}
	}
	if p != nil {
		view.Policy = fmt.Sprintf("已验证策略 v%d", p.PolicyVersion)
		view.ShowTrafficSummary = p.UI.ShowTrafficSummary
		if p.UI.Announcement != nil {
			view.Announcement = &p.UI.Announcement.Text
		}
	}
	if c.snapshot != nil {
		syncTime, until := c.snapshot.FullSyncCompletedAt, c.snapshot.UsableUntil
		view.LastSync = &syncTime
		view.UsableUntil = &until
		for _, n := range c.snapshot.Nodes {
			flag := nodeOperation(n.ID, p)
			if flag != nil && flag.HiddenFromList && (c.actualNode == nil || *c.actualNode != n.ID) {
				continue
			}
			node := NodeView{ID: n.ID, Name: n.Name, Group: n.Group, Region: n.Region, Protocol: n.Protocol, Compatible: Eligible(n, p, false), Reason: n.Incompatibility, Probe: "untested"}
			if flag != nil {
				if flag.Group != nil {
					node.Group = *flag.Group
				}
				if flag.DisabledForConnection {
					reason := "运营暂时停用"
					node.Reason = &reason
				}
			}
			if result, ok := c.probeResults[n.ID]; ok && result.fingerprint == n.ConnectionFingerprint {
				node.Probe = result.state
				node.Latency = result.latency
			}
			view.Nodes = append(view.Nodes, node)
		}
	}
	return view
}
func (c *ClientController) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopCancellation := context.AfterFunc(c.publicCtx, cancel)
	defer stopCancellation()
	c.mu.Lock()
	if c.started || c.closing {
		c.mu.Unlock()
		return NewAppError("CANCELLED")
	}
	c.started = true
	c.mu.Unlock()
	if driver, ok := c.deps.NetworkDriver.(interface{ Initialize(context.Context) error }); ok {
		if err := driver.Initialize(ctx); err != nil {
			c.fail(CodeOf(err))
		}
	}
	if ctx.Err() != nil {
		return NewAppError("CANCELLED")
	}
	if c.deps.Download != nil {
		if err := c.deps.Download.Prune(); err != nil {
			c.fail("UPDATE_DOWNLOAD_FAILED")
		}
	}
	if c.deps.Resources != nil {
		if err := c.deps.Resources.Restore(); err != nil {
			c.fail("POLICY_INVALID")
		}
		fingerprint := c.deps.Resources.Fingerprint()
		c.mu.Lock()
		if c.closing || ctx.Err() != nil {
			c.mu.Unlock()
			return NewAppError("CANCELLED")
		}
		c.installedRules = fingerprint
		c.mu.Unlock()
	}
	if prefs, err := c.deps.Preferences.Load(); err != nil {
		c.fail("STORAGE_FAILED")
	} else if prefs != nil {
		c.mu.Lock()
		if c.closing || ctx.Err() != nil {
			c.mu.Unlock()
			return NewAppError("CANCELLED")
		}
		c.preferences = *prefs
		c.mu.Unlock()
	}
	if record, err := c.deps.PolicyStore.Load(); err != nil {
		c.fail("POLICY_INVALID")
	} else if record != nil {
		if err := c.policy.Restore(*record); err != nil {
			c.fail("POLICY_INVALID")
		}
	}
	if record, err := c.deps.ReleaseStore.Load(); err != nil {
		c.fail("UPDATE_VERIFY_FAILED")
	} else if record != nil {
		signed, err := VerifyEnvelope(record.Envelope, c.deps.Build.UpdateKeys, "v2board-client-release-v1")
		var index ReleaseIndex
		if err == nil {
			err = DecodeStrict(signed.Payload, &index, 262144)
		}
		if err == nil {
			issued, _ := signedTime(index.IssuedAt)
			verified, e := VerifyRelease(record.Envelope, c.deps.Build, nil, issued)
			if e == nil && verified.Watermark == record.Watermark {
				c.mu.Lock()
				if c.closing || ctx.Err() != nil {
					c.mu.Unlock()
					return NewAppError("CANCELLED")
				}
				watermark := record.Watermark
				c.releaseWatermark = &watermark
				c.mu.Unlock()
			} else {
				c.fail("UPDATE_VERIFY_FAILED")
			}
		} else {
			c.fail("UPDATE_VERIFY_FAILED")
		}
	}
	if saved, err := c.deps.Secure.Load(); err != nil {
		c.fail(CodeOf(err))
	} else if saved != nil && saved.ProductID == c.deps.Build.ProductID && saved.Environment == c.deps.Build.Environment {
		c.mu.Lock()
		if c.closing || ctx.Err() != nil {
			c.mu.Unlock()
			return NewAppError("CANCELLED")
		}
		c.session = &saved.Session
		c.snapshot = saved.Snapshot
		c.account = saved.Account
		c.clock.RestoreUpper(saved.TimeUpper)
		for _, code := range saved.Restrictions {
			c.restrictions[code] = true
		}
		if c.account != nil {
			if code := Restriction(*c.account, c.clock.Now()); code != "" {
				c.restrictions[code] = true
			}
		}
		c.mu.Unlock()
	}
	if ctx.Err() != nil {
		return NewAppError("CANCELLED")
	}
	if err := c.network.Disconnect(ctx); err != nil {
		c.fail(CodeOf(err))
	}
	c.record("startup", "STARTUP_ATTEMPT")
	c.deps.Telemetry.Record("start", map[string]any{"helper": c.network.Ready(), "storage": c.deps.Secure.Mode(), "loggedIn": c.sessionCopy() != nil}, false)
	if c.deps.Telemetry != nil {
		go c.deps.Telemetry.Run(c.publicCtx)
	}
	if c.deps.Resources != nil && c.policy.Active() != nil {
		if envelope := c.policy.Envelope(); envelope != nil {
			go func() { _ = c.deps.Resources.Apply(c.publicCtx, *envelope) }()
		}
	}
	policyDone := make(chan struct{})
	go func() { c.checkPolicy(); close(policyDone) }()
	timer := time.NewTimer(3 * time.Second)
	select {
	case <-policyDone:
	case <-timer.C:
	case <-ctx.Done():
	}
	timer.Stop()
	if c.sessionCopy() != nil {
		_ = c.refresh(ctx, true)
	}
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return NewAppError("CANCELLED")
	}
	c.scheduleLocked()
	c.tickDone = make(chan struct{})
	done := c.tickDone
	auto := c.preferences.AutoConnect
	c.mu.Unlock()
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-c.publicCtx.Done():
				return
			case <-ticker.C:
				c.tick()
			}
		}
	}()
	// Update checks are not optional: at start and every policy interval.
	go c.checkUpdate(c.publicCtx)
	if auto && c.gate() == "" {
		if err := c.connect(ctx); err != nil {
			c.fail(CodeOf(err))
		}
	}
	c.emit()
	return nil
}
func (c *ClientController) scheduleLocked() {
	now := time.Now()
	r := DefaultRefresh
	update := 21600
	if p := c.policy.Active(); p != nil {
		r = p.Refresh
		update = p.Update.CheckIntervalSec
	}
	c.nextFull = now.Add(Jitter(r.SubscriptionIntervalSec))
	c.nextAccount = now.Add(Jitter(r.AccountIntervalSec))
	c.nextPolicy = now.Add(Jitter(r.PolicyIntervalSec))
	c.nextUpdate = now.Add(time.Duration(update) * time.Second)
	c.nextPersist = now.Add(time.Minute)
	c.nextPrune = now.Add(time.Hour)
}
func (c *ClientController) maintenance(now int64) bool {
	p := c.policy.Active()
	if p == nil || p.Maintenance == nil {
		return false
	}
	m := p.Maintenance
	from, e1 := signedTime(m.StartsAt)
	until, e2 := signedTime(m.EndsAt)
	if e1 != nil || e2 != nil || now < from || now >= until {
		return false
	}
	for _, platform := range m.Platforms {
		if platform == c.deps.Platform {
			return true
		}
	}
	return false
}
func (c *ClientController) tick() {
	now := c.now()
	mono := time.Now()
	p := c.policy.Active()
	r := DefaultRefresh
	update := 21600
	version := int64(0)
	if p != nil {
		r = p.Refresh
		update = p.Update.CheckIntervalSec
		version = p.PolicyVersion
	}
	rules := ""
	if c.deps.Resources != nil {
		rules = c.deps.Resources.Fingerprint()
	}
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return
	}
	denied := c.gateLocked() != "" || c.maintenance(now)
	authorized := int64(0)
	if !denied && c.snapshot != nil {
		authorized = c.snapshot.UsableUntil
	}
	if denied && c.probeCancel != nil {
		c.probeCancel()
	}
	rulesChanged := rules != c.installedRules
	c.installedRules = rules
	policyChanged := version != c.lastPolicyVersion
	if policyChanged {
		c.lastPolicyVersion = version
		if c.probeCancel != nil {
			c.probeCancel()
		}
		if c.snapshot != nil {
			s := TightenSnapshot(*c.snapshot, r.MaxSnapshotAgeSec, nil)
			c.snapshot = &s
		}
	}
	full := c.session != nil && (!mono.Before(c.nextFull) || c.snapshot != nil && now >= c.snapshot.UsableUntil-60000 && !mono.Before(c.nextAccount))
	poll := c.session != nil && !full && !mono.Before(c.nextAccount)
	if full {
		c.nextFull = mono.Add(Jitter(r.SubscriptionIntervalSec))
	}
	if full || poll {
		c.nextAccount = mono.Add(Jitter(r.AccountIntervalSec))
	}
	policyCheck := !mono.Before(c.nextPolicy)
	if policyCheck {
		c.nextPolicy = mono.Add(Jitter(r.PolicyIntervalSec))
	}
	updateCheck := !mono.Before(c.nextUpdate)
	if updateCheck {
		c.nextUpdate = mono.Add(time.Duration(update) * time.Second)
	}
	persist := policyChanged || !mono.Before(c.nextPersist)
	if persist {
		c.nextPersist = mono.Add(time.Minute)
	}
	prune := !mono.Before(c.nextPrune)
	if prune {
		c.nextPrune = mono.Add(time.Hour)
	}
	var account *Account
	generation := ""
	if c.account != nil && c.session != nil {
		a := *c.account
		account = &a
		generation = c.session.Generation
	}
	actual := c.actualNode
	snapshot := c.snapshot
	c.mu.Unlock()
	if driver, ok := c.deps.NetworkDriver.(interface{ SetAuthorizedUntil(int64) }); ok {
		driver.SetAuthorizedUntil(authorized)
	}
	if account != nil && !c.deps.Demo && c.deps.Reminders != nil {
		thresholds := []int{7, 3}
		if p != nil {
			thresholds = p.UI.ExpiryReminderDays
		}
		go func() {
			if err := c.deps.Reminders.Check(*account, thresholds, now, func() bool { return c.sessionCurrent(generation) }); err != nil {
				c.fail("STORAGE_FAILED")
			}
		}()
	}
	if denied && c.network.View().DesiredConnected {
		if err := c.network.Disconnect(c.publicCtx); err != nil {
			c.fail(CodeOf(err))
		}
	}
	if policyChanged && actual != nil && snapshot != nil {
		found := false
		for _, node := range snapshot.Nodes {
			if node.ID == *actual && Eligible(node, p, false) {
				found = true
				break
			}
		}
		if !found {
			_ = c.network.Disconnect(c.publicCtx)
		}
	}
	if rulesChanged && c.network.View().DesiredConnected {
		go c.NetworkChanged(c.publicCtx, false)
	}
	if full || poll {
		go c.refresh(c.publicCtx, full)
	}
	if policyCheck {
		go c.checkPolicy()
	}
	if updateCheck {
		go c.checkUpdate(c.publicCtx)
	}
	if persist {
		if err := c.persist(); err != nil {
			c.fail(CodeOf(err))
		}
	}
	if prune && c.deps.Download != nil {
		if err := c.deps.Download.Prune(); err != nil {
			c.fail("UPDATE_DOWNLOAD_FAILED")
		}
	}
	c.emit()
}
func (c *ClientController) refresh(ctx context.Context, full bool) error {
	c.mu.Lock()
	if c.session == nil || c.closing {
		c.mu.Unlock()
		return nil
	}
	c.syncStatus = "Syncing"
	c.mu.Unlock()
	c.emit()
	return c.syncer.Request(ctx, full)
}
func (c *ClientController) connect(ctx context.Context) error {
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return NewAppError("CANCELLED")
	}
	if code := c.gateLocked(); code != "" {
		c.mu.Unlock()
		return NewAppError(code)
	}
	if c.maintenance(c.clock.Now()) {
		c.mu.Unlock()
		return NewAppError("CONTROL_UNAVAILABLE")
	}
	if c.deps.Demo {
		c.mu.Unlock()
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	generation := c.session.Generation
	userIntent := c.intentGeneration
	policyGeneration := c.policy.Generation()
	networkGeneration := c.network.View().Generation
	nodes := append([]ProxyNode{}, c.snapshot.Nodes...)
	manual, current, tunnel := c.preferences.NodeID, c.actualNode, c.preferences.Tunnel
	c.mu.Unlock()
	// A node that cannot be used fails before TUN asks for a password to install the
	// network service, not after.
	if err := Selectable(nodes, c.policy.Active(), manual); err != nil {
		return err
	}
	// Only TUN needs the network service; system proxy mode never asks for a password.
	if !c.network.ReadyFor(tunnel) {
		if err := c.network.EnsureReadyFor(ctx, tunnel); err != nil {
			return err
		}
	}
	if !c.network.ReadyFor(tunnel) {
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	fresh := func() bool {
		c.mu.Lock()
		intentCurrent := c.intentGeneration == userIntent
		c.mu.Unlock()
		return intentCurrent && ctx.Err() == nil && c.sessionCurrent(generation) && c.gate() == "" && c.policy.Generation() == policyGeneration && c.network.View().Generation == networkGeneration
	}
	if !fresh() {
		return NewAppError("CANCELLED")
	}
	node, err := SelectNode(nodes, c.policy.Active(), manual, current, nil, c.deps.Probe, ctx)
	if err != nil {
		return err
	}
	if !fresh() {
		return NewAppError("CANCELLED")
	}
	c.mu.Lock()
	if c.closing || c.session == nil || c.session.Generation != generation || c.snapshot == nil || c.intentGeneration != userIntent {
		c.mu.Unlock()
		return NewAppError("CANCELLED")
	}
	mode, until, adBlock := c.preferences.Mode, c.snapshot.UsableUntil, c.preferences.AdBlock
	c.mu.Unlock()
	rules := EmptyRules()
	if c.deps.Resources != nil {
		rules = c.deps.Resources.Rules()
	}
	if !adBlock {
		rules = rules.WithoutTarget("block")
	}
	automatic := manual == nil
	pool := ConnectionPool(nodes, node, automatic, c.policy.Active())
	err = c.network.Connect(ctx, Candidate{Node: node, Pool: pool, Automatic: automatic, Mode: mode, Tunnel: tunnel, Rules: rules, AuthorizedUntil: until}, func() bool {
		c.mu.Lock()
		intentCurrent := c.intentGeneration == userIntent
		c.mu.Unlock()
		return intentCurrent && c.sessionCurrent(generation) && c.gate() == "" && c.policy.Generation() == policyGeneration && Eligible(node, c.policy.Active(), false)
	})
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.closing || c.session == nil || c.session.Generation != generation || c.intentGeneration != userIntent {
		c.mu.Unlock()
		_ = c.network.Disconnect(context.Background())
		return NewAppError("CANCELLED")
	}
	id := node.ID
	c.actualNode = &id
	c.mu.Unlock()
	return nil
}
func (c *ClientController) probeNodes(ctx context.Context, ids []string) error {
	c.mu.Lock()
	if denied := c.gateLocked(); denied != "" {
		c.mu.Unlock()
		return NewAppError(denied)
	}
	if c.deps.Demo || len(c.deps.Build.HealthTargets) < 2 {
		c.mu.Unlock()
		return NewAppError("COMPONENTS_UNAVAILABLE")
	}
	if c.probeCancel != nil || !c.lastProbeBatch.IsZero() && time.Since(c.lastProbeBatch) < 15*time.Second {
		c.mu.Unlock()
		return NewAppError("RATE_LIMITED")
	}
	p := c.policy.Active()
	nodes := []ProxyNode{}
	seen := map[string]bool{}
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		found := false
		for _, n := range c.snapshot.Nodes {
			if n.ID == id && Eligible(n, p, false) {
				nodes = append(nodes, n)
				found = true
				break
			}
		}
		if !found {
			c.mu.Unlock()
			return NewAppError("NO_COMPATIBLE_NODES")
		}
	}
	budget, cancel := context.WithTimeout(ctx, 30*time.Second)
	c.probeCancel = cancel
	c.probeGeneration++
	probeGeneration := c.probeGeneration
	c.lastProbeBatch = time.Now()
	generation := c.session.Generation
	policyGeneration := c.policy.Generation()
	c.mu.Unlock()
	currentLocked := func(n ProxyNode) bool {
		if budget.Err() != nil || c.closing || c.session == nil || c.session.Generation != generation || c.policy.Generation() != policyGeneration || c.gateLocked() != "" || c.snapshot == nil || !Eligible(n, c.policy.Active(), false) {
			return false
		}
		for _, v := range c.snapshot.Nodes {
			if n.ID == v.ID && n.ConnectionFingerprint == v.ConnectionFingerprint {
				return true
			}
		}
		return false
	}
	defer func() {
		cancel()
		c.mu.Lock()
		if c.probeGeneration == probeGeneration {
			c.probeCancel = nil
		}
		for id, p := range c.probeResults {
			if p.state == "testing" {
				delete(c.probeResults, id)
			}
		}
		c.mu.Unlock()
		c.emit()
	}()
	jobs := make(chan ProxyNode, len(nodes))
	for _, n := range nodes {
		jobs <- n
	}
	close(jobs)
	var wg sync.WaitGroup
	for range min(6, len(nodes)) {
		wg.Go(func() {
			for n := range jobs {
				c.mu.Lock()
				if !currentLocked(n) {
					c.mu.Unlock()
					return
				}
				c.probeResults[n.ID] = savedProbe{fingerprint: n.ConnectionFingerprint, state: "testing"}
				c.mu.Unlock()
				c.emit()
				result, err := c.deps.Probe(budget, n)
				c.mu.Lock()
				if currentLocked(n) {
					state := "timeout"
					var latency *float64
					if err == nil && result.Healthy {
						state = "healthy"
						latency = result.LatencyMs
					}
					c.probeResults[n.ID] = savedProbe{n.ConnectionFingerprint, latency, state}
				}
				c.mu.Unlock()
				c.emit()
			}
		})
	}
	wg.Wait()
	if budget.Err() != nil {
		return NewAppError("CANCELLED")
	}
	return nil
}
func (c *ClientController) checkPolicy() {
	c.mu.Lock()
	if c.policyBusy || c.closing {
		c.mu.Unlock()
		return
	}
	c.policyBusy = true
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.policyBusy = false; c.mu.Unlock(); c.emit() }()
	ctx, cancel := context.WithTimeout(c.publicCtx, 6*time.Second)
	defer cancel()
	for _, raw := range c.deps.Build.PolicyURLs {
		response, err := c.deps.HTTP.Request(ctx, HTTPRequest{URL: raw, MaxBytes: 262144})
		if err == nil {
			err = RequireSuccess(response, "public")
		}
		if err == nil {
			_, err = c.policy.Accept(response.Body)
		}
		if err == nil {
			if c.deps.Resources != nil {
				go func() { _ = c.deps.Resources.Apply(c.publicCtx, response.Body) }()
			}
			return
		}
		if ctx.Err() != nil {
			return
		}
	}
}
func (c *ClientController) checkUpdate(parent context.Context) error {
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return NewAppError("CANCELLED")
	}
	if c.updateBusy {
		done := c.updateDone
		c.mu.Unlock()
		select {
		case <-done:
			return nil
		case <-parent.Done():
			return NewAppError("CANCELLED")
		}
	}
	c.updateBusy = true
	c.updateDone = make(chan struct{})
	done := c.updateDone
	c.updateStatus = "正在检查更新"
	watermark := c.releaseWatermark
	c.mu.Unlock()
	c.emit()
	defer func() { c.mu.Lock(); c.updateBusy = false; close(done); c.mu.Unlock(); c.emit() }()
	if len(c.deps.Build.UpdateFeedURLs) == 0 {
		c.mu.Lock()
		c.updateStatus = "更新发布源尚未配置"
		c.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithTimeout(parent, 12*time.Second)
	defer cancel()
	for _, raw := range c.deps.Build.UpdateFeedURLs {
		response, err := c.deps.HTTP.Request(ctx, HTTPRequest{URL: raw, MaxBytes: 262144})
		if err == nil {
			err = RequireSuccess(response, "public")
		}
		var verified VerifiedRelease
		if err == nil {
			verified, err = VerifyRelease(response.Body, c.deps.Build, watermark, c.now())
		}
		if err == nil {
			err = c.deps.ReleaseStore.Save(PolicyRecord{Envelope: response.Body, Watermark: verified.Watermark}, func() bool { return ctx.Err() == nil })
		}
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			continue
		}
		artifact := SelectUpdate(verified.Index, UpdateTarget{Platform: c.deps.Platform, Arch: c.deps.Arch, Version: c.deps.Version, OSCompatible: c.deps.OSCompatible})
		if c.deps.Download != nil {
			if err := c.deps.Download.Select(artifact); err != nil {
				return err
			}
		}
		c.mu.Lock()
		if c.closing || ctx.Err() != nil {
			c.mu.Unlock()
			return NewAppError("CANCELLED")
		}
		c.releaseWatermark = &verified.Watermark
		c.releaseIndex = &verified.Index
		c.releaseEnvelope = response.Body
		c.updateArtifact = artifact
		switch {
		case artifact == nil:
			c.updateStatus = "当前没有兼容的新版本"
		case c.manualUpdateLocked():
			c.updateStatus = fmt.Sprintf("发现新版本 %s，请从下载页安装", artifact.Version)
		default:
			c.updateStatus = fmt.Sprintf("发现新版本 %s", artifact.Version)
		}
		c.mu.Unlock()
		return nil
	}
	c.mu.Lock()
	c.updateStatus = "无法验证更新，请稍后重试"
	c.mu.Unlock()
	return NewAppError("UPDATE_VERIFY_FAILED")
}

// openDownloadPage opens the first download domain, which also serves the download page.
func (c *ClientController) openDownloadPage() error {
	if len(c.deps.Build.TrustedUpdateOrigins) == 0 {
		return NewAppError("CONFIGURATION_REQUIRED")
	}
	u, err := url.Parse(c.deps.Build.TrustedUpdateOrigins[0])
	if err != nil {
		return NewAppError("CONFIGURATION_REQUIRED")
	}
	target, err := TrustedURL(u.Scheme+"://"+u.Host+"/", c.deps.Build.TrustedWebOrigins)
	if err != nil {
		return err
	}
	_, err = c.deps.OpenExternal(target, "")
	return err
}

// downloadThenInstall finishes the download the user asked to install, then installs
// it unless they cancelled in the meantime.
func (c *ClientController) downloadThenInstall(selected Artifact) {
	err := c.deps.Download.Start(c.publicCtx)
	c.mu.Lock()
	wanted := c.installWhenReady
	c.installWhenReady = false
	c.mu.Unlock()
	// Start reports a failed transfer in the download's status, not as an error: say
	// so, or the button comes back as if it had not been pressed.
	if status := c.deps.Download.View().Status; err == nil && wanted && status == "failed" {
		err = NewAppError("UPDATE_DOWNLOAD_FAILED")
	}
	if err == nil && wanted && c.deps.Download.View().Status == "ready" {
		err = c.installUpdate(c.publicCtx, selected)
	}
	if err != nil {
		c.fail(CodeOf(err))
	}
	c.emit()
}

// installUpdate re-checks the release index, disconnects and hands the verified file to
// the installer, which quits the app and starts the new version.
func (c *ClientController) installUpdate(ctx context.Context, selected Artifact) error {
	c.mu.Lock()
	if c.installing {
		c.mu.Unlock()
		return nil
	}
	c.installing = true
	c.releaseIndex = nil
	c.mu.Unlock()
	c.emit()
	err := func() error {
		if err := c.checkUpdate(ctx); err != nil {
			return err
		}
		c.mu.Lock()
		index := c.releaseIndex
		current := c.updateArtifact
		envelope := c.releaseEnvelope
		c.mu.Unlock()
		if index == nil || current == nil || current.ID != selected.ID || current.SHA256 != selected.SHA256 || envelope == "" {
			return NewAppError("UPDATE_VERIFY_FAILED")
		}
		if err := c.network.Disconnect(ctx); err != nil {
			return err
		}
		if err := InstallationGate(selected, *index, c.now(), c.network.View().State == "Disconnected"); err != nil {
			return err
		}
		path, err := c.deps.Download.VerifiedPath(selected)
		if err != nil {
			return err
		}
		return c.deps.Installer.Install(ctx, selected, path, envelope)
	}()
	c.mu.Lock()
	if err != nil {
		c.installing = false
		c.updateStatus = "更新没有完成，可以重试或从官网下载"
	} else {
		c.updateStatus = "正在安装更新，完成后会自动重新打开"
	}
	c.mu.Unlock()
	return err
}
func (c *ClientController) Command(ctx context.Context, raw json.RawMessage) CommandResult {
	cmd, err := ParseCommand(raw)
	if err == nil {
		c.mu.Lock()
		closing := c.closing
		c.mu.Unlock()
		if closing && cmd.Type != "state" && cmd.Type != "disconnect" && cmd.Type != "repair" {
			err = NewAppError("CANCELLED")
		} else {
			err = c.execute(ctx, cmd)
		}
	}
	if err != nil {
		code := CodeOf(err)
		c.fail(code)
		return CommandResult{OK: false, State: c.View(), Error: code}
	}
	c.emit()
	return CommandResult{OK: true, State: c.View()}
}
func (c *ClientController) execute(ctx context.Context, cmd Command) error {
	switch cmd.Type {
	case "state":
		return nil
	case "login":
		if c.deps.Secure.Mode() == "locked" {
			return NewAppError("STORAGE_LOCKED")
		}
		endpoints := c.pool.Candidates(c.policy.Active())
		if len(endpoints) == 0 {
			return NewAppError("CONFIGURATION_REQUIRED")
		}
		c.mu.Lock()
		if c.loginCancel != nil {
			c.loginCancel()
		}
		if c.probeCancel != nil {
			c.probeCancel()
		}
		c.probeResults = map[string]savedProbe{}
		c.loginGeneration++
		generation := c.loginGeneration
		loginCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		c.loginCancel = cancel
		c.mu.Unlock()
		defer func() {
			cancel()
			c.mu.Lock()
			if generation == c.loginGeneration {
				c.loginCancel = nil
			}
			c.mu.Unlock()
		}()
		started := time.Now()
		session, err := c.deps.Panel.Login(loginCtx, endpoints[0].ID, cmd.Email, cmd.Password)
		c.deps.Telemetry.Record("login", map[string]any{"ok": err == nil, "code": string(CodeOf(err)), "ms": time.Since(started).Milliseconds(), "email": cmd.Email}, err != nil)
		if err != nil {
			return err
		}
		c.mu.Lock()
		fresh := !c.closing && loginCtx.Err() == nil && generation == c.loginGeneration
		c.mu.Unlock()
		if !fresh {
			return NewAppError("CANCELLED")
		}
		c.syncer.Cancel()
		if err := c.network.Disconnect(loginCtx); err != nil {
			return err
		}
		c.mu.Lock()
		if c.closing || loginCtx.Err() != nil || generation != c.loginGeneration {
			c.mu.Unlock()
			return NewAppError("CANCELLED")
		}
		c.session = &session
		c.snapshot = nil
		c.account = nil
		c.restrictions = map[ErrorCode]bool{}
		c.startupAttempted = false
		c.mu.Unlock()
		if err := c.persist(); err != nil {
			return err
		}
		if !c.sessionCurrent(session.Generation) {
			return NewAppError("CANCELLED")
		}
		return c.refresh(loginCtx, true)
	case "sync":
		c.mu.Lock()
		if !c.lastManual.IsZero() && time.Since(c.lastManual) < 10*time.Second {
			c.mu.Unlock()
			return NewAppError("RATE_LIMITED")
		}
		c.lastManual = time.Now()
		c.mu.Unlock()
		return c.refresh(ctx, true)
	case "connect":
		started := time.Now()
		err := c.connect(ctx)
		c.recordConnect(err, time.Since(started))
		if err == nil {
			// Reconnect on the next launch, as the user left it.
			c.rememberConnected(true)
		}
		return err
	case "disconnect":
		c.mu.Lock()
		c.intentGeneration++
		c.mu.Unlock()
		if err := c.network.Disconnect(ctx); err != nil {
			return err
		}
		c.mu.Lock()
		c.actualNode = nil
		c.failure = ""
		c.mu.Unlock()
		c.rememberConnected(false)
		return nil
	case "report":
		return c.sendReport(ctx, cmd.Note)
	case "repair":
		c.mu.Lock()
		tunnel := c.preferences.Tunnel
		c.mu.Unlock()
		driver, ok := c.deps.NetworkDriver.(interface{ Repair(context.Context) error })
		if !ok && tunnel == "tun" {
			return NewAppError("COMPONENTS_UNAVAILABLE")
		}
		// Disconnecting restores the system proxy and network settings. Only TUN mode
		// goes on to reinstall the network service, which asks for a password.
		_ = c.network.Disconnect(ctx)
		if ok && tunnel == "tun" {
			if err := driver.Repair(ctx); err != nil {
				return err
			}
		}
		if err := c.network.Disconnect(ctx); err != nil {
			return err
		}
		c.mu.Lock()
		c.failure = ""
		c.mu.Unlock()
		return nil
	case "logout":
		c.mu.Lock()
		c.intentGeneration++
		session := c.session
		endpoint := ""
		if c.account != nil {
			endpoint = c.account.SourceEndpointID
		} else if len(c.deps.Build.APIEndpoints) > 0 {
			endpoint = c.deps.Build.APIEndpoints[0].ID
		}
		c.loginGeneration++
		logoutGeneration := c.loginGeneration
		if c.loginCancel != nil {
			c.loginCancel()
		}
		if c.probeCancel != nil {
			c.probeCancel()
		}
		c.session = nil
		c.snapshot = nil
		c.account = nil
		c.probeResults = map[string]savedProbe{}
		c.restrictions = map[ErrorCode]bool{}
		c.renewalUntil = 0
		c.actualNode = nil
		c.mu.Unlock()
		c.syncer.Cancel()
		clearErr := c.clearSession(logoutGeneration)
		cleanErr := c.network.Disconnect(ctx)
		if cleanErr != nil {
			return cleanErr
		}
		if clearErr != nil {
			return clearErr
		}
		c.mu.Lock()
		if c.session == nil && c.loginGeneration == logoutGeneration {
			c.syncStatus = "NeedsLogin"
			c.failure = ""
		}
		c.mu.Unlock()
		if session != nil && endpoint != "" && !c.deps.Demo {
			remote, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			if err := c.deps.Panel.Logout(remote, endpoint, *session); err != nil {
				c.record("lifecycle", "REMOTE_LOGOUT_UNAVAILABLE")
			}
		}
		return nil
	case "preferences":
		change := *cmd.Preferences
		c.mu.Lock()
		before := c.preferences
		c.mu.Unlock()
		if change.LaunchAtLogin != before.LaunchAtLogin {
			if err := c.deps.LaunchAtLogin(change.LaunchAtLogin); err != nil {
				return err
			}
		}
		reconnect := (change.Mode != before.Mode || change.Tunnel != before.Tunnel || change.AdBlock != before.AdBlock || selectedID(change.NodeID) != selectedID(before.NodeID)) && c.network.View().DesiredConnected
		if reconnect {
			if err := c.network.Disconnect(ctx); err != nil {
				return err
			}
		}
		if err := c.deps.Preferences.Save(change, func() bool { return ctx.Err() == nil }); err != nil {
			return err
		}
		c.mu.Lock()
		c.preferences = change
		c.mu.Unlock()
		if reconnect {
			return c.connect(ctx)
		}
		return nil
	case "check-update":
		return c.checkUpdate(ctx)
	case "download-update":
		c.mu.Lock()
		artifact := c.updateArtifact
		manual := c.manualUpdateLocked()
		c.mu.Unlock()
		if artifact == nil || c.deps.Download == nil {
			return NewAppError("CONFIGURATION_REQUIRED")
		}
		if manual {
			return c.openDownloadPage()
		}
		go func() {
			if err := c.deps.Download.Start(c.publicCtx); err != nil {
				c.fail("UPDATE_DOWNLOAD_FAILED")
			}
		}()
		return nil
	case "pause-update":
		if c.deps.Download != nil {
			return c.deps.Download.Pause()
		}
		return nil
	case "cancel-update":
		c.mu.Lock()
		c.installWhenReady = false
		c.mu.Unlock()
		if c.deps.Download != nil {
			return c.deps.Download.Cancel()
		}
		return nil
	case "install-update":
		// One click, as in Clash Party: download if needed, then install and restart.
		c.mu.Lock()
		manual := c.manualUpdateLocked()
		artifact := c.updateArtifact
		busy := c.installing || c.installWhenReady
		c.mu.Unlock()
		if manual {
			return c.openDownloadPage()
		}
		if artifact == nil || c.deps.Download == nil || c.deps.Installer == nil {
			return NewAppError("COMPONENTS_UNAVAILABLE")
		}
		if busy {
			return nil
		}
		if c.deps.Download.View().Status != "ready" {
			c.mu.Lock()
			c.installWhenReady = true
			c.mu.Unlock()
			go c.downloadThenInstall(*artifact)
			return nil
		}
		return c.installUpdate(ctx, *artifact)
	case "probe-nodes":
		return c.probeNodes(ctx, cmd.NodeIDs)
	case "diagnostics":
		c.diagnosticsMu.Lock()
		events := append([]map[string]any{}, c.diagnosticEvents...)
		c.diagnosticsMu.Unlock()
		return c.deps.ExportDiagnostics(map[string]any{"schemaVersion": 1, "version": c.deps.Version, "platform": c.deps.Platform, "arch": c.deps.Arch, "events": events})
	case "open-link":
		c.mu.Lock()
		link := c.linkLocked(cmd.Link, c.policy.Active())
		c.mu.Unlock()
		if link == nil {
			return NewAppError("CONFIGURATION_REQUIRED")
		}
		target, err := TrustedURL(*link, c.deps.Build.TrustedWebOrigins)
		if err != nil {
			return err
		}
		hint := ""
		if cmd.Link == "renew" {
			if account := c.View().Account; account != nil {
				hint = account.Email
			}
		}
		opened, err := c.deps.OpenExternal(target, hint)
		if err == nil && opened && cmd.Link == "renew" {
			c.mu.Lock()
			c.renewalUntil = c.clock.Now() + 600000
			c.mu.Unlock()
		}
		return err
	case "renewal-return":
		c.mu.Lock()
		refresh := c.renewalUntil > c.clock.Now() && (c.renewalRefresh.IsZero() || time.Since(c.renewalRefresh) >= 30*time.Second)
		if refresh {
			c.renewalRefresh = time.Now()
		}
		c.mu.Unlock()
		if refresh {
			return c.refresh(ctx, true)
		}
		return nil
	}
	return NewAppError("INVALID_INPUT")
}
func (c *ClientController) NetworkChanged(ctx context.Context, refresh bool) error {
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		return nil
	}
	if c.recovery != nil {
		f := c.recovery
		c.mu.Unlock()
		select {
		case <-f.done:
			return f.err
		case <-ctx.Done():
			return NewAppError("CANCELLED")
		}
	}
	f := &controllerFuture{done: make(chan struct{})}
	c.recovery = f
	state := c.network.View()
	intent := state.DesiredConnected && state.State == "Connected"
	session := ""
	if c.session != nil {
		session = c.session.Generation
	}
	c.mu.Unlock()
	defer func() { c.mu.Lock(); c.recovery = nil; close(f.done); c.mu.Unlock() }()
	if err := c.network.Disconnect(ctx); err != nil {
		f.err = err
		c.fail(CodeOf(err))
		return err
	}
	generation := c.network.View().Generation
	if refresh {
		_ = c.refresh(ctx, true)
	}
	if intent && c.sessionCurrent(session) && c.network.View().Generation == generation && c.gate() == "" && !c.maintenance(c.now()) {
		f.err = c.connect(ctx)
		if f.err != nil {
			c.fail(CodeOf(f.err))
		}
	}
	return f.err
}
func (c *ClientController) Suspend(ctx context.Context) error {
	state := c.network.View()
	c.mu.Lock()
	userGeneration := c.intentGeneration
	session := ""
	if c.session != nil {
		session = c.session.Generation
	}
	if c.probeCancel != nil {
		c.probeCancel()
	}
	c.mu.Unlock()
	if err := c.network.Disconnect(ctx); err != nil {
		return err
	}
	c.mu.Lock()
	c.suspended = &suspendIntent{state.DesiredConnected && state.State == "Connected", c.network.View().Generation, userGeneration, session}
	c.mu.Unlock()
	return c.persist()
}
func (c *ClientController) Resume(ctx context.Context) error {
	c.mu.Lock()
	saved := c.suspended
	c.suspended = nil
	c.mu.Unlock()
	if c.gate() != "" || c.maintenance(c.now()) {
		if err := c.network.Disconnect(ctx); err != nil {
			return err
		}
	}
	_ = c.refresh(ctx, true)
	c.mu.Lock()
	currentIntent := c.intentGeneration
	c.mu.Unlock()
	if saved != nil && saved.intent && saved.userGeneration == currentIntent && c.sessionCurrent(saved.session) && saved.generation == c.network.View().Generation && c.gate() == "" && !c.maintenance(c.now()) {
		return c.connect(ctx)
	}
	return nil
}
func (c *ClientController) NativeFailure(ctx context.Context, code ErrorCode) error {
	c.deps.Telemetry.Record("dropped", map[string]any{"code": string(code)}, true)
	c.mu.Lock()
	if c.recovery != nil {
		f := c.recovery
		c.mu.Unlock()
		select {
		case <-f.done:
			return f.err
		case <-ctx.Done():
			return NewAppError("CANCELLED")
		}
	}
	intended := c.network.View().DesiredConnected
	c.network.ExternalFailure(code)
	c.actualNode = nil
	closing := c.closing
	session := ""
	if c.session != nil {
		session = c.session.Generation
	}
	var recovery *controllerFuture
	if intended && !closing {
		recovery = &controllerFuture{done: make(chan struct{})}
		c.recovery = recovery
	}
	c.mu.Unlock()
	c.fail(code)
	if recovery == nil {
		return nil
	}
	defer func() { c.mu.Lock(); c.recovery = nil; close(recovery.done); c.mu.Unlock() }()
	if err := c.network.Disconnect(ctx); err != nil {
		recovery.err = err
		return err
	}
	generation := c.network.View().Generation
	if driver, ok := c.deps.NetworkDriver.(interface{ Initialize(context.Context) error }); ok {
		if err := driver.Initialize(ctx); err != nil {
			recovery.err = err
			return err
		}
	}
	c.mu.Lock()
	tunnel := c.preferences.Tunnel
	c.mu.Unlock()
	if c.network.ReadyFor(tunnel) && c.sessionCurrent(session) && c.network.View().Generation == generation && c.gate() == "" && !c.maintenance(c.now()) {
		recovery.err = c.connect(ctx)
		return recovery.err
	}
	return nil
}
func (c *ClientController) Stop(ctx context.Context) error {
	c.stopMu.Lock()
	defer c.stopMu.Unlock()
	c.mu.Lock()
	c.closing = true
	c.loginGeneration++
	if c.loginCancel != nil {
		c.loginCancel()
	}
	if c.probeCancel != nil {
		c.probeCancel()
	}
	c.cancelPublic()
	c.mu.Unlock()
	c.syncer.Cancel()
	// Network cleanup always precedes unrelated disk/download work. A failure is
	// returned to the shell so the user can retry without silently quitting.
	if err := c.network.Disconnect(ctx); err != nil {
		return err
	}
	if c.deps.Download != nil {
		if err := c.deps.Download.Pause(); err != nil {
			return err
		}
	}
	if c.deps.Resources != nil {
		c.deps.Resources.Stop()
	}
	if c.deps.Telemetry != nil {
		flush, cancel := context.WithTimeout(ctx, 2*time.Second)
		_ = c.deps.Telemetry.Flush(flush)
		cancel()
		c.deps.Telemetry.Persist()
	}
	return c.persist()
}

// recordConnect tells the operator how a connection attempt went: which step failed,
// what the data path proved, and which node and mode were used.
func (c *ClientController) recordConnect(err error, took time.Duration) {
	network := c.network.View()
	c.mu.Lock()
	fields := map[string]any{"ok": err == nil, "ms": took.Milliseconds(), "mode": c.preferences.Mode, "tunnel": c.preferences.Tunnel, "adBlock": c.preferences.AdBlock, "automatic": c.preferences.NodeID == nil, "stage": network.Stage, "helper": c.network.Ready()}
	if err != nil {
		fields["code"] = string(CodeOf(err))
	}
	id := c.actualNode
	if id == nil {
		id = c.preferences.NodeID
	}
	if c.snapshot != nil {
		fields["nodes"] = len(c.snapshot.Nodes)
		for _, n := range c.snapshot.Nodes {
			if id != nil && n.ID == *id {
				fields["node"] = n.Name
				fields["protocol"] = n.Protocol + "/" + n.Transport + "/" + n.Security
			}
		}
	}
	c.mu.Unlock()
	if p := network.Proof; p != nil {
		fields["tcp"], fields["dns"], fields["udp"], fields["ipv6"] = p.TCP, p.DNS, p.UDP, p.IPv6
	}
	c.deps.Telemetry.Record("connect", fields, err != nil)
}

func (c *ClientController) rememberConnected(connected bool) {
	c.mu.Lock()
	change := c.preferences
	c.mu.Unlock()
	if change.AutoConnect == connected {
		return
	}
	change.AutoConnect = connected
	if c.deps.Preferences.Save(change, nil) == nil {
		c.mu.Lock()
		c.preferences.AutoConnect = connected
		c.mu.Unlock()
	}
}

// sendReport uploads recent events with a fresh network self-check and shows the
// returned code, which the user gives to support.
func (c *ClientController) sendReport(parent context.Context, note string) error {
	if !c.deps.Telemetry.Enabled() {
		return NewAppError("CONFIGURATION_REQUIRED")
	}
	c.mu.Lock()
	if c.report.Status == "sending" {
		c.mu.Unlock()
		return nil
	}
	c.report = ReportView{Status: "sending"}
	nodes := []ProxyNode{}
	if c.snapshot != nil {
		nodes = append(nodes, c.snapshot.Nodes...)
	}
	c.mu.Unlock()
	c.emit()
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	view := c.View()
	state := map[string]any{"name": "client", "kind": "state", "connection": string(view.Connection), "helper": view.HelperReady, "sync": view.Sync, "mode": view.Preferences.Mode, "automatic": view.Preferences.NodeID == nil, "storage": view.Storage, "rules": view.Rules, "policy": view.Policy, "update": view.Update}
	if view.Error != nil {
		state["error"] = string(*view.Error)
	}
	if view.Account != nil {
		state["plan"], state["planStatus"] = view.Account.PlanName, view.Account.Status
		if view.Account.ExpiresAt != nil {
			state["expiresAt"] = *view.Account.ExpiresAt
		}
	}
	if view.UsableUntil != nil {
		state["usableUntil"] = float64(*view.UsableUntil)
	}
	checks := []map[string]any{normalizeEvent(state)}
	if c.deps.SelfCheck != nil {
		checks = append(checks, c.deps.SelfCheck(ctx, nodes)...)
	}
	c.diagnosticsMu.Lock()
	events := append([]map[string]any{}, c.deps.Telemetry.Recent(400)...)
	for _, e := range c.diagnosticEvents {
		events = append(events, map[string]any{"type": "local", "stage": e["stage"], "code": e["code"], "time": e["at"]})
	}
	c.diagnosticsMu.Unlock()
	code, err := c.deps.Telemetry.Report(ctx, note, events, checks)
	c.mu.Lock()
	if err != nil {
		c.report = ReportView{Status: "failed"}
	} else {
		c.report = ReportView{Status: "sent", Code: &code}
	}
	c.mu.Unlock()
	return err
}
