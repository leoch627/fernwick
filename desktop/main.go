package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"
	"work.starrail/client/desktop/core"
)

//go:embed all:frontend/dist assets
var bundled embed.FS

type shell struct {
	mu                  sync.Mutex
	app                 *application.App
	controller          *core.ClientController
	window              *application.WebviewWindow
	unsubscribe         func()
	name                string
	quitting, quitReady bool
	monitor             *core.NetworkEvents
	cancel              context.CancelFunc
	notifier            *notifications.NotificationService
	notificationsReady  atomic.Bool
	notificationMu      sync.Mutex
}

func readAsset(name string, value any) error {
	data, err := bundled.ReadFile("assets/" + name)
	if err != nil {
		return err
	}
	return core.DecodeStrict(data, value, 10*1024*1024)
}

func resourcePaths(executable string) (root, resources string, err error) {
	if production {
		root = filepath.Dir(executable)
		if runtime.GOOS == "darwin" {
			root = filepath.Clean(filepath.Join(root, "../.."))
			resources = filepath.Join(root, "Contents", "Resources")
		} else {
			resources = filepath.Join(root, "resources")
		}
		return root, resources, nil
	}
	// The development launcher runs from desktop/. Direct go run from the
	// repository is supported as well; neither path is used by production.
	cwd, err := os.Getwd()
	if err != nil {
		return "", "", err
	}
	for _, dir := range []string{cwd, filepath.Dir(cwd)} {
		if _, e := os.Stat(filepath.Join(dir, "resources", "core-lock.json")); e == nil {
			return dir, filepath.Join(dir, "resources"), nil
		}
	}
	return "", "", errors.New("development resources unavailable")
}

func frontendHandler() (http.Handler, error) {
	frontend, err := fs.Sub(bundled, "frontend/dist")
	if err != nil {
		return nil, err
	}
	var handler http.Handler = http.FileServer(http.FS(frontend))
	if !production && os.Getenv("STARRAIL_DEV_UI") == "1" {
		// Never accept an environment-provided remote origin for a privileged UI.
		target, _ := url.Parse("http://127.0.0.1:5173")
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.Transport = &http.Transport{Proxy: nil}
		proxy.ErrorLog = slog.NewLogLogger(slog.NewTextHandler(io.Discard, nil), slog.LevelError)
		handler = proxy
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		handler.ServeHTTP(w, r)
	}), nil
}

func (s *shell) show() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.quitting {
		return
	}
	if s.window != nil {
		s.window.Show()
		s.window.Focus()
		return
	}
	options := application.WebviewWindowOptions{
		Title: s.name, Width: 420, Height: 700, MinWidth: 360, MinHeight: 600, URL: "/",
		BackgroundColour: s.backgroundColour(),
		DevToolsEnabled:  !production, DefaultContextMenuDisabled: true,
		Permissions: map[application.PermissionType]application.Permission{
			application.PermissionMicrophone:    application.PermissionDeny,
			application.PermissionCamera:        application.PermissionDeny,
			application.PermissionGeolocation:   application.PermissionDeny,
			application.PermissionNotifications: application.PermissionDeny,
			application.PermissionClipboardRead: application.PermissionDeny,
		},
	}
	hardenWindow(&options)
	w := s.app.Window.NewWithOptions(options)
	s.window = w
	s.unsubscribe = s.controller.Subscribe(func(view core.AppView) {
		s.mu.Lock()
		active := s.window == w && !s.quitting
		s.mu.Unlock()
		if active {
			s.app.Event.Emit("starrail:state", view)
		}
	})
	w.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		s.mu.Lock()
		if s.quitting {
			s.mu.Unlock()
			return
		}
		s.mu.Unlock()
		view := s.controller.View()
		if runtime.GOOS != "linux" && view.Preferences.CloseBehavior == "tray" {
			s.mu.Lock()
			if s.window == w {
				s.window = nil
				if s.unsubscribe != nil {
					s.unsubscribe()
					s.unsubscribe = nil
				}
			}
			s.mu.Unlock()
			return
		}
		e.Cancel()
		go func() {
			if ask(s.app, "退出客户端", "退出将断开连接并停止同步。", []string{"继续使用", "退出客户端"}, 0) == 1 {
				s.app.Quit()
			}
		}()
	})
	w.OnWindowEvent(events.Common.WindowFocus, func(*application.WindowEvent) {
		go s.controller.Command(context.Background(), json.RawMessage(`{"type":"renewal-return"}`))
	})
}

// backgroundColour is the window colour shown before the page paints: the 三月七 or 黑塔
// background (src/renderer/tokens.css), so a dark system does not flash white.
func (s *shell) backgroundColour() application.RGBA {
	theme := s.controller.View().Preferences.Theme
	if theme == "dark" || theme == "system" && s.app.Env.IsDarkMode() {
		return application.NewRGB(16, 15, 28)
	}
	return application.NewRGB(247, 248, 253)
}

func (s *shell) shouldQuit() bool {
	s.mu.Lock()
	if s.quitReady {
		s.mu.Unlock()
		return true
	}
	if s.quitting {
		s.mu.Unlock()
		return false
	}
	s.quitting = true
	s.mu.Unlock()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := s.controller.Stop(ctx); err != nil {
			s.mu.Lock()
			s.quitting = false
			s.mu.Unlock()
			s.app.Dialog.Error().SetTitle("网络恢复未确认").SetMessage("客户端尚未确认网络已经恢复。请重试退出；如仍失败，请修复网络组件。").Show()
			return
		}
		s.cancel()
		if s.monitor != nil {
			s.monitor.Stop()
		}
		s.mu.Lock()
		s.quitReady = true
		s.mu.Unlock()
		s.app.Quit()
	}()
	return false
}

func (s *shell) notifyExpiry(remaining int64) error {
	if !s.notificationsReady.Load() {
		return nil
	}
	allowed, err := s.notifier.CheckNotificationAuthorization()
	if err != nil {
		return err
	}
	if !allowed {
		allowed, err = s.notifier.RequestNotificationAuthorization()
	}
	if err != nil || !allowed {
		return err
	}
	body := "套餐已到期，请打开客户端续费。"
	if remaining > 0 {
		body = fmt.Sprintf("套餐将在 %d 天内到期，请及时续费。", (remaining+86400000-1)/86400000)
	}
	return s.notifier.SendNotification(notifications.NotificationOptions{ID: "subscription-expiry", Title: s.name, Body: body, Sound: &notifications.NotificationSound{Silent: true}})
}

func run() error {
	// Wails' development runtime also inspects this variable independently of
	// the asset handler. Only our fixed loopback proxy is allowed.
	_ = os.Unsetenv("FRONTEND_DEVSERVER_URL")
	var build core.BuildConfig
	var contract core.PanelContract
	var manifest core.NativeManifest
	var baseline core.Rules
	var err error
	for _, asset := range []struct {
		name  string
		value any
	}{{"build-config.json", &build}, {"adapter-contract.json", &contract}, {"native-manifest.json", &manifest}, {"rules/baseline.json", &baseline}} {
		if err := readAsset(asset.name, asset.value); err != nil {
			return errors.New("invalid embedded configuration")
		}
	}
	if build, err = core.ValidateBuild(build); err != nil {
		return errors.New("invalid embedded configuration")
	}
	if err = contract.Validate(); err != nil {
		return errors.New("invalid embedded configuration")
	}
	if err = baseline.Validate(); err != nil {
		return errors.New("invalid embedded configuration")
	}
	version, _ := bundled.ReadFile("assets/version.txt")
	icon, _ := bundled.ReadFile("assets/icon.png")
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	executable, err = filepath.EvalSymlinks(executable)
	if err != nil {
		return err
	}
	root, resources, err := resourcePaths(executable)
	if err != nil {
		return err
	}
	config, err := os.UserConfigDir()
	if err != nil {
		return err
	}
	dataDir := filepath.Join(config, build.AppID)
	// Packaged builds refuse the fixture switch, as the Electron build did.
	demo := !production && slices.Contains(os.Args[1:], "--demo") && build.Environment == "test"
	if demo {
		dataDir, err = os.MkdirTemp("", "starrail-demo-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dataDir)
	}
	if err = os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &shell{name: build.Name, cancel: cancel}
	bridge := &Bridge{ready: make(chan struct{})}
	handler, err := frontendHandler()
	if err != nil {
		return err
	}
	s.app = application.New(application.Options{
		Name: build.Name, Description: "V2Board + Xray desktop client", Icon: icon,
		Services:   []application.Service{application.NewService(bridge)},
		Assets:     application.AssetOptions{Handler: handler, Middleware: runtimeSecurity},
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Mac:        application.MacOptions{ApplicationShouldTerminateAfterLastWindowClosed: false},
		Windows:    application.WindowsOptions{DisableQuitOnLastWindowClosed: true, WebviewUserDataPath: filepath.Join(dataDir, "webview")},
		Linux:      application.LinuxOptions{ProgramName: build.ProductID, ApplicationID: build.AppID},
		ShouldQuit: s.shouldQuit,
		OnShutdown: func() {
			cancel()
			cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cleanupCancel()
			if s.controller != nil {
				_ = s.controller.Stop(cleanupCtx)
			}
			s.notificationMu.Lock()
			defer s.notificationMu.Unlock()
			if s.notificationsReady.Swap(false) {
				_ = s.notifier.ServiceShutdown()
			}
		},
		SingleInstance: &application.SingleInstanceOptions{UniqueID: build.AppID, OnSecondInstanceLaunch: func(application.SecondInstanceData) { s.show() }},
	})
	var native *core.NativeDriver
	native = core.NewNativeDriver(build, manifest, resources, root, production, func(code core.ErrorCode) {
		if s.controller != nil {
			go s.controller.NativeFailure(ctx, code)
		}
	})
	probeManifest := manifest
	if !production {
		probeManifest.Components = slices.DeleteFunc(append([]core.NativeComponent{}, manifest.Components...), func(component core.NativeComponent) bool { return component.Type == "helper" })
	}
	coreRuntime, _ := core.LoadCoreRuntime(filepath.Join(resources, "native"), probeManifest)
	// System proxy mode runs the core as the user; TUN mode goes through the network service.
	proxy := core.NewProxyDriver(coreRuntime, core.NewSystemProxy(), filepath.Join(dataDir, "system-proxy.json"), build.HealthTargets, func(code core.ErrorCode) {
		if s.controller != nil {
			go s.controller.NativeFailure(ctx, code)
		}
	})
	var driver core.NetworkDriver = core.NewTunnelDriver(proxy, native)
	// Events go straight out (not through the helper): reports can exceed its control body limit.
	telemetry := core.NewTelemetry(build, filepath.Join(dataDir, "telemetry.json"), core.NewDirectHTTPSTransportTimeout(30*time.Second), func() core.TelemetryInfo {
		info := core.TelemetryInfo{Version: strings.TrimSpace(string(version)), Platform: runtime.GOOS, Arch: runtime.GOARCH}
		if info.Platform == "windows" {
			info.Platform = "win32"
		}
		if info.Arch == "amd64" {
			info.Arch = "x64"
		}
		info.OS, _ = systemVersion()
		if s.controller != nil {
			info.Email = s.controller.SessionEmail()
		}
		return info
	})
	var panel core.Panel = core.NewV2BoardAdapter(build, contract, core.NewObservedTransport(core.NewHelperTransport(native), telemetry))
	var key core.KeyProvider = &systemKeyProvider{service: build.AppID}
	if demo {
		driver = core.UnavailableDriver{}
		panel = core.NewDemoPanel()
		telemetry = nil
		key = core.KeyProviderFunc(func(bool) ([]byte, error) { return nil, core.ErrKeyUnavailable })
	}
	transport := core.NewHelperTransport(native)
	rules, err := core.NewResourceCoordinator(build, baseline, core.NewJSONStore[core.ResourceCache](filepath.Join(dataDir, "rules.json"), 68*1024*1024), transport, func() int64 { return time.Now().UnixMilli() })
	if err != nil {
		return err
	}
	reminderStore := core.NewJSONStore[core.ReminderState](filepath.Join(dataDir, "reminders.json"), 65536)
	reminders := core.NewExpiryReminders(build.TenantID, func(value core.ReminderState) error { return reminderStore.Save(value, nil) }, s.notifyExpiry)
	if saved, e := reminderStore.Load(); e == nil && saved != nil {
		_ = reminders.Restore(*saved)
	}
	platform := runtime.GOOS
	if platform == "windows" {
		platform = "win32"
	}
	updater := &core.SelfUpdater{Service: native, Platform: platform, Packaged: production && !demo, AppRoot: root, Executable: executable,
		Package: build.ProductID, UninstallKey: build.AppID, Work: filepath.Join(dataDir, "updates"), Quit: s.app.Quit}
	deps := core.ControllerDeps{
		Build: build, Version: strings.TrimSpace(string(version)), Panel: panel, Demo: demo, NetworkDriver: driver, Installer: updater, HTTP: transport,
		Secure:       core.NewSecureStore[core.Persisted](filepath.Join(dataDir, "session.v2.enc"), key),
		Preferences:  core.NewJSONStore[core.Preferences](filepath.Join(dataDir, "preferences.json"), 16384),
		PolicyStore:  core.NewJSONStore[core.PolicyRecord](filepath.Join(dataDir, "policy.json"), 1048576),
		ReleaseStore: core.NewJSONStore[core.PolicyRecord](filepath.Join(dataDir, "release-index.json"), 1048576),
		Resources:    rules, Reminders: reminders, Download: core.NewArtifactDownload(filepath.Join(dataDir, "updates"), build),
		Parse: subscriptionParser(build),
		Probe: func(ctx context.Context, node core.ProxyNode) (core.ProbeResult, error) {
			if demo || coreRuntime == nil {
				return core.ProbeResult{}, core.NewAppError("COMPONENTS_UNAVAILABLE")
			}
			return coreRuntime.Probe(ctx, node, build.HealthTargets)
		},
		OpenExternal: func(raw, hint string) (bool, error) {
			if hint != "" && ask(s.app, "确认续费账号", "请确认网页中登录的是 "+hint+"。系统浏览器可能已登录其他账号。", []string{"打开网站", "取消"}, 1) != 0 {
				return false, nil
			}
			return true, s.app.Browser.OpenURL(raw)
		},
		ExportDiagnostics: func(value any) error {
			if ask(s.app, "导出诊断", "仅导出版本、平台、时间、错误码与操作耗时，不包含账号、订阅链接、节点凭据或访问记录。文件仅保存在本机。", []string{"选择保存位置", "取消"}, 1) != 0 {
				return nil
			}
			path, e := s.app.Dialog.SaveFile().SetFilename(build.ProductID+"-diagnostics-"+time.Now().Format("2006-01-02")+".json").AddFilter("JSON", "*.json").PromptForSingleSelection()
			if e != nil {
				return e
			}
			if path == "" {
				return nil
			}
			body, e := core.EncodeJSON(value)
			if e != nil {
				return e
			}
			return core.AtomicWrite(path, body, nil)
		},
		LaunchAtLogin: func(on bool) error {
			if demo {
				return nil
			}
			if !production {
				return core.NewAppError("CONFIGURATION_REQUIRED")
			}
			if on {
				return s.app.Autostart.EnableWithOptions(application.AutostartOptions{Identifier: build.AppID, Arguments: []string{"--hidden", "--autostart"}})
			}
			return s.app.Autostart.Disable()
		},
		OSCompatible: func(minimum string) bool {
			actual, ok := systemVersion()
			return ok && core.OSVersionAtLeast(actual, minimum)
		},
		Telemetry: telemetry,
		SelfCheck: func(ctx context.Context, nodes []core.ProxyNode) []map[string]any {
			return core.SelfCheck(ctx, build, nodes)
		},
	}
	s.controller = core.NewClientController(deps)
	bridge.controller = s.controller
	s.monitor = core.NewNetworkEvents(func(ctx context.Context) error { return s.controller.NetworkChanged(ctx, true) })
	if !slices.Contains(os.Args[1:], "--hidden") || runtime.GOOS == "linux" {
		s.show()
	}
	if runtime.GOOS != "linux" {
		tray := s.app.SystemTray.New()
		tray.SetIcon(icon)
		menu := application.NewMenu()
		menu.Add("打开 " + build.Name).OnClick(func(*application.Context) { s.show() })
		menu.Add("断开连接").OnClick(func(*application.Context) { go s.controller.Command(ctx, json.RawMessage(`{"type":"disconnect"}`)) })
		menu.AddSeparator()
		menu.Add("退出").OnClick(func(*application.Context) { s.app.Quit() })
		tray.SetMenu(menu)
		tray.OnClick(s.show)
	}
	s.app.Event.OnApplicationEvent(events.Common.ApplicationStarted, func(*application.ApplicationEvent) {
		go func() {
			// macOS notifications require a real application bundle.
			if production && !demo {
				s.notificationMu.Lock()
				s.notifier = notifications.New()
				if s.notifier.ServiceStartup(ctx, application.ServiceOptions{}) == nil {
					if ctx.Err() == nil {
						s.notificationsReady.Store(true)
						s.notifier.OnNotificationResponse(func(notifications.NotificationResult) { s.show() })
					} else {
						_ = s.notifier.ServiceShutdown()
					}
				}
				s.notificationMu.Unlock()
			}
			// Started by the updater: the network service may still be restarting after
			// reinstalling itself. Give it a moment rather than asking to repair it.
			if slices.Contains(os.Args[1:], "--updated") && !demo {
				if _, err := os.Stat(filepath.Join(core.HelperRoot(build, root), "server-public.pem")); err == nil {
					for deadline := time.Now().Add(15 * time.Second); !native.Verified() && time.Now().Before(deadline) && ctx.Err() == nil; time.Sleep(500 * time.Millisecond) {
						_ = native.Initialize(ctx)
					}
				}
			}
			_ = s.controller.Start(ctx)
			if demo {
				_ = s.controller.Command(ctx, json.RawMessage(`{"type":"login","email":"demo@example.com","password":"demo-only"}`))
			}
			close(bridge.ready)
			if ctx.Err() == nil {
				s.monitor.Start()
			}
		}()
	})
	s.app.Event.OnApplicationEvent(events.Common.SystemWillSleep, func(*application.ApplicationEvent) { go s.controller.Suspend(ctx) })
	s.app.Event.OnApplicationEvent(events.Common.SystemDidWake, func(*application.ApplicationEvent) { go s.controller.Resume(ctx) })
	// Dock click only; ApplicationDidBecomeActive also fires on a --hidden autostart launch.
	s.app.Event.OnApplicationEvent(events.Mac.ApplicationShouldHandleReopen, func(*application.ApplicationEvent) { s.show() })
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	go func() {
		select {
		case <-signals:
			s.app.Quit()
		case <-ctx.Done():
		}
	}()
	return s.app.Run()
}

func subscriptionParser(build core.BuildConfig) func(context.Context, string, core.SubscriptionDescriptor) (core.ParsedNodes, error) {
	return func(parent context.Context, raw string, descriptor core.SubscriptionDescriptor) (core.ParsedNodes, error) {
		ctx, cancel := context.WithTimeout(parent, 3*time.Second)
		defer cancel()
		type result struct {
			nodes core.ParsedNodes
			err   error
		}
		done := make(chan result, 1)
		go func() {
			nodes, err := core.ParseSubscription(raw, core.ParserOptions{Capabilities: build.ProtocolCapabilities, ConfirmedTCPUDP: build.NodeCapabilitiesConfirmed || (build.Environment == "test" && build.AllowUnverifiedNodeTrials), AuthoritativeEmpty: descriptor.AuthoritativeEmpty, Source: build.AdapterID})
			done <- result{core.UsableNodes(nodes), err}
		}()
		select {
		case <-ctx.Done():
			return core.ParsedNodes{}, core.NewAppError("CANCELLED")
		case value := <-done:
			if ctx.Err() != nil {
				return core.ParsedNodes{}, core.NewAppError("CANCELLED")
			}
			return value.nodes, value.err
		}
	}
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "客户端启动失败，请检查安装完整性。")
		os.Exit(1)
	}
}
