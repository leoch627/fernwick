package main

import (
	"bytes"
	"context"
	"encoding/json"
	"image"
	"image/color"
	"image/png"
	"regexp"
	"slices"
	"sync"

	"github.com/wailsapp/wails/v3/pkg/application"
	"work.starrail/client/desktop/core"
)

// The tray menu answers the questions people open the window for: am I connected,
// connect or disconnect, switch to a line I use. Favorites come first, then recent
// lines; everything else is in the window.
const trayFavorites, trayRecent = 10, 5

type trayNode struct {
	id, label string
	selected  bool
}

// trayModel is what the menu shows; the menu is rebuilt only when it changes.
type trayModel struct {
	loggedIn, connected, working, recovery bool
	status                                 string
	auto                                   bool
	favorites, recent                      []trayNode
}

// Regional indicator symbols, two to a flag (Go regexp has no class name for them).
var leadingFlag = regexp.MustCompile(`^[\x{1F1E6}-\x{1F1FF}]{2}\s*`)

// trayLabel drops the flag a node name starts with: Windows menus draw it as two letters.
func trayLabel(name string) string {
	if label := leadingFlag.ReplaceAllString(name, ""); label != "" {
		return label
	}
	return name
}

func newTrayModel(view core.AppView) trayModel {
	m := trayModel{loggedIn: view.LoggedIn, auto: view.SelectedNode == nil}
	switch view.Connection {
	case "Connected":
		m.connected = true
	case "Preparing", "Connecting", "Switching", "Reconnecting", "Disconnecting":
		m.working = true
	case "RecoveryRequired":
		m.recovery = true
	}
	names := map[string]string{}
	usable := map[string]bool{}
	for _, node := range view.Nodes {
		names[node.ID] = trayLabel(node.Name)
		usable[node.ID] = node.Compatible
	}
	selected := func(id string) bool { return view.SelectedNode != nil && *view.SelectedNode == id }
	for _, id := range view.Preferences.FavoriteNodeIDs {
		if usable[id] && len(m.favorites) < trayFavorites {
			m.favorites = append(m.favorites, trayNode{id, names[id], selected(id)})
		}
	}
	for _, id := range view.Preferences.RecentNodeIDs {
		if usable[id] && len(m.recent) < trayRecent && !slices.Contains(view.Preferences.FavoriteNodeIDs, id) {
			m.recent = append(m.recent, trayNode{id, names[id], selected(id)})
		}
	}
	line := "自动选择"
	if view.ActualNode != nil && names[*view.ActualNode] != "" {
		line = names[*view.ActualNode]
	} else if view.SelectedNode != nil && names[*view.SelectedNode] != "" {
		line = names[*view.SelectedNode]
	}
	switch {
	case !view.LoggedIn:
		m.status = "未登录"
	case m.connected:
		m.status = "已连接 · " + line
	case view.Connection == "Disconnecting":
		m.status = "正在断开…"
	case m.working:
		m.status = "正在连接…"
	case m.recovery:
		m.status = "网络需要修复"
	default:
		m.status = "未连接"
	}
	return m
}

func (m trayModel) equal(o trayModel) bool {
	return m.loggedIn == o.loggedIn && m.connected == o.connected && m.working == o.working && m.recovery == o.recovery && m.status == o.status && m.auto == o.auto && slices.Equal(m.favorites, o.favorites) && slices.Equal(m.recent, o.recent)
}

type trayMenu struct {
	shell   *shell
	ctx     context.Context
	tray    *application.SystemTray
	menu    *application.Menu
	on, off []byte
	mu      sync.Mutex
	latest  *core.AppView
	shown   *trayModel
	wake    chan struct{}
}

func newTrayMenu(ctx context.Context, s *shell, icon []byte) *trayMenu {
	t := &trayMenu{shell: s, ctx: ctx, tray: s.app.SystemTray.New(), menu: application.NewMenu(), on: icon, off: dimmedIcon(icon), wake: make(chan struct{}, 1)}
	t.tray.SetIcon(t.off)
	t.tray.OnClick(s.show)
	t.apply(s.controller.View())
	s.controller.Subscribe(func(view core.AppView) {
		t.mu.Lock()
		t.latest = &view
		t.mu.Unlock()
		select {
		case t.wake <- struct{}{}:
		default:
		}
	})
	// Menu changes wait for the UI thread; they run here, never on the controller's
	// publishing goroutine, which also feeds the window.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.wake:
				t.mu.Lock()
				view := t.latest
				t.mu.Unlock()
				if view != nil {
					t.apply(*view)
				}
			}
		}
	}()
	return t
}

func (t *trayMenu) apply(view core.AppView) {
	model := newTrayModel(view)
	if t.shown != nil && t.shown.equal(model) {
		return
	}
	previous := t.shown
	t.shown = &model
	if previous == nil || previous.connected != model.connected {
		if model.connected {
			t.tray.SetIcon(t.on)
		} else {
			t.tray.SetIcon(t.off)
		}
	}
	t.tray.SetTooltip(t.shell.name + " · " + model.status)
	t.build(model, view.Preferences)
	t.tray.SetMenu(t.menu)
}

func (t *trayMenu) build(m trayModel, preferences core.Preferences) {
	menu := t.menu
	menu.Clear()
	menu.Add(m.status).SetEnabled(false)
	switch {
	case !m.loggedIn:
	case m.recovery:
		menu.Add("修复网络").OnClick(func(*application.Context) { t.command(`{"type":"repair"}`, true) })
	case m.connected || m.working:
		menu.Add("断开连接").OnClick(func(*application.Context) { t.command(`{"type":"disconnect"}`, false) })
	default:
		menu.Add("连接").OnClick(func(*application.Context) { t.command(`{"type":"connect"}`, true) })
	}
	if m.loggedIn {
		lines := menu.AddSubmenu("线路")
		lines.AddCheckbox("自动选择", m.auto).OnClick(func(*application.Context) { t.choose(preferences, nil) })
		for i, group := range [][]trayNode{m.favorites, m.recent} {
			if len(group) == 0 {
				continue
			}
			lines.AddSeparator()
			if i == 0 {
				lines.Add("收藏").SetEnabled(false)
			} else {
				lines.Add("最近").SetEnabled(false)
			}
			for _, node := range group {
				id := node.id
				lines.AddCheckbox(node.label, node.selected).OnClick(func(*application.Context) { t.choose(preferences, &id) })
			}
		}
		lines.AddSeparator()
		lines.Add("全部线路…").OnClick(func(*application.Context) { t.shell.show() })
	}
	menu.AddSeparator()
	menu.Add("打开 " + t.shell.name).OnClick(func(*application.Context) { t.shell.show() })
	menu.Add("退出").OnClick(func(*application.Context) { t.shell.app.Quit() })
}

// command runs a controller command off the UI thread; with reveal, a failure opens
// the window, where the problem and what to do about it are shown.
func (t *trayMenu) command(raw string, reveal bool) {
	go func() {
		result := t.shell.controller.Command(t.ctx, json.RawMessage(raw))
		if reveal && !result.OK {
			t.shell.show()
		}
	}()
}

// choose selects a line as the node list does: the controller reconnects if needed.
func (t *trayMenu) choose(preferences core.Preferences, id *string) {
	preferences.NodeID = id
	body, err := core.EncodeJSON(map[string]any{"type": "preferences", "preferences": preferences})
	if err == nil {
		t.command(string(body), true)
	}
}

// dimmedIcon is the tray icon while disconnected: grey and faded, so a glance tells.
func dimmedIcon(raw []byte) []byte {
	img, err := png.Decode(bytes.NewReader(raw))
	if err != nil {
		return raw
	}
	bounds := img.Bounds()
	out := image.NewNRGBA(bounds)
	for y := bounds.Min.Y; y < bounds.Max.Y; y++ {
		for x := bounds.Min.X; x < bounds.Max.X; x++ {
			c := color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA)
			grey := uint8((299*uint32(c.R) + 587*uint32(c.G) + 114*uint32(c.B)) / 1000)
			out.SetNRGBA(x, y, color.NRGBA{grey, grey, grey, uint8(uint32(c.A) * 60 / 100)})
		}
	}
	var buffer bytes.Buffer
	if png.Encode(&buffer, out) != nil {
		return raw
	}
	return buffer.Bytes()
}
