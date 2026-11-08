package main

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"

	"work.starrail/client/desktop/core"
)

func trayView(connection core.ConnectionState) core.AppView {
	selected, actual := "b", "b"
	return core.AppView{
		LoggedIn: true, Connection: connection, SelectedNode: &selected, ActualNode: &actual,
		Nodes:       []core.NodeView{{ID: "a", Name: "🇯🇵 东京 01", Compatible: true}, {ID: "b", Name: "🇸🇬 新加坡 01", Compatible: true}, {ID: "c", Name: "🇲🇴 澳门", Compatible: false}, {ID: "d", Name: "香港 02", Compatible: true}},
		Preferences: core.Preferences{FavoriteNodeIDs: []string{"a", "c", "gone"}, RecentNodeIDs: []string{"b", "a", "d"}},
	}
}

func TestTrayModelShowsStateAndUsableShortcuts(t *testing.T) {
	m := newTrayModel(trayView("Connected"))
	if !m.connected || m.status != "已连接 · 新加坡 01" || m.auto {
		t.Fatalf("%+v", m)
	}
	// Unusable or vanished favorites are left out; recent lines skip favorites.
	if len(m.favorites) != 1 || m.favorites[0] != (trayNode{"a", "东京 01", false}) {
		t.Fatalf("favorites %+v", m.favorites)
	}
	if len(m.recent) != 2 || m.recent[0] != (trayNode{"b", "新加坡 01", true}) || m.recent[1].label != "香港 02" {
		t.Fatalf("recent %+v", m.recent)
	}
	for state, status := range map[core.ConnectionState]string{"Connecting": "正在连接…", "Disconnecting": "正在断开…", "RecoveryRequired": "网络需要修复", "Disconnected": "未连接"} {
		if got := newTrayModel(trayView(state)).status; got != status {
			t.Fatalf("%s: %q", state, got)
		}
	}
	if m := newTrayModel(core.AppView{}); m.loggedIn || m.status != "未登录" {
		t.Fatalf("logged out %+v", m)
	}
	if !m.equal(newTrayModel(trayView("Connected"))) || m.equal(newTrayModel(trayView("Disconnected"))) {
		t.Fatal("menu rebuilt for nothing, or not when the state changed")
	}
}

func TestDimmedIconIsGreyAndFaded(t *testing.T) {
	img := image.NewNRGBA(image.Rect(0, 0, 2, 1))
	img.SetNRGBA(0, 0, color.NRGBA{255, 0, 0, 255})
	var raw bytes.Buffer
	if err := png.Encode(&raw, img); err != nil {
		t.Fatal(err)
	}
	out, err := png.Decode(bytes.NewReader(dimmedIcon(raw.Bytes())))
	if err != nil {
		t.Fatal(err)
	}
	c := color.NRGBAModel.Convert(out.At(0, 0)).(color.NRGBA)
	if c.R != c.G || c.G != c.B || c.A != 153 {
		t.Fatalf("pixel %+v", c)
	}
	if got := dimmedIcon([]byte("not a png")); string(got) != "not a png" {
		t.Fatal("an unreadable icon must be kept as it is")
	}
}
