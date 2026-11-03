package core

import (
	"context"
	"reflect"
	"sync"
	"testing"
)

func TestNodeListsPersistAndSurviveStaleSettings(t *testing.T) {
	h := newControllerHarness(t, nil, false)
	c := h.controller
	stale := c.View().Preferences
	id := c.View().Nodes[0].ID
	if r := commandForTest(c, map[string]any{"type": "favorite-node", "nodeId": id, "favorite": true}); !r.OK {
		t.Fatal(r)
	}
	if len(c.View().Preferences.RecentNodeIDs) != 0 || h.driver.starts.Load() != 0 {
		t.Fatal("favoriting connected or recorded history")
	}
	if r := commandForTest(c, map[string]any{"type": "connect"}); !r.OK {
		t.Fatal(r)
	}
	stale.Theme = "dark"
	if r := commandForTest(c, map[string]any{"type": "preferences", "preferences": stale}); !r.OK {
		t.Fatal(r)
	}
	view := c.View()
	if view.Preferences.Theme != "dark" || !reflect.DeepEqual(view.Preferences.FavoriteNodeIDs, []string{id}) || len(view.Preferences.RecentNodeIDs) != 1 || view.Preferences.RecentNodeIDs[0] != *view.ActualNode {
		t.Fatalf("lost lists: %+v", view.Preferences)
	}
	saved, err := c.deps.Preferences.Load()
	if err != nil || !reflect.DeepEqual(*saved, view.Preferences) {
		t.Fatalf("not persisted: %+v %v", saved, err)
	}
	view.Preferences.FavoriteNodeIDs[0] = "changed outside controller"
	if c.View().Preferences.FavoriteNodeIDs[0] != id {
		t.Fatal("view aliases controller state")
	}
	if r := commandForTest(c, map[string]any{"type": "favorite-node", "nodeId": id, "favorite": false}); !r.OK {
		t.Fatal(r)
	}
	saved, err = c.deps.Preferences.Load()
	if err != nil || len(saved.FavoriteNodeIDs) != 0 || saved.FavoriteNodeIDs == nil {
		t.Fatal("empty favorites must persist as []")
	}
}

func TestRecentNodesTrackSuccessfulConnectionsInOrder(t *testing.T) {
	h := newControllerHarness(t, func(d *ControllerDeps) { d.Panel.(*lifecyclePanel).nodes = 10 }, false)
	c := h.controller
	nodes := c.View().Nodes
	for _, node := range append(nodes, nodes[3]) {
		p := c.View().Preferences
		p.NodeID = &node.ID
		if r := commandForTest(c, map[string]any{"type": "preferences", "preferences": p}); !r.OK {
			t.Fatal(r)
		}
		if r := commandForTest(c, map[string]any{"type": "connect"}); !r.OK {
			t.Fatal(r)
		}
		if r := commandForTest(c, map[string]any{"type": "disconnect"}); !r.OK {
			t.Fatal(r)
		}
	}
	want := []string{nodes[3].ID, nodes[9].ID, nodes[8].ID, nodes[7].ID, nodes[6].ID, nodes[5].ID, nodes[4].ID, nodes[2].ID}
	if got := c.View().Preferences.RecentNodeIDs; !reflect.DeepEqual(got, want) {
		t.Fatalf("MRU %v want %v", got, want)
	}
}

type failedFavoriteDriver struct{ lifecycleDriver }

func (*failedFavoriteDriver) Start(context.Context, string) error {
	return NewAppError("CONNECT_TIMEOUT")
}

func TestFailedConnectionNeverBecomesRecent(t *testing.T) {
	h := newControllerHarness(t, func(d *ControllerDeps) { d.NetworkDriver = &failedFavoriteDriver{} }, false)
	if r := commandForTest(h.controller, map[string]any{"type": "connect"}); r.OK {
		t.Fatal("unexpected success")
	}
	if len(h.controller.View().Preferences.RecentNodeIDs) != 0 {
		t.Fatal("failed node recorded")
	}
}

func TestConcurrentFavoriteAndSettingsWritesKeepBoth(t *testing.T) {
	h := newControllerHarness(t, nil, false)
	c := h.controller
	p := c.View().Preferences
	p.Theme = "dark"
	var wg sync.WaitGroup
	for _, node := range c.View().Nodes {
		wg.Go(func() {
			if err := c.rememberFavorite(node.ID, true); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Go(func() {
		if r := commandForTest(c, map[string]any{"type": "preferences", "preferences": p}); !r.OK {
			t.Error(r)
		}
	})
	wg.Wait()
	view := c.View()
	saved, err := c.deps.Preferences.Load()
	if err != nil || !reflect.DeepEqual(*saved, view.Preferences) || view.Preferences.Theme != "dark" || len(saved.FavoriteNodeIDs) != len(view.Nodes) {
		t.Fatalf("lost concurrent write: %+v %v", saved, err)
	}
}
