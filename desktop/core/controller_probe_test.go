package core

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func probeController(t *testing.T, probe ProbeFunc, demo bool) *controllerHarness {
	return newControllerHarness(t, func(deps *ControllerDeps) {
		deps.Panel = &lifecyclePanel{nodes: 12}
		deps.Probe = probe
		deps.Demo = demo
	}, false)
}
func TestControllerProbeBatchBoundsConcurrencyAndCooldown(t *testing.T) {
	var active, peak, calls atomic.Int32
	h := probeController(t, func(context.Context, ProxyNode) (ProbeResult, error) {
		n := active.Add(1)
		calls.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
		active.Add(-1)
		latency := 23.0
		return ProbeResult{true, &latency}, nil
	}, false)
	ids := []string{}
	for _, node := range h.controller.View().Nodes[:10] {
		ids = append(ids, node.ID)
	}
	result := commandForTest(h.controller, map[string]any{"type": "probe-nodes", "nodeIds": ids})
	if !result.OK || peak.Load() != 4 || calls.Load() != 10 {
		t.Fatalf("probe limits peak%d calls%d result%+v", peak.Load(), calls.Load(), result)
	}
	healthy := 0
	for _, node := range result.State.Nodes {
		if node.Probe == "healthy" {
			healthy++
			if node.Latency == nil || *node.Latency != 23 {
				t.Fatal("latency lost")
			}
		}
	}
	if healthy != 10 {
		t.Fatal(healthy)
	}
	if next := commandForTest(h.controller, map[string]any{"type": "probe-nodes", "nodeIds": ids}); next.Error != "RATE_LIMITED" {
		t.Fatal(next)
	}
}
func TestControllerProbeRejectsOversizeUnknownAndDemoWithoutExecutor(t *testing.T) {
	var calls atomic.Int32
	probe := func(context.Context, ProxyNode) (ProbeResult, error) {
		calls.Add(1)
		return ProbeResult{Healthy: true}, nil
	}
	h := probeController(t, probe, false)
	ids := []string{}
	for _, node := range h.controller.View().Nodes {
		ids = append(ids, node.ID)
	}
	if result := commandForTest(h.controller, map[string]any{"type": "probe-nodes", "nodeIds": ids}); result.Error != "INVALID_INPUT" {
		t.Fatal(result)
	}
	if result := commandForTest(h.controller, map[string]any{"type": "probe-nodes", "nodeIds": []string{"unknown"}}); result.Error != "NO_COMPATIBLE_NODES" {
		t.Fatal(result)
	}
	demo := probeController(t, probe, true)
	if result := commandForTest(demo.controller, map[string]any{"type": "probe-nodes", "nodeIds": []string{demo.controller.View().Nodes[0].ID}}); result.Error != "COMPONENTS_UNAVAILABLE" {
		t.Fatal(result)
	}
	if result := commandForTest(demo.controller, map[string]any{"type": "connect"}); result.Error != "COMPONENTS_UNAVAILABLE" {
		t.Fatal(result)
	}
	if calls.Load() != 0 {
		t.Fatal("invalid/demo batch reached executor")
	}
}
func TestControllerLogoutCancelsProbeAndDiscardsLateLatency(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	h := probeController(t, func(context.Context, ProxyNode) (ProbeResult, error) {
		once.Do(func() { close(entered) })
		<-release
		latency := 1.0
		return ProbeResult{true, &latency}, nil
	}, false)
	result := make(chan CommandResult, 1)
	id := h.controller.View().Nodes[0].ID
	go func() {
		result <- commandForTest(h.controller, map[string]any{"type": "probe-nodes", "nodeIds": []string{id}})
	}()
	<-entered
	if logout := commandForTest(h.controller, map[string]any{"type": "logout"}); !logout.OK {
		t.Fatal(logout)
	}
	close(release)
	<-result
	view := h.controller.View()
	if view.LoggedIn || len(view.Nodes) != 0 {
		t.Fatal("late probe resurrected nodes")
	}
}
func TestControllerFailedProbeHasNoLatency(t *testing.T) {
	h := probeController(t, func(context.Context, ProxyNode) (ProbeResult, error) {
		latency := 999.0
		return ProbeResult{false, &latency}, nil
	}, false)
	id := h.controller.View().Nodes[0].ID
	result := commandForTest(h.controller, map[string]any{"type": "probe-nodes", "nodeIds": []string{id}})
	if !result.OK || result.State.Nodes[0].Probe != "timeout" || result.State.Nodes[0].Latency != nil {
		t.Fatal(result)
	}
}
