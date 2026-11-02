package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func selectionNodes(t *testing.T, count int) []ProxyNode {
	t.Helper()
	_, _, _, parsed, _ := authFixture(t)
	nodes := make([]ProxyNode, count)
	for i := range nodes {
		nodes[i] = parsed.Nodes[0]
		nodes[i].ID, nodes[i].Order = fmt.Sprintf("n%d", i), i
	}
	return nodes
}

func TestManualSelectionNeverFallsBack(t *testing.T) {
	nodes := selectionNodes(t, 3)
	calls := 0
	probe := func(context.Context, ProxyNode) (ProbeResult, error) {
		calls++
		return ProbeResult{}, nil
	}
	_, err := SelectNode(nodes, nil, &nodes[0].ID, nil, nil, probe, nil)
	if CodeOf(err) != "CONNECT_TIMEOUT" || calls != 1 {
		t.Fatalf("manual failure selected another node: calls=%d err=%v", calls, err)
	}
	_, err = SelectNode(nodes, nil, authPointer("removed-node"), nil, nil, probe, nil)
	if CodeOf(err) != "NO_AUTHORIZED_NODES" || calls != 1 {
		t.Fatal("missing manual selection started probing")
	}
	failed := NewAppError("COMPONENTS_UNAVAILABLE")
	_, err = SelectNode(nodes, nil, &nodes[0].ID, nil, nil, func(context.Context, ProxyNode) (ProbeResult, error) { return ProbeResult{}, failed }, nil)
	if !errors.Is(err, failed) {
		t.Fatalf("manual probe error was replaced: %v", err)
	}
}

func TestSelectableNamesWhyTheChosenNodeFails(t *testing.T) {
	nodes := selectionNodes(t, 2)
	nodes[0].Compatible, nodes[0].Incompatibility = false, nodeString("不支持的 flow")
	if err := Selectable(nodes, nil, &nodes[0].ID); CodeOf(err) != "NO_COMPATIBLE_NODES" {
		t.Fatalf("chosen incompatible node: %v", err)
	}
	if err := Selectable(nodes, nil, authPointer("removed-node")); CodeOf(err) != "NO_AUTHORIZED_NODES" {
		t.Fatalf("chosen node gone: %v", err)
	}
	if err := Selectable(nodes, nil, nil); err != nil {
		t.Fatalf("automatic with one usable node: %v", err)
	}
	if err := Selectable(nodes[:1], nil, nil); CodeOf(err) != "NO_COMPATIBLE_NODES" {
		t.Fatalf("automatic with none usable: %v", err)
	}
}

func TestAutomaticSelectionCapsProbesAndConcurrency(t *testing.T) {
	nodes := selectionNodes(t, 100)
	var mu sync.Mutex
	active, maximum, calls := 0, 0, 0
	firstBatch := make(chan struct{})
	probe := func(context.Context, ProxyNode) (ProbeResult, error) {
		mu.Lock()
		active++
		calls++
		maximum = max(maximum, active)
		if calls == 2 {
			close(firstBatch)
		}
		mu.Unlock()
		<-firstBatch
		mu.Lock()
		active--
		mu.Unlock()
		return ProbeResult{}, errors.New("unhealthy")
	}
	_, err := SelectNode(nodes, nil, nil, nil, nil, probe, nil)
	if CodeOf(err) != "CONNECT_TIMEOUT" || calls != 3 || maximum != 2 {
		t.Fatalf("calls=%d max=%d err=%v", calls, maximum, err)
	}
}

func TestAutomaticSelectionPreservesCurrentPriority(t *testing.T) {
	nodes := selectionNodes(t, 3)
	secondFinished := make(chan struct{})
	probe := func(_ context.Context, node ProxyNode) (ProbeResult, error) {
		if node.ID == "n2" {
			<-secondFinished
		} else {
			close(secondFinished)
		}
		return ProbeResult{Healthy: true}, nil
	}
	selected, err := SelectNode(nodes, nil, nil, &nodes[2].ID, nil, probe, nil)
	if err != nil || selected.ID != "n2" {
		t.Fatalf("fast backup preempted healthy current node: %s %v", selected.ID, err)
	}
}

func TestSelectionOperationsAndRegion(t *testing.T) {
	nodes := selectionNodes(t, 3)
	nodes[0].Region, nodes[1].Region, nodes[2].Region = authPointer("JP"), authPointer("US"), authPointer("US")
	policy := Policy{NodeOperations: []NodeOperation{{NodeID: "n0", HiddenFromList: true, EligibleForAuto: false}}}
	probe := func(context.Context, ProxyNode) (ProbeResult, error) { return ProbeResult{Healthy: true}, nil }
	selected, err := SelectNode(nodes, &policy, &nodes[0].ID, nil, nil, probe, nil)
	if err != nil || selected.ID != "n0" {
		t.Fatal("hidden or auto-disabled node lost manual eligibility")
	}
	_, err = SelectNode(nodes[:1], &policy, nil, nil, nil, probe, nil)
	if CodeOf(err) != "NO_COMPATIBLE_NODES" {
		t.Fatal("auto-disabled node remained automatically selectable")
	}
	policy.NodeOperations[0].DisabledForConnection = true
	_, err = SelectNode(nodes, &policy, &nodes[0].ID, nil, nil, probe, nil)
	if CodeOf(err) != "NO_COMPATIBLE_NODES" {
		t.Fatal("disabled node remained manually selectable")
	}
	probe = func(_ context.Context, node ProxyNode) (ProbeResult, error) {
		return ProbeResult{Healthy: node.ID != "n2"}, nil
	}
	selected, err = SelectNode(nodes, nil, nil, &nodes[2].ID, nil, probe, nil)
	if err != nil || selected.ID != "n1" {
		t.Fatalf("same-region fallback lost priority: %s %v", selected.ID, err)
	}
	policy = Policy{NodeOperations: []NodeOperation{{NodeID: "n2", EligibleForAuto: true, Order: authPointer(-1)}}}
	selected, err = SelectNode(nodes, &policy, nil, nil, nil, func(context.Context, ProxyNode) (ProbeResult, error) { return ProbeResult{Healthy: true}, nil }, nil)
	if err != nil || selected.ID != "n2" {
		t.Fatal("policy node ordering was ignored")
	}
}

func TestSelectionCancellationBoundsBatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started, finished := make(chan struct{}, 2), make(chan struct{}, 2)
	probe := func(ctx context.Context, _ ProxyNode) (ProbeResult, error) {
		started <- struct{}{}
		<-ctx.Done()
		finished <- struct{}{}
		return ProbeResult{Healthy: true}, nil // A late success cannot commit.
	}
	result := make(chan error, 1)
	nodes := selectionNodes(t, 3)
	go func() { _, err := SelectNode(nodes, nil, nil, nil, nil, probe, ctx); result <- err }()
	<-started
	<-started
	cancel()
	select {
	case err := <-result:
		if CodeOf(err) != "CANCELLED" {
			t.Fatalf("late success escaped cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled batch did not return")
	}
	<-finished
	<-finished
	_, err := SelectNode(nodes, nil, nil, nil, nil, func(context.Context, ProxyNode) (ProbeResult, error) {
		t.Error("probe started after cancellation")
		return ProbeResult{}, nil
	}, ctx)
	if CodeOf(err) != "CANCELLED" {
		t.Fatal("pre-cancelled selection succeeded")
	}
}
