package core

import (
	"context"
	"sort"
	"time"
)

type ProbeResult struct {
	Healthy   bool     `json:"healthy"`
	LatencyMs *float64 `json:"latencyMs"`
}

type ProbeFunc func(context.Context, ProxyNode) (ProbeResult, error)

func nodeOperation(nodeID string, policy *Policy) *NodeOperation {
	if policy != nil {
		for i := range policy.NodeOperations {
			if policy.NodeOperations[i].NodeID == nodeID {
				return &policy.NodeOperations[i]
			}
		}
	}
	return nil
}

func Eligible(node ProxyNode, policy *Policy, automatic bool) bool {
	flag := nodeOperation(node.ID, policy)
	return node.Compatible && node.TCP && node.UDP && (flag == nil || !flag.DisabledForConnection && (!automatic || flag.EligibleForAuto))
}

func selectedID(id *string) string {
	if id == nil {
		return ""
	}
	return *id
}

// SelectNode probes at most three candidates, two concurrently. A faster
// lower-ranked response never preempts a healthy current/manual selection.
func SelectNode(nodes []ProxyNode, policy *Policy, manual, current, recentHealthy *string, probe ProbeFunc, parent context.Context) (ProxyNode, error) {
	manualID, currentID, recentID := selectedID(manual), selectedID(current), selectedID(recentHealthy)
	candidates := make([]ProxyNode, 0, len(nodes))
	for _, node := range nodes {
		if Eligible(node, policy, manualID == "") {
			candidates = append(candidates, node)
		}
	}
	budget := NewBudget(6*time.Second, parent)
	defer budget.Dispose()
	if err := budget.Check(); err != nil {
		return ProxyNode{}, err
	}
	if manualID != "" {
		for _, node := range candidates {
			if node.ID == manualID {
				results, err := probeBatch(budget, []ProxyNode{node}, probe)
				if err != nil {
					return ProxyNode{}, err
				}
				if results[0].err != nil {
					return ProxyNode{}, results[0].err
				}
				if results[0].result.Healthy {
					return node, nil
				}
				return ProxyNode{}, NewAppError("CONNECT_TIMEOUT")
			}
		}
		return ProxyNode{}, NewAppError("NO_AUTHORIZED_NODES")
	}
	preferred := currentID
	if preferred == "" {
		preferred = recentID
	}
	var region *string
	for _, node := range candidates {
		if node.ID == preferred {
			region = node.Region
			break
		}
	}
	weight := func(node ProxyNode) int {
		switch {
		case currentID != "" && node.ID == currentID:
			return -3
		case recentID != "" && node.ID == recentID:
			return -2
		case region != nil && *region != "" && node.Region != nil && *region == *node.Region:
			return -1
		default:
			return 0
		}
	}
	order := func(node ProxyNode) int {
		if flag := nodeOperation(node.ID, policy); flag != nil && flag.Order != nil {
			return *flag.Order
		}
		return node.Order
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if a, b := weight(candidates[i]), weight(candidates[j]); a != b {
			return a < b
		}
		return order(candidates[i]) < order(candidates[j])
	})
	candidates = candidates[:min(len(candidates), 3)]
	if len(candidates) == 0 {
		return ProxyNode{}, NewAppError("NO_COMPATIBLE_NODES")
	}
	for i := 0; i < len(candidates); i += 2 {
		batch := candidates[i:min(i+2, len(candidates))]
		results, err := probeBatch(budget, batch, probe)
		if err != nil {
			return ProxyNode{}, err
		}
		for j, result := range results {
			if result.err == nil && result.result.Healthy {
				return batch[j], nil
			}
		}
	}
	return ProxyNode{}, NewAppError("CONNECT_TIMEOUT")
}

type nodeProbeOutcome struct {
	index  int
	result ProbeResult
	err    error
}

func probeBatch(budget *Budget, batch []ProxyNode, probe ProbeFunc) ([]nodeProbeOutcome, error) {
	if err := budget.Check(); err != nil {
		return nil, err
	}
	// Buffered sends let cooperative probes finish after the caller cancels.
	completed := make(chan nodeProbeOutcome, len(batch))
	for i, node := range batch {
		go func() {
			result, err := probe(budget.Context(), node)
			completed <- nodeProbeOutcome{index: i, result: result, err: err}
		}()
	}
	results := make([]nodeProbeOutcome, len(batch))
	for range batch {
		select {
		case <-budget.Context().Done():
			return nil, NewAppError("CANCELLED")
		case result := <-completed:
			results[result.index] = result
		}
	}
	return results, budget.Check()
}
