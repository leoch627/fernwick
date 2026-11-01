package core

import (
	"regexp"
	"unicode/utf8"
)

// Panels publish display-only entries (website, backup address, remaining traffic,
// expiry) as subscription nodes. 🇨🇳 nodes route back into mainland China and are
// of no use to users who are already there.
var infoNodeName = regexp.MustCompile(`官网|备用|剩余|到期|过期|套餐|重置|网址`)

// NodeRegion reads the ISO region code from a leading flag emoji such as "🇯🇵 Tokyo 01".
func NodeRegion(name string) string {
	first, size := utf8.DecodeRuneInString(name)
	second, _ := utf8.DecodeRuneInString(name[size:])
	const a = 0x1F1E6
	if first < a || first > a+25 || second < a || second > a+25 {
		return ""
	}
	return string(rune('A'+first-a)) + string(rune('A'+second-a))
}

// AICapable reports whether AI services accept the node's exit region. They refuse
// mainland China, Hong Kong and Macao; nodes without a flag are treated as unknown.
func AICapable(node ProxyNode) bool {
	return node.Region != nil && *node.Region != "" && *node.Region != "CN" && *node.Region != "HK" && *node.Region != "MO"
}

// ConnectionPool lists the nodes the core may balance across besides the chosen one:
// every automatic candidate when the user picked "automatic", otherwise only the
// AI-capable nodes needed to keep AI traffic off a node AI services refuse.
func ConnectionPool(nodes []ProxyNode, chosen ProxyNode, automatic bool, policy *Policy) []ProxyNode {
	if !automatic && AICapable(chosen) {
		return nil
	}
	pool := []ProxyNode{}
	for _, n := range nodes {
		if n.ID != chosen.ID && Eligible(n, policy, true) && (automatic || AICapable(n)) && len(pool) < 63 {
			pool = append(pool, n)
		}
	}
	return pool
}

// UsableNodes removes entries users cannot meaningfully connect to and tags
// each remaining node with its region.
func UsableNodes(parsed ParsedNodes) ParsedNodes {
	nodes := make([]ProxyNode, 0, len(parsed.Nodes))
	for _, n := range parsed.Nodes {
		region := NodeRegion(n.Name)
		if infoNodeName.MatchString(n.Name) || region == "CN" {
			continue
		}
		if region != "" {
			n.Region = &region
		}
		nodes = append(nodes, n)
	}
	parsed.Nodes = nodes
	return parsed
}
