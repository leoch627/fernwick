package core

import "testing"

func TestUsableNodes(t *testing.T) {
	parsed := ParsedNodes{Nodes: []ProxyNode{{Name: "官网 starrail.work"}, {Name: "备用 host.leiterup.de"}, {Name: "剩余流量：100 GB"}, {Name: "🇨🇳 Shanghai 01"}, {Name: "🇯🇵 Tokyo 01"}, {Name: "Plain node"}}}
	nodes := UsableNodes(parsed).Nodes
	if len(nodes) != 2 || nodes[0].Name != "🇯🇵 Tokyo 01" || nodes[1].Name != "Plain node" {
		t.Fatal(nodes)
	}
	if nodes[0].Region == nil || *nodes[0].Region != "JP" || nodes[1].Region != nil {
		t.Fatal(nodes[0].Region, nodes[1].Region)
	}
}
func TestNodeRegion(t *testing.T) {
	for name, want := range map[string]string{"🇺🇸 United States": "US", "🇭🇰": "HK", "🇪🇺 Europe": "EU", "US 01": "", "": "", "🇯": ""} {
		if got := NodeRegion(name); got != want {
			t.Errorf("NodeRegion(%q) = %q, want %q", name, got, want)
		}
	}
}
func TestConnectionPool(t *testing.T) {
	region := func(code string) *string { return &code }
	node := func(id, code string) ProxyNode {
		n := ProxyNode{ID: id, Compatible: true, TCP: true, UDP: true}
		if code != "" {
			n.Region = region(code)
		}
		return n
	}
	hk, jp, us, unknown := node("hk", "HK"), node("jp", "JP"), node("us", "US"), node("x", "")
	nodes := []ProxyNode{hk, jp, us, unknown}
	if !AICapable(jp) || AICapable(hk) || AICapable(unknown) {
		t.Fatal("AI capability by region")
	}
	ids := func(pool []ProxyNode) (out []string) {
		for _, n := range pool {
			out = append(out, n.ID)
		}
		return
	}
	if got := ids(ConnectionPool(nodes, jp, true, nil)); len(got) != 3 || got[0] != "hk" || got[1] != "us" || got[2] != "x" {
		t.Errorf("automatic pool = %v", got)
	}
	if got := ConnectionPool(nodes, jp, false, nil); got != nil {
		t.Errorf("manual AI-capable node got a pool: %v", ids(got))
	}
	if got := ids(ConnectionPool(nodes, hk, false, nil)); len(got) != 2 || got[0] != "jp" || got[1] != "us" {
		t.Errorf("manual Hong Kong node AI pool = %v", got)
	}
}
