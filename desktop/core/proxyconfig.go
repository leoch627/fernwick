package core

import "strconv"

// System proxy mode runs the pinned core as the user, with no network service: apps
// that follow the system proxy reach a loopback HTTP/SOCKS port, and the core routes
// from there. Routing, DNS and balancers follow the network service's TUN configuration
// (native/helper/compiler.go) without the TUN inbound or physical interface binding.

// ProxyPorts are the loopback ports of one system proxy session. Local is the
// unauthenticated HTTP+SOCKS port the system proxy points at; Health is an
// authenticated SOCKS port that proves the proxy path before the system proxy is set.
type ProxyPorts struct {
	Local  int
	Health ProbeAuth
}

// proxyNodeTag tags outbounds by role so balancer selectors can use prefixes: every
// node is a candidate for "auto", only node-ai-* nodes for "ai".
func proxyNodeTag(n ProxyNode, i int) string {
	if AICapable(n) {
		return "node-ai-" + strconv.Itoa(i)
	}
	return "node-" + strconv.Itoa(i)
}

func withTarget(rule map[string]any, target map[string]any) map[string]any {
	for k, v := range target {
		rule[k] = v
	}
	return rule
}

// WithoutTarget drops the sections that send traffic to target, e.g. "block" when the
// user turns ad blocking off.
func (r Rules) WithoutTarget(target string) Rules {
	kept := Rules{SchemaVersion: r.SchemaVersion, Sections: []RuleSection{}}
	for _, section := range r.Sections {
		if section.Target != target {
			kept.Sections = append(kept.Sections, section)
		}
	}
	return kept
}

// Names no rule list covers are resolved only through the proxy, never by a mainland
// resolver: asking one would show it every foreign site the user visits (a DNS leak),
// and a failed answer does not fall back to one. Google's resolver honours EDNS Client
// Subnet, so a fixed mainland subnet (AliDNS's anycast /24, not the user's address)
// still gets unlisted mainland sites their mainland CDN addresses, which then route
// direct. Cloudflare ignores ECS and returned overseas nodes, sending such sites abroad.
// native/helper/compiler.go uses the same pair for TUN mode.
const (
	UnlistedResolver     = "https://8.8.8.8/dns-query"
	MainlandClientSubnet = "223.5.5.0"
)

// CompileSystemProxy builds the core configuration for system proxy mode. It never
// creates a TUN inbound, and every inbound listens on loopback only.
func CompileSystemProxy(c Candidate, ports ProxyPorts) (map[string]any, error) {
	auth := ports.Health
	if ports.Local < 1024 || ports.Local > 65535 || auth.Port < 1024 || auth.Port > 65535 || auth.Port == ports.Local || jsUTF16Length(auth.User) < 1 || jsUTF16Length(auth.User) > 255 || jsUTF16Length(auth.Password) < 16 || jsUTF16Length(auth.Password) > 255 {
		return nil, NewAppError("INVALID_INPUT")
	}
	if c.Mode != "rule" && c.Mode != "global" {
		return nil, NewAppError("INVALID_INPUT")
	}
	if err := c.Rules.Validate(); err != nil {
		return nil, err
	}
	first, err := CompileOutbound(c.Node)
	if err != nil {
		return nil, err
	}
	first["tag"] = proxyNodeTag(c.Node, 0)
	nodes := []ProxyNode{c.Node}
	outbounds := []any{first}
	for _, n := range c.Pool {
		// A pool node the core cannot use is left out rather than failing the connection.
		outbound, err := CompileOutbound(n)
		if err != nil {
			continue
		}
		nodes = append(nodes, n)
		outbound["tag"] = proxyNodeTag(n, len(nodes)-1)
		outbounds = append(outbounds, outbound)
	}
	primary := map[string]any{"outboundTag": proxyNodeTag(c.Node, 0)}
	balancers := []any{}
	observed := []string{}
	if c.Automatic && len(nodes) > 1 {
		primary = map[string]any{"balancerTag": "auto"}
		balancers = append(balancers, map[string]any{"tag": "auto", "selector": []string{"node-"}, "strategy": map[string]any{"type": "leastPing"}, "fallbackTag": proxyNodeTag(c.Node, 0)})
		observed = []string{"node-"}
	}
	// AI services reject Hong Kong and mainland exits: AI traffic keeps to the user's
	// node only when it qualifies, and otherwise goes to the fastest qualifying node.
	ai := primary
	if c.Automatic || !AICapable(c.Node) {
		for i, n := range nodes {
			if AICapable(n) {
				ai = map[string]any{"balancerTag": "ai"}
				balancers = append(balancers, map[string]any{"tag": "ai", "selector": []string{"node-ai-"}, "strategy": map[string]any{"type": "leastPing"}, "fallbackTag": proxyNodeTag(n, i)})
				if len(observed) == 0 {
					observed = []string{"node-ai-"}
				}
				break
			}
		}
	}
	targets := map[string]map[string]any{"direct": {"outboundTag": "direct"}, "block": {"outboundTag": "block"}, "proxy": primary, "ai": ai}
	routes := []any{
		// The health port always tests the proxy path, whatever the rules say about its targets.
		withTarget(map[string]any{"type": "field", "inboundTag": []string{"health"}}, primary),
		map[string]any{"type": "field", "inboundTag": []string{"dns-direct"}, "outboundTag": "direct"},
		withTarget(map[string]any{"type": "field", "inboundTag": []string{"dns-proxy"}}, primary),
		map[string]any{"type": "field", "port": "53", "network": "tcp,udp", "outboundTag": "dns-out"},
		map[string]any{"type": "field", "ip": lanCIDRs, "outboundTag": "direct"},
	}
	// Each section's domains get a resolver for its exit: direct domains ask a mainland
	// resolver for nearby CDN addresses, everything else is resolved abroad through the
	// proxy. Xray consults matching servers in configuration order, as it does for routing.
	dns := []any{}
	for _, section := range c.Rules.Sections {
		// Global mode still blocks ads and keeps AI traffic off unsuitable exits.
		if c.Mode == "global" && section.Target != "block" && section.Target != "ai" {
			continue
		}
		if len(section.Domains) > 0 {
			routes = append(routes, withTarget(map[string]any{"type": "field", "domain": section.Domains}, targets[section.Target]))
			if c.Mode == "rule" && section.Target == "direct" {
				dns = append(dns, map[string]any{"address": "https://223.5.5.5/dns-query", "domains": section.Domains, "skipFallback": true, "tag": "dns-direct", "finalQuery": true})
			} else if c.Mode == "rule" && section.Target != "block" {
				dns = append(dns, map[string]any{"address": "https://1.1.1.1/dns-query", "domains": section.Domains, "skipFallback": true, "tag": "dns-proxy", "finalQuery": true})
			}
		}
		if len(section.IPs) > 0 {
			routes = append(routes, withTarget(map[string]any{"type": "field", "ip": section.IPs}, targets[section.Target]))
		}
	}
	// Apps hand the proxy a domain name, not an address. In rule mode a domain that no
	// list names is resolved and routed by address (mainland addresses go direct), as the
	// TUN configuration does after DNS. The final rule therefore matches addresses only:
	// a catch-all on network would match first and skip the resolution.
	strategy := "AsIs"
	if c.Mode == "rule" {
		strategy = "IPIfNonMatch"
		routes = append(routes, withTarget(map[string]any{"type": "field", "ip": []string{"0.0.0.0/0", "::/0"}}, primary))
	} else {
		routes = append(routes, withTarget(map[string]any{"type": "field", "network": "tcp,udp"}, primary))
	}
	// Everything else is resolved through the proxy only (see UnlistedResolver).
	if c.Mode == "rule" {
		dns = append(dns, map[string]any{"address": UnlistedResolver, "tag": "dns-proxy", "clientIP": MainlandClientSubnet, "skipFallback": false, "finalQuery": true})
	} else {
		dns = append(dns, map[string]any{"address": "https://1.1.1.1/dns-query", "tag": "dns-proxy", "skipFallback": false, "finalQuery": true})
	}
	outbounds = append(outbounds,
		// Prefer IPv4: "UseIP" picks a random A or AAAA answer, and on the many networks
		// without working IPv6 every other direct connection failed or hung.
		map[string]any{"tag": "direct", "protocol": "freedom", "settings": map[string]any{"domainStrategy": "UseIPv4v6", "finalRules": []any{map[string]any{"action": "allow", "ip": lanCIDRs}}}},
		map[string]any{"tag": "dns-out", "protocol": "dns", "settings": map[string]any{"rules": []any{map[string]any{"action": "hijack", "qType": "1,28"}, map[string]any{"action": "return", "rCode": 5}}}},
		map[string]any{"tag": "block", "protocol": "blackhole"},
	)
	routing := map[string]any{"domainStrategy": strategy, "rules": routes}
	config := map[string]any{
		"log": map[string]any{"loglevel": "none", "access": "none", "error": "none"},
		"inbounds": []any{
			map[string]any{"tag": "local", "listen": "127.0.0.1", "port": ports.Local, "protocol": "mixed", "settings": map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"}, "sniffing": map[string]any{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}},
			map[string]any{"tag": "health", "listen": "127.0.0.1", "port": auth.Port, "protocol": "socks", "settings": map[string]any{"auth": "password", "accounts": []any{map[string]any{"user": auth.User, "pass": auth.Password}}, "udp": false}},
		},
		"outbounds": outbounds,
		"dns":       map[string]any{"tag": "dns-proxy", "queryStrategy": "UseIP", "disableFallbackIfMatch": true, "useSystemHosts": false, "servers": dns},
		"routing":   routing,
	}
	if len(balancers) > 0 {
		routing["balancers"] = balancers
		// Like Mihomo's url-test: probe every five minutes and prefer the fastest node.
		config["observatory"] = map[string]any{"subjectSelector": observed, "probeUrl": "https://www.gstatic.com/generate_204", "probeInterval": "5m", "enableConcurrency": true}
	}
	return config, nil
}
