package main

import "runtime"

type object = map[string]any

var lan = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}

// Unlisted names resolve through the proxy only, with a fixed mainland ECS subnet so
// mainland CDNs still answer with mainland addresses; never a mainland resolver, which
// would see every foreign site visited. Mirrors desktop/core/proxyconfig.go.
const (
	unlistedResolver     = "https://8.8.8.8/dns-query"
	mainlandClientSubnet = "223.5.5.0"
)

func tunName() string {
	if runtime.GOOS == "darwin" {
		return "utun50"
	}
	if runtime.GOOS == "windows" {
		return "ProxyTun"
	}
	return "vbtun0"
}
func tunDNS() string {
	if runtime.GOOS == "darwin" {
		return "172.19.0.1"
	}
	return "172.19.0.2"
}
func compileOutbound(n Node, address, tag string, sock object) object {
	stream := object{"network": n.Transport, "security": n.Security, "sockopt": sock}
	if n.Security == "tls" {
		tls := object{"serverName": n.SNI, "allowInsecure": false, "fingerprint": n.Fingerprint}
		if n.ECH != "" {
			tls["echConfigList"] = n.ECH
		}
		stream["tlsSettings"] = tls
	}
	if n.Security == "reality" {
		stream["realitySettings"] = object{"serverName": n.SNI, "fingerprint": n.Fingerprint, "publicKey": n.PublicKey, "shortId": n.ShortID}
	}
	if n.Transport == "ws" {
		stream["wsSettings"] = object{"path": n.WSPath, "headers": object{"Host": n.WSHost}}
	}
	if n.Transport == "xhttp" {
		stream["xhttpSettings"] = object{"path": n.WSPath, "host": n.WSHost, "mode": n.Mode}
	}
	var settings object
	if n.Protocol == "vless" || n.Protocol == "vmess" {
		user := object{"id": n.Credential}
		if n.Protocol == "vless" {
			user["encryption"] = "none"
			user["flow"] = n.Flow
		} else {
			user["alterId"] = 0
			user["security"] = n.Method
			if n.Method == "" {
				user["security"] = "auto"
			}
		}
		settings = object{"vnext": []object{{"address": address, "port": n.Port, "users": []object{user}}}}
	} else {
		server := object{"address": address, "port": n.Port, "password": n.Credential}
		if n.Protocol == "shadowsocks" {
			server["method"] = n.Method
		}
		settings = object{"servers": []object{server}}
	}
	return object{"tag": tag, "protocol": n.Protocol, "settings": settings, "streamSettings": stream}
}

// Node outbounds are tagged by role so balancer selectors can use tag prefixes:
// every node is a candidate for "auto", only node-ai-* nodes for "ai".
func nodeTag(n Node, i int) string {
	if n.AI {
		return "node-ai-" + itoa(i)
	}
	return "node-" + itoa(i)
}

// route sends a rule to a fixed outbound or a balancer.
func route(rule object, target object) object {
	for k, v := range target {
		rule[k] = v
	}
	return rule
}

func compileCore(c Candidate, j Journal) []byte {
	sock := object{"interface": j.Interface.Name, "domainStrategy": "UseIP"}
	if runtime.GOOS == "linux" {
		sock["mark"] = mark
	}
	nodes := []Node{c.Node}
	outbounds := []object{compileOutbound(c.Node, j.NodeAddress, nodeTag(c.Node, 0), sock)}
	for i, n := range c.Pool {
		// Pool nodes whose address could not be resolved before connecting are left out.
		if i < len(j.PoolAddresses) && j.PoolAddresses[i] != "" {
			nodes = append(nodes, n)
			outbounds = append(outbounds, compileOutbound(n, j.PoolAddresses[i], nodeTag(n, len(nodes)-1), sock))
		}
	}
	primary := object{"outboundTag": nodeTag(c.Node, 0)}
	var balancers []object
	observed := []string{}
	if c.Automatic && len(nodes) > 1 {
		primary = object{"balancerTag": "auto"}
		balancers = append(balancers, object{"tag": "auto", "selector": []string{"node-"}, "strategy": object{"type": "leastPing"}, "fallbackTag": nodeTag(c.Node, 0)})
		observed = []string{"node-"}
	}
	// AI services reject Hong Kong and mainland exits: AI traffic keeps to the user's
	// node only when it qualifies, and otherwise goes to the fastest qualifying node.
	ai := primary
	if c.Automatic || !c.Node.AI {
		for i, n := range nodes {
			if n.AI {
				ai = object{"balancerTag": "ai"}
				balancers = append(balancers, object{"tag": "ai", "selector": []string{"node-ai-"}, "strategy": object{"type": "leastPing"}, "fallbackTag": nodeTag(n, i)})
				if len(observed) == 0 {
					observed = []string{"node-ai-"}
				}
				break
			}
		}
	}
	targets := map[string]object{"direct": {"outboundTag": "direct"}, "block": {"outboundTag": "block"}, "proxy": primary, "ai": ai}

	routes := []object{{"type": "field", "inboundTag": []string{"dns-direct"}, "outboundTag": "direct"}, route(object{"type": "field", "inboundTag": []string{"dns-proxy"}}, primary), {"type": "field", "port": "53", "network": "tcp,udp", "outboundTag": "dns-out"}, {"type": "field", "ip": lan, "outboundTag": "direct"}}
	// Each section's domains get a resolver for its exit: direct domains ask a mainland
	// resolver for nearby CDN addresses, everything else is resolved abroad through the
	// proxy. Xray consults matching servers in configuration order, so the first matching
	// section decides, as it does for routing.
	dns := []object{}
	for _, section := range c.Rules.Sections {
		// Global mode still blocks ads and keeps AI traffic off unsuitable exits.
		if c.Mode == "global" && section.Target != "block" && section.Target != "ai" {
			continue
		}
		if len(section.Domains) > 0 {
			routes = append(routes, route(object{"type": "field", "domain": section.Domains}, targets[section.Target]))
			if c.Mode == "rule" && section.Target == "direct" {
				dns = append(dns, object{"address": "https://223.5.5.5/dns-query", "domains": section.Domains, "skipFallback": true, "tag": "dns-direct", "finalQuery": true})
			} else if c.Mode == "rule" && section.Target != "block" {
				dns = append(dns, object{"address": "https://1.1.1.1/dns-query", "domains": section.Domains, "skipFallback": true, "tag": "dns-proxy", "finalQuery": true})
			}
		}
		if len(section.IPs) > 0 {
			routes = append(routes, route(object{"type": "field", "ip": section.IPs}, targets[section.Target]))
		}
	}
	routes = append(routes, route(object{"type": "field", "network": "tcp,udp"}, primary))
	// Every other name, including each app's own lookups captured by the TUN, is resolved
	// through the proxy only; a failure never falls back to a mainland resolver.
	if c.Mode == "rule" {
		dns = append(dns, object{"address": unlistedResolver, "tag": "dns-proxy", "clientIP": mainlandClientSubnet, "skipFallback": false, "finalQuery": true})
	} else {
		dns = append(dns, object{"address": "https://1.1.1.1/dns-query", "tag": "dns-proxy", "skipFallback": false, "finalQuery": true})
	}
	tun := object{"name": j.Tun, "desc": ruleTag() + " TUN", "mtu": 1500, "gateway": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}, "autoSystemRoutingTable": []string{}, "autoOutboundsInterface": j.Interface.Name, "autoSystemDnsToGateway": false}
	// Windows Xray owns its adapter's routes, DNS and dynamic WFP filters. Other platforms use helper-owned routing/DNS.
	if runtime.GOOS == "windows" {
		tun["autoSystemRoutingTable"] = []string{"0.0.0.0/0", "::/0"}
		tun["dns"] = []string{tunDNS()}
		tun["autoSystemWfpBlockLeak"] = []string{"dns", "misconfigtun"}
	}
	outbounds = append(outbounds, object{"tag": "direct", "protocol": "freedom", "settings": object{"domainStrategy": "UseIPv4v6", "finalRules": []object{{"action": "allow", "ip": lan}}}, "streamSettings": object{"sockopt": sock}}, object{"tag": "dns-out", "protocol": "dns", "settings": object{"rules": []object{{"action": "hijack", "qType": "1,28"}, {"action": "return", "rCode": 5}}}}, object{"tag": "block", "protocol": "blackhole"})
	routing := object{"domainStrategy": "AsIs", "rules": routes}
	config := object{"log": object{"loglevel": "none", "access": "none", "error": "none"}, "inbounds": []object{{"tag": "tun", "protocol": "tun", "settings": tun, "sniffing": object{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}}}, "outbounds": outbounds, "dns": object{"tag": "dns-proxy", "queryStrategy": "UseIP", "disableFallbackIfMatch": true, "useSystemHosts": false, "servers": dns}, "routing": routing}
	if len(balancers) > 0 {
		routing["balancers"] = balancers
		// Like Mihomo's url-test: probe every five minutes and prefer the fastest node.
		config["observatory"] = object{"subjectSelector": observed, "probeUrl": "https://www.gstatic.com/generate_204", "probeInterval": "5m", "enableConcurrency": true}
	}
	return jsonBytes(config)
}
