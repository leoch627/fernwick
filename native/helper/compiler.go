package main

import "runtime"

type object = map[string]any

var lan = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}

func tagged(prefix string, values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = prefix + v
	}
	return out
}
func tunName() string {
	if runtime.GOOS == "darwin" {
		return "utun50"
	}
	if runtime.GOOS == "windows" {
		return "StarRailTun"
	}
	return "starr0"
}
func tunDNS() string {
	if runtime.GOOS == "darwin" {
		return "172.19.0.1"
	}
	return "172.19.0.2"
}
func compileCore(c Candidate, j Journal) []byte {
	n := c.Node
	sock := object{"interface": j.Interface.Name, "domainStrategy": "UseIP"}
	if runtime.GOOS == "linux" {
		sock["mark"] = mark
	}
	stream := object{"network": n.Transport, "security": n.Security, "sockopt": sock}
	if n.Security == "tls" {
		stream["tlsSettings"] = object{"serverName": n.SNI, "allowInsecure": false, "fingerprint": n.Fingerprint}
	}
	if n.Security == "reality" {
		stream["realitySettings"] = object{"serverName": n.SNI, "fingerprint": n.Fingerprint, "publicKey": n.PublicKey, "shortId": n.ShortID}
	}
	if n.Transport == "ws" {
		stream["wsSettings"] = object{"path": n.WSPath, "headers": object{"Host": n.WSHost}}
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
		settings = object{"vnext": []object{{"address": j.NodeAddress, "port": n.Port, "users": []object{user}}}}
	} else {
		server := object{"address": j.NodeAddress, "port": n.Port, "password": n.Credential}
		if n.Protocol == "shadowsocks" {
			server["method"] = n.Method
		}
		settings = object{"servers": []object{server}}
	}
	routes := []object{{"type": "field", "inboundTag": []string{"dns-direct"}, "outboundTag": "direct"}, {"type": "field", "inboundTag": []string{"dns-proxy"}, "outboundTag": "proxy"}, {"type": "field", "port": "53", "network": "tcp,udp", "outboundTag": "dns-out"}}
	if len(c.Rules.BlockedDomains) > 0 {
		routes = append(routes, object{"type": "field", "domain": tagged("domain:", c.Rules.BlockedDomains), "outboundTag": "block"})
	}
	routes = append(routes, object{"type": "field", "ip": lan, "outboundTag": "direct"})
	dns := []object{}
	if c.Mode == "rule" {
		for _, v := range []struct {
			items       []string
			prefix, tag string
		}{{c.Rules.ProxyDomains, "domain:", "proxy"}, {c.Rules.DirectDomains, "domain:", "direct"}, {c.Rules.DirectFullDomains, "full:", "direct"}} {
			if len(v.items) > 0 {
				routes = append(routes, object{"type": "field", "domain": tagged(v.prefix, v.items), "outboundTag": v.tag})
			}
		}
		if len(c.Rules.DirectIPs) > 0 {
			routes = append(routes, object{"type": "field", "ip": c.Rules.DirectIPs, "outboundTag": "direct"})
		}
		if len(c.Rules.ProxyDomains) > 0 {
			dns = append(dns, object{"address": "https://1.1.1.1/dns-query", "domains": tagged("domain:", c.Rules.ProxyDomains), "skipFallback": true, "tag": "dns-proxy", "finalQuery": true})
		}
		direct := append(tagged("domain:", c.Rules.DirectDomains), tagged("full:", c.Rules.DirectFullDomains)...)
		if len(direct) > 0 {
			dns = append(dns, object{"address": "https://223.5.5.5/dns-query", "domains": direct, "skipFallback": true, "tag": "dns-direct", "finalQuery": true})
		}
	}
	routes = append(routes, object{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})
	dns = append(dns, object{"address": "https://1.1.1.1/dns-query", "tag": "dns-proxy", "skipFallback": false, "finalQuery": true})
	tun := object{"name": j.Tun, "desc": "StarRail Network TUN", "mtu": 1500, "gateway": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"}, "autoSystemRoutingTable": []string{}, "autoOutboundsInterface": j.Interface.Name, "autoSystemDnsToGateway": false}
	// Windows Xray owns its adapter's routes, DNS and dynamic WFP filters. Other platforms use helper-owned routing/DNS.
	if runtime.GOOS == "windows" {
		tun["autoSystemRoutingTable"] = []string{"0.0.0.0/0", "::/0"}
		tun["dns"] = []string{tunDNS()}
		tun["autoSystemWfpBlockLeak"] = []string{"dns", "misconfigtun"}
	}
	return jsonBytes(object{"log": object{"loglevel": "none", "access": "none", "error": "none"}, "inbounds": []object{{"tag": "tun", "protocol": "tun", "settings": tun, "sniffing": object{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true}}}, "outbounds": []object{{"tag": "proxy", "protocol": n.Protocol, "settings": settings, "streamSettings": stream}, {"tag": "direct", "protocol": "freedom", "settings": object{"domainStrategy": "UseIP", "finalRules": []object{{"action": "allow", "ip": lan}}}, "streamSettings": object{"sockopt": sock}}, {"tag": "dns-out", "protocol": "dns", "settings": object{"rules": []object{{"action": "hijack", "qType": "1,28"}, {"action": "return", "rCode": 5}}}}, {"tag": "block", "protocol": "blackhole"}}, "dns": object{"tag": "dns-proxy", "queryStrategy": "UseIP", "disableFallbackIfMatch": true, "useSystemHosts": false, "servers": dns}, "routing": object{"domainStrategy": "AsIs", "rules": routes}})
}
