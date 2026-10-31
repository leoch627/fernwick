package core

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

type Rules struct {
	SchemaVersion     int      `json:"schemaVersion"`
	DirectDomains     []string `json:"directDomains"`
	DirectFullDomains []string `json:"directFullDomains,omitempty"`
	ProxyDomains      []string `json:"proxyDomains"`
	BlockedDomains    []string `json:"blockedDomains"`
	DirectIPs         []string `json:"directIPs"`
}

var ruleDomainLabel = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
var ruleCIDRLength = regexp.MustCompile(`^(0|[1-9][0-9]{0,2})$`)
var lanCIDRs = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}

func (r Rules) Validate() error {
	if r.SchemaVersion != 1 || r.DirectDomains == nil || r.ProxyDomains == nil || r.BlockedDomains == nil || r.DirectIPs == nil || len(r.DirectDomains) > 200000 || len(r.DirectFullDomains) > 200000 || len(r.ProxyDomains) > 100000 || len(r.BlockedDomains) > 100000 || len(r.DirectIPs) > 100000 {
		return NewAppError("INVALID_INPUT")
	}
	for _, group := range [][]string{r.DirectDomains, r.DirectFullDomains, r.ProxyDomains, r.BlockedDomains} {
		for _, domain := range group {
			if len(domain) < 1 || len(domain) > 253 {
				return NewAppError("INVALID_INPUT")
			}
			for _, label := range strings.Split(domain, ".") {
				if !ruleDomainLabel.MatchString(label) {
					return NewAppError("INVALID_INPUT")
				}
			}
		}
	}
	for _, value := range r.DirectIPs {
		parts := strings.Split(value, "/")
		if len(value) > 64 || len(parts) > 2 {
			return NewAppError("INVALID_INPUT")
		}
		addr, err := netip.ParseAddr(parts[0])
		if err != nil || addr.Zone() != "" && !subscriptionIPZone.MatchString(addr.Zone()) {
			return NewAppError("INVALID_INPUT")
		}
		if len(parts) == 2 {
			if !ruleCIDRLength.MatchString(parts[1]) {
				return NewAppError("INVALID_INPUT")
			}
			prefix, _ := strconv.Atoi(parts[1])
			maximum := 128
			if addr.Is4() {
				maximum = 32
			}
			if prefix > maximum {
				return NewAppError("INVALID_INPUT")
			}
		}
	}
	return nil
}

func optionalMapString(target map[string]any, key string, value *string) {
	if value != nil {
		if utf8.ValidString(*value) {
			target[key] = *value
		} else {
			// Preserve JSON's escaped UTF-16 surrogates retained by StrictJSON.
			// encoding/json would otherwise replace each WTF-8 byte separately.
			target[key] = json.RawMessage(JSString(*value))
		}
	}
}
func defaultNodeString(value *string, fallback string) string {
	if value == nil {
		return fallback
	}
	return *value
}

// CompileOutbound emits only the frozen protocol templates. Callers must not
// pass any panel-provided configuration through to the privileged helper.
func CompileOutbound(node ProxyNode) (map[string]any, error) {
	if !node.Compatible || !node.TCP || !node.UDP {
		return nil, NewAppError("NO_COMPATIBLE_NODES")
	}
	stream := map[string]any{"network": node.Transport, "security": node.Security}
	if node.Security == "tls" {
		tls := map[string]any{"allowInsecure": false, "fingerprint": defaultNodeString(node.Fingerprint, DefaultTLSFingerprint)}
		optionalMapString(tls, "serverName", node.SNI)
		stream["tlsSettings"] = tls
	}
	if node.Security == "reality" {
		reality := map[string]any{"fingerprint": defaultNodeString(node.Fingerprint, DefaultTLSFingerprint)}
		optionalMapString(reality, "serverName", node.SNI)
		optionalMapString(reality, "publicKey", node.PublicKey)
		optionalMapString(reality, "shortId", node.ShortID)
		stream["realitySettings"] = reality
	}
	if node.Transport == "ws" {
		headers := map[string]any{}
		optionalMapString(headers, "Host", node.WSHost)
		ws := map[string]any{"headers": headers}
		optionalMapString(ws, "path", node.WSPath)
		stream["wsSettings"] = ws
	}
	var settings map[string]any
	if node.Protocol == "vless" || node.Protocol == "vmess" {
		user := map[string]any{"id": node.Credential}
		if node.Protocol == "vless" {
			user["encryption"] = "none"
			user["flow"] = defaultNodeString(node.Flow, "")
		} else {
			user["alterId"] = 0
			user["security"] = defaultNodeString(node.Method, "auto")
		}
		settings = map[string]any{"vnext": []any{map[string]any{"address": node.Host, "port": node.Port, "users": []any{user}}}}
	} else {
		server := map[string]any{"address": node.Host, "port": node.Port, "password": node.Credential}
		if node.Protocol == "shadowsocks" {
			optionalMapString(server, "method", node.Method)
		}
		settings = map[string]any{"servers": []any{server}}
	}
	return map[string]any{"tag": "proxy", "protocol": node.Protocol, "settings": settings, "streamSettings": stream}, nil
}

func prefixedDomains(prefix string, domains []string) []string {
	result := make([]string, len(domains))
	for i, domain := range domains {
		result[i] = prefix + domain
	}
	return result
}

func CompileRouting(mode string, rules Rules) (map[string]any, error) {
	if mode != "rule" && mode != "global" {
		return nil, NewAppError("INVALID_INPUT")
	}
	if err := rules.Validate(); err != nil {
		return nil, err
	}
	output := []any{map[string]any{"type": "field", "inboundTag": []string{"health"}, "outboundTag": "proxy"}, map[string]any{"type": "field", "port": "53", "network": "tcp,udp", "outboundTag": "dns-out"}}
	if len(rules.BlockedDomains) > 0 {
		output = append(output, map[string]any{"type": "field", "domain": prefixedDomains("domain:", rules.BlockedDomains), "outboundTag": "block"})
	}
	output = append(output, map[string]any{"type": "field", "ip": append([]string{}, lanCIDRs...), "outboundTag": "direct"})
	if mode == "rule" {
		if len(rules.ProxyDomains) > 0 {
			output = append(output, map[string]any{"type": "field", "domain": prefixedDomains("domain:", rules.ProxyDomains), "outboundTag": "proxy"})
		}
		if len(rules.DirectDomains) > 0 {
			output = append(output, map[string]any{"type": "field", "domain": prefixedDomains("domain:", rules.DirectDomains), "outboundTag": "direct"})
		}
		if len(rules.DirectFullDomains) > 0 {
			output = append(output, map[string]any{"type": "field", "domain": prefixedDomains("full:", rules.DirectFullDomains), "outboundTag": "direct"})
		}
		if len(rules.DirectIPs) > 0 {
			output = append(output, map[string]any{"type": "field", "ip": append([]string{}, rules.DirectIPs...), "outboundTag": "direct"})
		}
	}
	output = append(output, map[string]any{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})
	return map[string]any{"domainStrategy": "AsIs", "rules": output}, nil
}

func CompileCandidate(node ProxyNode, mode string, rules Rules) (map[string]any, error) {
	outbound, err := CompileOutbound(node)
	if err != nil {
		return nil, err
	}
	routing, err := CompileRouting(mode, rules)
	if err != nil {
		return nil, err
	}
	return map[string]any{"log": map[string]any{"loglevel": "warning", "access": "none"}, "outbounds": []any{outbound, map[string]any{"tag": "direct", "protocol": "freedom"}, map[string]any{"tag": "block", "protocol": "blackhole"}}, "routing": routing}, nil
}
