package core

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// RuleSection routes matching domains or addresses to one target: direct, proxy,
// ai (the AI-capable exit) or block. Sections are evaluated in order; domains use
// Xray's domain:, full:, keyword: and regexp: matcher forms.
type RuleSection struct {
	Target  string   `json:"target"`
	Domains []string `json:"domains,omitempty"`
	IPs     []string `json:"ips,omitempty"`
}
type Rules struct {
	SchemaVersion int           `json:"schemaVersion"`
	Sections      []RuleSection `json:"sections"`
}

var ruleDomainLabel = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$`)
var ruleKeyword = regexp.MustCompile(`^[a-z0-9.-]{1,253}$`)
var ruleCIDRLength = regexp.MustCompile(`^(0|[1-9][0-9]{0,2})$`)
var lanCIDRs = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "::1/128", "fc00::/7", "fe80::/10"}

func validRuleDomain(value string) bool {
	kind, rest, ok := strings.Cut(value, ":")
	if !ok {
		return false
	}
	switch kind {
	case "domain", "full":
		if len(rest) < 1 || len(rest) > 253 {
			return false
		}
		for _, label := range strings.Split(rest, ".") {
			if !ruleDomainLabel.MatchString(label) {
				return false
			}
		}
		return true
	case "keyword":
		return ruleKeyword.MatchString(rest)
	case "regexp":
		if len(rest) < 1 || len(rest) > 512 {
			return false
		}
		for _, r := range rest {
			if r < 0x20 || r > 0x7e {
				return false
			}
		}
		_, err := regexp.Compile(rest)
		return err == nil
	}
	return false
}
func validRuleAddress(value string) bool {
	parts := strings.Split(value, "/")
	if len(value) > 64 || len(parts) > 2 {
		return false
	}
	addr, err := netip.ParseAddr(parts[0])
	if err != nil || addr.Zone() != "" {
		return false
	}
	if len(parts) == 2 {
		if !ruleCIDRLength.MatchString(parts[1]) {
			return false
		}
		prefix, _ := strconv.Atoi(parts[1])
		maximum := 128
		if addr.Is4() {
			maximum = 32
		}
		return prefix <= maximum
	}
	return true
}

func (r Rules) Validate() error {
	if r.SchemaVersion != 2 || r.Sections == nil || len(r.Sections) > 64 {
		return NewAppError("INVALID_INPUT")
	}
	domains, addresses := 0, 0
	for _, section := range r.Sections {
		if section.Target != "direct" && section.Target != "proxy" && section.Target != "ai" && section.Target != "block" {
			return NewAppError("INVALID_INPUT")
		}
		domains += len(section.Domains)
		addresses += len(section.IPs)
		if domains > 200000 || addresses > 100000 {
			return NewAppError("INVALID_INPUT")
		}
		for _, value := range section.Domains {
			if !validRuleDomain(value) {
				return NewAppError("INVALID_INPUT")
			}
		}
		for _, value := range section.IPs {
			if !validRuleAddress(value) {
				return NewAppError("INVALID_INPUT")
			}
		}
	}
	return nil
}

// EmptyRules routes everything that is not local through the proxy.
func EmptyRules() Rules { return Rules{SchemaVersion: 2, Sections: []RuleSection{}} }

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
		optionalMapString(tls, "echConfigList", node.ECH)
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
	if node.Transport == "xhttp" {
		xhttp := map[string]any{}
		optionalMapString(xhttp, "path", node.WSPath)
		optionalMapString(xhttp, "host", node.WSHost)
		optionalMapString(xhttp, "mode", node.Mode)
		stream["xhttpSettings"] = xhttp
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
