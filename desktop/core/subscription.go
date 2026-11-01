package core

import (
	"cmp"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

type ParserOptions struct {
	Capabilities       []string `json:"capabilities"`
	ConfirmedTCPUDP    bool     `json:"confirmedTcpUdp"`
	AuthoritativeEmpty bool     `json:"authoritativeEmpty,omitempty"`
	Source             string   `json:"source"`
}

var (
	subscriptionBase64 = regexp.MustCompile(`^[A-Za-z0-9+/_-]+={0,2}$`)
	subscriptionHost   = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)
	subscriptionUUID   = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	subscriptionScheme = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]*://`)
	unsupportedScheme  = regexp.MustCompile(`(?i)^(?:hysteria2?|hy2|tuic|wireguard|ssr|socks5?|https?)://`)
	realityPublicKey   = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	realityShortID     = regexp.MustCompile(`(?i)^(?:[a-f0-9]{2}){0,8}$`)
	subscriptionIPZone = regexp.MustCompile(`^[0-9A-Za-z.:-]+$`)
	subscriptionNumber = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)
)

func invalidSubscription() error { return NewAppError("SUBSCRIPTION_INVALID") }

// DecodeBase64 accepts the reference parser's canonical padded/unpadded and URL
// alphabets. A decode/re-encode round trip rejects nonzero unused padding bits.
func DecodeBase64(value string) ([]byte, error) {
	if !subscriptionBase64.MatchString(value) {
		return nil, invalidSubscription()
	}
	normalized := strings.TrimRight(strings.NewReplacer("-", "+", "_", "/").Replace(value), "=")
	if len(normalized)%4 == 1 {
		return nil, invalidSubscription()
	}
	decoded, err := base64.RawStdEncoding.DecodeString(normalized)
	if err != nil || base64.RawStdEncoding.EncodeToString(decoded) != normalized {
		return nil, invalidSubscription()
	}
	return decoded, nil
}

func subscriptionUTF8(raw []byte) (string, error) {
	if !utf8.Valid(raw) {
		return "", invalidSubscription()
	}
	// TextDecoder's default ignoreBOM=false consumes the leading BOM.
	return strings.TrimPrefix(string(raw), "\ufeff"), nil
}

func jsWhitespace(r rune) bool {
	return r == '\t' || r == '\n' || r == '\v' || r == '\f' || r == '\r' || r == ' ' || r == 0xa0 || r == 0x1680 || r >= 0x2000 && r <= 0x200a || r == 0x2028 || r == 0x2029 || r == 0x202f || r == 0x205f || r == 0x3000 || r == 0xfeff
}
func jsTrim(s string) string { return strings.TrimFunc(s, jsWhitespace) }
func jsStringRune(s string) (rune, int) {
	// StrictJSON preserves escaped, unpaired UTF-16 surrogates as WTF-8.
	if len(s) >= 3 && s[0] == 0xed && s[1] >= 0xa0 && s[1] <= 0xbf && s[2] >= 0x80 && s[2] <= 0xbf {
		return rune(s[0]&15)<<12 | rune(s[1]&63)<<6 | rune(s[2]&63), 3
	}
	return utf8.DecodeRuneInString(s)
}
func jsUTF16Length(s string) int {
	n := 0
	for s != "" {
		r, width := jsStringRune(s)
		s = s[width:]
		n++
		if r > 0xffff {
			n++
		}
	}
	return n
}
func nodeString(s string) *string { return &s }
func nodeValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func subscriptionField(v any, maxLen int) (string, error) {
	s, ok := v.(string)
	if !ok || len(s) == 0 || jsUTF16Length(s) > maxLen {
		return "", invalidSubscription()
	}
	for _, r := range s {
		if r < 0x20 {
			return "", invalidSubscription()
		}
	}
	return s, nil
}

func subscriptionPort(v any) (int, error) {
	var n float64
	switch value := v.(type) {
	case json.Number:
		n, _ = strconv.ParseFloat(string(value), 64)
	case float64:
		n = value
	case bool:
		if value {
			n = 1
		}
	case []any:
		return subscriptionPort(subscriptionJSString(value))
	case string:
		value = jsTrim(value)
		if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") || strings.HasPrefix(value, "0b") || strings.HasPrefix(value, "0B") || strings.HasPrefix(value, "0o") || strings.HasPrefix(value, "0O") {
			if strings.Contains(value, "_") {
				return 0, invalidSubscription()
			}
			u, err := strconv.ParseUint(value, 0, 64)
			if err != nil {
				return 0, invalidSubscription()
			}
			n = float64(u)
		} else {
			if !subscriptionNumber.MatchString(value) {
				return 0, invalidSubscription()
			}
			var err error
			n, err = strconv.ParseFloat(value, 64)
			if err != nil {
				return 0, invalidSubscription()
			}
		}
	default:
		return 0, invalidSubscription()
	}
	if math.IsNaN(n) || math.IsInf(n, 0) || math.Trunc(n) != n || n < 1 || n > 65535 {
		return 0, invalidSubscription()
	}
	return int(n), nil
}

func subscriptionHostname(v any) (string, error) {
	h, err := subscriptionField(v, 256)
	if err != nil {
		return "", err
	}
	h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	addr, ipErr := netip.ParseAddr(h)
	if (ipErr != nil || addr.Zone() != "" && !subscriptionIPZone.MatchString(addr.Zone())) && (len(h) > 253 || !subscriptionHost.MatchString(h)) {
		return "", invalidSubscription()
	}
	return strings.ToLower(h), nil
}

func subscriptionCredential(v any) (string, error) {
	s, err := subscriptionField(v, 256)
	if err != nil || !subscriptionUUID.MatchString(s) {
		return "", invalidSubscription()
	}
	return strings.ToLower(s), nil
}

func jsTruthy(v any) bool {
	switch value := v.(type) {
	case nil:
		return false
	case bool:
		return value
	case string:
		return value != ""
	case json.Number:
		f, _ := value.Float64()
		return f != 0 && !math.IsNaN(f)
	case float64:
		return value != 0 && !math.IsNaN(value)
	default:
		return true
	}
}
func firstTruthy(values ...any) any {
	for _, value := range values {
		if jsTruthy(value) {
			return value
		}
	}
	return values[len(values)-1]
}
func subscriptionJSString(v any) string {
	switch value := v.(type) {
	case nil:
		return "null"
	case string:
		return value
	case bool:
		return strconv.FormatBool(value)
	case json.Number:
		f, _ := value.Float64()
		if f == 0 {
			return "0"
		}
		return strconv.FormatFloat(f, 'f', -1, 64)
	case []any:
		var out []string
		for _, item := range value {
			if item == nil {
				out = append(out, "")
			} else {
				out = append(out, subscriptionJSString(item))
			}
		}
		return strings.Join(out, ",")
	default:
		return "[object Object]"
	}
}

// JSString produces JSON.stringify's string bytes, without encoding/json's
// HTML/U+2028/U+2029 escaping. These bytes are part of persisted node identities.
func JSString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for s != "" {
		r, width := jsStringRune(s)
		s = s[width:]
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(`\u00`)
				b.WriteByte("0123456789abcdef"[r>>4])
				b.WriteByte("0123456789abcdef"[r&15])
			} else if r >= 0xd800 && r <= 0xdfff {
				fmt.Fprintf(&b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func connectionJSON(node ProxyNode, explicitFingerprint bool) string {
	var b strings.Builder
	b.WriteByte('{')
	first := true
	add := func(key, value string) {
		if !first {
			b.WriteByte(',')
		}
		first = false
		b.WriteString(JSString(key))
		b.WriteByte(':')
		b.WriteString(value)
	}
	str := func(key, value string) { add(key, JSString(value)) }
	optional := func(key string, value *string) {
		if value != nil {
			str(key, *value)
		}
	}
	str("protocol", node.Protocol)
	str("host", node.Host)
	add("port", strconv.Itoa(node.Port))
	str("credential", node.Credential)
	str("transport", node.Transport)
	str("security", node.Security)
	add("tcp", strconv.FormatBool(node.TCP))
	add("udp", strconv.FormatBool(node.UDP))
	str("ipv6", node.IPv6)
	switch node.Protocol {
	case "vmess":
		optional("method", node.Method)
		optional("sni", node.SNI)
		optional("wsHost", node.WSHost)
		optional("wsPath", node.WSPath)
		optional("fingerprint", node.Fingerprint)
	case "shadowsocks":
		optional("method", node.Method)
	default:
		optional("sni", node.SNI)
		optional("flow", node.Flow)
		if explicitFingerprint {
			optional("fingerprint", node.Fingerprint)
		}
		optional("publicKey", node.PublicKey)
		optional("shortId", node.ShortID)
		if !explicitFingerprint {
			optional("fingerprint", node.Fingerprint)
		}
		// Absent for TCP nodes, so their IDs are unchanged.
		optional("wsHost", node.WSHost)
		optional("wsPath", node.WSPath)
		optional("mode", node.Mode)
		optional("ech", node.ECH)
	}
	b.WriteByte('}')
	return b.String()
}
func subscriptionHash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func queryDecode(value string) string {
	value = strings.ReplaceAll(value, "+", " ")
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		if value[i] == '%' && i+2 < len(value) {
			if n, err := strconv.ParseUint(value[i+1:i+3], 16, 8); err == nil {
				b.WriteByte(byte(n))
				i += 2
				continue
			}
		}
		b.WriteByte(value[i])
	}
	return replacementUTF8(b.String())
}

// WHATWG's UTF-8 decoder replaces each maximal invalid subpart. Go's
// strings.ToValidUTF8 merges adjacent failures, which changes accepted node IDs.
func replacementUTF8(raw string) string {
	var b strings.Builder
	for len(raw) > 0 {
		r, n := utf8.DecodeRuneInString(raw)
		if r != utf8.RuneError || n != 1 {
			b.WriteRune(r)
			raw = raw[n:]
			continue
		}
		n = 1
		lead := raw[0]
		expected := 0
		lower, upper := byte(0x80), byte(0xbf)
		switch {
		case lead >= 0xc2 && lead <= 0xdf:
			expected = 2
		case lead >= 0xe0 && lead <= 0xef:
			expected = 3
			if lead == 0xe0 {
				lower = 0xa0
			}
			if lead == 0xed {
				upper = 0x9f
			}
		case lead >= 0xf0 && lead <= 0xf4:
			expected = 4
			if lead == 0xf0 {
				lower = 0x90
			}
			if lead == 0xf4 {
				upper = 0x8f
			}
		}
		for n < expected && n < len(raw) {
			lo, hi := byte(0x80), byte(0xbf)
			if n == 1 {
				lo, hi = lower, upper
			}
			if raw[n] < lo || raw[n] > hi {
				break
			}
			n++
		}
		b.WriteRune(utf8.RuneError)
		raw = raw[n:]
	}
	return b.String()
}

func subscriptionURLPath(path string) string {
	segments := strings.Split(path, "/")
	out := make([]string, 0, len(segments))
	for i, part := range segments {
		dot := strings.ReplaceAll(strings.ToLower(part), "%2e", ".")
		if dot == "." || dot == ".." {
			if dot == ".." && len(out) > 1 {
				out = out[:len(out)-1]
			}
			if i == len(segments)-1 {
				out = append(out, "")
			}
		} else {
			out = append(out, part)
		}
	}
	return strings.Join(out, "/")
}
func subscriptionQuery(raw string) (map[string]string, error) {
	q := make(map[string]string)
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		key, value, _ := strings.Cut(pair, "=")
		key = queryDecode(key)
		if _, exists := q[key]; exists {
			return nil, invalidSubscription()
		}
		q[key] = queryDecode(value)
	}
	return q, nil
}

func canonicalURLHost(host string) string {
	addr, err := netip.ParseAddr(host)
	if err != nil || !addr.Is6() {
		return host
	}
	// WHATWG writes IPv4-mapped IPv6 tails as hexadecimal groups too.
	if addr.Is4In6() {
		bytes := addr.As16()
		return fmt.Sprintf("::ffff:%x:%x", uint16(bytes[12])<<8|uint16(bytes[13]), uint16(bytes[14])<<8|uint16(bytes[15]))
	}
	return addr.String()
}

// echValue is a base64 ECHConfigList or a DNS source for it, such as
// "cloudflare-ech.com+https://1.1.1.1/dns-query"; Xray resolves either form.
var echValue = regexp.MustCompile(`^[A-Za-z0-9+/=._:@-]+$`)

func parseSubscriptionLine(line string, index int, options ParserOptions) (ProxyNode, error) {
	node := ProxyNode{Group: "全部节点", Order: index, Protocol: "unsupported", Transport: "tcp", Security: "none", TCP: options.ConfirmedTCPUDP, UDP: options.ConfirmedTCPUDP, IPv6: "unknown", Source: options.Source}
	if jsUTF16Length(line) > 16384 {
		return node, invalidSubscription()
	}
	capability := ""
	explicitFingerprint := false
	if strings.HasPrefix(line, "vmess://") {
		bytes, err := DecodeBase64(line[8:])
		if err != nil {
			return node, err
		}
		raw, err := subscriptionUTF8(bytes)
		if err != nil {
			return node, err
		}
		parsed, err := StrictJSON([]byte(raw), 16384)
		if err != nil {
			return node, invalidSubscription()
		}
		data, ok := parsed.(map[string]any)
		if !ok {
			return node, invalidSubscription()
		}
		allowed := []string{"v", "ps", "add", "port", "id", "aid", "scy", "net", "type", "host", "path", "tls", "sni", "alpn", "fp", "allowInsecure", "pcs"}
		for key := range data {
			if !slices.Contains(allowed, key) {
				return node, invalidSubscription()
			}
		}
		node.Protocol = "vmess"
		node.Host, err = subscriptionHostname(data["add"])
		if err != nil {
			return node, err
		}
		node.Port, err = subscriptionPort(data["port"])
		if err != nil {
			return node, err
		}
		node.Credential, err = subscriptionCredential(data["id"])
		if err != nil {
			return node, err
		}
		node.Name = fmt.Sprintf("VMess %d", index+1)
		if name, ok := data["ps"].(string); ok && name != "" {
			node.Name, err = subscriptionField(name, 256)
			if err != nil {
				return node, err
			}
		}
		aid := data["aid"]
		if aid == nil {
			aid = "0"
		}
		scy, hasSCY := data["scy"]
		scyText, scyString := scy.(string)
		insecure, hasInsecure := data["allowInsecure"]
		safeInsecure := !hasInsecure || insecure == false || insecure == "0"
		if number, ok := insecure.(json.Number); ok {
			f, _ := number.Float64()
			safeInsecure = f == 0
		}
		if subscriptionJSString(aid) != "0" || data["net"] != "ws" || data["tls"] != "tls" || hasSCY && (!scyString || !slices.Contains([]string{"auto", "aes-128-gcm", "chacha20-poly1305", ""}, scyText)) || jsTruthy(data["type"]) && data["type"] != "none" || jsTruthy(data["alpn"]) || !safeInsecure || jsTruthy(data["pcs"]) {
			node.Incompatibility = nodeString("仅支持 VMess AEAD / WebSocket / TLS 模板，禁止弱化 TLS 或忽略证书固定")
		}
		node.Method = nodeString(subscriptionJSString(firstTruthy(scy, "auto")))
		node.Transport = "ws"
		node.Security = "tls"
		sni, err := subscriptionField(firstTruthy(data["sni"], data["host"], data["add"]), 256)
		if err != nil {
			return node, err
		}
		node.SNI = &sni
		wsHost, err := subscriptionField(firstTruthy(data["host"], data["sni"], data["add"]), 256)
		if err != nil {
			return node, err
		}
		node.WSHost = &wsHost
		wsPath, err := subscriptionField(firstTruthy(data["path"], "/"), 2048)
		if err != nil {
			return node, err
		}
		node.WSPath = &wsPath
		if jsTruthy(data["fp"]) {
			fp, err := subscriptionField(data["fp"], 256)
			if err != nil {
				return node, err
			}
			node.Fingerprint = &fp
		}
		capability = "vmess-ws-tls"
	} else if strings.HasPrefix(line, "vless://") || strings.HasPrefix(line, "trojan://") || strings.HasPrefix(line, "ss://") {
		cleaned := strings.NewReplacer("\t", "", "\r", "", "\n", "").Replace(line)
		u, err := url.Parse(cleaned)
		if err != nil || u.Opaque != "" || u.User == nil || u.Host == "" {
			return node, invalidSubscription()
		}
		// net/url accepts unbracketed IPv6 and RFC6874 zones that WHATWG URL
		// rejects. VMess JSON hosts are checked separately and may carry a zone.
		if strings.Contains(u.Hostname(), ":") && !strings.HasPrefix(u.Host, "[") || strings.Contains(u.Hostname(), "%") {
			return node, invalidSubscription()
		}
		q, err := subscriptionQuery(u.RawQuery)
		if err != nil {
			return node, err
		}
		allowed := []string{"type", "security", "sni", "flow", "pbk", "sid", "fp", "encryption", "host", "path", "headerType", "quicSecurity", "serviceName", "insecure", "allowInsecure", "pcs", "peer", "mode", "ech"}
		for key := range q {
			if u.Scheme == "ss" || !slices.Contains(allowed, key) {
				return node, invalidSubscription()
			}
		}
		node.Host, err = subscriptionHostname(canonicalURLHost(u.Hostname()))
		if err != nil {
			return node, err
		}
		node.Port, err = subscriptionPort(u.Port())
		if err != nil {
			return node, err
		}
		node.Name = fmt.Sprintf("节点 %d", index+1)
		if u.Fragment != "" {
			if !utf8.ValidString(u.Fragment) {
				return node, invalidSubscription()
			}
			node.Name, err = subscriptionField(u.Fragment, 256)
			if err != nil {
				return node, err
			}
		}
		if path := subscriptionURLPath(u.EscapedPath()); path != "" && path != "/" {
			return node, invalidSubscription()
		}
		user, password := u.User.Username(), ""
		password, _ = u.User.Password()
		if !utf8.ValidString(user) || !utf8.ValidString(password) {
			return node, invalidSubscription()
		}
		if u.Scheme == "ss" {
			node.Protocol = "shadowsocks"
			raw := user + ":" + password
			if password == "" {
				bytes, err := DecodeBase64(user)
				if err != nil {
					return node, err
				}
				raw, err = subscriptionUTF8(bytes)
				if err != nil {
					return node, err
				}
			}
			method, credential, found := strings.Cut(raw, ":")
			if !found || method == "" {
				return node, invalidSubscription()
			}
			node.Method = &method
			node.Credential, err = subscriptionField(credential, 1024)
			if err != nil {
				return node, err
			}
			if !slices.Contains([]string{"chacha20-ietf-poly1305", "aes-128-gcm", "aes-256-gcm", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}, method) {
				node.Incompatibility = nodeString("不支持的 Shadowsocks 加密方法")
			}
			capability = "shadowsocks-aead"
		} else {
			if password != "" {
				return node, invalidSubscription()
			}
			node.Protocol = u.Scheme
			if node.Protocol == "vless" {
				node.Credential, err = subscriptionCredential(user)
			} else {
				node.Credential, err = subscriptionField(user, 1024)
			}
			if err != nil {
				return node, err
			}
			security, hasSecurity := q["security"]
			if !hasSecurity {
				security = "none"
				if node.Protocol == "trojan" {
					security = "tls"
				}
			}
			if security == "tls" || security == "reality" {
				node.Security = security
			}
			transport := q["type"]
			if transport == "" {
				transport = "tcp"
			}
			encryption, hasEncryption := q["encryption"]
			// VLESS also runs over WebSocket behind a CDN (TLS only) and over XHTTP (TLS or REALITY).
			layered := node.Protocol == "vless" && (transport == "ws" && security == "tls" || transport == "xhttp")
			if transport != "tcp" && !layered || !slices.Contains([]string{"tls", "reality"}, security) || node.Protocol == "trojan" && security != "tls" || hasEncryption && encryption != "none" {
				node.Incompatibility = nodeString("不支持的传输或安全组合")
			}
			sni, err := subscriptionField(firstTruthy(q["sni"], q["peer"], node.Host), 256)
			if err != nil {
				return node, err
			}
			node.SNI = &sni
			node.Flow = nodeString(q["flow"])
			if q["peer"] != "" && q["sni"] != "" && q["peer"] != q["sni"] {
				node.Incompatibility = nodeString("TLS serverName 字段冲突")
			}
			unsafe := false
			for _, key := range []string{"serviceName", "pcs"} {
				unsafe = unsafe || q[key] != ""
			}
			if layered {
				node.Transport = transport
				path, err := subscriptionField(cmp.Or(q["path"], "/"), 2048)
				if err != nil {
					return node, err
				}
				node.WSPath = &path
				host := q["host"]
				if transport == "ws" {
					host = cmp.Or(host, sni)
				}
				node.WSHost = &host
				unsafe = unsafe || !strings.HasPrefix(path, "/") || host != "" && !subscriptionHost.MatchString(host)
				if transport == "xhttp" {
					mode := cmp.Or(q["mode"], "auto")
					node.Mode = &mode
					unsafe = unsafe || !slices.Contains([]string{"auto", "packet-up", "stream-up", "stream-one"}, mode)
				}
			} else {
				unsafe = unsafe || q["host"] != "" || q["path"] != ""
			}
			unsafe = unsafe || q["mode"] != "" && transport != "xhttp"
			if value, present := q["ech"]; present && value != "" {
				ech, err := subscriptionField(value, 1024)
				if err != nil {
					return node, err
				}
				node.ECH = &ech
				unsafe = unsafe || security != "tls" || !echValue.MatchString(ech)
			}
			for _, key := range []string{"headerType", "quicSecurity"} {
				unsafe = unsafe || q[key] != "" && q[key] != "none"
			}
			for _, key := range []string{"insecure", "allowInsecure"} {
				unsafe = unsafe || !slices.Contains([]string{"", "0", "false"}, q[key])
			}
			if unsafe {
				node.Incompatibility = nodeString("不支持的安全或传输参数")
			}
			if !slices.Contains([]string{"", "xtls-rprx-vision"}, *node.Flow) || *node.Flow != "" && (node.Protocol == "trojan" || node.Transport != "tcp") {
				node.Incompatibility = nodeString("不支持的 flow")
			}
			if value, present := q["fp"]; present {
				fp, err := subscriptionField(value, 256)
				if err != nil {
					return node, err
				}
				node.Fingerprint = &fp
				explicitFingerprint = true
			}
			if security == "reality" {
				key, err := subscriptionField(q["pbk"], 256)
				if err != nil {
					return node, err
				}
				node.PublicKey = &key
				node.ShortID = nodeString(q["sid"])
				if !realityPublicKey.MatchString(key) || !realityShortID.MatchString(*node.ShortID) {
					return node, invalidSubscription()
				}
				capability = "vless-reality"
			} else {
				_, hasKey := q["pbk"]
				_, hasID := q["sid"]
				if hasKey || hasID {
					return node, invalidSubscription()
				}
				capability = "trojan-tls"
				if node.Protocol == "vless" {
					capability = "vless-tls"
				}
			}
		}
	} else if location := unsupportedScheme.FindStringIndex(line); location != nil && location[1] < len(line) {
		for _, r := range line[location[1]:] {
			if jsWhitespace(r) {
				return node, invalidSubscription()
			}
		}
		node.Name = fmt.Sprintf("不兼容节点 %d", index+1)
		node.Incompatibility = nodeString("协议不在首版支持范围")
		node.ConnectionFingerprint = subscriptionHash(JSString(line))
		node.ID = node.ConnectionFingerprint
		return node, nil
	} else {
		return node, invalidSubscription()
	}
	if (node.Security == "tls" || node.Security == "reality") && node.Fingerprint == nil {
		node.Fingerprint = nodeString(DefaultTLSFingerprint)
	}
	if node.Fingerprint != nil && *node.Fingerprint != "" && !supportedTLSFingerprints[*node.Fingerprint] {
		node.Incompatibility = nodeString("未验证的 TLS 指纹")
	}
	if capability != "" && !slices.Contains(options.Capabilities, capability) {
		node.Incompatibility = nodeString("此协议模板尚未通过部署验证")
	}
	if !options.ConfirmedTCPUDP && node.Incompatibility == nil {
		node.Incompatibility = nodeString("尚未确认节点 TCP / UDP 能力")
	}
	node.ConnectionFingerprint = subscriptionHash(connectionJSON(node, explicitFingerprint))
	node.ID = node.ConnectionFingerprint
	node.Compatible = node.Incompatibility == nil
	return node, nil
}

// ParseSubscription retains incompatible nodes, quarantines malformed entries,
// and rejects an incomplete response before it can revoke a cached subscription.
func ParseSubscription(raw string, options ParserOptions) (ParsedNodes, error) {
	result := ParsedNodes{Nodes: []ProxyNode{}, Quarantined: []QuarantinedNode{}}
	if len(raw) > 14*1024*1024 || !utf8.ValidString(raw) {
		return result, invalidSubscription()
	}
	text := jsTrim(raw)
	if text == "" {
		if options.AuthoritativeEmpty {
			result.AuthoritativeEmpty = true
			return result, nil
		}
		return result, invalidSubscription()
	}
	if !strings.Contains(text, "://") {
		bytes, err := DecodeBase64(strings.NewReplacer("\r", "", "\n", "").Replace(text))
		if err != nil {
			return result, err
		}
		text, err = subscriptionUTF8(bytes)
		if err != nil {
			return result, err
		}
	}
	if len(text) > 10*1024*1024 || strings.HasPrefix(jsTrim(text), "<") {
		return result, invalidSubscription()
	}
	lines := make([]string, 0)
	for _, line := range strings.Split(text, "\n") {
		if line = jsTrim(line); line != "" {
			if !subscriptionScheme.MatchString(line) {
				return result, invalidSubscription()
			}
			lines = append(lines, line)
			if len(lines) > 5000 {
				return result, invalidSubscription()
			}
		}
	}
	if len(lines) == 0 {
		return result, invalidSubscription()
	}
	ids := make(map[string]bool)
	for index, line := range lines {
		node, err := parseSubscriptionLine(line, index, options)
		if err != nil {
			result.Quarantined = append(result.Quarantined, QuarantinedNode{Index: index, Reason: "节点字段不符合冻结格式"})
			continue
		}
		if !ids[node.ID] {
			ids[node.ID] = true
			result.Nodes = append(result.Nodes, node)
		}
	}
	if len(result.Nodes) == 0 {
		return ParsedNodes{Nodes: []ProxyNode{}, Quarantined: []QuarantinedNode{}}, invalidSubscription()
	}
	return result, nil
}
