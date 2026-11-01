package core

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var unsafeURLPattern = regexp.MustCompile(`[\\\x00-\x20]`)
var encodedPathSeparator = regexp.MustCompile(`(?i)%(?:2f|5c|00)`)
var testIdentityPattern = regexp.MustCompile(`(?i)test|example|unconfigured`)
var testHostnamePattern = regexp.MustCompile(`(^|\.)(example\.(com|org|net)|localhost|invalid|test)$`)
var numericHostSuffix = regexp.MustCompile(`(?i)^(?:[0-9]+|0x[0-9a-f]*)$`)

// HTTPSURL enforces credential, fragment and encoded-separator exclusions.
// Until a complete WHATWG/IDNA implementation is integrated, non-ASCII hostnames
// and noncanonical legacy IPv4 spellings are rejected instead of being trusted
// under a different origin from the WebView. Punycode hostnames are supported.
func HTTPSURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || unsafeURLPattern.MatchString(raw) || strings.ToLower(u.Scheme) != "https" || u.Host == "" || u.Opaque != "" || u.Fragment != "" || encodedPathSeparator.MatchString(u.EscapedPath()) {
		return nil, NewAppError("INVALID_INPUT")
	}
	if u.User != nil {
		password, _ := u.User.Password()
		if u.User.Username() != "" || password != "" {
			return nil, NewAppError("INVALID_INPUT")
		}
		u.User = nil
	}
	u.Scheme = "https"
	host := strings.ToLower(u.Hostname())
	for _, c := range host {
		if c >= 127 {
			return nil, NewAppError("INVALID_INPUT")
		}
	}
	if host == "" || strings.ContainsAny(host, " #%/:<>?@[\\]^|") && !strings.Contains(host, ":") {
		return nil, NewAppError("INVALID_INPUT")
	}
	if strings.Contains(host, ":") {
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is6() || address.Zone() != "" {
			return nil, NewAppError("INVALID_INPUT")
		}
		host = "[" + ipv6URLHost(address) + "]"
	} else {
		labels := strings.Split(strings.TrimSuffix(host, "."), ".")
		if numericHostSuffix.MatchString(labels[len(labels)-1]) {
			address, err := netip.ParseAddr(host)
			if err != nil || !address.Is4() || address.String() != host {
				return nil, NewAppError("INVALID_INPUT")
			}
		}
	}
	port := u.Port()
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 0 || number > 65535 {
			return nil, NewAppError("INVALID_INPUT")
		}
		if number == 443 {
			port = ""
		} else {
			port = strconv.Itoa(number)
		}
	}
	u.Host = host
	if port != "" {
		u.Host += ":" + port
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	// WHATWG URL removes literal and percent-encoded dot path segments.
	segments := strings.Split(path, "/")
	clean := []string{""}
	for i, segment := range segments[1:] {
		decoded, _ := url.PathUnescape(segment)
		switch decoded {
		case ".":
			if i == len(segments)-2 {
				clean = append(clean, "")
			}
		case "..":
			if len(clean) > 1 {
				clean = clean[:len(clean)-1]
			}
			if i == len(segments)-2 {
				clean = append(clean, "")
			}
		default:
			clean = append(clean, segment)
		}
	}
	path = strings.Join(clean, "/")
	if path == "" {
		path = "/"
	}
	u.Path, err = url.PathUnescape(path)
	if err != nil {
		return nil, NewAppError("INVALID_INPUT")
	}
	u.RawPath = path
	return u, nil
}

// WHATWG serializes IPv4-mapped IPv6 using hexadecimal groups as well.
func ipv6URLHost(address netip.Addr) string {
	bytes := address.As16()
	parts := make([]string, 8)
	words := make([]uint16, 8)
	for i := range words {
		words[i] = uint16(bytes[2*i])<<8 | uint16(bytes[2*i+1])
		parts[i] = strconv.FormatUint(uint64(words[i]), 16)
	}
	bestStart, bestLen := -1, 1
	for i := 0; i < 8; {
		if words[i] != 0 {
			i++
			continue
		}
		start := i
		for i < 8 && words[i] == 0 {
			i++
		}
		if i-start > bestLen {
			bestStart, bestLen = start, i-start
		}
	}
	if bestStart < 0 {
		return strings.Join(parts, ":")
	}
	return strings.Join(parts[:bestStart], ":") + "::" + strings.Join(parts[bestStart+bestLen:], ":")
}

func TrustedURL(raw string, origins []string) (string, error) {
	u, err := HTTPSURL(raw)
	if err != nil {
		return "", err
	}
	for _, origin := range origins {
		o, err := HTTPSURL(origin)
		if err != nil {
			return "", err
		}
		if o.Scheme == u.Scheme && o.Host == u.Host && o.Path == "/" && o.RawQuery == "" {
			return u.String(), nil
		}
	}
	return "", NewAppError("INVALID_INPUT")
}

func ValidateBuild(config BuildConfig) (BuildConfig, error) {
	if err := config.Validate(); err != nil {
		return BuildConfig{}, err
	}
	if !ValidProductID(config.ProductID) || !ValidAppID(config.AppID) || !ValidDisplayName(config.Name) {
		return BuildConfig{}, NewAppError("CONFIGURATION_REQUIRED")
	}
	if (config.Environment == "production") != (config.Channel == "stable") {
		return BuildConfig{}, NewAppError("INVALID_INPUT")
	}
	ids := map[string]bool{}
	for _, endpoint := range config.APIEndpoints {
		if ids[endpoint.ID] {
			return BuildConfig{}, NewAppError("INVALID_INPUT")
		}
		ids[endpoint.ID] = true
	}
	origins := []string{}
	for _, group := range [][]string{config.TrustedSubscriptionOrigins, config.TrustedWebOrigins, config.TrustedResourceOrigins, config.TrustedUpdateOrigins} {
		origins = append(origins, group...)
	}
	for _, raw := range origins {
		u, err := HTTPSURL(raw)
		if err != nil || u.Path != "/" || u.RawQuery != "" {
			return BuildConfig{}, NewAppError("INVALID_INPUT")
		}
	}
	for _, endpoint := range config.APIEndpoints {
		u, err := HTTPSURL(endpoint.BaseURL)
		if err != nil || u.RawQuery != "" {
			return BuildConfig{}, NewAppError("INVALID_INPUT")
		}
	}
	for _, group := range [][]string{config.PolicyURLs, config.UpdateFeedURLs} {
		for _, raw := range group {
			if _, err := HTTPSURL(raw); err != nil {
				return BuildConfig{}, err
			}
		}
	}
	for _, target := range config.HealthTargets {
		u, err := HTTPSURL(target.URL)
		if err != nil || u.RawQuery != "" {
			return BuildConfig{}, NewAppError("INVALID_INPUT")
		}
	}
	links := []*string{config.Links.Website, config.Links.Renew, config.Links.Help}
	for _, link := range links {
		if link != nil {
			if _, err := TrustedURL(*link, config.TrustedWebOrigins); err != nil {
				return BuildConfig{}, err
			}
		}
	}
	for _, keys := range []map[string]string{config.PolicyKeys, config.UpdateKeys} {
		for _, key := range keys {
			block, rest := pem.Decode([]byte(key))
			if block == nil || block.Type != "PUBLIC KEY" || strings.TrimSpace(string(rest)) != "" {
				return BuildConfig{}, NewAppError("INVALID_INPUT")
			}
			parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return BuildConfig{}, NewAppError("INVALID_INPUT")
			}
			if _, ok := parsed.(ed25519.PublicKey); !ok {
				return BuildConfig{}, NewAppError("INVALID_INPUT")
			}
		}
	}
	if config.Environment == "production" {
		domains := map[string]bool{}
		for _, target := range config.HealthTargets {
			domains[target.FailureDomain] = true
		}
		if config.AllowUnverifiedNodeTrials || len(config.HealthTargets) < 2 || len(domains) < 2 || !config.DeploymentVerified || !config.NodeCapabilitiesConfirmed || len(config.ProtocolCapabilities) != 5 || len(config.APIEndpoints) == 0 || len(config.PolicyURLs) == 0 || len(config.UpdateFeedURLs) == 0 || len(origins) == 0 || len(config.PolicyKeys) == 0 || len(config.UpdateKeys) == 0 || testIdentityPattern.MatchString(config.AppID+config.ProductID+config.TenantID) {
			return BuildConfig{}, NewAppError("CONFIGURATION_REQUIRED")
		}
		urls := append([]string{}, origins...)
		urls = append(urls, config.PolicyURLs...)
		urls = append(urls, config.UpdateFeedURLs...)
		for _, endpoint := range config.APIEndpoints {
			urls = append(urls, endpoint.BaseURL)
		}
		for _, link := range links {
			if link == nil || *link == "" {
				return BuildConfig{}, NewAppError("CONFIGURATION_REQUIRED")
			}
			urls = append(urls, *link)
		}
		for _, raw := range urls {
			u, _ := HTTPSURL(raw)
			host := u.Hostname()
			if testHostnamePattern.MatchString(host) || strings.HasSuffix(host, ".example") || strings.HasSuffix(host, ".invalid") {
				return BuildConfig{}, NewAppError("CONFIGURATION_REQUIRED")
			}
		}
	}
	if config.HealthTargets == nil {
		config.HealthTargets = []HealthTarget{}
	}
	return config, nil
}

// MirrorURLs lists raw, then the same path on each other trusted origin. An endpoint
// reachable under several domains signs its URLs with the primary one; when that
// domain is blocked the file is still fetched, and still verified by its hash.
func MirrorURLs(raw string, origins []string) []string {
	out := []string{raw}
	u, err := url.Parse(raw)
	if err != nil {
		return out
	}
	for _, origin := range origins {
		mirror, err := url.Parse(origin)
		if err != nil || mirror.Scheme != "https" || mirror.Host == u.Host {
			continue
		}
		location := *u
		location.Host = mirror.Host
		out = append(out, location.String())
	}
	return out
}
