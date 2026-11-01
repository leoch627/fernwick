package core

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// macOS keeps proxies per network service. networksetup changes them as the logged-in
// administrator without a password prompt, which is what Clash-style clients rely on.
const networksetup = "/usr/sbin/networksetup"

var macBypass = []string{"localhost", "127.0.0.1", "::1", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "*.local"}

type macProxy struct {
	Enabled bool   `json:"enabled"`
	Server  string `json:"server"`
	Port    int    `json:"port"`
}
type macService struct {
	Name   string   `json:"name"`
	Web    macProxy `json:"web"`
	Secure macProxy `json:"secure"`
	Socks  macProxy `json:"socks"`
	Bypass []string `json:"bypass"`
}
type macProxyState struct {
	Services []macService `json:"services"`
}

// macKinds are the get, set and state verbs for HTTP, HTTPS and SOCKS proxies.
var macKinds = [][3]string{
	{"-getwebproxy", "-setwebproxy", "-setwebproxystate"},
	{"-getsecurewebproxy", "-setsecurewebproxy", "-setsecurewebproxystate"},
	{"-getsocksfirewallproxy", "-setsocksfirewallproxy", "-setsocksfirewallproxystate"},
}

type macSystemProxy struct {
	run func(ctx context.Context, args ...string) (string, error)
}

func NewSystemProxy() SystemProxy {
	return macSystemProxy{run: func(ctx context.Context, args ...string) (string, error) {
		out, err := systemCommand(ctx, networksetup, args...)
		// networksetup reports some failures, such as missing rights, with exit status 0.
		if err == nil && strings.Contains(out, "** Error") {
			err = NewAppError("SYSTEM_PROXY_FAILED")
		}
		return out, err
	}}
}

var macServiceLine = regexp.MustCompile(`^\(\d+\)\s+(.+)$`)
var macDeviceLine = regexp.MustCompile(`Device:\s*([^)]*)\)\s*$`)

// services lists enabled services that have a network device, in service order.
// VPN services and disabled services are left alone.
func (m macSystemProxy) services(ctx context.Context) ([]string, error) {
	out, err := m.run(ctx, "-listnetworkserviceorder")
	if err != nil {
		return nil, err
	}
	names := []string{}
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		match := macServiceLine.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil || i+1 >= len(lines) {
			continue
		}
		device := macDeviceLine.FindStringSubmatch(strings.TrimSpace(lines[i+1]))
		if device != nil && strings.TrimSpace(device[1]) != "" {
			names = append(names, match[1])
		}
	}
	if len(names) == 0 {
		return nil, NewAppError("SYSTEM_PROXY_FAILED")
	}
	return names, nil
}
func parseMacProxy(out string) macProxy {
	var value macProxy
	for _, line := range strings.Split(out, "\n") {
		key, rest, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		rest = strings.TrimSpace(rest)
		switch strings.TrimSpace(key) {
		case "Enabled":
			value.Enabled = rest == "Yes"
		case "Server":
			value.Server = rest
		case "Port":
			value.Port, _ = strconv.Atoi(rest)
		}
	}
	return value
}
func (m macSystemProxy) Snapshot(ctx context.Context) (json.RawMessage, error) {
	names, err := m.services(ctx)
	if err != nil {
		return nil, err
	}
	state := macProxyState{}
	for _, name := range names {
		service := macService{Name: name, Bypass: []string{}}
		proxies := []*macProxy{&service.Web, &service.Secure, &service.Socks}
		for i, kind := range macKinds {
			out, err := m.run(ctx, kind[0], name)
			if err != nil {
				return nil, err
			}
			*proxies[i] = parseMacProxy(out)
		}
		out, err := m.run(ctx, "-getproxybypassdomains", name)
		if err != nil {
			return nil, err
		}
		if !strings.Contains(out, "There aren't any") {
			for _, line := range strings.Split(out, "\n") {
				if line = strings.TrimSpace(line); line != "" {
					service.Bypass = append(service.Bypass, line)
				}
			}
		}
		state.Services = append(state.Services, service)
	}
	return json.Marshal(state)
}
func (m macSystemProxy) Apply(ctx context.Context, saved json.RawMessage, port int) error {
	var state macProxyState
	if err := json.Unmarshal(saved, &state); err != nil {
		return NewAppError("STORAGE_FAILED")
	}
	for _, service := range state.Services {
		for _, kind := range macKinds {
			if _, err := m.run(ctx, kind[1], service.Name, "127.0.0.1", strconv.Itoa(port)); err != nil {
				return err
			}
		}
		if _, err := m.run(ctx, append([]string{"-setproxybypassdomains", service.Name}, macBypass...)...); err != nil {
			return err
		}
	}
	return nil
}
func (m macSystemProxy) Restore(ctx context.Context, saved json.RawMessage) error {
	var state macProxyState
	if err := json.Unmarshal(saved, &state); err != nil {
		return NewAppError("STORAGE_FAILED")
	}
	current, err := m.services(ctx)
	if err != nil {
		return err
	}
	for _, service := range state.Services {
		// A service removed meanwhile, such as an unplugged adapter, has nothing to restore.
		if !slices.Contains(current, service.Name) {
			continue
		}
		for i, kind := range macKinds {
			previous := []macProxy{service.Web, service.Secure, service.Socks}[i]
			if previous.Server != "" && previous.Port > 0 {
				if _, err := m.run(ctx, kind[1], service.Name, previous.Server, strconv.Itoa(previous.Port)); err != nil {
					return err
				}
				if previous.Enabled {
					continue
				}
			}
			if _, err := m.run(ctx, kind[2], service.Name, "off"); err != nil {
				return err
			}
		}
		bypass := service.Bypass
		if len(bypass) == 0 {
			bypass = []string{"Empty"}
		}
		if _, err := m.run(ctx, append([]string{"-setproxybypassdomains", service.Name}, bypass...)...); err != nil {
			return err
		}
	}
	return nil
}
