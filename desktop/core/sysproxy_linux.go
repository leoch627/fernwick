package core

import (
	"context"
	"encoding/json"
	"os/exec"
	"strconv"
)

// GNOME keeps the system proxy in GSettings; Ubuntu's desktop and most GTK apps and
// browsers follow it. Values are saved and restored as GVariant text, exactly as read.
type gnomeProxy struct {
	run func(ctx context.Context, args ...string) (string, error)
}

var gnomeProxyKeys = [][2]string{
	{"org.gnome.system.proxy.http", "host"}, {"org.gnome.system.proxy.http", "port"},
	{"org.gnome.system.proxy.https", "host"}, {"org.gnome.system.proxy.https", "port"},
	{"org.gnome.system.proxy.socks", "host"}, {"org.gnome.system.proxy.socks", "port"},
	{"org.gnome.system.proxy", "ignore-hosts"},
	// The mode goes last so the proxy is switched on or off only once the rest is in place.
	{"org.gnome.system.proxy", "mode"},
}

func NewSystemProxy() SystemProxy {
	return gnomeProxy{run: func(ctx context.Context, args ...string) (string, error) {
		program, err := exec.LookPath("gsettings")
		if err != nil {
			return "", NewAppError("SYSTEM_PROXY_FAILED")
		}
		return systemCommand(ctx, program, args...)
	}}
}
func (g gnomeProxy) Snapshot(ctx context.Context) (json.RawMessage, error) {
	saved := map[string]string{}
	for _, key := range gnomeProxyKeys {
		value, err := g.run(ctx, "get", key[0], key[1])
		if err != nil {
			return nil, err
		}
		saved[key[0]+" "+key[1]] = value
	}
	return json.Marshal(saved)
}
func (g gnomeProxy) Apply(ctx context.Context, _ json.RawMessage, port int) error {
	local, number := "'127.0.0.1'", strconv.Itoa(port)
	values := map[string]string{
		"org.gnome.system.proxy.http host": local, "org.gnome.system.proxy.http port": number,
		"org.gnome.system.proxy.https host": local, "org.gnome.system.proxy.https port": number,
		"org.gnome.system.proxy.socks host": local, "org.gnome.system.proxy.socks port": number,
		"org.gnome.system.proxy ignore-hosts": "['localhost', '127.0.0.0/8', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '169.254.0.0/16', '*.local']",
		"org.gnome.system.proxy mode":         "'manual'",
	}
	return g.set(ctx, values)
}
func (g gnomeProxy) Restore(ctx context.Context, saved json.RawMessage) error {
	var values map[string]string
	if err := json.Unmarshal(saved, &values); err != nil {
		return NewAppError("STORAGE_FAILED")
	}
	return g.set(ctx, values)
}
func (g gnomeProxy) set(ctx context.Context, values map[string]string) error {
	for _, key := range gnomeProxyKeys {
		value, ok := values[key[0]+" "+key[1]]
		if !ok {
			continue
		}
		if _, err := g.run(ctx, "set", key[0], key[1], value); err != nil {
			return err
		}
	}
	return nil
}
