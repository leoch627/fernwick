package core

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestGnomeProxyRestoresExactlyWhatItRead(t *testing.T) {
	settings := map[string]string{
		"org.gnome.system.proxy mode": "'auto'", "org.gnome.system.proxy ignore-hosts": "['corp.example']",
		"org.gnome.system.proxy.http host": "'corp-proxy'", "org.gnome.system.proxy.http port": "3128",
		"org.gnome.system.proxy.https host": "''", "org.gnome.system.proxy.https port": "0",
		"org.gnome.system.proxy.socks host": "''", "org.gnome.system.proxy.socks port": "0",
	}
	original := map[string]string{}
	for k, v := range settings {
		original[k] = v
	}
	sets := []string{}
	proxy := gnomeProxy{run: func(_ context.Context, args ...string) (string, error) {
		key := args[1] + " " + args[2]
		if args[0] == "get" {
			return settings[key], nil
		}
		sets = append(sets, key)
		settings[key] = args[3]
		return "", nil
	}}
	saved, err := proxy.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err = proxy.Apply(context.Background(), saved, 7890); err != nil {
		t.Fatal(err)
	}
	if settings["org.gnome.system.proxy mode"] != "'manual'" || settings["org.gnome.system.proxy.http host"] != "'127.0.0.1'" || settings["org.gnome.system.proxy.socks port"] != "7890" || !strings.Contains(settings["org.gnome.system.proxy ignore-hosts"], "192.168.0.0/16") {
		t.Fatalf("applied %v", settings)
	}
	if sets[len(sets)-1] != "org.gnome.system.proxy mode" {
		t.Fatalf("mode must switch last: %v", sets)
	}
	if err = proxy.Restore(context.Background(), saved); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(settings, original) {
		t.Fatalf("restored %v, want %v", settings, original)
	}
}
