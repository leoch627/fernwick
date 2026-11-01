package core

import (
	"context"
	"slices"
	"strings"
	"testing"
)

func TestMacProxyCoversDeviceServicesAndRestores(t *testing.T) {
	calls := [][]string{}
	proxy := macSystemProxy{run: func(_ context.Context, args ...string) (string, error) {
		calls = append(calls, args)
		switch {
		case args[0] == "-listnetworkserviceorder":
			return "An asterisk (*) denotes that a network service is disabled.\n(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n\n(2) Thunderbolt Bridge\n(Hardware Port: Thunderbolt Bridge, Device: bridge0)\n\n(3) Corp VPN\n(Hardware Port: Corp VPN, Device: )\n\n(*) USB LAN\n(Hardware Port: USB LAN, Device: en5)", nil
		case args[0] == "-getwebproxy" && args[1] == "Wi-Fi":
			return "Enabled: Yes\nServer: corp-proxy\nPort: 3128\nAuthenticated Proxy Enabled: 0", nil
		case strings.HasPrefix(args[0], "-get") && args[0] != "-getproxybypassdomains":
			return "Enabled: No\nServer: \nPort: 0\nAuthenticated Proxy Enabled: 0", nil
		case args[0] == "-getproxybypassdomains" && args[1] == "Wi-Fi":
			return "*.corp.example\n10.0.0.0/8", nil
		case args[0] == "-getproxybypassdomains":
			return "There aren't any bypass domains set on " + args[1] + ".", nil
		}
		return "", nil
	}}
	saved, err := proxy.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	calls = nil
	if err = proxy.Apply(context.Background(), saved, 7890); err != nil {
		t.Fatal(err)
	}
	touched := map[string]bool{}
	for _, call := range calls {
		touched[call[1]] = true
		if strings.HasPrefix(call[0], "-set") && call[0] != "-setproxybypassdomains" && (call[2] != "127.0.0.1" || call[3] != "7890") {
			t.Fatalf("apply %v", call)
		}
	}
	if !touched["Wi-Fi"] || !touched["Thunderbolt Bridge"] || touched["Corp VPN"] || touched["USB LAN"] {
		t.Fatalf("services touched: %v", touched)
	}
	calls = nil
	if err = proxy.Restore(context.Background(), saved); err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"-listnetworkserviceorder"},
		{"-setwebproxy", "Wi-Fi", "corp-proxy", "3128"},
		{"-setsecurewebproxystate", "Wi-Fi", "off"},
		{"-setsocksfirewallproxystate", "Wi-Fi", "off"},
		{"-setproxybypassdomains", "Wi-Fi", "*.corp.example", "10.0.0.0/8"},
		{"-setwebproxystate", "Thunderbolt Bridge", "off"},
		{"-setsecurewebproxystate", "Thunderbolt Bridge", "off"},
		{"-setsocksfirewallproxystate", "Thunderbolt Bridge", "off"},
		{"-setproxybypassdomains", "Thunderbolt Bridge", "Empty"},
	}
	if !slices.EqualFunc(calls, want, slices.Equal[[]string]) {
		t.Fatalf("restore calls:\n%v\nwant\n%v", calls, want)
	}
}
