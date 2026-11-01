package main

import (
	"strings"
	"testing"
)

func TestValidateProxyConfigAcceptsOnlyLoopbackProxies(t *testing.T) {
	inbounds := `[{"tag":"local","listen":"127.0.0.1","port":7890,"protocol":"mixed","settings":{"auth":"noauth","udp":true},"sniffing":{"enabled":true}},{"tag":"health","listen":"127.0.0.1","port":40000,"protocol":"socks","settings":{"auth":"password"}}]`
	outbounds := `[{"tag":"node-0","protocol":"vless","settings":{},"streamSettings":{"network":"tcp"}},{"tag":"direct","protocol":"freedom","settings":{}},{"tag":"dns-out","protocol":"dns","settings":{}},{"tag":"block","protocol":"blackhole"}]`
	config := func(in, out string) []byte {
		return []byte(`{"log":{"loglevel":"none"},"inbounds":` + in + `,"outbounds":` + out + `,"dns":{"servers":[]},"routing":{"rules":[]},"observatory":{"subjectSelector":["node-"]}}`)
	}
	if e := validateProxyConfig(config(inbounds, outbounds)); e != nil {
		t.Fatalf("system proxy configuration rejected: %v", e)
	}
	for name, raw := range map[string][]byte{
		"tun inbound":      config(strings.Replace(inbounds, `"protocol":"mixed"`, `"protocol":"tun"`, 1), outbounds),
		"network listener": config(strings.Replace(inbounds, `"listen":"127.0.0.1","port":7890`, `"listen":"0.0.0.0","port":7890`, 1), outbounds),
		"privileged port":  config(strings.Replace(inbounds, `"port":7890`, `"port":80`, 1), outbounds),
		"dokodemo inbound": config(strings.Replace(inbounds, `"protocol":"socks"`, `"protocol":"dokodemo-door"`, 1), outbounds),
		"unknown outbound": config(inbounds, strings.Replace(outbounds, `"protocol":"blackhole"`, `"protocol":"loopback"`, 1)),
		"unknown field":    []byte(strings.Replace(string(config(inbounds, outbounds)), `"log"`, `"api":{},"log"`, 1)),
		"no inbound":       config(`[]`, outbounds),
	} {
		if validateProxyConfig(raw) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
