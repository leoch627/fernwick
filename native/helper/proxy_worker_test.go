package main

import (
	"encoding/binary"
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
		"unknown field":    []byte(strings.Replace(string(config(inbounds, outbounds)), `"log"`, `"reverse":{},"log"`, 1)),
		"no inbound":       config(`[]`, outbounds),
	} {
		if validateProxyConfig(raw) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The core's byte counters are the only API the system proxy core may serve.
func TestValidateProxyConfigAcceptsOnlyTheStatsService(t *testing.T) {
	base := `{"log":{"loglevel":"none"},"inbounds":[{"tag":"local","listen":"127.0.0.1","port":7890,"protocol":"mixed","settings":{}}],"outbounds":[{"tag":"direct","protocol":"freedom","settings":{}}]`
	stats := `"api":{"tag":"api","listen":"127.0.0.1:40001","services":["StatsService"]},"stats":{},"policy":{"system":{"statsOutboundUplink":true,"statsOutboundDownlink":true}}`
	if e := validateProxyConfig([]byte(base + "," + stats + "}")); e != nil {
		t.Fatalf("stats rejected: %v", e)
	}
	for name, section := range map[string]string{
		"handler service":   strings.Replace(stats, `["StatsService"]`, `["StatsService","HandlerService"]`, 1),
		"routing service":   strings.Replace(stats, `["StatsService"]`, `["RoutingService"]`, 1),
		"network listener":  strings.Replace(stats, `127.0.0.1:40001`, `0.0.0.0:40001`, 1),
		"privileged port":   strings.Replace(stats, `127.0.0.1:40001`, `127.0.0.1:80`, 1),
		"user policy":       strings.Replace(stats, `"system":{`, `"levels":{"0":{"handshake":1}},"system":{`, 1),
		"stats without api": `"stats":{},"policy":{"system":{}}`,
		"api null":          strings.Replace(stats, `{"tag":"api","listen":"127.0.0.1:40001","services":["StatsService"]}`, `null`, 1),
	} {
		if validateProxyConfig([]byte(base+","+section+"}")) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParseTrafficSumsOutbounds(t *testing.T) {
	stat := func(name string, value byte) []byte {
		inner := append([]byte{0x0a, byte(len(name))}, name...)
		inner = append(inner, 0x10, value)
		return append([]byte{0x0a, byte(len(inner))}, inner...)
	}
	var message []byte
	for _, s := range []struct {
		name  string
		value byte
	}{{"outbound>>>node-0>>>traffic>>>uplink", 10}, {"outbound>>>node-0>>>traffic>>>downlink", 100}, {"outbound>>>direct>>>traffic>>>downlink", 20}, {"outbound>>>dns-out>>>traffic>>>downlink", 90}, {"outbound>>>block>>>traffic>>>uplink", 90}, {"inbound>>>local>>>traffic>>>uplink", 90}} {
		message = append(message, stat(s.name, s.value)...)
	}
	frame := append(binary.BigEndian.AppendUint32([]byte{0}, uint32(len(message))), message...)
	if traffic, e := parseTraffic(frame); e != nil || traffic != (Traffic{Up: 10, Down: 120}) {
		t.Fatalf("%+v %v", traffic, e)
	}
	for name, bad := range map[string][]byte{"short": frame[:4], "length": frame[:len(frame)-1], "compressed": append([]byte{1}, frame[1:]...), "truncated field": {0, 0, 0, 0, 2, 0x0a, 5}} {
		if _, e := parseTraffic(bad); e == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
