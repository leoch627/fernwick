package core

import (
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func statsFrame(stats map[string]uint64) []byte {
	var message []byte
	for name, value := range stats {
		inner := append([]byte{0x0a, byte(len(name))}, name...)
		inner = binary.AppendUvarint(append(inner, 0x10), value)
		message = append(append(message, 0x0a, byte(len(inner))), inner...)
	}
	return append(binary.BigEndian.AppendUint32([]byte{0}, uint32(len(message))), message...)
}

func TestParseTrafficStatsSumsOutbounds(t *testing.T) {
	frame := statsFrame(map[string]uint64{
		"outbound>>>node-0>>>traffic>>>uplink":    10,
		"outbound>>>node-ai-1>>>traffic>>>uplink": 5,
		"outbound>>>node-0>>>traffic>>>downlink":  100000,
		"outbound>>>direct>>>traffic>>>downlink":  20,
		"outbound>>>dns-out>>>traffic>>>downlink": 900,
		"outbound>>>block>>>traffic>>>uplink":     900,
		"inbound>>>local>>>traffic>>>uplink":      900,
	})
	up, down, err := parseTrafficStats(frame)
	if err != nil || up != 15 || down != 100020 {
		t.Fatalf("%d %d %v", up, down, err)
	}
	// The reply Xray 26.10.31 sent for one direct request.
	real := []byte{0, 0, 0, 0, 0x58, 0x0a, 0x2b, 0x0a, 0x26}
	real = append(real, "outbound>>>direct>>>traffic>>>downlink"...)
	real = append(real, 0x10, 0xf1, 0x3f, 0x0a, 0x29, 0x0a, 0x24)
	real = append(real, "outbound>>>direct>>>traffic>>>uplink"...)
	real = append(real, 0x10, 0xc9, 0x04)
	if up, down, err = parseTrafficStats(real); err != nil || up != 585 || down != 8177 {
		t.Fatalf("real reply: %d %d %v", up, down, err)
	}
	for name, bad := range map[string][]byte{"short": frame[:4], "length": frame[:len(frame)-1], "compressed": append([]byte{1}, frame[1:]...), "truncated field": {0, 0, 0, 0, 3, 0x0a, 5, 1}, "group wire type": {0, 0, 0, 0, 1, 0x0b}} {
		if _, _, err := parseTrafficStats(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// CoreTraffic speaks gRPC over HTTP/2 without TLS, as the core's API port does.
func TestCoreTrafficQueriesTheStatsService(t *testing.T) {
	var path, contentType string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, contentType = r.URL.Path, r.Header.Get("content-type")
		w.Header().Set("content-type", "application/grpc")
		w.Header().Set("trailer", "grpc-status")
		_, _ = w.Write(statsFrame(map[string]uint64{"outbound>>>node-0>>>traffic>>>uplink": 7, "outbound>>>node-0>>>traffic>>>downlink": 70}))
		w.Header().Set("grpc-status", "0")
	}))
	server.Config.Protocols = new(http.Protocols)
	server.Config.Protocols.SetUnencryptedHTTP2(true)
	server.Start()
	defer server.Close()
	_, portText, _ := net.SplitHostPort(server.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	sample, err := CoreTraffic(context.Background(), port)
	if err != nil || sample.Up != 7 || sample.Down != 70 || time.Since(sample.At) > time.Second {
		t.Fatalf("%+v %v", sample, err)
	}
	if path != "/xray.app.stats.command.StatsService/QueryStats" || contentType != "application/grpc" {
		t.Fatalf("%s %s", path, contentType)
	}
	if _, err := CoreTraffic(context.Background(), 80); err == nil {
		t.Fatal("privileged port accepted")
	}
}

func TestTrafficMeterRates(t *testing.T) {
	start := time.Unix(1000, 0)
	var meter TrafficMeter
	if rate := meter.Add(TrafficSample{Up: 100, Down: 1000, At: start}); rate != (TrafficRate{}) {
		t.Fatalf("first sample %+v", rate)
	}
	if rate := meter.Add(TrafficSample{Up: 1100, Down: 21000, At: start.Add(2 * time.Second)}); rate != (TrafficRate{Up: 500, Down: 10000}) {
		t.Fatalf("rate %+v", rate)
	}
	// A heartbeat sample seen twice keeps the rate.
	if rate := meter.Add(TrafficSample{Up: 1100, Down: 21000, At: start.Add(2*time.Second + 100*time.Millisecond)}); rate != (TrafficRate{Up: 500, Down: 10000}) {
		t.Fatalf("repeat %+v", rate)
	}
	// A restarted core starts over.
	if rate := meter.Add(TrafficSample{Up: 5, Down: 5, At: start.Add(3 * time.Second)}); rate != (TrafficRate{}) {
		t.Fatalf("restart %+v", rate)
	}
	if rate := meter.Add(TrafficSample{Up: 5, Down: 1029, At: start.Add(4 * time.Second)}); rate != (TrafficRate{Up: 0, Down: 1024}) {
		t.Fatalf("after restart %+v", rate)
	}
}

func TestFormatRateAndLevel(t *testing.T) {
	for _, c := range []struct {
		rate  uint64
		text  string
		level int
	}{
		{0, "0 B/s", 0},
		{999, "999 B/s", 0},
		{1000, "1.0 KB/s", 0},
		{1229, "1.2 KB/s", 1},
		{9011, "8.8 KB/s", 2},
		{10189, "10 KB/s", 2},
		{364544, "356 KB/s", 5},
		{1023 * 1024, "1.0 MB/s", 5},
		{12 * 1024 * 1024, "12 MB/s", 7},
		{16 * 1024 * 1024, "16 MB/s", 8},
		{3 << 30, "3.0 GB/s", 8},
		{5000 << 30, "5000 GB/s", 8},
	} {
		if text, level := FormatRate(c.rate), RateLevel(c.rate); text != c.text || level != c.level {
			t.Errorf("%d: %q %d, want %q %d", c.rate, text, level, c.text, c.level)
		}
	}
}

func TestCompileSystemProxyServesOnlyStats(t *testing.T) {
	node := proxyTestNode(t, "vless://00000000-0000-4000-8000-000000000001@jp.example.invalid:443?security=tls&type=tcp&sni=jp.example.invalid#JP")
	candidate := Candidate{Node: node, Mode: "rule", Rules: proxyTestRules()}
	ports := proxyTestPorts()
	ports.Stats = 17892
	config, err := CompileSystemProxy(candidate, ports)
	if err != nil {
		t.Fatal(err)
	}
	api, _ := config["api"].(map[string]any)
	if api["listen"] != "127.0.0.1:17892" || len(api["services"].([]string)) != 1 || api["services"].([]string)[0] != "StatsService" || config["stats"] == nil || config["policy"] == nil {
		t.Fatalf("%+v", config)
	}
	for _, port := range []int{80, ports.Local, ports.Health.Port} {
		bad := ports
		bad.Stats = port
		if _, err := CompileSystemProxy(candidate, bad); err == nil {
			t.Errorf("stats port %d accepted", port)
		}
	}
	ports.Stats = 0
	if config, _ = CompileSystemProxy(candidate, ports); config["api"] != nil || config["stats"] != nil {
		t.Fatalf("stats without a port: %+v", config)
	}
}

// The demo connection makes up traffic so the speed can be seen without a network.
func TestDemoDriverReportsTraffic(t *testing.T) {
	driver := &DemoDriver{}
	if _, ok := driver.Traffic(context.Background()); ok {
		t.Fatal("traffic before connecting")
	}
	_ = driver.Start(context.Background(), "demo")
	time.Sleep(20 * time.Millisecond)
	first, ok := driver.Traffic(context.Background())
	time.Sleep(20 * time.Millisecond)
	second, _ := driver.Traffic(context.Background())
	if !ok || second.Down <= first.Down || second.Up > second.Down {
		t.Fatalf("%+v %+v", first, second)
	}
	_ = driver.Cleanup(context.Background())
	if _, ok := driver.Traffic(context.Background()); ok {
		t.Fatal("traffic after disconnecting")
	}
}
