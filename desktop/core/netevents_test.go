package core

import (
	"testing"
	"time"
)

func TestNetworkEventsDebounceAndIgnoreOwnedTUN(t *testing.T) {
	now := time.Unix(0, 0)
	records := []NetworkAddress{{Name: "eth0", Family: "IPv4", Address: "192.0.2.1", Netmask: "255.255.255.0"}, {Name: "eth0", Family: "IPv4", Address: "192.0.2.2", Netmask: "255.255.255.0"}}
	monitor := NewNetworkEventsWithSources(nil, func() ([]NetworkAddress, error) { return records, nil }, func() time.Time { return now })
	if monitor.Sample() {
		t.Fatal("initial sample changed")
	}
	records[0], records[1] = records[1], records[0]
	if monitor.Sample() {
		t.Fatal("order changed generation")
	}
	records = append(records, NetworkAddress{Name: "vbtun0", Address: "172.19.0.1"})
	if monitor.Sample() {
		t.Fatal("owned TUN changed generation")
	}
	records = []NetworkAddress{{Name: "eth0", Family: "IPv4", Address: "192.0.2.3", Netmask: "255.255.255.0"}}
	if monitor.Sample() {
		t.Fatal("no debounce")
	}
	now = now.Add(time.Second)
	if monitor.Sample() {
		t.Fatal("short debounce")
	}
	now = now.Add(time.Second)
	if !monitor.Sample() || monitor.Sample() {
		t.Fatal("change not emitted exactly once")
	}
}
