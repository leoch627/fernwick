package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type NetworkAddress struct {
	Name, Family, Address, Netmask string
	ScopeID                        int
	Internal                       bool
}
type NetworkEvents struct {
	mu                sync.Mutex
	previous, pending string
	pendingSince      time.Time
	read              func() ([]NetworkAddress, error)
	now               func() time.Time
	changed           func(context.Context) error
	cancel            context.CancelFunc
	done              chan struct{}
}

func NewNetworkEvents(changed func(context.Context) error) *NetworkEvents {
	return NewNetworkEventsWithSources(changed, readNetworkAddresses, time.Now)
}
func NewNetworkEventsWithSources(changed func(context.Context) error, read func() ([]NetworkAddress, error), now func() time.Time) *NetworkEvents {
	if changed == nil {
		changed = func(context.Context) error { return nil }
	}
	return &NetworkEvents{changed: changed, read: read, now: now}
}
func readNetworkAddresses() ([]NetworkAddress, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	result := []NetworkAddress{}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			ip, ipnet, err := net.ParseCIDR(address.String())
			if err != nil {
				continue
			}
			family := "IPv6"
			mask := net.IP(ipnet.Mask).String()
			if ip.To4() != nil {
				family = "IPv4"
				mask = net.IP(ipnet.Mask).To4().String()
			}
			scope := 0
			if family == "IPv6" && ip.IsLinkLocalUnicast() {
				scope = iface.Index
			}
			result = append(result, NetworkAddress{Name: iface.Name, Family: family, Address: ip.String(), Netmask: mask, ScopeID: scope, Internal: iface.Flags&net.FlagLoopback != 0 || ip.IsLoopback()})
		}
	}
	return result, nil
}
func (n *NetworkEvents) Sample() bool {
	addresses, err := n.read()
	if err != nil {
		return false
	}
	records := []string{}
	for _, a := range addresses {
		if a.Internal || a.Name == TUNName("darwin") || a.Name == TUNName("win32") || a.Name == TUNName("linux") {
			continue
		}
		records = append(records, strings.Join([]string{a.Name, a.Family, a.Address, a.Netmask, strconv.Itoa(a.ScopeID)}, "|"))
	}
	sort.Strings(records)
	sum := sha256.Sum256([]byte(strings.Join(records, "\n")))
	hash := hex.EncodeToString(sum[:])
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.previous == "" {
		n.previous = hash
		return false
	}
	if hash == n.previous {
		n.pending = ""
		return false
	}
	if hash != n.pending {
		n.pending = hash
		n.pendingSince = n.now()
		return false
	}
	if n.now().Sub(n.pendingSince) < 2*time.Second {
		return false
	}
	n.previous = hash
	n.pending = ""
	return true
}
func (n *NetworkEvents) Start() {
	n.mu.Lock()
	if n.cancel != nil {
		n.mu.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	n.cancel = cancel
	n.done = make(chan struct{})
	done := n.done
	n.mu.Unlock()
	n.Sample()
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n.Sample() {
					_ = n.changed(ctx)
				}
			}
		}
	}()
}
func (n *NetworkEvents) Stop() {
	n.mu.Lock()
	cancel, done := n.cancel, n.done
	n.cancel = nil
	n.done = nil
	n.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}
