//go:build darwin

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func stateRoot() string  { return "/Library/Application Support/StarRail Network" }
func helperRoot() string { return "/Library/PrivilegedHelperTools/work.starrail.network" }
func socketPath() string { return "/var/run/starrail-network/helper.sock" }
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
}
func configureChild(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func processBirth(pid int) (string, error) {
	p, e := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if e != nil {
		return "", e
	}
	return fmt.Sprintf("%d:%d", p.Proc.P_starttime.Sec, p.Proc.P_starttime.Usec), nil
}
func processIdentity(pid int) (string, string, error) {
	raw, e := unix.SysctlRaw("kern.procargs2", pid)
	if e != nil || len(raw) < 5 {
		return "", "", failure("PERMISSION_REQUIRED")
	}
	argc := int(binary.LittleEndian.Uint32(raw[:4]))
	raw = raw[4:]
	end := bytes.IndexByte(raw, 0)
	if end < 0 || argc < 1 || argc > 128 {
		return "", "", failure("PERMISSION_REQUIRED")
	}
	path := string(raw[:end])
	raw = bytes.TrimLeft(raw[end:], "\x00")
	parts := bytes.Split(raw, []byte{0})
	if len(parts) < argc {
		return "", "", failure("PERMISSION_REQUIRED")
	}
	return path, string(bytes.Join(parts[:argc], []byte{0})), nil
}
func peerForConnection(conn net.Conn) (Peer, error) {
	c, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}, failure("PERMISSION_REQUIRED")
	}
	raw, e := c.SyscallConn()
	if e != nil {
		return Peer{}, e
	}
	var pid int
	var uid uint32
	var pe error
	_ = raw.Control(func(fd uintptr) {
		pid, pe = unix.GetsockoptInt(int(fd), 0, unix.LOCAL_PEERPID)
		if pe == nil {
			var credential *unix.Xucred
			credential, pe = unix.GetsockoptXucred(int(fd), 0, unix.LOCAL_PEERCRED)
			if pe == nil {
				uid = credential.Uid
			}
		}
	})
	if pe != nil {
		return Peer{}, pe
	}
	path, args, e := processIdentity(pid)
	if e != nil {
		return Peer{}, e
	}
	birth, e := processBirth(pid)
	return Peer{PID: pid, User: strconv.FormatUint(uint64(uid), 10), Birth: birth, Executable: path, Arguments: args}, e
}
func bindPhysical(network, address string, raw syscall.RawConn, p Interface) error {
	var err error
	e := raw.Control(func(fd uintptr) {
		if strings.Contains(address, "]:") || network == "tcp6" || network == "udp6" {
			err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, p.Index)
		} else {
			err = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, p.Index)
		}
	})
	if e != nil {
		return e
	}
	return err
}
func routeInfo(ctx context.Context, prefix string) (string, error) {
	family := "-inet"
	if strings.Contains(prefix, ":") {
		family = "-inet6"
	}
	data, e := run(ctx, "/sbin/route", nil, "-n", "get", family, prefix)
	return string(data), e
}
func field(output, key string) string {
	for _, line := range strings.Split(output, "\n") {
		parts := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(parts) == 2 && parts[0] == key {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}
func discoverInterface(ctx context.Context) (Interface, error) {
	data, e := routeInfo(ctx, "default")
	if e != nil {
		return Interface{}, e
	}
	name := field(data, "interface")
	iface, e := net.InterfaceByName(name)
	if e != nil || name == tunName() {
		return Interface{}, failure("NETWORK_CONFLICT")
	}
	out := Interface{Name: name, Index: iface.Index, Gateway: field(data, "gateway")}
	addresses, _ := iface.Addrs()
	for _, v := range addresses {
		ip, _, e := net.ParseCIDR(v.String())
		if e == nil {
			out.Addresses = append(out.Addresses, ip.String())
		}
	}
	return out, nil
}

var macRoutes = []string{"0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"}

func platformPrepare(ctx context.Context, j *Journal) error {
	if _, e := net.InterfaceByName(j.Tun); e == nil {
		return failure("NETWORK_CONFLICT")
	}
	// A split route from another VPN cannot be replaced or claimed.
	data, e := run(ctx, "/usr/sbin/netstat", nil, "-rn")
	if e != nil {
		return e
	}
	for _, line := range strings.Split(string(data), "\n") {
		p := strings.Fields(line)
		if len(p) > 0 && contains([]string{"0/1", "128.0/1", "::/1", "8000::/1"}, p[0]) {
			return failure("NETWORK_CONFLICT")
		}
	}
	order, e := run(ctx, "/usr/sbin/networksetup", nil, "-listnetworkserviceorder")
	if e != nil {
		return e
	}
	service := ""
	for _, line := range strings.Split(string(order), "\n") {
		if regexp.MustCompile(`^\([0-9]+\) `).MatchString(line) {
			service = regexp.MustCompile(`^\([0-9]+\) `).ReplaceAllString(line, "")
		}
		if service != "" && strings.Contains(line, "Device: "+j.Interface.Name+")") {
			dns, e := run(ctx, "/usr/sbin/networksetup", nil, "-getdnsservers", service)
			if e != nil {
				return e
			}
			previous := []string{}
			for _, a := range strings.Fields(string(dns)) {
				if net.ParseIP(a) != nil {
					previous = append(previous, a)
				}
			}
			j.Interface.DNS = append(j.Interface.DNS, DNSBackup{Service: service, Addresses: previous, Applied: tunDNS()})
		}
	}
	if len(j.Interface.DNS) == 0 {
		return failure("COMPONENTS_UNAVAILABLE")
	}
	return nil
}
func anchorName(j *Journal) string { return "com.apple/StarRail." + j.ID }
func platformProtect(ctx context.Context, j *Journal) error {
	// macOS's default pf.conf already evaluates com.apple/* anchors. Refuse custom roots that do not.
	active, e := run(ctx, "/sbin/pfctl", nil, "-sr")
	if e != nil || !strings.Contains(string(active), `anchor "com.apple/*"`) {
		return failure("NETWORK_CONFLICT")
	}
	c := exec.CommandContext(ctx, "/sbin/pfctl", "-E")
	c.Env = safeEnvironment()
	out, e := c.CombinedOutput()
	if e != nil {
		return failure("NETWORK_RECOVERY_REQUIRED")
	}
	token := regexp.MustCompile(`Token\s*:\s*([0-9]+)`).FindSubmatch(out)
	if len(token) != 2 {
		return failure("NETWORK_RECOVERY_REQUIRED")
	}
	j.FilterToken = string(token[1])
	if e = writeJournal(j); e != nil {
		return e
	}
	destinations := append(append([]string{}, lan...), j.Bypass...)
	rules := "pass out quick on lo0 all\npass out quick on " + j.Tun + " all\npass out quick inet6 proto icmp6 icmp6-type { 1, 2, 3, 4, 133, 134, 135, 136 }\npass out quick to { " + strings.Join(destinations, ", ") + " }\nblock drop out quick all\n"
	if _, e = run(ctx, "/sbin/pfctl", []byte(rules), "-a", anchorName(j), "-f", "-"); e != nil {
		return e
	}
	for _, address := range j.Interface.Addresses {
		if _, e = run(ctx, "/sbin/pfctl", nil, "-k", address); e != nil {
			return e
		}
	}
	return nil
}
func platformApply(ctx context.Context, j *Journal) error {
	for _, prefix := range macRoutes {
		family := "-inet"
		if strings.Contains(prefix, ":") {
			family = "-inet6"
		}
		if _, e := run(ctx, "/sbin/route", nil, "-n", "add", family, "-net", prefix, "-interface", j.Tun); e != nil {
			return e
		}
	}
	for _, dns := range j.Interface.DNS {
		if _, e := run(ctx, "/usr/sbin/networksetup", nil, "-setdnsservers", dns.Service, dns.Applied); e != nil {
			return e
		}
	}
	_, _ = run(ctx, "/usr/bin/dscacheutil", nil, "-flushcache")
	return nil
}
func platformRecover(ctx context.Context, j *Journal) error {
	var last error
	if j.Routes {
		for _, prefix := range macRoutes {
			data, e := routeInfo(ctx, strings.Split(prefix, "/")[0])
			if e == nil && field(data, "interface") == j.Tun {
				family := "-inet"
				if strings.Contains(prefix, ":") {
					family = "-inet6"
				}
				if _, e = run(ctx, "/sbin/route", nil, "-n", "delete", family, "-net", prefix, "-interface", j.Tun); e != nil {
					last = e
				}
			}
		}
	}
	if j.DNS {
		for _, dns := range j.Interface.DNS {
			data, e := run(ctx, "/usr/sbin/networksetup", nil, "-getdnsservers", dns.Service)
			if e != nil {
				last = e
				continue
			}
			if strings.TrimSpace(string(data)) != dns.Applied {
				continue
			}
			addresses := dns.Addresses
			if len(addresses) == 0 {
				addresses = []string{"empty"}
			}
			if _, e = run(ctx, "/usr/sbin/networksetup", nil, append([]string{"-setdnsservers", dns.Service}, addresses...)...); e != nil {
				last = e
			}
		}
	}
	_, _ = run(ctx, "/usr/bin/dscacheutil", nil, "-flushcache")
	return last
}
func platformUnprotect(ctx context.Context, j *Journal) error {
	if !j.Protection {
		return nil
	}
	if _, e := run(ctx, "/sbin/pfctl", nil, "-a", anchorName(j), "-F", "rules"); e != nil {
		return e
	}
	if j.FilterToken != "" {
		if _, e := run(ctx, "/sbin/pfctl", nil, "-X", j.FilterToken); e != nil {
			return e
		}
		j.FilterToken = ""
	}
	return nil
}
func platformStopService(ctx context.Context) error {
	if _, e := run(ctx, "/bin/launchctl", nil, "print", "system/work.starrail.network"); e != nil {
		return nil
	}
	_, e := run(ctx, "/bin/launchctl", nil, "bootout", "system/work.starrail.network")
	return e
}
func platformInstall(Installation) error {
	value := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>Label</key><string>work.starrail.network</string><key>ProgramArguments</key><array><string>/Library/PrivilegedHelperTools/work.starrail.network/helper</string><string>serve</string></array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/><key>ThrottleInterval</key><integer>1</integer><key>ExitTimeOut</key><integer>8</integer><key>Umask</key><integer>63</integer></dict></plist>`
	if e := os.WriteFile("/Library/LaunchDaemons/work.starrail.network.plist", []byte(value), 0644); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, e := run(ctx, "/bin/launchctl", nil, "bootstrap", "system", "/Library/LaunchDaemons/work.starrail.network.plist")
	return e
}
func platformUninstall() error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = platformStopService(ctx)
	return os.Remove("/Library/LaunchDaemons/work.starrail.network.plist")
}
func fileOwner(path string, p Peer) error {
	s, e := os.Lstat(path)
	if e != nil || !s.Mode().IsRegular() {
		return failure("UPDATE_VERIFY_FAILED")
	}
	owner := s.Sys().(*syscall.Stat_t)
	if strconv.FormatUint(uint64(owner.Uid), 10) != p.User || owner.Nlink != 1 {
		return failure("UPDATE_VERIFY_FAILED")
	}
	return nil
}
func platformNetworkFingerprint(ctx context.Context, p Interface) (string, error) {
	a, e := routeInfo(ctx, "default")
	if e != nil {
		return "", e
	}
	data := "interface=" + field(a, "interface") + ";gateway=" + field(a, "gateway")
	for _, dns := range p.DNS {
		value, e := run(ctx, "/usr/sbin/networksetup", nil, "-getdnsservers", dns.Service)
		if e != nil {
			return "", e
		}
		data += string(value)
	}
	return stringHash(data), nil
}
