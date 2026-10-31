//go:build linux

package main

import (
	"context"
	"encoding/json"
	"golang.org/x/sys/unix"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func stateRoot() string  { return "/var/lib/starrail-network" }
func helperRoot() string { return "/usr/lib/starrail-network" }
func socketPath() string { return "/run/starrail-network/helper.sock" }
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
}
func configureChild(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
}
func processBirth(pid int) (string, error) {
	value, e := os.ReadFile("/proc/" + itoa(pid) + "/stat")
	if e != nil {
		return "", e
	}
	end := strings.LastIndexByte(string(value), ')')
	if end < 0 {
		return "", failure("PERMISSION_REQUIRED")
	}
	fields := strings.Fields(string(value[end+1:]))
	if len(fields) < 20 {
		return "", failure("PERMISSION_REQUIRED")
	}
	return fields[19], nil
}
func processIdentity(pid int) (string, string, error) {
	path, e := os.Readlink("/proc/" + itoa(pid) + "/exe")
	if e != nil {
		return "", "", e
	}
	args, e := os.ReadFile("/proc/" + itoa(pid) + "/cmdline")
	return path, string(args), e
}
func peerForConnection(conn net.Conn) (Peer, error) {
	connection, ok := conn.(*net.UnixConn)
	if !ok {
		return Peer{}, failure("PERMISSION_REQUIRED")
	}
	raw, e := connection.SyscallConn()
	if e != nil {
		return Peer{}, e
	}
	var peer *unix.Ucred
	var pe error
	e = raw.Control(func(fd uintptr) { peer, pe = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if e != nil || pe != nil || peer == nil {
		return Peer{}, failure("PERMISSION_REQUIRED")
	}
	path, args, e := processIdentity(int(peer.Pid))
	if e != nil {
		return Peer{}, e
	}
	birth, e := processBirth(int(peer.Pid))
	return Peer{PID: int(peer.Pid), User: strconv.FormatUint(uint64(peer.Uid), 10), Birth: birth, Executable: path, Arguments: args}, e
}
func bindPhysical(network, address string, raw syscall.RawConn, physical Interface) error {
	var err error
	e := raw.Control(func(fd uintptr) {
		err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
		if err == nil {
			err = unix.BindToDevice(int(fd), physical.Name)
		}
	})
	if e != nil {
		return e
	}
	return err
}
func fixedTool(name string) string {
	for _, directory := range []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		path := filepath.Join(directory, name)
		if stat, e := os.Stat(path); e == nil && !stat.IsDir() {
			return path
		}
	}
	return "/usr/bin/" + name
}
func ipCommand(ctx context.Context, input string, args ...string) ([]byte, error) {
	return run(ctx, fixedTool("ip"), []byte(input), args...)
}
func discoverInterface(ctx context.Context) (Interface, error) {
	data, e := ipCommand(ctx, "", "-j", "-4", "route", "show", "default")
	if e != nil {
		return Interface{}, e
	}
	var routes []struct {
		Dev     string `json:"dev"`
		Gateway string `json:"gateway"`
		Metric  int    `json:"metric"`
	}
	if json.Unmarshal(data, &routes) != nil {
		return Interface{}, failure("COMPONENTS_UNAVAILABLE")
	}
	var best *struct {
		Dev     string `json:"dev"`
		Gateway string `json:"gateway"`
		Metric  int    `json:"metric"`
	}
	for i := range routes {
		if routes[i].Dev != tunName() && (best == nil || routes[i].Metric < best.Metric) {
			best = &routes[i]
		}
	}
	if best == nil {
		return Interface{}, failure("CONNECT_TIMEOUT")
	}
	iface, e := net.InterfaceByName(best.Dev)
	if e != nil {
		return Interface{}, e
	}
	addresses, _ := iface.Addrs()
	out := Interface{Name: iface.Name, Index: iface.Index, Gateway: best.Gateway}
	for _, address := range addresses {
		ip, _, e := net.ParseCIDR(address.String())
		if e == nil {
			out.Addresses = append(out.Addresses, ip.String())
		}
	}
	return out, nil
}
func platformPrepare(ctx context.Context, j *Journal) error {
	if _, e := os.Stat("/dev/net/tun"); e != nil {
		return failure("COMPONENTS_UNAVAILABLE")
	}
	for _, tool := range []string{"ip", "nft", "resolvectl"} {
		if _, e := os.Stat(fixedTool(tool)); e != nil {
			return failure("COMPONENTS_UNAVAILABLE")
		}
	}
	if _, e := net.InterfaceByName(j.Tun); e == nil {
		return failure("NETWORK_CONFLICT")
	}
	for _, family := range []string{"-4", "-6"} {
		data, e := ipCommand(ctx, "", "-j", family, "rule", "show")
		if e != nil {
			return e
		}
		var rules []struct {
			Priority int `json:"priority"`
			Table    any `json:"table"`
		}
		if json.Unmarshal(data, &rules) != nil {
			return failure("NETWORK_CONFLICT")
		}
		for _, rule := range rules {
			if rule.Priority == 17800 {
				return failure("NETWORK_CONFLICT")
			}
		}
		data, _ = ipCommand(ctx, "", "-j", family, "route", "show", "table", "20260")
		if len(data) > 0 && strings.TrimSpace(string(data)) != "[]" {
			return failure("NETWORK_CONFLICT")
		}
	}
	link, e := filepath.EvalSymlinks("/etc/resolv.conf")
	if e != nil || link != "/run/systemd/resolve/stub-resolv.conf" {
		return failure("COMPONENTS_UNAVAILABLE")
	}
	return nil
}
func nftName(j *Journal) string { return "starrail_" + j.ID[:16] }
func platformProtect(ctx context.Context, j *Journal) error {
	var ipv4, ipv6 []string
	for _, v := range append(append([]string{}, lan...), j.Bypass...) {
		address := strings.Split(v, "/")[0]
		if ip := net.ParseIP(address); ip != nil {
			if ip.To4() != nil {
				ipv4 = append(ipv4, v)
			} else {
				ipv6 = append(ipv6, v)
			}
		}
	}
	rules := "table inet " + nftName(j) + " {\n comment \"StarRail:" + j.ID + "\"\n chain output { type filter hook output priority -150; policy accept;\n oifname { \"lo\", \"" + j.Tun + "\" } accept\n meta mark " + itoa(mark) + " accept\n"
	if len(ipv4) > 0 {
		rules += "ip daddr { " + strings.Join(ipv4, ", ") + " } accept\n"
	}
	if len(ipv6) > 0 {
		rules += "ip6 daddr { " + strings.Join(ipv6, ", ") + " } accept\n"
	}
	rules += "icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert, packet-too-big } accept\ncounter drop\n }\n}\n"
	_, e := run(ctx, fixedTool("nft"), []byte(rules), "-f", "-")
	return e
}
func platformApply(ctx context.Context, j *Journal) error {
	for _, family := range []string{"-4", "-6"} {
		batch := "route add default dev " + j.Tun + " table 20260 proto 186\n"
		for _, prefix := range lan {
			ipv6 := strings.Contains(prefix, ":")
			if (family == "-6") == ipv6 {
				batch += "route add throw " + prefix + " table 20260 proto 186\n"
			}
		}
		batch += "rule add priority 17800 not fwmark " + itoa(mark) + " table 20260 protocol 186\n"
		if _, e := ipCommand(ctx, batch, family, "-batch", "-"); e != nil {
			return e
		}
	}
	for _, args := range [][]string{{"dns", j.Tun, tunDNS()}, {"domain", j.Tun, "~."}, {"default-route", j.Tun, "true"}} {
		if _, e := run(ctx, fixedTool("resolvectl"), nil, args...); e != nil {
			return e
		}
	}
	return nil
}
func platformUnprotect(ctx context.Context, j *Journal) error {
	if j == nil || !j.Protection {
		return nil
	}
	data, e := run(ctx, fixedTool("nft"), nil, "-j", "list", "tables")
	if e != nil {
		return e
	}
	if !strings.Contains(string(data), `"`+nftName(j)+`"`) {
		return nil
	}
	data, e = run(ctx, fixedTool("nft"), nil, "list", "table", "inet", nftName(j))
	if e != nil || !strings.Contains(string(data), "StarRail:"+j.ID) {
		return failure("NETWORK_RECOVERY_REQUIRED")
	}
	_, e = run(ctx, fixedTool("nft"), nil, "delete", "table", "inet", nftName(j))
	return e
}
func platformRecover(ctx context.Context, j *Journal) error {
	var last error
	if _, e := net.InterfaceByName(j.Tun); e == nil && j.DNS {
		if _, e = run(ctx, fixedTool("resolvectl"), nil, "revert", j.Tun); e != nil {
			last = e
		}
	}
	if j.Routes {
		for _, family := range []string{"-4", "-6"} {
			data, e := ipCommand(ctx, "", "-j", family, "rule", "show")
			if e != nil {
				last = e
				continue
			}
			var entries []struct {
				Priority int `json:"priority"`
				Table    any `json:"table"`
				Protocol any `json:"protocol"`
			}
			if json.Unmarshal(data, &entries) != nil {
				last = failure("NETWORK_RECOVERY_REQUIRED")
				continue
			}
			for _, entry := range entries {
				if entry.Priority == 17800 && entry.Table == float64(20260) && (entry.Protocol == float64(186) || entry.Protocol == "186") {
					if _, e = ipCommand(ctx, "", family, "rule", "del", "priority", "17800", "not", "fwmark", itoa(mark), "table", "20260", "protocol", "186"); e != nil {
						last = e
					}
				}
			}
			if _, e = ipCommand(ctx, "", family, "route", "flush", "table", "20260", "proto", "186"); e != nil {
				last = e
			}
		}
	}
	return last
}
func platformStopService(ctx context.Context) error {
	_, e := run(ctx, fixedTool("systemctl"), nil, "stop", "starrail-network.service")
	return e
}
func platformInstall(value Installation) error {
	unit := "[Unit]\nDescription=StarRail Network protected network service\nAfter=network.target systemd-resolved.service\nWants=systemd-resolved.service\n[Service]\nType=simple\nExecStart=/usr/lib/starrail-network/helper serve\nExecStopPost=/usr/lib/starrail-network/helper recover\nRestart=on-failure\nRestartSec=1\nTimeoutStopSec=8\nKillMode=control-group\nUMask=0077\nRuntimeDirectory=starrail-network\nRuntimeDirectoryMode=0755\nProtectHome=read-only\nProtectSystem=strict\nReadWritePaths=/var/lib/starrail-network /run/starrail-network\nPrivateTmp=true\nNoNewPrivileges=true\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\nCapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_KILL\n[Install]\nWantedBy=multi-user.target\n"
	if e := os.WriteFile("/etc/systemd/system/starrail-network.service", []byte(unit), 0644); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, e := run(ctx, fixedTool("systemctl"), nil, "daemon-reload"); e != nil {
		return e
	}
	_, e := run(ctx, fixedTool("systemctl"), nil, "enable", "--now", "starrail-network.service")
	return e
}
func platformUninstall() error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_, _ = run(ctx, fixedTool("systemctl"), nil, "disable", "--now", "starrail-network.service")
	if e := os.Remove("/etc/systemd/system/starrail-network.service"); e != nil && !os.IsNotExist(e) {
		return e
	}
	_, e := run(ctx, fixedTool("systemctl"), nil, "daemon-reload")
	return e
}
func fileOwner(path string, peer Peer) error {
	stat, e := os.Lstat(path)
	if e != nil || !stat.Mode().IsRegular() {
		return failure("UPDATE_VERIFY_FAILED")
	}
	owner := stat.Sys().(*syscall.Stat_t)
	if strconv.FormatUint(uint64(owner.Uid), 10) != peer.User || owner.Nlink != 1 {
		return failure("UPDATE_VERIFY_FAILED")
	}
	return nil
}
func secureMacApplication(string) error { return nil }
func platformNetworkFingerprint(ctx context.Context, p Interface) (string, error) {
	a, e := ipCommand(ctx, "", "-j", "-4", "route", "show", "default")
	if e != nil {
		return "", e
	}
	b, e := ipCommand(ctx, "", "-j", "-6", "route", "show", "default")
	if e != nil {
		return "", e
	}
	c, e := run(ctx, fixedTool("resolvectl"), nil, "dns", p.Name)
	if e != nil {
		return "", e
	}
	stable := func(raw []byte) string {
		var rows []struct {
			Dev     string `json:"dev"`
			Gateway string `json:"gateway"`
			Metric  int    `json:"metric"`
			Pref    string `json:"pref"`
		}
		_ = json.Unmarshal(raw, &rows)
		return string(jsonBytes(rows))
	}
	return stringHash(stable(a) + stable(b) + string(c)), nil
}
