//go:build windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func targetOS() string         { return "windows" }
func targetID() string         { return "win32-x64" }
func windowsDirectory() string { v, _ := windows.GetSystemDirectory(); return v }
func stateRoot() string {
	v, _ := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	return filepath.Join(v, "StarRail Network")
}
func helperRoot() string {
	v, _ := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	return filepath.Join(v, "StarRail Network Service")
}
func socketPath() string        { return `\\.\pipe\StarRailNetwork.Helper.v1` }
func samePath(a, b string) bool { return strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) }
func safeEnvironment() []string {
	return []string{"SystemRoot=" + filepath.Dir(windowsDirectory()), "WINDIR=" + filepath.Dir(windowsDirectory()), "PATH=" + windowsDirectory(), "TEMP=" + stateRoot(), "TMP=" + stateRoot(), "XRAY_LOCATION_ASSET=" + filepath.Dir(installed.CorePath)}
}
func configureChild(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}
func replaceFile(from, to string) error {
	a, _ := windows.UTF16PtrFromString(from)
	b, _ := windows.UTF16PtrFromString(to)
	return windows.MoveFileEx(a, b, windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH)
}
func syncDirectory(string) error { return nil }
func requireAdministrator() error {
	token := windows.GetCurrentProcessToken()
	if !token.IsElevated() {
		return failure("PERMISSION_REQUIRED")
	}
	return nil
}
func protectDirectory(path string) error {
	sd, e := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)")
	if e != nil {
		return e
	}
	dacl, _, e := sd.DACL()
	if e != nil {
		return e
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
func protectedFile(path string) error {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		s, e := os.Lstat(current)
		if e != nil || s.Mode()&os.ModeSymlink != 0 {
			return failure("PERMISSION_REQUIRED")
		}
		sd, e := windows.GetNamedSecurityInfo(current, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if e != nil {
			return e
		}
		dacl, _, e := sd.DACL()
		if e != nil || dacl == nil {
			return failure("PERMISSION_REQUIRED")
		}
		for i := uint32(0); i < uint32(dacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if windows.GetAce(dacl, i, &ace) != nil {
				return failure("PERMISSION_REQUIRED")
			}
			if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
				continue
			}
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
			if ace.Mask&(windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.WRITE_DAC|windows.WRITE_OWNER|windows.DELETE|windows.GENERIC_WRITE|windows.GENERIC_ALL) != 0 && !contains([]string{"S-1-5-18", "S-1-5-32-544", "S-1-3-0", "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"}, sid) {
				return failure("PERMISSION_REQUIRED")
			}
		}
		parent := filepath.Dir(current)
		if samePath(parent, current) || samePath(current, helperRoot()) || samePath(current, stateRoot()) || samePath(current, filepath.Dir(helperRoot())) {
			return nil
		}
	}
}

type handleCloser windows.Handle

func (h handleCloser) Close() error { return windows.CloseHandle(windows.Handle(h)) }
func machineLock() (io.Closer, error) {
	sd, e := windows.SecurityDescriptorFromString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	if e != nil {
		return nil, e
	}
	name, _ := windows.UTF16PtrFromString(`Global\StarRailNetwork.NetworkOwner`)
	h, e := windows.CreateMutex(&windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}, true, name)
	if e != nil {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return nil, failure("NETWORK_CONFLICT")
	}
	return handleCloser(h), nil
}
func listenIPC() (net.Listener, error) {
	return winio.ListenPipe(socketPath(), &winio.PipeConfig{SecurityDescriptor: "D:P(D;;GA;;;NU)(A;;GA;;;SY)(A;;GRGW;;;IU)(A;;GA;;;BA)", InputBufferSize: 65536, OutputBufferSize: 65536})
}
func openProcess(pid int) (windows.Handle, error) {
	return windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
}
func processBirth(pid int) (string, error) {
	h, e := openProcess(pid)
	if e != nil {
		return "", e
	}
	defer windows.CloseHandle(h)
	var a, b, c, d windows.Filetime
	e = windows.GetProcessTimes(h, &a, &b, &c, &d)
	return fmt.Sprintf("%d:%d", a.HighDateTime, a.LowDateTime), e
}
func processIdentity(pid int) (string, string, error) {
	h, e := openProcess(pid)
	if e != nil {
		return "", "", e
	}
	defer windows.CloseHandle(h)
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	if e = windows.QueryFullProcessImageName(h, 0, &buffer[0], &size); e != nil {
		return "", "", e
	}
	path := windows.UTF16ToString(buffer[:size])
	query := windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryInformationProcess")
	data := make([]byte, 65536)
	var length uint32
	status, _, _ := query.Call(uintptr(h), 60, uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)), uintptr(unsafe.Pointer(&length)))
	if status != 0 {
		return "", "", failure("PERMISSION_REQUIRED")
	}
	value := (*struct {
		Length        uint16
		MaximumLength uint16
		Buffer        *uint16
	})(unsafe.Pointer(&data[0]))
	if value.Length > 32768 || value.Buffer == nil {
		return "", "", failure("PERMISSION_REQUIRED")
	}
	return path, windows.UTF16ToString(unsafe.Slice(value.Buffer, int(value.Length)/2)), nil
}
func peerForConnection(conn net.Conn) (Peer, error) {
	file, ok := conn.(interface{ Fd() uintptr })
	if !ok {
		return Peer{}, failure("PERMISSION_REQUIRED")
	}
	var pid uint32
	if e := windows.GetNamedPipeClientProcessId(windows.Handle(file.Fd()), &pid); e != nil {
		return Peer{}, e
	}
	h, e := openProcess(int(pid))
	if e != nil {
		return Peer{}, e
	}
	defer windows.CloseHandle(h)
	var token windows.Token
	if e = windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); e != nil {
		return Peer{}, e
	}
	defer token.Close()
	user, e := token.GetTokenUser()
	if e != nil {
		return Peer{}, e
	}
	path, args, e := processIdentity(int(pid))
	if e != nil {
		return Peer{}, e
	}
	birth, e := processBirth(int(pid))
	return Peer{PID: int(pid), User: user.User.Sid.String(), Birth: birth, Executable: path, Arguments: args}, e
}
func validAppArguments(value, path string) bool {
	argv, e := windows.DecomposeCommandLine(value)
	if e != nil || len(argv) == 0 || !samePath(argv[0], path) {
		return false
	}
	for _, a := range argv[1:] {
		if !contains([]string{"--hidden", "--autostart", "--updated"}, a) {
			return false
		}
	}
	return true
}
func bindPhysical(network, address string, raw syscall.RawConn, p Interface) error {
	var err error
	e := raw.Control(func(fd uintptr) {
		index := p.Index
		if strings.Contains(address, "]:") || network == "tcp6" || network == "udp6" {
			err = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, 31, index)
		} else {
			index = int((uint32(index)&0xff)<<24 | (uint32(index)&0xff00)<<8 | (uint32(index)&0xff0000)>>8 | (uint32(index)&0xff000000)>>24)
			err = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, 31, index)
		}
	})
	if e != nil {
		return e
	}
	return err
}

var coreJob windows.Handle

func attachCore(c *exec.Cmd) error {
	if coreJob == 0 {
		job, e := windows.CreateJobObject(nil, nil)
		if e != nil {
			return e
		}
		limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
		limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
		if _, e = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); e != nil {
			windows.CloseHandle(job)
			return e
		}
		coreJob = job
	}
	h, e := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(c.Process.Pid))
	if e != nil {
		return e
	}
	defer windows.CloseHandle(h)
	return windows.AssignProcessToJobObject(coreJob, h)
}
func terminateChild(c *exec.Cmd) error {
	if c.Process == nil {
		return nil
	}
	return c.Process.Kill()
}
func terminateOrphan(j *Journal) error {
	birth, e := processBirth(j.CorePID)
	if e != nil || birth != j.CoreBirth {
		return nil
	}
	path, _, e := processIdentity(j.CorePID)
	if e != nil || !samePath(path, j.CorePath) {
		return failure("NETWORK_RECOVERY_REQUIRED")
	}
	p, e := os.FindProcess(j.CorePID)
	if e != nil {
		return e
	}
	return p.Kill()
}
func powershell(ctx context.Context, script string, value any) ([]byte, error) {
	return run(ctx, filepath.Join(windowsDirectory(), "WindowsPowerShell", "v1.0", "powershell.exe"), jsonBytes(value), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", `$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); $v=[Console]::In.ReadToEnd()|ConvertFrom-Json; `+script)
}
func discoverInterface(ctx context.Context) (Interface, error) {
	data, e := powershell(ctx, `$r=Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object {$_.InterfaceAlias -ne 'StarRailTun'} | Sort-Object RouteMetric | Select-Object -First 1; if(!$r){throw 'route'}; $a=Get-NetIPAddress -InterfaceIndex $r.InterfaceIndex; @{name=$r.InterfaceAlias;index=[int]$r.InterfaceIndex;gateway=$r.NextHop;addresses=@($a.IPAddress)}|ConvertTo-Json -Compress`, nil)
	if e != nil {
		return Interface{}, e
	}
	var physical Interface
	e = json.Unmarshal(bytes.TrimPrefix(data, []byte{239, 187, 191}), &physical)
	return physical, e
}
func platformPrepare(ctx context.Context, j *Journal) error {
	_, e := powershell(ctx, `if(Get-NetAdapter -Name 'StarRailTun' -ErrorAction SilentlyContinue){throw 'conflict'}; if(!(Test-Path -LiteralPath $v.dll)){throw 'driver'}`, object{"dll": filepath.Join(helperRoot(), "wintun.dll")})
	return e
}
func subtractPrefix(root, except netip.Prefix) []netip.Prefix {
	if !root.Overlaps(except) {
		return []netip.Prefix{root}
	}
	if except.Bits() <= root.Bits() {
		return nil
	}
	bits := root.Bits() + 1
	left := netip.PrefixFrom(root.Addr(), bits)
	bytes := root.Addr().AsSlice()
	bytes[root.Bits()/8] |= byte(1 << uint(7-root.Bits()%8))
	rightAddr, _ := netip.AddrFromSlice(bytes)
	right := netip.PrefixFrom(rightAddr, bits)
	return append(subtractPrefix(left, except), subtractPrefix(right, except)...)
}
func blockedAddresses(j *Journal) []string {
	prefixes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
	for _, raw := range append(append([]string{}, append(lan, "ff02::/16")...), j.Bypass...) {
		p, e := netip.ParsePrefix(raw)
		if e != nil {
			a, e := netip.ParseAddr(raw)
			if e != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		var next []netip.Prefix
		for _, current := range prefixes {
			next = append(next, subtractPrefix(current, p)...)
		}
		prefixes = next
	}
	out := []string{}
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out
}
func platformProtect(ctx context.Context, j *Journal) error {
	_, e := powershell(ctx, `New-NetFirewallRule -Name ('StarRail.'+$v.id) -DisplayName 'StarRail connection transition' -Group ('StarRail.'+$v.id) -Direction Outbound -Action Block -Enabled True -Profile Any -InterfaceAlias $v.interface -RemoteAddress $v.blocked | Out-Null`, object{"id": j.ID, "interface": j.Interface.Name, "blocked": blockedAddresses(j)})
	return e
}
func platformApply(context.Context, *Journal) error { return nil } // Xray owns adapter routes, DNS and dynamic WFP filters on Windows.
func platformUnprotect(ctx context.Context, j *Journal) error {
	if !j.Protection {
		return nil
	}
	_, e := powershell(ctx, `Get-NetFirewallRule -Group ('StarRail.'+$v.id) -ErrorAction SilentlyContinue | Remove-NetFirewallRule`, object{"id": j.ID})
	return e
}
func platformRecover(ctx context.Context, j *Journal) error {
	_, e := powershell(ctx, `$a=Get-NetAdapter -Name 'StarRailTun' -ErrorAction SilentlyContinue; if($a -and $a.InterfaceDescription -like '*StarRail*'){Get-NetRoute -InterfaceIndex $a.ifIndex -ErrorAction SilentlyContinue | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0')} | Remove-NetRoute -Confirm:$false; Set-DnsClientServerAddress -InterfaceIndex $a.ifIndex -ResetServerAddresses}; Get-NetFirewallRule -Group ('StarRail.'+$v.id) -ErrorAction SilentlyContinue | Remove-NetFirewallRule`, object{"id": j.ID})
	if e == nil {
		j.Protection = false
	}
	return e
}
func fileOwner(path string, p Peer) error {
	stat, e := os.Lstat(path)
	if e != nil || !stat.Mode().IsRegular() {
		return failure("UPDATE_VERIFY_FAILED")
	}
	sd, e := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if e != nil {
		return e
	}
	owner, _, e := sd.Owner()
	if e != nil || owner.String() != p.User {
		return failure("UPDATE_VERIFY_FAILED")
	}
	return nil
}

type serviceHandler struct{}

func (serviceHandler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	status <- svc.Status{State: svc.StartPending}
	go func() { result <- serve(ctx) }()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case e := <-result:
			if e != nil {
				return false, 1
			}
			return false, 0
		case r := <-requests:
			switch r.Cmd {
			case svc.Interrogate:
				status <- r.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				if e := <-result; e != nil {
					return false, 1
				}
				return false, 0
			}
		}
	}
}
func runService() error { return svc.Run("StarRailNetwork", serviceHandler{}) }
func platformStopService(ctx context.Context) error {
	manager, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer manager.Disconnect()
	service, e := manager.OpenService("StarRailNetwork")
	if e != nil {
		return nil
	}
	defer service.Close()
	_, _ = service.Control(svc.Stop)
	for {
		state, e := service.Query()
		if e != nil || state.State == svc.Stopped {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func stopInstalledService() error {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	return platformStopService(ctx)
}
func platformInstall(value Installation) error {
	manager, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer manager.Disconnect()
	service, e := manager.OpenService("StarRailNetwork")
	if e != nil {
		service, e = manager.CreateService("StarRailNetwork", value.HelperPath, mgr.Config{DisplayName: "StarRail Network Service", StartType: mgr.StartAutomatic, ServiceStartName: "LocalSystem"}, "serve")
	}
	if e != nil {
		return e
	}
	defer service.Close()
	_ = service.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: time.Second}, {Type: mgr.ServiceRestart, Delay: time.Second}}, 86400)
	return service.Start()
}
func platformUninstall() error {
	_ = stopInstalledService()
	manager, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer manager.Disconnect()
	s, e := manager.OpenService("StarRailNetwork")
	if e != nil {
		return nil
	}
	defer s.Close()
	return s.Delete()
}
func startDetached(path string, args ...string) error {
	command := exec.Command(path, args...)
	command.Env = safeEnvironment()
	command.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS}
	if e := command.Start(); e != nil {
		return e
	}
	return command.Process.Release()
}
func platformNetworkFingerprint(ctx context.Context, p Interface) (string, error) {
	data, e := powershell(ctx, `$r=@(Get-NetRoute | Where-Object {$_.DestinationPrefix -in @('0.0.0.0/0','::/0') -and $_.InterfaceAlias -ne 'StarRailTun'} | Sort-Object InterfaceIndex,DestinationPrefix,NextHop | Select-Object InterfaceIndex,DestinationPrefix,NextHop,RouteMetric);$d=@(Get-DnsClientServerAddress | Where-Object {$_.InterfaceAlias -ne 'StarRailTun'} | Sort-Object InterfaceIndex,AddressFamily | Select-Object InterfaceIndex,AddressFamily,ServerAddresses);@{routes=$r;dns=$d}|ConvertTo-Json -Depth 5 -Compress`, nil)
	if e != nil {
		return "", e
	}
	var value any
	if e = json.Unmarshal(data, &value); e != nil {
		return "", e
	}
	return stringHash(string(jsonBytes(value))), nil
}
