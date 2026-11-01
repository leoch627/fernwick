//go:build windows

package main

import (
	"context"
	"crypto/md5"
	"fmt"
	winio "github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
	"io"
	"net"
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
	return filepath.Join(v, serviceID())
}
func helperRoot() string {
	v, _ := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	return filepath.Join(v, serviceID()+"-service")
}
func socketPath() string        { return `\\.\pipe\` + serviceID() + `.helper.v1` }
func samePath(a, b string) bool { return strings.EqualFold(filepath.Clean(a), filepath.Clean(b)) }
func safeEnvironment() []string {
	return []string{"SystemRoot=" + filepath.Dir(windowsDirectory()), "WINDIR=" + filepath.Dir(windowsDirectory()), "PATH=" + windowsDirectory(), "TEMP=" + stateRoot(), "TMP=" + stateRoot(), "XRAY_LOCATION_ASSET=" + filepath.Dir(installed.CorePath)}
}
func configureChild(c *exec.Cmd) {
	c.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}
func configureWorkerChild(c *exec.Cmd) { configureChild(c) }
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
	name, _ := windows.UTF16PtrFromString(`Global\` + serviceID() + `.network-owner`)
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

// adapters lists the network adapters with their gateways, as the net package does.
func adapters() ([]*windows.IpAdapterAddresses, error) {
	size := uint32(16 * 1024)
	for range 4 {
		buffer := make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buffer[0]))
		e := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_GATEWAYS|windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST, 0, first, &size)
		if e == nil {
			var out []*windows.IpAdapterAddresses
			for a := first; a != nil; a = a.Next {
				out = append(out, a)
			}
			return out, nil
		}
		if e != windows.ERROR_BUFFER_OVERFLOW {
			return nil, e
		}
	}
	return nil, windows.ERROR_BUFFER_OVERFLOW
}

// discoverInterface finds the adapter of the IPv4 default route with the lowest metric,
// leaving out the TUN, through the IP Helper API: PowerShell's network cmdlets take
// seconds to load on a cold system, which a connection cannot wait for.
func discoverInterface(context.Context) (Interface, error) {
	list, e := adapters()
	if e != nil {
		return Interface{}, failure("CONNECT_TIMEOUT")
	}
	var best *windows.IpAdapterAddresses
	gateway := ""
	for _, a := range list {
		if a.OperStatus != windows.IfOperStatusUp || a.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK || windows.UTF16PtrToString(a.FriendlyName) == tunName() {
			continue
		}
		for g := a.FirstGatewayAddress; g != nil; g = g.Next {
			ip := g.Address.IP()
			if ip.To4() == nil || ip.IsUnspecified() {
				continue
			}
			if best == nil || a.Ipv4Metric < best.Ipv4Metric {
				best, gateway = a, ip.String()
			}
			break
		}
	}
	if best == nil {
		return Interface{}, failure("CONNECT_TIMEOUT")
	}
	out := Interface{Name: windows.UTF16PtrToString(best.FriendlyName), Index: int(best.IfIndex), Gateway: gateway}
	for u := best.FirstUnicastAddress; u != nil; u = u.Next {
		if ip := u.Address.IP(); ip != nil {
			out.Addresses = append(out.Addresses, ip.String())
		}
	}
	return out, nil
}

// removeTunAdapter removes this product's Wintun adapter when one is left behind, as
// v2rayN does before it starts a TUN: the core is ended, not asked to stop, and an
// adapter that outlives it would keep the routes and DNS the core gave it. Wintun
// names the device after the GUID Xray derives from the adapter name. Best effort:
// pnputil can remove devices from Windows 10 2004 on, and Xray reuses an adapter of
// its name anyway.
func removeTunAdapter(ctx context.Context, name string) {
	list, e := adapters()
	if e != nil {
		return
	}
	for _, a := range list {
		if windows.UTF16PtrToString(a.FriendlyName) != name || !strings.Contains(windows.UTF16PtrToString(a.Description), ruleTag()) {
			continue
		}
		_, _ = run(ctx, filepath.Join(windowsDirectory(), "pnputil.exe"), nil, "/remove-device", `SWD\Wintun\`+wintunGUID(name))
		return
	}
}
func wintunGUID(name string) string {
	sum := md5.Sum([]byte(name))
	return (*windows.GUID)(unsafe.Pointer(&sum[0])).String()
}
func platformPrepare(ctx context.Context, j *Journal) error {
	if _, e := os.Stat(filepath.Join(helperRoot(), "wintun.dll")); e != nil {
		return failure("COMPONENTS_UNAVAILABLE")
	}
	removeTunAdapter(ctx, j.Tun)
	return nil
}

// Xray owns the TUN's routes, DNS and leak filters (coreOwnsRoutes); nothing guards the
// transition, as with v2rayN.
func platformProtect(context.Context, *Journal) error { return nil }

// platformApply waits until the core's routes lead to the TUN, so the probe that follows
// tests the TUN and not the network around it.
func platformApply(ctx context.Context, j *Journal) error {
	for {
		if tun, e := net.InterfaceByName(j.Tun); e == nil {
			var index uint32
			if windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: [4]byte{1, 1, 1, 1}}, &index) == nil && int(index) == tun.Index {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			logEvent("start: the core's routes to %s did not appear in time", j.Tun)
			return errCancelled
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// Only a connection made by an earlier version guarded its transition, with a firewall
// rule that recovery still removes.
func platformUnprotect(ctx context.Context, j *Journal) error {
	if !j.Protection {
		return nil
	}
	_, e := powershell(ctx, `Get-NetFirewallRule -Group ($v.tag+'.'+$v.id) -ErrorAction SilentlyContinue | Remove-NetFirewallRule`, object{"id": j.ID, "tag": ruleTag()})
	return e
}

// The core has been ended before recovery runs; with its adapter its routes, DNS and
// filters are gone.
func platformRecover(ctx context.Context, j *Journal) error {
	removeTunAdapter(ctx, j.Tun)
	return nil
}

// Xray follows the default route itself (coreOwnsRoutes): a network change needs no
// reconnection.
func (s *service) monitorNetwork(context.Context) {}
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
func runService() error { return svc.Run(serviceID(), serviceHandler{}) }
func platformStopService(ctx context.Context) error {
	manager, e := mgr.Connect()
	if e != nil {
		return e
	}
	defer manager.Disconnect()
	service, e := manager.OpenService(serviceID())
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
	service, e := manager.OpenService(serviceID())
	if e != nil {
		service, e = manager.CreateService(serviceID(), value.HelperPath, mgr.Config{DisplayName: build.DisplayName + " Service", StartType: mgr.StartAutomatic, ServiceStartName: "LocalSystem"}, "serve")
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
	s, e := manager.OpenService(serviceID())
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
