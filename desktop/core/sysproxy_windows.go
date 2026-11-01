package core

import (
	"context"
	"encoding/json"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows keeps the system proxy per user. WinINet's per-connection options update it
// for the current user, the same settings page Windows shows, without administrator
// rights; browsers and most apps pick the change up at once.
var (
	wininet             = windows.NewLazySystemDLL("wininet.dll")
	internetSetOption   = wininet.NewProc("InternetSetOptionW")
	internetQueryOption = wininet.NewProc("InternetQueryOptionW")
	globalFree          = windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalFree")
)

const (
	internetOptionRefresh         = 37
	internetOptionSettingsChanged = 39
	internetOptionPerConnection   = 75
	perConnFlags                  = 1
	perConnProxyServer            = 2
	perConnProxyBypass            = 3
	perConnAutoConfigURL          = 4
	proxyTypeDirect               = 1
	proxyTypeProxy                = 2
)

var windowsBypass = []string{"localhost", "127.*", "10.*", "172.16.*", "172.17.*", "172.18.*", "172.19.*", "172.20.*", "172.21.*", "172.22.*", "172.23.*", "172.24.*", "172.25.*", "172.26.*", "172.27.*", "172.28.*", "172.29.*", "172.30.*", "172.31.*", "192.168.*", "169.254.*", "<local>"}

// perConnOption is INTERNET_PER_CONN_OPTIONW: a DWORD option and an 8-byte union that
// holds a DWORD or a string pointer.
type perConnOption struct {
	Option uint32
	Value  uint64
}

// perConnOptionList is INTERNET_PER_CONN_OPTION_LISTW; a nil connection is the LAN setting.
type perConnOptionList struct {
	Size        uint32
	Connection  *uint16
	OptionCount uint32
	OptionError uint32
	Options     *perConnOption
}

func (o *perConnOption) text() **uint16 { return (**uint16)(unsafe.Pointer(&o.Value)) }

type windowsProxyState struct {
	Flags         uint32 `json:"flags"`
	Server        string `json:"server"`
	Bypass        string `json:"bypass"`
	AutoConfigURL string `json:"autoConfigUrl"`
}
type windowsSystemProxy struct{}

func NewSystemProxy() SystemProxy { return windowsSystemProxy{} }

func (windowsSystemProxy) Snapshot(context.Context) (json.RawMessage, error) {
	options := []perConnOption{{Option: perConnFlags}, {Option: perConnProxyServer}, {Option: perConnProxyBypass}, {Option: perConnAutoConfigURL}}
	list := perConnOptionList{Size: uint32(unsafe.Sizeof(perConnOptionList{})), OptionCount: uint32(len(options)), Options: &options[0]}
	size := list.Size
	ok, _, _ := internetQueryOption.Call(0, internetOptionPerConnection, uintptr(unsafe.Pointer(&list)), uintptr(unsafe.Pointer(&size)))
	runtime.KeepAlive(options)
	if ok == 0 {
		return nil, NewAppError("SYSTEM_PROXY_FAILED")
	}
	// WinINet allocates the returned strings; each is copied and then released.
	text := func(o *perConnOption) string {
		pointer := *o.text()
		if pointer == nil {
			return ""
		}
		value := windows.UTF16PtrToString(pointer)
		_, _, _ = globalFree.Call(uintptr(unsafe.Pointer(pointer)))
		return value
	}
	state := windowsProxyState{Flags: uint32(options[0].Value), Server: text(&options[1]), Bypass: text(&options[2]), AutoConfigURL: text(&options[3])}
	return json.Marshal(state)
}
func (windowsSystemProxy) Apply(_ context.Context, saved json.RawMessage, port int) error {
	var state windowsProxyState
	if err := json.Unmarshal(saved, &state); err != nil {
		return NewAppError("STORAGE_FAILED")
	}
	// Automatic detection and the PAC script are switched off while connected; the
	// PAC address is kept so that restoring brings it back unchanged.
	return setWindowsProxy(proxyTypeDirect|proxyTypeProxy, "127.0.0.1:"+strconv.Itoa(port), strings.Join(windowsBypass, ";"), state.AutoConfigURL)
}
func (windowsSystemProxy) Restore(_ context.Context, saved json.RawMessage) error {
	var state windowsProxyState
	if err := json.Unmarshal(saved, &state); err != nil {
		return NewAppError("STORAGE_FAILED")
	}
	if state.Flags == 0 {
		state.Flags = proxyTypeDirect
	}
	return setWindowsProxy(state.Flags, state.Server, state.Bypass, state.AutoConfigURL)
}
func setWindowsProxy(flags uint32, server, bypass, autoConfig string) error {
	values := make([]*uint16, 3)
	for i, value := range []string{server, bypass, autoConfig} {
		pointer, err := windows.UTF16PtrFromString(value)
		if err != nil {
			return NewAppError("SYSTEM_PROXY_FAILED")
		}
		values[i] = pointer
	}
	options := []perConnOption{{Option: perConnFlags, Value: uint64(flags)}, {Option: perConnProxyServer}, {Option: perConnProxyBypass}, {Option: perConnAutoConfigURL}}
	for i := range values {
		*options[i+1].text() = values[i]
	}
	list := perConnOptionList{Size: uint32(unsafe.Sizeof(perConnOptionList{})), OptionCount: uint32(len(options)), Options: &options[0]}
	ok, _, _ := internetSetOption.Call(0, internetOptionPerConnection, uintptr(unsafe.Pointer(&list)), uintptr(list.Size))
	runtime.KeepAlive(values)
	runtime.KeepAlive(options)
	if ok == 0 {
		return NewAppError("SYSTEM_PROXY_FAILED")
	}
	// Tell running programs that the settings changed so they reload them.
	_, _, _ = internetSetOption.Call(0, internetOptionSettingsChanged, 0, 0)
	_, _, _ = internetSetOption.Call(0, internetOptionRefresh, 0, 0)
	return nil
}
