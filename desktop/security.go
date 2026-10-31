package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/wailsapp/wails/v3/pkg/application"
	"work.starrail/client/desktop/core"
)

// Wails exposes native Browser, Window, Dialog and Clipboard runtime subsystems
// independently of registered services. The client only needs Bridge.Command,
// call cancellation, and harmless runtime system queries. Event subscriptions
// are entirely frontend-local and receive Go pushes without an Events RPC.
func runtimeSecurity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), clipboard-read=(), payment=(), usb=(), serial=(), bluetooth=(), accelerometer=(), gyroscope=(), magnetometer=()")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		if strings.HasPrefix(r.URL.Path, "/wails/stream/") {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/wails/runtime" {
			next.ServeHTTP(w, r)
			return
		}
		if !allowedRuntimeOrigin(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		for key := range r.Header {
			if strings.HasPrefix(strings.ToLower(key), "x-wails-chunk-") {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}
		raw, err := io.ReadAll(io.LimitReader(r.Body, 32*1024+1))
		if err != nil || len(raw) > 32*1024 {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		_ = r.Body.Close()
		var object, method int
		var args any
		if len(raw) > 0 {
			value, err := core.StrictJSON(raw, 32*1024)
			if err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}
			message, ok := value.(map[string]any)
			if !ok || len(message) < 2 || len(message) > 3 {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}
			for key := range message {
				if key != "object" && key != "method" && key != "args" {
					http.Error(w, "Invalid request", http.StatusBadRequest)
					return
				}
			}
			var valid bool
			object, valid = runtimeNumber(message["object"])
			if !valid {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}
			method, valid = runtimeNumber(message["method"])
			if !valid {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}
			args = message["args"]
		} else {
			query := r.URL.Query()
			for key, values := range query {
				if (key != "object" && key != "method" && key != "args") || len(values) != 1 {
					http.Error(w, "Invalid request", http.StatusBadRequest)
					return
				}
			}
			object, err = strconv.Atoi(query.Get("object"))
			if err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}
			method, err = strconv.Atoi(query.Get("method"))
			if err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}
			if query.Get("args") != "" {
				args, err = core.StrictJSON([]byte(query.Get("args")), 32*1024)
				if err != nil {
					http.Error(w, "Invalid request", http.StatusBadRequest)
					return
				}
			}
		}
		if !allowedRuntimeCall(object, method, args) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(raw))
		next.ServeHTTP(w, r)
	})
}
func runtimeNumber(value any) (int, bool) {
	n, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	i, err := n.Int64()
	return int(i), err == nil && i >= 0 && i <= 100
}
func allowedRuntimeCall(object, method int, args any) bool {
	if object == 8 {
		return method >= 0 && method <= 3 && (args == nil || lenMap(args) == 0)
	}
	values, ok := args.(map[string]any)
	if !ok {
		return false
	}
	callID, ok := values["call-id"].(string)
	if !ok || len(callID) < 1 || len(callID) > 256 {
		return false
	}
	if object == 10 {
		return method == 0 && len(values) == 1
	}
	if object != 0 || method != 0 || len(values) != 3 || values["methodName"] != "main.Bridge.Command" {
		return false
	}
	arguments, ok := values["args"].([]any)
	return ok && len(arguments) == 1
}
func lenMap(value any) int {
	if m, ok := value.(map[string]any); ok {
		return len(m)
	}
	return -1
}
func allowedRuntimeOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" {
		return false
	}
	if parsed.Scheme != "wails" && parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func hardenWindow(options *application.WebviewWindowOptions) {
	options.AllowSimpleEventEmit = false
	options.EnableFileDrop = false
	options.DefaultContextMenuDisabled = true
	options.Permissions = map[application.PermissionType]application.Permission{application.PermissionMicrophone: application.PermissionDeny, application.PermissionCamera: application.PermissionDeny, application.PermissionGeolocation: application.PermissionDeny, application.PermissionNotifications: application.PermissionDeny, application.PermissionClipboardRead: application.PermissionDeny}
	options.Windows.Permissions = map[application.CoreWebView2PermissionKind]application.CoreWebView2PermissionState{}
	for kind := application.CoreWebView2PermissionKindUnknownPermission; kind <= application.CoreWebView2PermissionKindClipboardRead; kind++ {
		options.Windows.Permissions[kind] = application.CoreWebView2PermissionStateDeny
	}
	options.JS = windowNavigationGuard
}

// All intentional browser navigation goes through a validated Go command. This
// guards authored DOM navigation and new windows; CSP separately blocks forms,
// frames, external scripts and assets. It does not claim to be a WebKit-native
// navigation policy, which Wails v3 does not currently expose as a public hook.
const windowNavigationGuard = `(()=>{
  Object.defineProperty(window,'open',{value:()=>null,writable:false,configurable:false});
  const stopLink=e=>{const target=e.target instanceof Element?e.target.closest('a,area'):null;if(target&&target.hasAttribute('href')){e.preventDefault();e.stopImmediatePropagation();}};
  document.addEventListener('click',stopLink,true);
  document.addEventListener('auxclick',stopLink,true);
  // preventDefault alone blocks the navigation; stopping propagation here would
  // also hide the event from React's root listener and break the login form.
  document.addEventListener('submit',e=>e.preventDefault(),true);
  document.addEventListener('dragover',e=>e.preventDefault(),true);
  document.addEventListener('drop',e=>e.preventDefault(),true);
  if(window.navigation)window.navigation.addEventListener('navigate',e=>{if(e.cancelable&&!e.hashChange)e.preventDefault();});
})();`
