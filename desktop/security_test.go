package main

import (
	"github.com/wailsapp/wails/v3/pkg/application"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestRuntimeSecurityRestrictsNativeSurface(t *testing.T) {
	for _, test := range []struct {
		body   string
		status int
	}{
		{`{"object":0,"method":0,"args":{"call-id":"abc","methodName":"main.Bridge.Command","args":[{"type":"state"}]}}`, 204},
		{`{"object":10,"method":0,"args":{"call-id":"abc"}}`, 204},
		{`{"object":8,"method":1}`, 204},
		{`{"object":9,"method":0,"args":{"url":"https://evil.invalid"}}`, 403},
		{`{"object":6,"method":0,"args":{}}`, 403},
		{`{"object":3,"method":0,"args":{"name":"starrail:state"}}`, 403},
		{`{"object":0,"method":0,"args":{"call-id":"abc","methodName":"main.Other.Run","args":[{}]}}`, 403},
		{`{"object":0,"method":0,"args":{"call-id":"abc","methodID":123,"args":[{}]}}`, 403},
		{`{"object":0,"object":9,"method":0}`, 400},
		{`{"object":0,"method":0,"args":{"call-id":"abc","methodName":"main.Bridge.Command","args":[]}}`, 403},
	} {
		t.Run(test.body, func(t *testing.T) {
			handler := runtimeSecurity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				if string(body) != test.body {
					t.Error("request body lost")
				}
				w.WriteHeader(204)
			}))
			request := httptest.NewRequest(http.MethodPost, "http://wails.localhost/wails/runtime", strings.NewReader(test.body))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("got %d, want %d: %s", response.Code, test.status, response.Body.String())
			}
		})
	}
}
func TestRuntimeSecurityRejectsForeignOriginAndChunkBypass(t *testing.T) {
	body := `{"object":8,"method":1}`
	for _, headers := range []http.Header{{"Origin": []string{"https://evil.invalid"}}, {"Origin": []string{"null"}}, {"X-Wails-Chunk-Id": []string{"x"}}} {
		request := httptest.NewRequest(http.MethodPost, "http://wails.localhost/wails/runtime", strings.NewReader(body))
		request.Header = headers
		response := httptest.NewRecorder()
		runtimeSecurity(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("unsafe call passed") })).ServeHTTP(response, request)
		if response.Code != 403 {
			t.Fatal(response.Code)
		}
	}
}
func TestRuntimeSecurityAllowsGTKQueryTransport(t *testing.T) {
	query := url.Values{"object": []string{"0"}, "method": []string{"0"}, "args": []string{`{"call-id":"abc","methodName":"main.Bridge.Command","args":[{"type":"state"}]}`}}
	request := httptest.NewRequest(http.MethodGet, "wails://wails.localhost/wails/runtime?"+query.Encode(), nil)
	request.Header.Set("Origin", "wails://wails.localhost")
	response := httptest.NewRecorder()
	runtimeSecurity(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })).ServeHTTP(response, request)
	if response.Code != 204 {
		t.Fatal(response.Code, response.Body.String())
	}
}
func TestRuntimeSecurityAssetAndWindowPolicy(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://wails.localhost/assets/main.js", nil)
	response := httptest.NewRecorder()
	runtimeSecurity(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })).ServeHTTP(response, request)
	if response.Code != 204 || response.Header().Get("Permissions-Policy") == "" {
		t.Fatal(response)
	}
	options := application.WebviewWindowOptions{}
	hardenWindow(&options)
	for _, permission := range options.Permissions {
		if permission != application.PermissionDeny {
			t.Fatal("permission not denied")
		}
	}
	if len(options.Windows.Permissions) != 7 || options.JS == "" || options.AllowSimpleEventEmit {
		t.Fatal("window not restricted")
	}
}
