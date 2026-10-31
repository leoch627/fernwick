package core

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDirectHTTPSRejectsRedirectsOversizeAndCancellation(t *testing.T) {
	targetCalls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/target", http.StatusFound)
		case "/target":
			targetCalls++
			w.Write([]byte("secret"))
		case "/large":
			w.Write([]byte(strings.Repeat("x", 100)))
		default:
			w.Write([]byte("ok"))
		}
	}))
	defer server.Close()
	transport := NewDirectHTTPSTransport()
	transport.client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: server.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs}
	if _, err := transport.Request(context.Background(), HTTPRequest{URL: server.URL + "/redirect"}); CodeOf(err) != "CONTROL_UNAVAILABLE" || targetCalls != 0 {
		t.Fatal("redirect followed")
	}
	if _, err := transport.Request(context.Background(), HTTPRequest{URL: server.URL + "/large", MaxBytes: 10}); CodeOf(err) != "CONTROL_UNAVAILABLE" {
		t.Fatal("oversize accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := transport.Request(ctx, HTTPRequest{URL: server.URL}); CodeOf(err) != "CANCELLED" {
		t.Fatal(err)
	}
	if transport.client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("system proxy enabled")
	}
	response, err := transport.Request(context.Background(), HTTPRequest{URL: server.URL})
	if err != nil || response.Body != "ok" {
		t.Fatalf("request %+v %v", response, err)
	}
}
func TestHTTPAuthenticationScopesAndRetryAfter(t *testing.T) {
	for scope, want := range map[string]ErrorCode{"account": "AUTH_INVALID", "subscription": "SUBSCRIPTION_CREDENTIAL_INVALID", "login": "LOGIN_FAILED", "public": "CONTROL_UNAVAILABLE"} {
		if code := CodeOf(RequireSuccess(HTTPResponse{Status: 401}, scope)); code != want {
			t.Fatalf("%s %s", scope, code)
		}
	}
	if RetryAfter("120", 0) != 120000 || RetryAfter("0", 0) != 1000 || RetryAfter("", 0) != 30000 || RetryAfter("invalid", 0) != 30000 {
		t.Fatal("retry bounds")
	}
	now := time.Now().UTC().Truncate(time.Second)
	if RetryAfter(now.Add(time.Minute).Format(http.TimeFormat), now.UnixMilli()) != 60000 {
		t.Fatal("date retry")
	}
	if err := RequireSuccess(HTTPResponse{Status: 204}, "public"); err != nil {
		t.Fatal(err)
	}
}
