package core

import (
	"context"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type HTTPRequest struct {
	URL      string
	Method   string
	Headers  map[string]string
	Body     string
	MaxBytes int
}
type HTTPResponse struct {
	Status  int
	Headers map[string]string
	Body    string
}
type Transport interface {
	Request(context.Context, HTTPRequest) (HTTPResponse, error)
}
type DirectHTTPSTransport struct {
	client  *http.Client
	timeout time.Duration
}

func NewDirectHTTPSTransport() *DirectHTTPSTransport {
	return NewDirectHTTPSTransportTimeout(6 * time.Second)
}

// NewDirectHTTPSTransportTimeout allows a longer total time per request, for uploads
// such as problem reports over slow links.
func NewDirectHTTPSTransportTimeout(timeout time.Duration) *DirectHTTPSTransport {
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 3 * time.Second}).DialContext, TLSHandshakeTimeout: 3 * time.Second, DisableKeepAlives: true, DisableCompression: true, ResponseHeaderTimeout: timeout}
	return &DirectHTTPSTransport{client: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, timeout: timeout}
}
func (t *DirectHTTPSTransport) Request(ctx context.Context, input HTTPRequest) (HTTPResponse, error) {
	if ctx.Err() != nil {
		return HTTPResponse{}, NewAppError("CANCELLED")
	}
	u, err := HTTPSURL(input.URL)
	if err != nil {
		return HTTPResponse{}, err
	}
	method := input.Method
	if method == "" {
		method = "GET"
	}
	if method != "GET" && method != "POST" {
		return HTTPResponse{}, NewAppError("INVALID_INPUT")
	}
	deadline, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(deadline, method, u.String(), strings.NewReader(input.Body))
	if err != nil {
		return HTTPResponse{}, NewAppError("INVALID_INPUT")
	}
	request.Header.Set("cache-control", "no-store")
	request.Header.Set("user-agent", "V2BoardDesktop/0.1")
	for k, v := range input.Headers {
		request.Header.Set(k, v)
	}
	response, err := t.client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return HTTPResponse{}, NewAppError("CANCELLED")
		}
		return HTTPResponse{}, NewAppError("CONTROL_UNAVAILABLE")
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return HTTPResponse{}, NewAppError("CONTROL_UNAVAILABLE")
	}
	limit := input.MaxBytes
	if limit == 0 {
		limit = 512 * 1024
	}
	if limit < 0 {
		return HTTPResponse{}, NewAppError("INVALID_INPUT")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if ctx.Err() != nil {
		return HTTPResponse{}, NewAppError("CANCELLED")
	}
	if err != nil || len(raw) > limit {
		return HTTPResponse{}, NewAppError("CONTROL_UNAVAILABLE")
	}
	headers := map[string]string{}
	for k, v := range response.Header {
		headers[strings.ToLower(k)] = strings.Join(v, ",")
	}
	return HTTPResponse{response.StatusCode, headers, strings.ToValidUTF8(string(raw), "�")}, nil
}
func RetryAfter(value string, now int64) int64 {
	if value == "" {
		return 30000
	}
	if strings.TrimSpace(value) == "" {
		return 1000
	}
	if number, err := strconv.ParseFloat(strings.TrimSpace(value), 64); err == nil {
		if math.IsNaN(number) || math.IsInf(number, 0) {
			return 30000
		}
		if number > float64(MaxSafeInteger)/1000 {
			return MaxSafeInteger
		}
		return max(1000, int64(number*1000))
	}
	if date, err := http.ParseTime(value); err == nil {
		delay := date.UnixMilli() - now
		if delay != 0 {
			return max(1000, delay)
		}
	}
	return 30000
}
func RequireSuccess(response HTTPResponse, authentication string) error {
	status := response.Status
	if status == 429 {
		return &AppError{Code: "RATE_LIMITED", RetryAfterMs: RetryAfter(response.Headers["retry-after"], time.Now().UnixMilli())}
	}
	if status == 401 || status == 403 {
		code := ErrorCode("CONTROL_UNAVAILABLE")
		switch authentication {
		case "account":
			code = "AUTH_INVALID"
		case "subscription":
			code = "SUBSCRIPTION_CREDENTIAL_INVALID"
		case "login":
			code = "LOGIN_FAILED"
		}
		return NewAppError(code)
	}
	if status < 200 || status >= 300 {
		if authentication == "login" && status < 500 {
			return NewAppError("LOGIN_FAILED")
		}
		return NewAppError("CONTROL_UNAVAILABLE")
	}
	return nil
}
