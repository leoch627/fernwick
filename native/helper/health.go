package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

func dnsQuestion(name string, kind uint16) []byte {
	b := make([]byte, 12)
	_, _ = rand.Read(b[:2])
	b[2] = 1
	b[5] = 1
	for _, label := range strings.Split(name, ".") {
		b = append(b, byte(len(label)))
		b = append(b, []byte(label)...)
	}
	return append(b, 0, byte(kind>>8), byte(kind), 0, 1)
}
func dnsAnswers(message, question []byte) ([]string, error) {
	if len(message) < 12 || len(question) < 12 || !bytes.Equal(message[:2], question[:2]) || message[2]&0x80 == 0 || message[3]&15 != 0 {
		return nil, failure("CONNECT_TIMEOUT")
	}
	skip := func(offset int) (int, error) {
		for i := 0; i < 128; i++ {
			if offset >= len(message) {
				break
			}
			n := int(message[offset])
			offset++
			if n == 0 {
				return offset, nil
			}
			if n&0xc0 == 0xc0 {
				if offset < len(message) {
					return offset + 1, nil
				}
				break
			}
			if n > 63 || offset+n > len(message) {
				break
			}
			offset += n
		}
		return 0, failure("CONNECT_TIMEOUT")
	}
	offset := 12
	for i := 0; i < int(binary.BigEndian.Uint16(message[4:6])); i++ {
		var e error
		offset, e = skip(offset)
		if e != nil || offset+4 > len(message) {
			return nil, failure("CONNECT_TIMEOUT")
		}
		offset += 4
	}
	answers := []string{}
	count := int(binary.BigEndian.Uint16(message[6:8]))
	if count > 256 {
		return nil, failure("CONNECT_TIMEOUT")
	}
	for i := 0; i < count; i++ {
		var e error
		offset, e = skip(offset)
		if e != nil || offset+10 > len(message) {
			return nil, failure("CONNECT_TIMEOUT")
		}
		kind := binary.BigEndian.Uint16(message[offset:])
		size := int(binary.BigEndian.Uint16(message[offset+8:]))
		offset += 10
		if offset+size > len(message) {
			return nil, failure("CONNECT_TIMEOUT")
		}
		if kind == 1 && size == 4 || kind == 28 && size == 16 {
			answers = append(answers, net.IP(message[offset:offset+size]).String())
		}
		offset += size
	}
	if len(answers) == 0 {
		return nil, failure("CONNECT_TIMEOUT")
	}
	return answers, nil
}
func physicalTransport(physical Interface) *http.Transport {
	dialer := &net.Dialer{Timeout: 2 * time.Second, Control: func(network, address string, c syscall.RawConn) error {
		return bindPhysical(network, address, c, physical)
	}}
	return &http.Transport{Proxy: nil, DialContext: dialer.DialContext, TLSHandshakeTimeout: 2 * time.Second, DisableKeepAlives: true, ForceAttemptHTTP2: true}
}
func controlRequest(ctx context.Context, input *ControlRequest, physical Interface) (*ControlResponse, error) {
	if input == nil || !contains(build.ControlOrigins, safeOrigin(input.URL)) || len(input.URL) > 16384 || len(input.Body) > 65536 || len(input.Headers) > 12 {
		return nil, failure("INVALID_INPUT")
	}
	if input.Method == "" {
		input.Method = "GET"
	}
	if input.Method != "GET" && input.Method != "POST" {
		return nil, failure("INVALID_INPUT")
	}
	if input.MaxBytes <= 0 {
		input.MaxBytes = 524288
	}
	if input.MaxBytes > 33554432 {
		return nil, failure("INVALID_INPUT")
	}
	u, e := url.Parse(input.URL)
	if e != nil {
		return nil, failure("INVALID_INPUT")
	}
	address, e := resolvePhysical(ctx, u.Hostname(), physical)
	if e != nil {
		return nil, failure("CONTROL_UNAVAILABLE")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	transport := physicalTransport(physical)
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return dial(ctx, network, net.JoinHostPort(address, port))
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 6 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, e := http.NewRequestWithContext(ctx, input.Method, input.URL, strings.NewReader(input.Body))
	if e != nil {
		return nil, failure("INVALID_INPUT")
	}
	for name, value := range input.Headers {
		if !contains([]string{"authorization", "content-type", "accept", "cache-control", "if-none-match", "if-modified-since"}, strings.ToLower(name)) || len(value) > 8192 || strings.ContainsAny(value, "\r\n") {
			return nil, failure("INVALID_INPUT")
		}
		request.Header.Set(name, value)
	}
	request.Header.Set("User-Agent", "v2board-client/"+build.Version)
	request.Header.Set("Accept-Encoding", "identity")
	response, e := client.Do(request)
	if e != nil {
		return nil, failure("CONTROL_UNAVAILABLE")
	}
	defer response.Body.Close()
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return nil, failure("CONTROL_UNAVAILABLE")
	}
	data, e := io.ReadAll(io.LimitReader(response.Body, input.MaxBytes+1))
	if e != nil || int64(len(data)) > input.MaxBytes {
		return nil, failure("CONTROL_UNAVAILABLE")
	}
	headers := map[string]string{}
	for _, name := range []string{"content-type", "etag", "retry-after", "last-modified"} {
		if value := response.Header.Get(name); value != "" {
			headers[name] = value
		}
	}
	return &ControlResponse{Status: response.StatusCode, Headers: headers, Body: string(data)}, nil
}
func resolvePhysical(ctx context.Context, host string, physical Interface) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	if !domain(host) {
		return "", failure("INVALID_INPUT")
	}
	transport := physicalTransport(physical)
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, kind := range []uint16{1, 28} {
		query := dnsQuestion(host, kind)
		request, e := http.NewRequestWithContext(ctx, "POST", "https://223.5.5.5/dns-query", bytes.NewReader(query))
		if e != nil {
			return "", e
		}
		request.Header.Set("Content-Type", "application/dns-message")
		request.Header.Set("Accept", "application/dns-message")
		response, e := client.Do(request)
		if e != nil {
			continue
		}
		data, e := io.ReadAll(io.LimitReader(response.Body, 65537))
		response.Body.Close()
		if e == nil && response.StatusCode == 200 && len(data) <= 65536 {
			if values, e := dnsAnswers(data, query); e == nil {
				return values[0], nil
			}
		}
	}
	return "", failure("CONNECT_TIMEOUT")
}
func boundedHTTP(ctx context.Context, target HealthTarget) bool {
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext, TLSHandshakeTimeout: 2 * time.Second, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 2500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, e := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	if e != nil {
		return false
	}
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("Cache-Control", "no-store")
	request.Header.Set("User-Agent", "v2board-client-health/"+build.Version)
	response, e := client.Do(request)
	if e != nil {
		return false
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	sum := sha256.Sum256(data)
	return e == nil && len(data) <= 65536 && response.StatusCode == target.Status && hex.EncodeToString(sum[:]) == target.BodySHA256
}
func udpDNS(ctx context.Context) bool {
	connection, e := (&net.Dialer{}).DialContext(ctx, "udp", net.JoinHostPort(tunDNS(), "53"))
	if e != nil {
		return false
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	_ = connection.SetDeadline(deadline)
	query := dnsQuestion("example.com", 1)
	if _, e = connection.Write(query); e != nil {
		return false
	}
	data := make([]byte, 4096)
	n, e := connection.Read(data)
	if e != nil {
		return false
	}
	_, e = dnsAnswers(data[:n], query)
	return e == nil
}
func stunUDP(ctx context.Context) bool {
	connection, e := (&net.Dialer{}).DialContext(ctx, "udp4", "162.159.207.0:3478")
	if e != nil {
		return false
	}
	defer connection.Close()
	deadline, _ := ctx.Deadline()
	_ = connection.SetDeadline(deadline)
	query := make([]byte, 20)
	query[1] = 1
	binary.BigEndian.PutUint32(query[4:8], 0x2112a442)
	_, _ = rand.Read(query[8:])
	if _, e = connection.Write(query); e != nil {
		return false
	}
	response := make([]byte, 4096)
	n, e := connection.Read(response)
	return e == nil && n >= 20 && binary.BigEndian.Uint16(response[:2]) == 0x0101 && binary.BigEndian.Uint32(response[4:8]) == 0x2112a442 && bytes.Equal(response[8:20], query[8:20]) && int(binary.BigEndian.Uint16(response[2:4])) == n-20
}
func ipv6HTTPS(ctx context.Context) bool {
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 2500 * time.Millisecond}).DialContext(ctx, "tcp6", "[2606:4700:4700::1111]:443")
	}, TLSHandshakeTimeout: 2500 * time.Millisecond, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3500 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	query := dnsQuestion("example.com", 28)
	request, e := http.NewRequestWithContext(ctx, "POST", "https://cloudflare-dns.com/dns-query", bytes.NewReader(query))
	if e != nil {
		return false
	}
	request.Header.Set("Content-Type", "application/dns-message")
	response, e := client.Do(request)
	if e != nil {
		return false
	}
	defer response.Body.Close()
	data, e := io.ReadAll(io.LimitReader(response.Body, 65537))
	if e != nil || len(data) > 65536 || response.StatusCode != 200 {
		return false
	}
	_, e = dnsAnswers(data, query)
	return e == nil
}
func probeDataPath(parent context.Context, j *Journal) (Proof, error) {
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	var result Proof
	var wait sync.WaitGroup
	wait.Add(4)
	go func() {
		defer wait.Done()
		for _, target := range build.HealthTargets {
			if boundedHTTP(ctx, target) {
				result.TCP = true
				break
			}
		}
	}()
	go func() { defer wait.Done(); result.DNS = udpDNS(ctx) }()
	go func() { defer wait.Done(); result.UDP = stunUDP(ctx) }()
	go func() { defer wait.Done(); result.IPv6 = ipv6HTTPS(ctx) }()
	wait.Wait()
	if !result.TCP || !result.DNS || !result.UDP || !result.IPv6 {
		return result, failure("CONNECT_TIMEOUT")
	}
	return result, nil
}
