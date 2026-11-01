package core

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// SelfCheck gathers what support needs when a user cannot connect: whether the local
// resolver's answers differ from a mainland DoH resolver (poisoning), and whether TCP,
// TLS or HTTPS to each API and endpoint host is blocked, reset or slow; then whether
// node servers accept TCP at all. Results hold host names, addresses and timings only.
func SelfCheck(ctx context.Context, build BuildConfig, nodes []ProxyNode) []map[string]any {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	type job struct {
		name, kind, host, port string
		https                  bool
	}
	jobs := []job{{"www.baidu.com", "baseline", "www.baidu.com", "443", true}}
	seen := map[string]bool{"www.baidu.com": true}
	add := func(kind, raw string) {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" && !seen[u.Host] {
			seen[u.Host] = true
			port := u.Port()
			if port == "" {
				port = "443"
			}
			jobs = append(jobs, job{u.Hostname(), kind, u.Hostname(), port, true})
		}
	}
	for _, e := range build.APIEndpoints {
		add("api", e.BaseURL)
	}
	for _, raw := range build.UpdateFeedURLs {
		add("endpoint", raw)
	}
	count := 0
	for _, n := range nodes {
		if count == 20 {
			break
		}
		if n.Compatible && !seen[n.Host+":"+strconv.Itoa(n.Port)] {
			seen[n.Host+":"+strconv.Itoa(n.Port)] = true
			jobs = append(jobs, job{n.Name, "node", n.Host, strconv.Itoa(n.Port), false})
			count++
		}
	}
	results := make([]map[string]any, len(jobs))
	slots := make(chan struct{}, 8)
	var wait sync.WaitGroup
	for i, j := range jobs {
		wait.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			results[i] = checkHost(ctx, j.name, j.kind, j.host, j.port, j.https)
		})
	}
	wait.Wait()
	return results
}

func checkHost(ctx context.Context, name, kind, host, port string, https bool) map[string]any {
	result := map[string]any{"name": name, "kind": kind, "host": host, "port": port, "ok": false}
	started := time.Now()
	addresses := []string{host}
	if net.ParseIP(host) == nil {
		lookup, cancel := context.WithTimeout(ctx, 3*time.Second)
		ips, err := net.DefaultResolver.LookupHost(lookup, host)
		cancel()
		result["dnsMs"] = float64(time.Since(started).Milliseconds())
		if err != nil {
			result["dns"] = classifyNetError(err)
		} else {
			result["dns"] = strings.Join(ips[:min(4, len(ips))], " ")
			addresses = ips
		}
		if answer := dohLookup(ctx, host); answer != "" {
			result["doh"] = answer
		}
		if err != nil {
			return result
		}
	}
	dialStarted := time.Now()
	dial, cancel := context.WithTimeout(ctx, 4*time.Second)
	connection, err := (&net.Dialer{}).DialContext(dial, "tcp", net.JoinHostPort(addresses[0], port))
	cancel()
	result["tcpMs"] = float64(time.Since(dialStarted).Milliseconds())
	if err != nil {
		result["tcp"] = classifyNetError(err)
		return result
	}
	result["tcp"] = "ok"
	if !https {
		connection.Close()
		result["ok"] = true
		return result
	}
	tlsStarted := time.Now()
	_ = connection.SetDeadline(time.Now().Add(4 * time.Second))
	secure := tls.Client(connection, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}})
	err = secure.HandshakeContext(ctx)
	result["tlsMs"] = float64(time.Since(tlsStarted).Milliseconds())
	if err != nil {
		connection.Close()
		result["tls"] = classifyNetError(err)
		return result
	}
	result["tls"] = "ok"
	httpStarted := time.Now()
	request, _ := http.NewRequestWithContext(ctx, "GET", "https://"+net.JoinHostPort(host, port)+"/", nil)
	request.Header.Set("User-Agent", "V2BoardDesktop-selfcheck")
	if err = request.Write(secure); err == nil {
		var response *http.Response
		response, err = http.ReadResponse(bufio.NewReader(secure), request)
		if err == nil {
			result["status"] = float64(response.StatusCode)
			response.Body.Close()
		}
	}
	secure.Close()
	result["httpMs"] = float64(time.Since(httpStarted).Milliseconds())
	if err != nil {
		result["http"] = classifyNetError(err)
		return result
	}
	result["ok"] = true
	result["ms"] = float64(time.Since(started).Milliseconds())
	return result
}

// dohLookup asks AliDNS over HTTPS, which poisoning on port 53 does not affect.
func dohLookup(ctx context.Context, host string) string {
	lookup, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(lookup, "GET", "https://223.5.5.5/resolve?type=1&name="+url.QueryEscape(host), nil)
	if err != nil {
		return ""
	}
	client := &http.Client{Transport: &http.Transport{Proxy: nil, DisableKeepAlives: true}}
	response, err := client.Do(request)
	if err != nil {
		return "error: " + classifyNetError(err)
	}
	defer response.Body.Close()
	var answer struct {
		Answer []struct {
			Type int    `json:"type"`
			Data string `json:"data"`
		} `json:"Answer"`
	}
	if json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&answer) != nil {
		return ""
	}
	ips := []string{}
	for _, a := range answer.Answer {
		if a.Type == 1 && len(ips) < 4 {
			ips = append(ips, a.Data)
		}
	}
	return strings.Join(ips, " ")
}

// classifyNetError names the failure the way a support person reads it: a reset or
// refused connection on a reachable route usually means blocking, a timeout a dead
// route, a certificate error interception or a wrong server.
func classifyNetError(err error) string {
	var dns *net.DNSError
	var certificate *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	switch {
	case errors.As(err, &dns) && dns.IsNotFound:
		return "nxdomain"
	case errors.As(err, &dns) && dns.IsTimeout:
		return "dns-timeout"
	case errors.As(err, &dns):
		return "dns-error"
	case errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded):
		return "timeout"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH):
		return "unreachable"
	case errors.As(err, &certificate) || errors.As(err, &unknownAuthority) || errors.As(err, &hostname):
		return "certificate"
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		return "eof"
	}
	var timeout interface{ Timeout() bool }
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "timeout"
	}
	text := err.Error()
	for _, known := range []string{"reset", "refused", "unreachable"} {
		if strings.Contains(text, known) {
			return known
		}
	}
	return "error"
}
