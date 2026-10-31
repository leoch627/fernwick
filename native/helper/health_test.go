package main

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"
)

func TestControlRequestWhitelist(t *testing.T) {
	// An IP origin keeps resolution offline; port 1 is never listening.
	withBuild(t, Build{ControlOrigins: []string{"https://127.0.0.1:1"}})
	allowed := "https://127.0.0.1:1/api/v1/user/info"
	headers := func(n int) map[string]string {
		out := map[string]string{}
		for i := 0; i < n; i++ {
			out["Accept"+strings.Repeat("x", i)] = "a"
		}
		return out
	}
	cases := []struct {
		name  string
		input *ControlRequest
		want  string
	}{
		{"nil", nil, "INVALID_INPUT"},
		{"other origin", &ControlRequest{URL: "https://127.0.0.2:1/"}, "INVALID_INPUT"},
		{"plain http", &ControlRequest{URL: "http://127.0.0.1:1/"}, "INVALID_INPUT"},
		{"userinfo", &ControlRequest{URL: "https://user@127.0.0.1:1/"}, "INVALID_INPUT"},
		{"default port differs", &ControlRequest{URL: "https://127.0.0.1/"}, "INVALID_INPUT"},
		{"oversized url", &ControlRequest{URL: allowed + "?" + strings.Repeat("a", 16384)}, "INVALID_INPUT"},
		{"oversized body", &ControlRequest{URL: allowed, Method: "POST", Body: strings.Repeat("a", 65537)}, "INVALID_INPUT"},
		{"too many headers", &ControlRequest{URL: allowed, Headers: headers(13)}, "INVALID_INPUT"},
		{"method", &ControlRequest{URL: allowed, Method: "DELETE"}, "INVALID_INPUT"},
		{"response limit", &ControlRequest{URL: allowed, MaxBytes: 33554433}, "INVALID_INPUT"},
		{"forbidden header", &ControlRequest{URL: allowed, Headers: map[string]string{"Host": "evil.example"}}, "INVALID_INPUT"},
		{"cookie header", &ControlRequest{URL: allowed, Headers: map[string]string{"Cookie": "a=b"}}, "INVALID_INPUT"},
		{"header injection", &ControlRequest{URL: allowed, Headers: map[string]string{"Authorization": "a\r\nHost: evil.example"}}, "INVALID_INPUT"},
		{"oversized header", &ControlRequest{URL: allowed, Headers: map[string]string{"Authorization": strings.Repeat("a", 8193)}}, "INVALID_INPUT"},
		// Passing every check reaches the network, which is unavailable here.
		{"allowed request", &ControlRequest{URL: allowed, Method: "POST", Headers: map[string]string{"Authorization": "token", "Content-Type": "application/json"}, Body: "{}"}, "CONTROL_UNAVAILABLE"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			response, e := controlRequest(context.Background(), tc.input, Interface{Name: "lo"})
			if got := errorCode(e); got != tc.want || response != nil {
				t.Fatalf("controlRequest = %v, %q; want %q", response, got, tc.want)
			}
		})
	}
}

// dnsResponse answers question with the given records, pointing each name at the question.
func dnsResponse(question []byte, records ...[]byte) []byte {
	message := append([]byte{}, question...)
	message[2] |= 0x80
	binary.BigEndian.PutUint16(message[6:8], uint16(len(records)))
	for _, r := range records {
		message = append(message, 0xc0, 0x0c)
		message = append(message, r...)
	}
	return message
}
func dnsRecord(kind uint16, data []byte) []byte {
	r := make([]byte, 10)
	binary.BigEndian.PutUint16(r[0:2], kind)
	binary.BigEndian.PutUint16(r[2:4], 1)
	binary.BigEndian.PutUint32(r[4:8], 60)
	binary.BigEndian.PutUint16(r[8:10], uint16(len(data)))
	return append(r, data...)
}

func TestDNSAnswers(t *testing.T) {
	question := dnsQuestion("api.starrail.work", 1)
	cname := dnsRecord(5, []byte{3, 'c', 'd', 'n', 0xc0, 0x0c})
	a := dnsRecord(1, []byte{203, 0, 113, 7})
	aaaa := dnsRecord(28, []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	got, e := dnsAnswers(dnsResponse(question, cname, a, aaaa), question)
	if e != nil || len(got) != 2 || got[0] != "203.0.113.7" || got[1] != "2001:db8::1" {
		t.Fatalf("dnsAnswers = %v, %v", got, e)
	}

	valid := dnsResponse(question, a)
	mismatched := append([]byte{}, valid...)
	mismatched[0] ^= 0xff
	notResponse := append([]byte{}, valid...)
	notResponse[2] &^= 0x80
	nxdomain := append([]byte{}, valid...)
	nxdomain[3] |= 3
	tooMany := append([]byte{}, valid...)
	binary.BigEndian.PutUint16(tooMany[6:8], 257)
	loop := dnsResponse(question, dnsRecord(1, []byte{1, 2, 3, 4}))
	loop = append(loop[:len(question)], 63)
	invalid := map[string][]byte{
		"short":           valid[:11],
		"transaction id":  mismatched,
		"not a response":  notResponse,
		"error rcode":     nxdomain,
		"truncated":       valid[:len(valid)-2],
		"no addresses":    dnsResponse(question, cname),
		"answer overflow": tooMany,
		"bad label":       loop,
		"wrong size A":    dnsResponse(question, dnsRecord(1, []byte{1, 2, 3})),
	}
	for name, message := range invalid {
		if got, e := dnsAnswers(message, question); e == nil {
			t.Errorf("%s: accepted %v", name, got)
		}
	}
}

func FuzzDNSAnswers(f *testing.F) {
	question := dnsQuestion("api.starrail.work", 1)
	f.Add(dnsResponse(question, dnsRecord(1, []byte{1, 2, 3, 4})))
	f.Add(dnsResponse(question, dnsRecord(5, []byte{0xc0, 0x0c}), dnsRecord(28, make([]byte, 16))))
	f.Fuzz(func(t *testing.T, message []byte) {
		answers, e := dnsAnswers(message, question)
		if e == nil && len(answers) == 0 {
			t.Fatal("success without answers")
		}
	})
}
