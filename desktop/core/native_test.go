package core

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func testRPCDriver(t *testing.T, mutate func(*nativeReply), action func(map[string]any) nativeReply) *NativeDriver {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	key := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	driver := NewNativeDriver(BuildConfig{ProductID: "test-product", AppID: "test.product"}, NativeManifest{BuildID: strings.Repeat("a", 64)}, "", "", false, nil)
	driver.checkSocket = func(string) error { return nil }
	driver.readIdentity = func(string) ([]byte, error) { return key, nil }
	driver.dial = func(ctx context.Context, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer server.Close()
			reader := bufio.NewReader(server)
			raw, err := reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var hello map[string]any
			if json.Unmarshal(raw, &hello) != nil {
				return
			}
			proof := []byte("starrail-helper-v1\n" + hello["challenge"].(string) + "\n" + driver.build.ProductID + "\n" + driver.manifest.BuildID)
			reply := nativeReply{ID: hello["id"].(string), OK: true, Protocol: 1, ProductID: driver.build.ProductID, BuildID: driver.manifest.BuildID, Version: "0.1.0", State: "Disconnected", Ready: true, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(private, proof))}
			if mutate != nil {
				mutate(&reply)
			}
			data, _ := json.Marshal(reply)
			data = append(data, '\n')
			for len(data) > 0 {
				count := min(7, len(data))
				if _, err := server.Write(data[:count]); err != nil {
					return
				}
				data = data[count:]
			}
			raw, err = reader.ReadBytes('\n')
			if err != nil {
				return
			}
			var input map[string]any
			if json.Unmarshal(raw, &input) != nil {
				return
			}
			reply = action(input)
			reply.ID = input["id"].(string)
			reply.Protocol = 1
			reply.ProductID = driver.build.ProductID
			reply.BuildID = driver.manifest.BuildID
			reply.Version = "0.1.0"
			data, _ = json.Marshal(reply)
			_, _ = server.Write(append(data, '\n'))
		}()
		return client, nil
	}
	return driver
}
func TestNativeRPCAuthenticatesFragmentedHandshake(t *testing.T) {
	driver := testRPCDriver(t, nil, func(input map[string]any) nativeReply {
		if input["action"] != "status" {
			t.Error(input)
		}
		return nativeReply{OK: true, Ready: true, State: "Disconnected"}
	})
	reply, err := driver.rpc(context.Background(), "status", nil)
	if err != nil || !reply.Ready {
		t.Fatalf("%#v %v", reply, err)
	}
}
func TestNativeRPCRejectsForgedIdentityBeforeCommand(t *testing.T) {
	for name, mutate := range map[string]func(*nativeReply){"signature": func(r *nativeReply) { r.Signature = base64.RawURLEncoding.EncodeToString(make([]byte, 64)) }, "product": func(r *nativeReply) { r.ProductID = "evil" }, "build": func(r *nativeReply) { r.BuildID = "evil" }, "id": func(r *nativeReply) { r.ID = "evil" }, "protocol": func(r *nativeReply) { r.Protocol = 2 }} {
		t.Run(name, func(t *testing.T) {
			driver := testRPCDriver(t, mutate, func(map[string]any) nativeReply { t.Error("unauthenticated command sent"); return nativeReply{} })
			if _, err := driver.rpc(context.Background(), "prepare", nil); CodeOf(err) != "COMPONENTS_UNAVAILABLE" {
				t.Fatal(err)
			}
		})
	}
}
func TestNativeRPCMapsOnlyKnownErrors(t *testing.T) {
	for _, code := range []string{"NETWORK_CONFLICT", "SECRET_FATAL_DETAILS"} {
		driver := testRPCDriver(t, nil, func(map[string]any) nativeReply { return nativeReply{OK: false, Error: code} })
		_, err := driver.rpc(context.Background(), "stop", nil)
		want := ErrorCode(code)
		if code == "SECRET_FATAL_DETAILS" {
			want = "COMPONENTS_UNAVAILABLE"
		}
		if CodeOf(err) != want {
			t.Fatal(err)
		}
	}
}
func TestNativeRPCCancellationClosesPipe(t *testing.T) {
	driver := testRPCDriver(t, nil, func(map[string]any) nativeReply { return nativeReply{OK: true} })
	driver.dial = func(ctx context.Context, _ string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() { defer server.Close(); _, _ = io.Copy(io.Discard, server) }()
		return client, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := driver.rpc(ctx, "status", nil); CodeOf(err) != "CANCELLED" {
		t.Fatal(err)
	}
}
func TestNativePrepareSendsOnlyFrozenCandidateFields(t *testing.T) {
	driver := testRPCDriver(t, nil, func(input map[string]any) nativeReply {
		if input["action"] == "prepare" {
			candidate := input["candidate"].(map[string]any)
			node := candidate["node"].(map[string]any)
			if _, ok := node["id"]; ok {
				t.Error("node view metadata reached helper")
			}
			if node["credential"] != "secret" {
				t.Error(node)
			}
			// The subscription asked for 360; the helper gets the client's own choice.
			if node["fingerprint"] != ChromeTLSFingerprint {
				t.Errorf("fingerprint = %v", node["fingerprint"])
			}
			return nativeReply{OK: true, Ticket: "owner-ticket", State: "Prepared"}
		}
		return nativeReply{OK: true}
	})
	ticket, err := driver.Prepare(context.Background(), Candidate{Node: ProxyNode{ID: "private-id", Credential: "secret", Protocol: "trojan", Host: "node.invalid", Port: 443, Transport: "tcp", Security: "tls", Fingerprint: nodeString("360")}, Mode: "rule", Rules: EmptyRules(), AuthorizedUntil: time.Now().Add(time.Hour).UnixMilli()})
	if err != nil || ticket != "owner-ticket" {
		t.Fatal(ticket, err)
	}
	if err = driver.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestHeartbeatFailureClassification(t *testing.T) {
	cases := []struct {
		reply nativeReply
		err   error
		want  ErrorCode
	}{
		{err: NewAppError("COMPONENTS_UNAVAILABLE"), want: ""},
		{err: NewAppError("CANCELLED"), want: ""},
		{err: NewAppError("NETWORK_CONFLICT"), want: "ENDED"},
		{reply: nativeReply{OK: true, Owned: false, State: "Disconnected"}, want: "ENDED"},
		{reply: nativeReply{OK: true, Owned: true, State: "RecoveryRequired"}, want: "NETWORK_RECOVERY_REQUIRED"},
	}
	for _, c := range cases {
		if got := heartbeatFailure(c.reply, c.err); got != c.want {
			t.Errorf("heartbeatFailure(%+v, %v) = %q, want %q", c.reply, c.err, got, c.want)
		}
	}
}

// A connection the service has ended and cleaned up is reported as dropped, not as a
// network to repair, and leaves the service usable.
func TestHeartbeatReportsConnectionEndedByService(t *testing.T) {
	reported := make(chan ErrorCode, 1)
	driver := testRPCDriver(t, nil, func(input map[string]any) nativeReply {
		if input["action"] == "heartbeat" {
			return nativeReply{OK: false, Error: "NETWORK_CONFLICT"}
		}
		return nativeReply{OK: true, Ready: true, State: "Disconnected"}
	})
	driver.failed = func(code ErrorCode) { reported <- code }
	driver.verified, driver.ticket = true, "ticket"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go driver.heartbeat(ctx, "ticket")
	select {
	case code := <-reported:
		if code != "CONNECT_TIMEOUT" {
			t.Fatalf("reported %s", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ended connection not reported")
	}
	if !driver.Verified() {
		t.Error("an ended connection marked the service as needing repair")
	}
}

// The elevated install passes on the helper's own error code, so a failed install is no
// longer shown as a missing permission; a dismissed password prompt still is.
func TestInstallFailure(t *testing.T) {
	for stderr, want := range map[string]ErrorCode{
		"0:180: execution error: starrail-network-helper: NETWORK_CONFLICT (1)\n": "NETWORK_CONFLICT",
		"0:180: execution error: User canceled. (-128)\n":                         "PERMISSION_REQUIRED",
		"starrail-network-helper: PERMISSION_REQUIRED\n":                          "PERMISSION_REQUIRED",
		"starrail-network-helper: NETWORK_RECOVERY_REQUIRED\n":                    "COMPONENTS_UNAVAILABLE",
		"starrail-network-helper: NOT_A_CODE\n":                                   "COMPONENTS_UNAVAILABLE",
		"":                                                                        "PERMISSION_REQUIRED",
	} {
		if got := CodeOf(installFailure(context.Background(), "starrail-network", stderr)); got != want {
			t.Errorf("installFailure(%q) = %s, want %s", stderr, got, want)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := CodeOf(installFailure(ctx, "starrail-network", "starrail-network-helper: NETWORK_CONFLICT")); got != "CANCELLED" {
		t.Errorf("cancelled install = %s", got)
	}
}
