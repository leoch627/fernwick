package core

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"filippo.io/age"
	"filippo.io/age/armor"
)

func ageArmor(t *testing.T, recipient age.Recipient, clear string) string {
	t.Helper()
	var out bytes.Buffer
	armored := armor.NewWriter(&out)
	w, err := age.Encrypt(armored, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write([]byte(clear)); err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if err = armored.Close(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

func TestFetchNodesOpensAgeArmoredSubscription(t *testing.T) {
	f := newSignedFixture(t)
	f.build.TrustedSubscriptionOrigins = []string{"https://host.leiterup.de"}
	descriptor := SubscriptionDescriptor{URL: "https://host.leiterup.de/api/v1/client/subscribe?token=SUB_SECRET&flag=", Format: "v2ray-uri-base64-v1"}
	list := base64.StdEncoding.EncodeToString([]byte("trojan://secret@node.example.invalid:443?sni=node.example.invalid#A\n"))
	seen := []string{}
	respond := func(body func(recipient *age.X25519Recipient) string) Panel {
		return NewV2BoardAdapter(f.build, contractFixture(t), transportFunc(func(_ context.Context, input HTTPRequest) (HTTPResponse, error) {
			if _, ok := input.Headers["authorization"]; ok {
				t.Fatal("account token sent with the subscription request")
			}
			recipient, err := age.ParseX25519Recipient(input.Headers[subscriptionAgeHeader])
			if err != nil {
				t.Fatalf("recipient header %q: %v", input.Headers[subscriptionAgeHeader], err)
			}
			seen = append(seen, recipient.String())
			if input.MaxBytes != subscriptionArmoredLimit {
				t.Fatalf("response limit %d", input.MaxBytes)
			}
			return HTTPResponse{Status: 200, Body: body(recipient)}, nil
		}))
	}

	// Encrypted to the key the request named, CRLF line ends and stray blank lines included.
	panel := respond(func(r *age.X25519Recipient) string {
		return "\r\n" + strings.ReplaceAll(ageArmor(t, r, list), "\n", "\r\n") + "\r\n"
	})
	for range 2 {
		raw, err := panel.FetchNodes(context.Background(), descriptor)
		if err != nil || raw != list {
			t.Fatalf("armored subscription %q %v", raw, err)
		}
	}
	if len(seen) != 2 || seen[0] == seen[1] {
		t.Fatalf("each request needs its own key, got %v", seen)
	}

	// A panel that ignores the header still answers in the clear.
	raw, err := respond(func(*age.X25519Recipient) string { return list }).FetchNodes(context.Background(), descriptor)
	if err != nil || raw != list {
		t.Fatalf("clear subscription %q %v", raw, err)
	}

	other, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	refused := map[string]func(*age.X25519Recipient) string{
		"another key": func(*age.X25519Recipient) string { return ageArmor(t, other.Recipient(), list) },
		"truncated": func(r *age.X25519Recipient) string {
			armored := ageArmor(t, r, list)
			return armored[:len(armored)/2]
		},
		"not age": func(*age.X25519Recipient) string { return armor.Header + "\nAAAA\n" + armor.Footer + "\n" },
		"too long": func(r *age.X25519Recipient) string {
			return ageArmor(t, r, strings.Repeat("a", subscriptionPlainLimit+1))
		},
	}
	for name, body := range refused {
		if raw, err := respond(body).FetchNodes(context.Background(), descriptor); CodeOf(err) != "SUBSCRIPTION_INVALID" || raw != "" {
			t.Fatalf("%s: %q %v", name, raw, err)
		}
	}
	if _, err := respond(func(*age.X25519Recipient) string { return strings.Repeat("a", subscriptionPlainLimit+1) }).FetchNodes(context.Background(), descriptor); CodeOf(err) != "CONTROL_UNAVAILABLE" {
		t.Fatalf("oversized clear subscription: %v", err)
	}
}
