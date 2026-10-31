package core

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type DemoPanel struct{}

func NewDemoPanel() *DemoPanel { return &DemoPanel{} }
func (*DemoPanel) Login(ctx context.Context, endpoint, email, password string) (Session, error) {
	if ctx.Err() != nil {
		return Session{}, NewAppError("CANCELLED")
	}
	return Session{AccountID: "demo-account", Email: email, Token: "development-fixture-only", Generation: newUUID()}, nil
}
func (*DemoPanel) FetchAccount(ctx context.Context, endpoint string, session Session) (Account, error) {
	if ctx.Err() != nil {
		return Account{}, NewAppError("CANCELLED")
	}
	now := time.Now().UnixMilli()
	expiry, used, quota := isoTime(now+19*86400000), "31353261260", "214748364800"
	return Account{AccountID: session.AccountID, Email: session.Email, PlanName: "标准套餐（示例）", SessionStatus: "valid", ServiceAllowed: "yes", Banned: "no", HasPlan: "yes", TrafficExhausted: "no", ExpiryKind: "finite", ExpiresAt: &expiry, QuotaKind: "finite", UsedBytes: &used, QuotaBytes: &quota, ObservedAt: isoTime(now), SourceEndpointID: "fixture", AuthorizationEvidence: "explicit-development-fixture"}, nil
}
func (*DemoPanel) FetchSubscriptionDescriptor(context.Context, string, Session) (SubscriptionDescriptor, error) {
	return SubscriptionDescriptor{URL: "https://fixture.invalid/subscription", Format: "v2ray-uri-base64-v1"}, nil
}
func (*DemoPanel) FetchNodes(context.Context, SubscriptionDescriptor) (string, error) {
	names := []string{"日本 · 东京 01", "新加坡 · 狮城 01", "香港 · 港岛 01", "美国 · 洛杉矶 01"}
	lines := []string{}
	for i, name := range names {
		lines = append(lines, fmt.Sprintf("vless://00000000-0000-4000-8000-00000000000%d@node%d.example.invalid:443?security=tls&type=tcp&sni=node%d.example.invalid#%s", i, i, i, url.PathEscape(name)))
	}
	return strings.Join(lines, "\n"), nil
}
func (*DemoPanel) Logout(context.Context, string, Session) error { return nil }
