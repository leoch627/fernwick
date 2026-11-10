package core

import (
	"context"
	"fmt"
	"math"
	"net/url"
	"strings"
	"sync"
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

// The development fixture also signs people up and resets passwords; the code is 123456.
func (*DemoPanel) SignupConfig(ctx context.Context, endpoint string) (SignupConfig, error) {
	return SignupConfig{EmailCode: true, InviteRequired: true, EmailSuffixes: []string{"qq.com", "163.com", "gmail.com"}, InApp: true}, nil
}
func (*DemoPanel) SendEmailCode(context.Context, string, string, bool) error { return nil }
func (p *DemoPanel) Register(ctx context.Context, endpoint string, form Registration) (Session, error) {
	if form.EmailCode != "123456" {
		return Session{}, &AppError{Code: "PANEL_REJECTED", Detail: "邮箱验证码有误"}
	}
	return p.Login(ctx, endpoint, form.Email, form.Password)
}
func (*DemoPanel) ResetPassword(ctx context.Context, endpoint, email, password, code string) error {
	if code != "123456" {
		return &AppError{Code: "PANEL_REJECTED", Detail: "邮箱验证码有误"}
	}
	return nil
}
func (*DemoPanel) QuickLoginURL(context.Context, string, Session, string) (string, error) {
	return "", NewAppError("CONFIGURATION_REQUIRED")
}
func (*DemoPanel) Invite(context.Context, string, Session) (InviteView, error) {
	return InviteView{Code: "DEMO2026", Invited: 3}, nil
}

// DemoDriver pretends to connect for the development fixture: it changes nothing on
// the system and makes up traffic, so the connected window and tray can be seen.
type DemoDriver struct {
	mu            sync.Mutex
	started, last time.Time
	down          float64
}

func (*DemoDriver) Verified() bool { return true }
func (*DemoDriver) Prepare(ctx context.Context, _ Candidate) (string, error) {
	if ctx.Err() != nil {
		return "", NewAppError("CANCELLED")
	}
	return "demo", nil
}
func (*DemoDriver) Protect(context.Context, string, time.Time) error { return nil }
func (d *DemoDriver) Start(context.Context, string) error {
	d.mu.Lock()
	d.started, d.last, d.down = time.Now(), time.Now(), 0
	d.mu.Unlock()
	return nil
}
func (*DemoDriver) Probe(context.Context, string) (NetworkProof, error) {
	return NetworkProof{TCP: true, DNS: true}, nil
}
func (*DemoDriver) Commit(context.Context, string) error { return nil }
func (d *DemoDriver) Cleanup(context.Context) error {
	d.mu.Lock()
	d.started = time.Time{}
	d.mu.Unlock()
	return nil
}

// Traffic rises and falls between 1 KB/s and 3 MB/s down every 40 seconds, on a log
// scale; up is a tenth of it.
func (d *DemoDriver) Traffic(context.Context) (TrafficSample, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.started.IsZero() {
		return TrafficSample{}, false
	}
	now := time.Now()
	phase := now.Sub(d.started).Seconds() * 2 * math.Pi / 40
	d.down += now.Sub(d.last).Seconds() * 1024 * math.Pow(3000, (1-math.Cos(phase))/2)
	d.last = now
	return TrafficSample{Up: uint64(d.down / 10), Down: uint64(d.down), At: now}, true
}
