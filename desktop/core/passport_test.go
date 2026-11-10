package core

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// The panel's live sign-up settings (2026-11-08): email code and invitation required,
// a list of allowed mail domains, no captcha.
const liveSignupConfig = `{"data":{"tos_url":null,"is_email_verify":1,"is_invite_force":1,"email_whitelist_suffix":["gmail.com","qq.com","163.com"],"is_recaptcha":0,"recaptcha_site_key":"site-key","app_description":"x","app_url":"https:\/\/www.starrail.work","logo":"https:\/\/img.invalid\/logo.png"}}`

type recordedRequest struct {
	url, method, body string
	headers           map[string]string
}

func passportAdapter(t *testing.T, reply func(HTTPRequest) HTTPResponse) (*V2BoardAdapter, *[]recordedRequest) {
	t.Helper()
	f := newSignedFixture(t)
	f.build.TrustedWebOrigins = []string{"https://www.starrail.work"}
	var mu sync.Mutex
	requests := []recordedRequest{}
	adapter := NewV2BoardAdapter(f.build, contractFixture(t), transportFunc(func(_ context.Context, input HTTPRequest) (HTTPResponse, error) {
		mu.Lock()
		requests = append(requests, recordedRequest{input.URL, input.Method, input.Body, input.Headers})
		mu.Unlock()
		return reply(input), nil
	}))
	return adapter, &requests
}

func TestSignupConfigReadsThePanelSettings(t *testing.T) {
	adapter, requests := passportAdapter(t, func(HTTPRequest) HTTPResponse { return HTTPResponse{Status: 200, Body: liveSignupConfig} })
	config, err := adapter.SignupConfig(context.Background(), "primary")
	if err != nil || !config.EmailCode || !config.InviteRequired || !config.InApp || strings.Join(config.EmailSuffixes, ",") != "gmail.com,qq.com,163.com" {
		t.Fatalf("config %+v %v", config, err)
	}
	if r := (*requests)[0]; r.method != "GET" || !strings.HasSuffix(r.url, "/api/v1/guest/comm/config") || r.headers["content-language"] != "zh-CN" {
		t.Fatalf("request %+v", r)
	}
	for _, c := range []struct {
		from, to string
		inApp    bool
		suffixes int
	}{
		{`"is_recaptcha":0`, `"is_recaptcha":1`, false, 3},
		{`["gmail.com","qq.com","163.com"]`, `0`, true, 0},
		{`["gmail.com","qq.com","163.com"]`, `["gmail.com","not a domain"]`, true, 0},
	} {
		body := strings.Replace(liveSignupConfig, c.from, c.to, 1)
		adapter, _ := passportAdapter(t, func(HTTPRequest) HTTPResponse { return HTTPResponse{Status: 200, Body: body} })
		config, err := adapter.SignupConfig(context.Background(), "primary")
		if err != nil || config.InApp != c.inApp || config.EmailSuffixes == nil || len(config.EmailSuffixes) != c.suffixes {
			t.Fatalf("%s: %+v %v", c.to, config, err)
		}
	}
}

func TestPassportRefusalsCarryThePanelsWords(t *testing.T) {
	cases := []struct {
		status int
		body   string
		code   ErrorCode
		detail string
	}{
		{500, `{"message":"邀请码无效"}`, "PANEL_REJECTED", "邀请码无效"},
		{422, `{"message":"邮箱格式不正确","errors":{"email":["邮箱格式不正确"]}}`, "PANEL_REJECTED", "邮箱格式不正确"},
		{429, `{"message":"请求过多，请稍后再试"}`, "RATE_LIMITED", "请求过多，请稍后再试"},
		{500, `<html>oops</html>`, "PANEL_REJECTED", ""},
		{502, `{"message":"edge"}`, "CONTROL_UNAVAILABLE", ""},
		{500, `{"message":"line\nbreak‮` + strings.Repeat("长", 200) + `"}`, "PANEL_REJECTED", "line break " + strings.Repeat("长", panelMessageLimit-11) + "…"},
	}
	for _, c := range cases {
		adapter, _ := passportAdapter(t, func(HTTPRequest) HTTPResponse { return HTTPResponse{Status: c.status, Body: c.body} })
		err := adapter.SendEmailCode(context.Background(), "primary", "alice@qq.com", false)
		if CodeOf(err) != c.code || DetailOf(err) != c.detail {
			t.Fatalf("%d %s: %v %q", c.status, c.body, CodeOf(err), DetailOf(err))
		}
	}
}

func TestEmailCodeAndResetRequests(t *testing.T) {
	adapter, requests := passportAdapter(t, func(HTTPRequest) HTTPResponse { return HTTPResponse{Status: 200, Body: `{"data":true}`} })
	if err := adapter.SendEmailCode(context.Background(), "primary", "alice@qq.com", true); err != nil {
		t.Fatal(err)
	}
	if err := adapter.ResetPassword(context.Background(), "primary", "alice@qq.com", "new-password", "123456"); err != nil {
		t.Fatal(err)
	}
	send, reset := (*requests)[0], (*requests)[1]
	if send.method != "POST" || !strings.HasSuffix(send.url, "/api/v1/passport/comm/sendEmailVerify") || send.body != `{"email":"alice@qq.com","isforget":1}` {
		t.Fatalf("send %+v", send)
	}
	if !strings.HasSuffix(reset.url, "/api/v1/passport/auth/forget") || reset.body != `{"email":"alice@qq.com","email_code":"123456","password":"new-password"}` {
		t.Fatalf("reset %+v", reset)
	}
	adapter, _ = passportAdapter(t, func(HTTPRequest) HTTPResponse { return HTTPResponse{Status: 200, Body: `{"data":false}`} })
	if err := adapter.ResetPassword(context.Background(), "primary", "alice@qq.com", "new-password", "123456"); CodeOf(err) != "CONTROL_UNAVAILABLE" {
		t.Fatalf("unconfirmed reset accepted: %v", err)
	}
}

func TestRegisterSignsInWithTheReturnedToken(t *testing.T) {
	account := `{"data":{"email":"alice@qq.com","banned":0,"plan_id":null,"expired_at":null,"transfer_enable":null,"u":0,"d":0}}`
	adapter, requests := passportAdapter(t, func(input HTTPRequest) HTTPResponse {
		if strings.HasSuffix(input.URL, "/register") {
			return HTTPResponse{Status: 200, Body: `{"data":{"token":"subscription-token","is_admin":0,"auth_data":"NEW_ACCOUNT_TOKEN"}}`}
		}
		if input.Headers["authorization"] != "NEW_ACCOUNT_TOKEN" {
			t.Errorf("account read without the new token: %+v", input.Headers)
		}
		return HTTPResponse{Status: 200, Body: account}
	})
	session, err := adapter.Register(context.Background(), "primary", Registration{Email: "alice@qq.com", Password: "password1", EmailCode: "123456"})
	if err != nil || session.Token != "NEW_ACCOUNT_TOKEN" || session.AccountID != "alice@qq.com" {
		t.Fatalf("session %+v %v", session, err)
	}
	if body := (*requests)[0].body; body != `{"email":"alice@qq.com","email_code":"123456","password":"password1"}` {
		t.Fatalf("an empty invitation must not be sent: %s", body)
	}
}

func TestLoginRefusalKeepsThePanelsWords(t *testing.T) {
	adapter, requests := passportAdapter(t, func(HTTPRequest) HTTPResponse {
		return HTTPResponse{Status: 500, Body: `{"message":"邮箱或密码错误"}`}
	})
	_, err := adapter.Login(context.Background(), "primary", "alice@qq.com", "wrong")
	if CodeOf(err) != "LOGIN_FAILED" || DetailOf(err) != "邮箱或密码错误" || (*requests)[0].headers["content-language"] != "zh-CN" {
		t.Fatalf("%v %q", err, DetailOf(err))
	}
}

func TestQuickLoginTargetAcceptsOnlyThePanelsShape(t *testing.T) {
	origins := []string{"https://www.starrail.work"}
	code := "0123456789abcdef0123456789abcdef"
	good := "https://www.starrail.work/#/login?verify=" + code + "&redirect=plan"
	if target, err := QuickLoginTarget(good, origins, "plan"); err != nil || target != good {
		t.Fatalf("%q %v", target, err)
	}
	for _, bad := range []string{
		"https://evil.invalid/#/login?verify=" + code + "&redirect=plan",
		"http://www.starrail.work/#/login?verify=" + code + "&redirect=plan",
		"https://www.starrail.work/#/login?verify=" + code + "&redirect=dashboard",
		"https://www.starrail.work/#/login?verify=" + code + "&redirect=plan&next=https://evil.invalid",
		"https://www.starrail.work/#/login?verify=short&redirect=plan",
		"https://www.starrail.work/?x=1#/login?verify=" + code + "&redirect=plan&",
		"https://user@www.starrail.work/#/login?verify=" + code + "&redirect=plan",
		"https://www.starrail.work/",
	} {
		if _, err := QuickLoginTarget(bad, origins, "plan"); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
	adapter, requests := passportAdapter(t, func(HTTPRequest) HTTPResponse { return HTTPResponse{Status: 200, Body: `{"data":"` + good + `"}`} })
	target, err := adapter.QuickLoginURL(context.Background(), "primary", Session{Token: "ACCOUNT_TOKEN"}, "plan")
	r := (*requests)[0]
	if err != nil || target != good || !strings.HasSuffix(r.url, "/api/v1/user/getQuickLoginUrl") || r.headers["authorization"] != "ACCOUNT_TOKEN" || r.body != `{"redirect":"plan"}` {
		t.Fatalf("%q %v %+v", target, err, r)
	}
}

type passportPanel struct {
	lifecyclePanel
	mu         sync.Mutex
	quick      string
	quickErr   error
	redirects  []string
	inviteErr  error
	resetFails map[string]ErrorCode
	resets     []string
	logins     int
}

func (p *passportPanel) QuickLoginURL(_ context.Context, _ string, _ Session, redirect string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.redirects = append(p.redirects, redirect)
	return p.quick, p.quickErr
}
func (p *passportPanel) Invite(ctx context.Context, endpoint string, session Session) (InviteView, error) {
	p.mu.Lock()
	err := p.inviteErr
	p.mu.Unlock()
	if err != nil {
		return InviteView{}, err
	}
	return p.DemoPanel.Invite(ctx, endpoint, session)
}
func (p *passportPanel) ResetPassword(ctx context.Context, endpoint, email, password, code string) error {
	p.mu.Lock()
	p.resets = append(p.resets, endpoint)
	failure := p.resetFails[endpoint]
	p.mu.Unlock()
	if failure != "" {
		return NewAppError(failure)
	}
	return nil
}
func (p *passportPanel) Login(ctx context.Context, endpoint, email, password string) (Session, error) {
	p.mu.Lock()
	p.logins++
	p.mu.Unlock()
	return p.DemoPanel.Login(ctx, endpoint, email, password)
}

// Renewal opens the plans page logged in when the panel gives a link to the same site,
// without the "which account is the browser on" question; otherwise the plain link.
func TestRenewOpensTheWebsiteLoggedIn(t *testing.T) {
	panel := &passportPanel{}
	type opened struct{ target, hint string }
	var mu sync.Mutex
	var last opened
	h := newControllerHarness(t, func(deps *ControllerDeps) {
		deps.Panel = panel
		deps.OpenExternal = func(target, hint string) (bool, error) {
			mu.Lock()
			last = opened{target, hint}
			mu.Unlock()
			return true, nil
		}
	}, false)
	link := "https://host.leiterup.de/#/login?verify=0123456789abcdef0123456789abcdef&redirect=plan"
	for _, c := range []struct {
		quick  string
		err    error
		target string
		hint   bool
	}{
		{link, nil, link, false},
		{"https://api.starrail.work/#/login?verify=0123456789abcdef0123456789abcdef&redirect=plan", nil, "https://host.leiterup.de/", true},
		{"", NewAppError("AUTH_INVALID"), "https://host.leiterup.de/", true},
	} {
		panel.mu.Lock()
		panel.quick, panel.quickErr = c.quick, c.err
		panel.mu.Unlock()
		if result := commandForTest(h.controller, map[string]any{"type": "open-link", "link": "renew"}); !result.OK || !result.State.PendingRenewal {
			t.Fatalf("renew %+v", result)
		}
		mu.Lock()
		got := last
		mu.Unlock()
		if got.target != c.target || (got.hint != "") != c.hint {
			t.Fatalf("quick %q: opened %+v", c.quick, got)
		}
	}
}

func TestRegisterAndResetFromTheController(t *testing.T) {
	panel := &passportPanel{resetFails: map[string]ErrorCode{"primary": "CONTROL_UNAVAILABLE"}}
	h := newControllerHarness(t, func(deps *ControllerDeps) { deps.Panel = panel }, false)
	if result := commandForTest(h.controller, map[string]any{"type": "signup-config"}); !result.OK || result.State.Signup == nil || !result.State.Signup.InviteRequired {
		t.Fatalf("signup config %+v", result.State.Signup)
	}
	wrong := commandForTest(h.controller, map[string]any{"type": "register", "email": "new@qq.com", "password": "password1", "emailCode": "000000", "inviteCode": "abc"})
	if wrong.OK || wrong.Error != "PANEL_REJECTED" || wrong.Message != "邮箱验证码有误" {
		t.Fatalf("wrong code %+v", wrong)
	}
	if result := commandForTest(h.controller, map[string]any{"type": "register", "email": "new@qq.com", "password": "password1", "emailCode": "123456", "inviteCode": "abc"}); !result.OK || !result.State.LoggedIn || result.State.Account == nil {
		t.Fatalf("register %+v", result)
	}
	panel.mu.Lock()
	panel.logins = 0
	panel.mu.Unlock()
	if result := commandForTest(h.controller, map[string]any{"type": "reset-password", "email": "new@qq.com", "password": "password2", "emailCode": "123456"}); !result.OK || !result.State.LoggedIn {
		t.Fatalf("reset %+v", result)
	}
	panel.mu.Lock()
	defer panel.mu.Unlock()
	// The unreachable primary is skipped once; the accepted reset is not repeated.
	if strings.Join(panel.resets, ",") != "primary,backup" || panel.logins != 1 {
		t.Fatalf("resets %v logins %d", panel.resets, panel.logins)
	}
}

func TestQuotaRemindersOncePerLevel(t *testing.T) {
	saved := 0
	notified := []int{}
	r := NewExpiryReminders("tenant", func(ReminderState) error { saved++; return nil }, nil)
	r.NotifyQuota = func(percent int) error { notified = append(notified, percent); return nil }
	_, _, account, _, _ := authFixture(t)
	use := func(used string, warn bool) {
		a := account
		a.UsedBytes, a.QuotaBytes = &used, authPointer("1000")
		if err := r.CheckQuota(a, warn, nil); err != nil {
			t.Fatal(err)
		}
	}
	use("899", true)
	use("900", true)
	use("950", true)
	use("1000", true)
	use("1200", true)
	use("10", true) // a new period
	use("910", false)
	use("990", true)
	if got := fmt.Sprint(notified); got != "[90 100 90]" {
		t.Fatalf("notified %v saved %d", notified, saved)
	}
	if err := r.state.Validate(); err != nil || len(r.state.Quota) != 1 {
		t.Fatalf("state %+v %v", r.state, err)
	}
}

// An account without an invite code gets one: the panel creates codes on a GET.
func TestInviteFetchesOrCreatesACode(t *testing.T) {
	fetches := 0
	adapter, requests := passportAdapter(t, func(r HTTPRequest) HTTPResponse {
		if strings.HasSuffix(r.URL, "/invite/save") {
			return HTTPResponse{Status: 200, Body: `{"data":true}`}
		}
		if fetches++; fetches == 1 {
			return HTTPResponse{Status: 200, Body: `{"data":{"codes":[],"stat":[0,0,0,10,0]}}`}
		}
		return HTTPResponse{Status: 200, Body: `{"data":{"codes":[{"id":1,"code":"bad code!","status":0},{"id":2,"code":"AbCd1234","pv":0,"status":0}],"stat":[3,1200,0,10,0]}}`}
	})
	invite, err := adapter.Invite(context.Background(), "primary", Session{Token: "ACCOUNT_TOKEN"})
	if err != nil || invite != (InviteView{Code: "AbCd1234", Invited: 3}) {
		t.Fatalf("%+v %v", invite, err)
	}
	paths := []string{}
	for _, r := range *requests {
		if r.method != "GET" || r.headers["authorization"] != "ACCOUNT_TOKEN" {
			t.Fatalf("request %+v", r)
		}
		paths = append(paths, r.url[strings.Index(r.url, "/api/"):])
	}
	if strings.Join(paths, " ") != "/api/v1/user/invite/fetch /api/v1/user/invite/save /api/v1/user/invite/fetch" {
		t.Fatalf("paths %v", paths)
	}
	// The panel refuses a new code past its limit, in its own words.
	adapter, _ = passportAdapter(t, func(r HTTPRequest) HTTPResponse {
		if strings.HasSuffix(r.URL, "/invite/save") {
			return HTTPResponse{Status: 500, Body: `{"message":"已达到创建数量上限"}`}
		}
		return HTTPResponse{Status: 200, Body: `{"data":{"codes":[],"stat":[0]}}`}
	})
	if _, err := adapter.Invite(context.Background(), "primary", Session{Token: "ACCOUNT_TOKEN"}); CodeOf(err) != "PANEL_REJECTED" || DetailOf(err) != "已达到创建数量上限" {
		t.Fatalf("limit: %v", err)
	}
	for _, body := range []string{`{"data":null}`, `{"data":{"stat":[1]}}`, `{"data":[]}`} {
		adapter, _ = passportAdapter(t, func(HTTPRequest) HTTPResponse { return HTTPResponse{Status: 200, Body: body} })
		if _, err := adapter.Invite(context.Background(), "primary", Session{Token: "ACCOUNT_TOKEN"}); err == nil {
			t.Errorf("%s accepted", body)
		}
	}
}

// The invite code shows in the window until the account changes; failing to fetch it
// does not mark the connection as having a problem.
func TestInviteCommand(t *testing.T) {
	panel := &passportPanel{}
	h := newControllerHarness(t, func(deps *ControllerDeps) { deps.Panel = panel }, false)
	if result := commandForTest(h.controller, map[string]any{"type": "invite"}); !result.OK || result.State.Invite == nil || result.State.Invite.Code != "DEMO2026" {
		t.Fatalf("invite %+v", result)
	}
	panel.mu.Lock()
	panel.inviteErr = &AppError{Code: "PANEL_REJECTED", Detail: "已达到创建数量上限"}
	panel.mu.Unlock()
	if result := commandForTest(h.controller, map[string]any{"type": "invite"}); result.OK || result.Message != "已达到创建数量上限" || result.State.Error != nil {
		t.Fatalf("refused invite %+v", result)
	}
	if result := commandForTest(h.controller, map[string]any{"type": "logout"}); !result.OK || result.State.Invite != nil {
		t.Fatalf("logout kept the invite %+v", result.State.Invite)
	}
}

// 联系客服 opens the operator's chat page as set at build time, with nothing added to it.
func TestSupportOpensTheChat(t *testing.T) {
	panel := &passportPanel{}
	var opened, hint string
	h := newControllerHarness(t, func(deps *ControllerDeps) {
		deps.Panel = panel
		deps.OpenExternal = func(target, h string) (bool, error) { opened, hint = target, h; return true, nil }
	}, false)
	chat := "https://go.crisp.chat/chat/embed/?website_id=e1bee65a-29ce-412b-b653-1e309aa1a63a"
	if result := commandForTest(h.controller, map[string]any{"type": "open-link", "link": "support"}); !result.OK || !result.State.Links.Support || opened != chat || hint != "" || result.State.PendingRenewal {
		t.Fatalf("support %+v %q", result, opened)
	}
	panel.mu.Lock()
	asked := len(panel.redirects)
	panel.mu.Unlock()
	if asked != 0 {
		t.Fatalf("asked the panel for a web login %d times", asked)
	}
	without := newControllerHarness(t, func(deps *ControllerDeps) { deps.Build.Links.Support = nil }, false)
	if result := commandForTest(without.controller, map[string]any{"type": "open-link", "link": "support"}); result.OK || result.Error != "CONFIGURATION_REQUIRED" || result.State.Links.Support {
		t.Fatalf("unset support %+v", result)
	}
}
