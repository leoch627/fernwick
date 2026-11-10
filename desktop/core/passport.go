package core

import (
	"context"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// PassportPaths are the panel's sign-up, password reset and one-time web login
// endpoints and invite codes (wyx2685/v2board: guest/comm/config,
// passport/comm/sendEmailVerify, passport/auth/register, passport/auth/forget,
// user/getQuickLoginUrl, user/invite/fetch, user/invite/save).
type PassportPaths struct {
	ConfigPath       string `json:"configPath"`
	EmailCodePath    string `json:"emailCodePath"`
	RegisterPath     string `json:"registerPath"`
	ResetPath        string `json:"resetPath"`
	QuickLoginPath   string `json:"quickLoginPath"`
	InviteFetchPath  string `json:"inviteFetchPath"`
	InviteCreatePath string `json:"inviteCreatePath"`
}

// InviteView is the account's invite code, which new accounts need to sign up, and how
// many people signed up with this account's codes.
type InviteView struct {
	Code    string `json:"code"`
	Invited int    `json:"invited"`
}

// SignupConfig is what the panel asks of a new account.
type SignupConfig struct {
	EmailCode      bool     `json:"emailCode"`
	InviteRequired bool     `json:"inviteRequired"`
	EmailSuffixes  []string `json:"emailSuffixes"`
	// InApp is false when the panel wants a captcha, which only its website can show.
	InApp bool `json:"inApp"`
}
type Registration struct {
	Email, Password, EmailCode, InviteCode string
}

// Passport is implemented by panels that can create accounts, reset passwords and
// hand out a one-time link that opens the website already logged in.
type Passport interface {
	SignupConfig(ctx context.Context, endpoint string) (SignupConfig, error)
	SendEmailCode(ctx context.Context, endpoint, email string, reset bool) error
	Register(ctx context.Context, endpoint string, form Registration) (Session, error)
	ResetPassword(ctx context.Context, endpoint, email, password, code string) error
	QuickLoginURL(ctx context.Context, endpoint string, session Session, redirect string) (string, error)
	Invite(ctx context.Context, endpoint string, session Session) (InviteView, error)
}

const panelMessageLimit = 120

// panelMessage is the explanation in a panel refusal ({"message": "..."}), cleaned for
// display: one line, no control characters, at most 120 characters.
func panelMessage(body string) string {
	parsed, err := StrictJSON([]byte(body), 65536)
	if err != nil {
		return ""
	}
	object, ok := parsed.(map[string]any)
	if !ok {
		return ""
	}
	message, ok := object["message"].(string)
	if !ok {
		return ""
	}
	message = strings.Join(strings.FieldsFunc(message, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '�'
	}), " ")
	if runes := []rune(message); len(runes) > panelMessageLimit {
		message = string(runes[:panelMessageLimit]) + "…"
	}
	return message
}

func (p *V2BoardAdapter) passportPaths() (*PassportPaths, error) {
	if p.contract.Passport == nil {
		return nil, NewAppError("CONFIGURATION_REQUIRED")
	}
	return p.contract.Passport, nil
}

// passportRequest sends a passport call and returns the reply's data. The panel refuses
// with HTTP 500 (or 422 for a malformed form) and its own words; those come back as
// PANEL_REJECTED carrying the message. 502-504 from the edge mean the panel is down.
func (p *V2BoardAdapter) passportRequest(ctx context.Context, endpoint, path string, headers map[string]string, body any) (any, error) {
	u, err := p.endpointURL(endpoint, path)
	if err != nil {
		return nil, err
	}
	request := HTTPRequest{URL: u, Method: "GET", Headers: map[string]string{"content-language": "zh-CN"}}
	for k, v := range headers {
		request.Headers[k] = v
	}
	if body != nil {
		raw, err := EncodeJSON(body)
		if err != nil {
			return nil, NewAppError("INVALID_INPUT")
		}
		request.Method, request.Body, request.Headers["content-type"] = "POST", string(raw), "application/json"
	}
	response, err := p.http.Request(ctx, request)
	if err != nil {
		return nil, err
	}
	status := response.Status
	if status == 429 {
		return nil, &AppError{Code: "RATE_LIMITED", RetryAfterMs: RetryAfter(response.Headers["retry-after"], time.Now().UnixMilli()), Detail: panelMessage(response.Body)}
	}
	if status == 500 || status >= 400 && status < 500 && status != 401 && status != 403 {
		return nil, &AppError{Code: "PANEL_REJECTED", Detail: panelMessage(response.Body)}
	}
	if err = RequireSuccess(response, ""); err != nil {
		return nil, err
	}
	parsed, err := StrictJSON([]byte(response.Body), 262144)
	if err != nil {
		return nil, err
	}
	object, ok := parsed.(map[string]any)
	if !ok {
		return nil, NewAppError("CONTROL_UNAVAILABLE")
	}
	data, ok := object["data"]
	if !ok {
		return nil, NewAppError("CONTROL_UNAVAILABLE")
	}
	return data, nil
}

var emailSuffixPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`)

func (p *V2BoardAdapter) SignupConfig(ctx context.Context, endpoint string) (SignupConfig, error) {
	paths, err := p.passportPaths()
	if err != nil {
		return SignupConfig{}, err
	}
	data, err := p.passportRequest(ctx, endpoint, paths.ConfigPath, nil, nil)
	if err != nil {
		return SignupConfig{}, err
	}
	object, ok := data.(map[string]any)
	if !ok {
		return SignupConfig{}, NewAppError("CONTROL_UNAVAILABLE")
	}
	on := func(key string) bool { return jsNumberEquals(fieldValue(object, key), 1) || object[key] == true }
	config := SignupConfig{EmailCode: on("is_email_verify"), InviteRequired: on("is_invite_force"), EmailSuffixes: []string{}, InApp: !on("is_recaptcha")}
	// 0 when any address is accepted, else the allowed domains. A list the client cannot
	// read is left to the panel to enforce.
	if list, ok := object["email_whitelist_suffix"].([]any); ok && len(list) <= 64 {
		for _, item := range list {
			suffix, ok := item.(string)
			suffix = strings.ToLower(strings.TrimSpace(suffix))
			if !ok || len(suffix) > 253 || !emailSuffixPattern.MatchString(suffix) {
				config.EmailSuffixes = []string{}
				break
			}
			config.EmailSuffixes = append(config.EmailSuffixes, suffix)
		}
	}
	return config, nil
}
func (p *V2BoardAdapter) SendEmailCode(ctx context.Context, endpoint, email string, reset bool) error {
	paths, err := p.passportPaths()
	if err != nil {
		return err
	}
	// isforget: 0 refuses an address that already has an account, 1 one that has none,
	// so the person learns that before waiting for an email.
	forget := 0
	if reset {
		forget = 1
	}
	data, err := p.passportRequest(ctx, endpoint, paths.EmailCodePath, nil, map[string]any{"email": email, "isforget": forget})
	if err != nil {
		return err
	}
	if data != true {
		return NewAppError("CONTROL_UNAVAILABLE")
	}
	return nil
}
func (p *V2BoardAdapter) Register(ctx context.Context, endpoint string, form Registration) (Session, error) {
	paths, err := p.passportPaths()
	if err != nil {
		return Session{}, err
	}
	body := map[string]string{"email": form.Email, "password": form.Password}
	if form.EmailCode != "" {
		body["email_code"] = form.EmailCode
	}
	if form.InviteCode != "" {
		body["invite_code"] = form.InviteCode
	}
	data, err := p.passportRequest(ctx, endpoint, paths.RegisterPath, nil, body)
	if err != nil {
		return Session{}, err
	}
	object, ok := data.(map[string]any)
	if !ok {
		return Session{}, NewAppError("CONTROL_UNAVAILABLE")
	}
	return p.sessionFor(ctx, endpoint, form.Email, object["auth_data"])
}
func (p *V2BoardAdapter) ResetPassword(ctx context.Context, endpoint, email, password, code string) error {
	paths, err := p.passportPaths()
	if err != nil {
		return err
	}
	data, err := p.passportRequest(ctx, endpoint, paths.ResetPath, nil, map[string]string{"email": email, "email_code": code, "password": password})
	if err != nil {
		return err
	}
	if data != true {
		return NewAppError("CONTROL_UNAVAILABLE")
	}
	return nil
}
func (p *V2BoardAdapter) QuickLoginURL(ctx context.Context, endpoint string, session Session, redirect string) (string, error) {
	paths, err := p.passportPaths()
	if err != nil {
		return "", err
	}
	data, err := p.passportRequest(ctx, endpoint, paths.QuickLoginPath, map[string]string{"authorization": p.contract.AuthPrefix + session.Token}, map[string]string{"redirect": redirect})
	if err != nil {
		return "", err
	}
	raw, ok := data.(string)
	if !ok {
		return "", NewAppError("CONTROL_UNAVAILABLE")
	}
	return QuickLoginTarget(raw, p.build.TrustedWebOrigins, redirect)
}

var inviteCodePattern = regexp.MustCompile(`^[A-Za-z0-9]{4,32}$`)

// Invite returns the account's invite code, creating one when it has none.
func (p *V2BoardAdapter) Invite(ctx context.Context, endpoint string, session Session) (InviteView, error) {
	paths, err := p.passportPaths()
	if err != nil {
		return InviteView{}, err
	}
	auth := map[string]string{"authorization": p.contract.AuthPrefix + session.Token}
	for attempt := 0; ; attempt++ {
		data, err := p.passportRequest(ctx, endpoint, paths.InviteFetchPath, auth, nil)
		if err != nil {
			return InviteView{}, err
		}
		invite, found, err := readInvite(data)
		if err != nil || found {
			return invite, err
		}
		if attempt > 0 {
			return InviteView{}, NewAppError("CONTROL_UNAVAILABLE")
		}
		// The panel creates codes on a GET.
		if created, err := p.passportRequest(ctx, endpoint, paths.InviteCreatePath, auth, nil); err != nil {
			return InviteView{}, err
		} else if created != true {
			return InviteView{}, NewAppError("CONTROL_UNAVAILABLE")
		}
	}
}

// readInvite reads invite/fetch: {codes: [{code, ...}], stat: [invited, ...]}. found is
// false when the account has no code yet.
func readInvite(data any) (InviteView, bool, error) {
	object, ok := data.(map[string]any)
	codes, listed := object["codes"].([]any)
	if !ok || !listed {
		return InviteView{}, false, NewAppError("CONTROL_UNAVAILABLE")
	}
	invite := InviteView{}
	if stat, ok := object["stat"].([]any); ok && len(stat) > 0 {
		if count, ok := jsNumeric(stat[0]); ok && count >= 0 && count <= 1e9 && count == float64(int(count)) {
			invite.Invited = int(count)
		}
	}
	for _, item := range codes {
		entry, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if code, ok := entry["code"].(string); ok && inviteCodePattern.MatchString(code) {
			invite.Code = code
			return invite, true, nil
		}
	}
	return invite, false, nil
}

var quickLoginFragment = regexp.MustCompile(`^/login\?verify=([A-Za-z0-9-]{16,64})&redirect=([A-Za-z0-9_-]{1,32})$`)

// QuickLoginTarget accepts the panel's one-time login link only on a trusted website
// origin and only in the shape the panel builds: {app_url}/#/login?verify=…&redirect=….
func QuickLoginTarget(raw string, origins []string, redirect string) (string, error) {
	base, fragment, found := strings.Cut(raw, "#")
	match := quickLoginFragment.FindStringSubmatch(fragment)
	if !found || match == nil || match[2] != redirect {
		return "", NewAppError("INVALID_INPUT")
	}
	trusted, err := TrustedURL(base, origins)
	if err != nil {
		return "", err
	}
	return trusted + "#/login?verify=" + match[1] + "&redirect=" + match[2], nil
}
