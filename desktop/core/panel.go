package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math"
	"math/big"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type Panel interface {
	Login(context.Context, string, string, string) (Session, error)
	FetchAccount(context.Context, string, Session) (Account, error)
	FetchSubscriptionDescriptor(context.Context, string, Session) (SubscriptionDescriptor, error)
	FetchNodes(context.Context, SubscriptionDescriptor) (string, error)
	Logout(context.Context, string, Session) error
}
type PanelFields struct {
	AccountID       string `json:"accountId"`
	Email           string `json:"email"`
	Banned          string `json:"banned"`
	PlanID          string `json:"planId"`
	Expires         string `json:"expires"`
	Quota           string `json:"quota"`
	Upload          string `json:"upload"`
	Download        string `json:"download"`
	SubscriptionURL string `json:"subscriptionUrl"`
}
type PanelContract struct {
	Verified       bool    `json:"verified"`
	Deployment     string  `json:"deployment"`
	BranchCommit   string  `json:"branchCommit"`
	LoginPath      string  `json:"loginPath"`
	AccountPath    string  `json:"accountPath"`
	DescriptorPath string  `json:"descriptorPath"`
	AuthPrefix     string  `json:"authPrefix"`
	ExpiryUnit     string  `json:"expiryUnit"`
	LogoutPath     *string `json:"logoutPath,nullable" default:"null"`
	// Passport names the sign-up, password reset and one-time web login paths; without
	// it the client sends people to the website for those.
	Passport                    *PassportPaths `json:"passport,nullable" default:"null"`
	ActivePlanAuthorizesService bool           `json:"activePlanAuthorizesService"`
	NullExpiryIsUnlimited       bool           `json:"nullExpiryIsUnlimited"`
	ZeroQuotaIsUnlimited        bool           `json:"zeroQuotaIsUnlimited"`
	Fields                      PanelFields    `json:"fields"`
}

var apiPathPattern = regexp.MustCompile(`^/api/[a-zA-Z0-9/_-]+$`)
var sessionClaimPattern = regexp.MustCompile(`^[a-zA-Z0-9-]{1,128}$`)

func (c PanelContract) Validate() error {
	passport := c.Passport == nil || apiPathPattern.MatchString(c.Passport.ConfigPath) && apiPathPattern.MatchString(c.Passport.EmailCodePath) && apiPathPattern.MatchString(c.Passport.RegisterPath) && apiPathPattern.MatchString(c.Passport.ResetPath) && apiPathPattern.MatchString(c.Passport.QuickLoginPath)
	return invalidUnless(apiPathPattern.MatchString(c.LoginPath) && apiPathPattern.MatchString(c.AccountPath) && apiPathPattern.MatchString(c.DescriptorPath) && nullableCheck(c.LogoutPath, apiPathPattern.MatchString) && passport && oneOf(c.AuthPrefix, "", "Bearer ") && c.ExpiryUnit == "seconds")
}

type missingValue struct{}

func fieldValue(data map[string]any, name string) any {
	v, ok := data[name]
	if !ok {
		return missingValue{}
	}
	return v
}
func jsValueString(value any) string {
	switch v := value.(type) {
	case missingValue:
		return "undefined"
	case nil:
		return "null"
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case json.Number:
		return jsNumberString(v)
	case []any:
		parts := make([]string, len(v))
		for i, item := range v {
			if item != nil {
				parts[i] = jsValueString(item)
			}
		}
		return strings.Join(parts, ",")
	default:
		return "[object Object]"
	}
}
func jsNumeric(value any) (float64, bool) {
	n, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	number, err := n.Float64()
	return number, err == nil
}
func jsNumberEquals(value any, want float64) bool { n, ok := jsNumeric(value); return ok && n == want }
func jsStrictEqual(a, b any) bool {
	switch v := a.(type) {
	case missingValue:
		_, ok := b.(missingValue)
		return ok
	case nil:
		return b == nil
	case string:
		other, ok := b.(string)
		return ok && v == other
	case bool:
		other, ok := b.(bool)
		return ok && v == other
	case json.Number:
		n, ok := jsNumeric(b)
		m, _ := v.Float64()
		return ok && m == n
	default:
		return false
	}
}
func byteCount(value any) *big.Int {
	if str, ok := value.(string); ok && decimalPattern.MatchString(str) {
		n, _ := new(big.Int).SetString(str, 10)
		return n
	}
	if n, ok := jsNumeric(value); ok && math.Trunc(n) == n && n >= 0 && n <= float64(MaxSafeInteger) {
		return big.NewInt(int64(n))
	}
	return nil
}
func isoTime(ms int64) string { return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z") }
func NormalizeAccount(data map[string]any, contract PanelContract, session Session, endpoint string, now int64) (Account, error) {
	f := contract.Fields
	id := fieldValue(data, f.AccountID)
	email, ok := fieldValue(data, f.Email).(string)
	if !ok || jsValueString(id) != session.AccountID || !strings.EqualFold(email, session.Email) {
		return Account{}, NewAppError("CONTROL_UNAVAILABLE")
	}
	rawBanned := fieldValue(data, f.Banned)
	banned := "unknown"
	if jsNumberEquals(rawBanned, 1) || rawBanned == true {
		banned = "yes"
	} else if jsNumberEquals(rawBanned, 0) || rawBanned == false {
		banned = "no"
	}
	rawPlan := fieldValue(data, f.PlanID)
	hasPlan := "unknown"
	if rawPlan == nil || jsNumberEquals(rawPlan, 0) {
		hasPlan = "no"
	} else if n, ok := jsNumeric(rawPlan); ok && n > 0 && math.Trunc(n) == n && n <= float64(MaxSafeInteger) {
		hasPlan = "yes"
	}
	expiry := fieldValue(data, f.Expires)
	seconds, numeric := jsNumeric(expiry)
	finite := numeric && seconds > 0 && seconds < 253402300800 && math.Trunc(seconds) == seconds
	expiryKind := "unknown"
	var expires *string
	if finite {
		expiryKind = "finite"
		v := isoTime(int64(seconds) * 1000)
		expires = &v
	} else if expiry == nil && contract.NullExpiryIsUnlimited {
		expiryKind = "unlimited"
	}
	quota, up, down := byteCount(fieldValue(data, f.Quota)), byteCount(fieldValue(data, f.Upload)), byteCount(fieldValue(data, f.Download))
	var used *big.Int
	if up != nil && down != nil {
		used = new(big.Int).Add(up, down)
	}
	quotaKind := "unknown"
	if quota != nil {
		quotaKind = "finite"
		if quota.Sign() == 0 && contract.ZeroQuotaIsUnlimited {
			quotaKind = "unlimited"
		}
	}
	traffic := "unknown"
	if quotaKind == "unlimited" {
		traffic = "no"
	} else if quotaKind == "finite" && used != nil {
		traffic = "no"
		if used.Cmp(quota) >= 0 {
			traffic = "yes"
		}
	}
	service := "unknown"
	if banned == "yes" || hasPlan == "no" || jsNumberEquals(expiry, 0) {
		service = "no"
	} else if contract.ActivePlanAuthorizesService && banned == "no" && hasPlan == "yes" && traffic == "no" && (finite || expiry == nil && contract.NullExpiryIsUnlimited) {
		service = "yes"
	}
	plan := "当前套餐"
	if object, ok := data["plan"].(map[string]any); ok {
		if name, ok := object["name"].(string); ok {
			plan = name
		}
	}
	var usedString, quotaString *string
	if used != nil {
		v := used.String()
		usedString = &v
	}
	if quotaKind == "finite" {
		v := quota.String()
		quotaString = &v
	}
	evidence := ""
	if service == "yes" {
		evidence = "deployment-contract:" + contract.BranchCommit + ":active-plan-and-quota"
	}
	account := Account{AccountID: session.AccountID, Email: email, PlanName: plan, SessionStatus: "valid", ServiceAllowed: service, Banned: banned, HasPlan: hasPlan, TrafficExhausted: traffic, ExpiryKind: expiryKind, ExpiresAt: expires, QuotaKind: quotaKind, UsedBytes: usedString, QuotaBytes: quotaString, ObservedAt: isoTime(now), SourceEndpointID: endpoint, AuthorizationEvidence: evidence}
	if err := account.Validate(); err != nil {
		return Account{}, err
	}
	return account, nil
}

type V2BoardAdapter struct {
	build    BuildConfig
	contract PanelContract
	http     Transport
}

func NewV2BoardAdapter(build BuildConfig, contract PanelContract, transport Transport) *V2BoardAdapter {
	return &V2BoardAdapter{build, contract, transport}
}
func (p *V2BoardAdapter) endpointURL(endpoint, path string) (string, error) {
	if !p.contract.Verified {
		return "", NewAppError("CONFIGURATION_REQUIRED")
	}
	for _, entry := range p.build.APIEndpoints {
		if entry.ID == endpoint {
			return strings.TrimSuffix(entry.BaseURL, "/") + path, nil
		}
	}
	return "", NewAppError("CONFIGURATION_REQUIRED")
}
func panelData(body string) (map[string]any, error) {
	parsed, err := StrictJSON([]byte(body), 262144)
	if err != nil {
		return nil, err
	}
	object, ok := parsed.(map[string]any)
	if !ok {
		return nil, NewAppError("CONTROL_UNAVAILABLE")
	}
	data, ok := object["data"].(map[string]any)
	if !ok {
		return nil, NewAppError("CONTROL_UNAVAILABLE")
	}
	return data, nil
}
func (p *V2BoardAdapter) readAccount(ctx context.Context, endpoint string, session Session) (map[string]any, error) {
	u, err := p.endpointURL(endpoint, p.contract.AccountPath)
	if err != nil {
		return nil, err
	}
	response, err := p.http.Request(ctx, HTTPRequest{URL: u, Headers: map[string]string{"authorization": p.contract.AuthPrefix + session.Token}})
	if err != nil {
		return nil, err
	}
	if err = RequireSuccess(response, "account"); err != nil {
		return nil, err
	}
	return panelData(response.Body)
}
func (p *V2BoardAdapter) Login(ctx context.Context, endpoint, email, password string) (Session, error) {
	u, err := p.endpointURL(endpoint, p.contract.LoginPath)
	if err != nil {
		return Session{}, err
	}
	body, _ := EncodeJSON(struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{email, password})
	// zh-CN: the panel then explains a refusal in Chinese ("邮箱或密码错误").
	response, err := p.http.Request(ctx, HTTPRequest{URL: u, Method: "POST", Headers: map[string]string{"content-type": "application/json", "content-language": "zh-CN"}, Body: string(body)})
	if err != nil {
		return Session{}, err
	}
	if response.Status == 500 {
		return Session{}, &AppError{Code: "LOGIN_FAILED", Detail: panelMessage(response.Body)}
	}
	if err = RequireSuccess(response, "login"); err != nil {
		return Session{}, err
	}
	data, err := panelData(response.Body)
	if err != nil {
		return Session{}, err
	}
	return p.sessionFor(ctx, endpoint, email, data["auth_data"])
}

// sessionFor checks the account access token a login or sign-up returned and reads the
// account it belongs to.
func (p *V2BoardAdapter) sessionFor(ctx context.Context, endpoint, email string, value any) (Session, error) {
	token, ok := value.(string)
	if !ok || token == "" || jsUTF16Length(token) > 8192 || strings.ContainsAny(token, "\r\n") {
		return Session{}, NewAppError("LOGIN_FAILED")
	}
	session := Session{Email: email, Token: token, Generation: newUUID()}
	identity, err := p.readAccount(ctx, endpoint, session)
	if err != nil {
		return Session{}, err
	}
	id := fieldValue(identity, p.contract.Fields.AccountID)
	str, isString := id.(string)
	num, isNumber := jsNumeric(id)
	if !(isString && str != "" || isNumber && math.Trunc(num) == num && math.Abs(num) <= float64(MaxSafeInteger)) {
		return Session{}, NewAppError("CONTROL_UNAVAILABLE")
	}
	session.AccountID = jsValueString(id)
	if _, err = NormalizeAccount(identity, p.contract, session, endpoint, time.Now().UnixMilli()); err != nil {
		return Session{}, err
	}
	return session, nil
}
func (p *V2BoardAdapter) FetchAccount(ctx context.Context, endpoint string, session Session) (Account, error) {
	info, err := p.readAccount(ctx, endpoint, session)
	if err != nil {
		return Account{}, err
	}
	banned := fieldValue(info, p.contract.Fields.Banned)
	if jsNumberEquals(banned, 1) || banned == true {
		return NormalizeAccount(info, p.contract, session, endpoint, time.Now().UnixMilli())
	}
	u, err := p.endpointURL(endpoint, p.contract.DescriptorPath)
	if err != nil {
		return Account{}, err
	}
	response, err := p.http.Request(ctx, HTTPRequest{URL: u, Headers: map[string]string{"authorization": p.contract.AuthPrefix + session.Token}})
	if err != nil {
		return Account{}, err
	}
	if err = RequireSuccess(response, "account"); err != nil {
		return Account{}, err
	}
	subscription, err := panelData(response.Body)
	if err != nil {
		return Account{}, err
	}
	f := p.contract.Fields
	if jsValueString(fieldValue(info, f.AccountID)) != jsValueString(fieldValue(subscription, f.AccountID)) || !jsStrictEqual(fieldValue(info, f.Email), fieldValue(subscription, f.Email)) || !jsStrictEqual(fieldValue(info, f.Expires), fieldValue(subscription, f.Expires)) || !jsStrictEqual(fieldValue(info, f.PlanID), fieldValue(subscription, f.PlanID)) || jsValueString(fieldValue(info, f.Quota)) != jsValueString(fieldValue(subscription, f.Quota)) {
		return Account{}, NewAppError("CONTROL_UNAVAILABLE")
	}
	for key, value := range info {
		subscription[key] = value
	}
	return NormalizeAccount(subscription, p.contract, session, endpoint, time.Now().UnixMilli())
}
func (p *V2BoardAdapter) FetchSubscriptionDescriptor(ctx context.Context, endpoint string, session Session) (SubscriptionDescriptor, error) {
	u, err := p.endpointURL(endpoint, p.contract.DescriptorPath)
	if err != nil {
		return SubscriptionDescriptor{}, err
	}
	response, err := p.http.Request(ctx, HTTPRequest{URL: u, Headers: map[string]string{"authorization": p.contract.AuthPrefix + session.Token}})
	if err != nil {
		return SubscriptionDescriptor{}, err
	}
	if err = RequireSuccess(response, "account"); err != nil {
		return SubscriptionDescriptor{}, err
	}
	data, err := panelData(response.Body)
	if err != nil {
		return SubscriptionDescriptor{}, err
	}
	raw, ok := data[p.contract.Fields.SubscriptionURL].(string)
	if !ok || jsUTF16Length(raw) > 8192 {
		return SubscriptionDescriptor{}, NewAppError("SUBSCRIPTION_INVALID")
	}
	trusted, err := TrustedURL(raw, p.build.TrustedSubscriptionOrigins)
	if err != nil {
		return SubscriptionDescriptor{}, err
	}
	selected, _ := url.Parse(trusted)
	parts := []string{}
	inserted := false
	for _, part := range strings.Split(selected.RawQuery, "&") {
		if part == "" {
			continue
		}
		pair := strings.SplitN(part, "=", 2)
		key, _ := url.QueryUnescape(pair[0])
		value := ""
		if len(pair) == 2 {
			value, _ = url.QueryUnescape(pair[1])
		}
		if key == "flag" {
			if inserted {
				continue
			}
			value = ""
			inserted = true
		}
		escape := func(s string) string { return strings.ReplaceAll(url.QueryEscape(s), "~", "%7E") }
		parts = append(parts, escape(key)+"="+escape(value))
	}
	if !inserted {
		parts = append(parts, "flag=")
	}
	selected.RawQuery = strings.Join(parts, "&")
	return SubscriptionDescriptor{URL: selected.String(), Format: "v2ray-uri-base64-v1"}, nil
}
func (p *V2BoardAdapter) FetchNodes(ctx context.Context, descriptor SubscriptionDescriptor) (string, error) {
	u, err := TrustedURL(descriptor.URL, p.build.TrustedSubscriptionOrigins)
	if err != nil {
		return "", err
	}
	response, err := p.http.Request(ctx, HTTPRequest{URL: u, MaxBytes: 14 * 1024 * 1024})
	if err != nil {
		return "", err
	}
	if err = RequireSuccess(response, "subscription"); err != nil {
		return "", err
	}
	return response.Body, nil
}
func (p *V2BoardAdapter) Logout(ctx context.Context, endpoint string, session Session) error {
	if p.contract.LogoutPath == nil {
		return nil
	}
	parts := strings.Split(session.Token, ".")
	if len(parts) != 3 {
		return NewAppError("CONTROL_UNAVAILABLE")
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return NewAppError("CONTROL_UNAVAILABLE")
	}
	claim, err := StrictJSON(raw, 262144)
	if err != nil {
		return err
	}
	object, ok := claim.(map[string]any)
	if !ok {
		return NewAppError("CONTROL_UNAVAILABLE")
	}
	sessionID, ok := object["session"].(string)
	if !ok || !sessionClaimPattern.MatchString(sessionID) {
		return NewAppError("CONTROL_UNAVAILABLE")
	}
	u, err := p.endpointURL(endpoint, *p.contract.LogoutPath)
	if err != nil {
		return err
	}
	body, _ := EncodeJSON(map[string]string{"session_id": sessionID})
	response, err := p.http.Request(ctx, HTTPRequest{URL: u, Method: "POST", Headers: map[string]string{"authorization": p.contract.AuthPrefix + session.Token, "content-type": "application/json"}, Body: string(body)})
	if err != nil {
		return err
	}
	if err = RequireSuccess(response, "account"); err != nil {
		return err
	}
	value, err := StrictJSON([]byte(response.Body), 262144)
	if err != nil {
		return err
	}
	out, ok := value.(map[string]any)
	if !ok || out["data"] != true {
		return NewAppError("CONTROL_UNAVAILABLE")
	}
	return nil
}
