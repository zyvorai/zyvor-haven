// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// OAuth 2.0 Device Authorization Grant (RFC 8628). See docs/device-flow.md.
//
// Authentication of the approving user is NOT implemented here: when the
// browser has no live SSO session it is sent through the ordinary /auth
// endpoint as the built-in public client deviceClientID, so the normal login
// (lockout, email verification, MFA/passkey step hooks) runs and completeLogin
// starts the SSO session. /device/continue then only reads that session.

const (
	deviceGrant    = "urn:ietf:params:oauth:grant-type:device_code"
	deviceClientID = "haven-device" // built-in pseudo client, see authorizeClient
	deviceCodeTTL  = 10 * time.Minute
	deviceInterval = 5 // seconds

	// user code: 8 chars from a vowel-free alphabet (no 0/O/1/I/L confusion).
	userCodeAlphabet = "BCDFGHJKLMNPQRSTVWXZ"
	userCodeLen      = 8

	deviceCSRFCookie   = "haven_device_csrf"
	deviceStatePurpose = "device-login"

	// Limits on guessable operations (fixed window, shared across replicas).
	deviceLookupWindow   = 10 * time.Minute
	deviceLookupPerIP    = 30  // user-code lookups per IP per window
	deviceLookupPerRealm = 600 // user-code lookups per realm per window
	deviceStartPerIP     = 60  // device authorization requests per IP per window
)

func init() {
	registerFeature(func(p *Provider, mux *http.ServeMux) {
		r := "/realms/{realm}"
		mux.HandleFunc("POST "+r+oidcPath+"/auth/device", p.deviceAuthorize)
		mux.HandleFunc("GET "+r+"/device", p.deviceVerify)
		mux.HandleFunc("POST "+r+"/device", p.deviceVerify)
		mux.HandleFunc("GET "+r+"/device/continue", p.deviceContinue)
	})
	registerDiscovery(func(p *Provider, realm string, doc map[string]any) {
		if _, ok := p.deviceStore(); !ok {
			return
		}
		doc["device_authorization_endpoint"] = p.endpoint(realm, "auth/device")
		if g, ok := doc["grant_types_supported"].([]string); ok {
			doc["grant_types_supported"] = append(slices.Clone(g), deviceGrant)
		}
	})
	registerGrant(deviceGrant, (*Provider).grantDevice)
}

func (p *Provider) deviceStore() (core.DeviceStore, bool) {
	return core.StoreAs[core.DeviceStore](p.cfg.Store)
}

// authorizeClient resolves the client of an /auth request. The built-in
// device-login pseudo client exists ONLY here (never in the store, so the
// token endpoint knows nothing about it) and only while the device flow is
// available. Its redirect URI is the realm's /device/continue page.
func (p *Provider) authorizeClient(ctx context.Context, realm, clientID string) (core.Client, error) {
	if clientID == deviceClientID {
		if _, ok := p.deviceStore(); !ok {
			return core.Client{}, idp.ErrNotFound
		}
		return core.Client{Realm: realm, ClientID: deviceClientID, Name: "Haven device login", Enabled: true,
			Public: true, AuthCodeFlow: true, RequirePKCE: true,
			RedirectURIs: []string{p.deviceURL(realm) + "/continue"}}, nil
	}
	if clientID == cibaClientID { // CIBA approver login (ciba.go)
		return p.cibaLoginClient(realm)
	}
	return p.cfg.Store.GetClientByClientID(ctx, realm, clientID)
}

func (p *Provider) deviceURL(realm string) string { return p.issuer(realm) + "/device" }

// ---- user codes ----

// newUserCode returns an 8-char code from userCodeAlphabet, uniformly (the
// alphabet length divides 240, so rejection sampling above 239 is unbiased).
func newUserCode() string {
	out := make([]byte, 0, userCodeLen)
	buf := make([]byte, 16)
	for len(out) < userCodeLen {
		if _, err := rand.Read(buf); err != nil {
			panic("oidc: entropy source failed: " + err.Error())
		}
		for _, b := range buf {
			if b < 240 && len(out) < userCodeLen {
				out = append(out, userCodeAlphabet[int(b)%len(userCodeAlphabet)])
			}
		}
	}
	return string(out)
}

func displayUserCode(c string) string { return c[:4] + "-" + c[4:] }

// normalizeUserCode upper-cases, drops dashes and spaces and reports whether
// the result is a well-formed user code.
func normalizeUserCode(s string) (string, bool) {
	if len(s) > 64 {
		return "", false
	}
	var b strings.Builder
	for _, r := range strings.ToUpper(s) {
		if r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	c := b.String()
	if len(c) != userCodeLen {
		return "", false
	}
	for i := 0; i < len(c); i++ {
		if strings.IndexByte(userCodeAlphabet, c[i]) < 0 {
			return "", false
		}
	}
	return c, true
}

func userCodeHash(normalized string) string { return HashSecret(normalized) }

// ---- device authorization endpoint ----

func (p *Provider) deviceError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func (p *Provider) deviceAuthorize(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("realm")
	rl, ok := p.realm(r.Context(), name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "realm_not_found"})
		return
	}
	ds, ok := p.deviceStore()
	if !ok {
		p.deviceError(w, http.StatusNotImplemented, "feature_unavailable", "the device flow is not available")
		return
	}
	if err := r.ParseForm(); err != nil {
		p.deviceError(w, http.StatusBadRequest, "invalid_request", "malformed body")
		return
	}
	ctx := r.Context()
	ip := p.clientIP(r)
	allowed, err := p.hitLimit(ctx, "devstart", name, ip, deviceStartPerIP)
	if err != nil {
		p.cfg.Logger.Error("oidc: device rate limit", "err", err)
		p.deviceError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "try again later")
		return
	}
	if !allowed {
		p.deviceError(w, http.StatusTooManyRequests, "slow_down", "too many device authorization requests")
		return
	}

	cl, _, basic, terr := p.authClient(r, name)
	if terr != nil {
		p.event(ctx, rl, "DEVICE_AUTH_REQUEST_ERROR", "", r.PostForm.Get("client_id"), ip, terr.code)
		p.writeTokenErr(w, terr, basic)
		return
	}
	if !cl.DeviceFlow {
		p.event(ctx, rl, "DEVICE_AUTH_REQUEST_ERROR", "", cl.ClientID, ip, "unauthorized_client")
		p.deviceError(w, http.StatusBadRequest, "unauthorized_client", "client may not use the device flow")
		return
	}
	scope := strings.Fields(r.PostForm.Get("scope"))
	for _, s := range scope {
		if !slices.Contains(knownScopes, s) {
			p.deviceError(w, http.StatusBadRequest, "invalid_scope", "unknown scope")
			return
		}
	}
	sc := filterScope(strings.Join(scope, " "))
	if sc == "" {
		sc = "openid"
	}
	res, rerr := p.authzResources(name, cl.ClientID, r.PostForm["resource"]) // resources.go
	if rerr != nil {
		p.deviceError(w, http.StatusBadRequest, "invalid_target", rerr.Error())
		return
	}
	now := p.now()
	ua := r.UserAgent()
	if len(ua) > maxUALen {
		ua = ua[:maxUALen]
	}
	deviceCode := randToken(32) + encodeResources(res)
	var userCode string
	for attempt := 0; ; attempt++ {
		userCode = newUserCode()
		err = ds.PutDeviceCode(ctx, core.DeviceCode{
			DeviceCodeHash: HashSecret(deviceCode), UserCodeHash: userCodeHash(userCode), Realm: name,
			ClientID: cl.ClientID, Scope: sc, Status: core.DevicePending, RequestIP: ip, RequestUA: ua,
			Interval: deviceInterval, CreatedAt: now, ExpiresAt: now.Add(deviceCodeTTL),
		})
		if !errors.Is(err, idp.ErrConflict) || attempt >= 5 {
			break
		}
	}
	if err != nil {
		p.cfg.Logger.Error("oidc: store device code", "err", err)
		p.deviceError(w, http.StatusInternalServerError, "server_error", "temporary error")
		return
	}
	p.event(ctx, rl, "DEVICE_AUTH_REQUEST", "", cl.ClientID, ip, "scope="+sc)
	verify := p.deviceURL(name)
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 displayUserCode(userCode),
		"verification_uri":          verify,
		"verification_uri_complete": verify + "?user_code=" + url.QueryEscape(displayUserCode(userCode)),
		"expires_in":                int(deviceCodeTTL.Seconds()),
		"interval":                  deviceInterval,
	})
}

// hitLimit records a hit against a fixed-window limiter keyed by the sha256 of
// "<purpose>|realm|ip" (raw IPs are never stored). ip "" is a realm-wide key.
func (p *Provider) hitLimit(ctx context.Context, purpose, realm, ip string, max int) (bool, error) {
	sum := sha256.Sum256([]byte(purpose + "|" + realm + "|" + ip))
	return p.cfg.Store.HitRateLimit(ctx, hex.EncodeToString(sum[:]), p.now(), deviceLookupWindow, max)
}

// ---- token endpoint grant ----

func (p *Provider) grantDevice(r *http.Request, rl core.Realm, cl core.Client, _ bool) (map[string]any, *tokenErr) {
	ctx := r.Context()
	ds, ok := p.deviceStore()
	if !ok {
		return nil, &tokenErr{http.StatusNotImplemented, "feature_unavailable", "the device flow is not available"}
	}
	if !cl.DeviceFlow {
		return nil, oerr("unauthorized_client", "client may not use this grant")
	}
	code := r.PostForm.Get("device_code")
	if code == "" || len(code) > maxTokenLen {
		return nil, oerr("invalid_request", "device_code is required")
	}
	hash := HashSecret(code)
	now := p.now()
	// Unknown codes and codes of another client or realm look identical.
	bad := oerr("invalid_grant", "invalid device code")
	d, tooFast, err := ds.PollDeviceCode(ctx, rl.Name, cl.ClientID, hash, now)
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return nil, bad
		}
		p.cfg.Logger.Error("oidc: poll device code", "err", err)
		return nil, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	if !now.Before(d.ExpiresAt) {
		return nil, oerr("expired_token", "the device code has expired")
	}
	if tooFast {
		return nil, oerr("slow_down", fmt.Sprintf("polling too fast; interval is now %d seconds", d.Interval))
	}
	switch d.Status {
	case core.DevicePending:
		return nil, oerr("authorization_pending", "the user has not decided yet")
	case core.DeviceDenied:
		return nil, oerr("access_denied", "the user denied the request")
	case core.DeviceApproved:
	default:
		return nil, bad
	}
	// Resource check before the code is consumed, so a mistaken request does not burn it.
	granted, rok := decodeResources(code) // resources.go
	if !rok {
		return nil, bad
	}
	aud, kept, terr := p.resolveResources(r, rl, cl, granted, false)
	if terr != nil {
		return nil, terr
	}
	r = withResources(r, aud, kept)
	// Single use: whoever deletes the row issues the tokens.
	d, err = ds.ConsumeDeviceCode(ctx, rl.Name, cl.ClientID, hash, now)
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return nil, bad
		}
		p.cfg.Logger.Error("oidc: consume device code", "err", err)
		return nil, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	u, err := p.cfg.Store.GetUser(ctx, rl.Name, d.UserID)
	if err != nil || !u.Enabled {
		return nil, bad
	}
	// As for authorization codes: tokens bound to an SSO session are worthless
	// once that session is over.
	if d.SessionID == "" || !p.sessionAlive(r, rl.Name, d.SessionID) {
		return nil, bad
	}
	resp, terr := p.issue(r, rl, cl, u, d.Scope, "", d.AuthTime, randToken(16), "", true, deviceGrant, d.SessionID, true)
	if terr != nil {
		return nil, terr
	}
	p.event(ctx, rl, "DEVICE_TOKEN", u.ID, cl.ClientID, p.clientIP(r), "")
	return resp, nil
}

// ---- verification UI ----

const deviceNotValid = "That code is not valid, has expired, or was already used. Check the code on your device and try again."

// deviceSessionUser returns the signed-in user behind the browser's SSO
// session, applying the same checks as silent SSO login: the user must exist,
// be enabled and (when the realm demands it) have a verified email. A session
// of a vanished or disabled user is ended.
func (p *Provider) deviceSessionUser(w http.ResponseWriter, r *http.Request, rl core.Realm) (core.Session, core.User, bool) {
	s, ok := p.currentSession(r, rl)
	if !ok {
		return core.Session{}, core.User{}, false
	}
	u, err := p.cfg.Store.GetUser(r.Context(), rl.Name, s.UserID)
	if err != nil || !u.Enabled {
		if err == nil || errors.Is(err, idp.ErrNotFound) {
			_, _ = p.sessions().End(r.Context(), rl.Name, s.ID)
			p.clearSSOCookie(w, rl.Name)
		}
		return core.Session{}, core.User{}, false
	}
	if rl.EmailVerificationRequired && !u.EmailVerified {
		return core.Session{}, core.User{}, false
	}
	return s, u, true
}

// lookupUserCode applies the rate limits and looks a code up. found=false
// covers unknown, expired and already decided codes alike; tooMany and
// unavailable are reported separately because they say nothing about a code.
func (p *Provider) lookupUserCode(r *http.Request, rl core.Realm, ds core.DeviceStore, raw string) (d core.DeviceCode, norm string, found, tooMany, unavailable bool) {
	ctx := r.Context()
	ip := p.clientIP(r)
	for _, l := range []struct {
		ip  string
		max int
	}{{ip, deviceLookupPerIP}, {"", deviceLookupPerRealm}} {
		ok, err := p.hitLimit(ctx, "devcode", rl.Name, l.ip, l.max)
		if err != nil {
			p.cfg.Logger.Error("oidc: device lookup rate limit", "err", err)
			return d, "", false, false, true // fail closed
		}
		if !ok {
			return d, "", false, true, false
		}
	}
	norm, wellFormed := normalizeUserCode(raw)
	if !wellFormed {
		// Same work and same answer as a miss: hash something, then say no.
		_, _ = ds.GetDeviceCodeByUserCode(ctx, rl.Name, userCodeHash("-"))
		return d, "", false, false, false
	}
	d, err := ds.GetDeviceCodeByUserCode(ctx, rl.Name, userCodeHash(norm))
	if err != nil {
		if !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: device code lookup", "err", err)
			return d, "", false, false, true
		}
		return d, "", false, false, false
	}
	if d.Status != core.DevicePending || !p.now().Before(d.ExpiresAt) {
		return core.DeviceCode{}, "", false, false, false
	}
	return d, norm, true, false, false
}

// deviceClient loads the client of a request; it must still exist, be
// enabled and still have the device flow switched on.
func (p *Provider) deviceClient(ctx context.Context, d core.DeviceCode) (core.Client, bool) {
	cl, err := p.cfg.Store.GetClientByClientID(ctx, d.Realm, d.ClientID)
	if err != nil || !cl.Enabled || !cl.DeviceFlow {
		return core.Client{}, false
	}
	return cl, true
}

type deviceView struct {
	Title, Nonce, Realm, CSRF, Action, Error string
	Mode                                     string // entry | approve | done
	UserCode                                 string
	Client, User                             string
	Scopes                                   []string
	IP, UA, When, Ago                        string
	Approved                                 bool
}

var scopeWords = map[string]string{
	"openid":         "Confirm who you are",
	"profile":        "See your name and profile",
	"email":          "See your email address",
	"roles":          "See your roles in this realm",
	"offline_access": "Stay signed in on that device without asking you again (long-lived access)",
}

var deviceTmpl = template.Must(template.New("device").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style nonce="{{.Nonce}}">
body{font-family:system-ui,sans-serif;background:#f4f5f7;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
main{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.15);width:min(26rem,92vw)}
h1{font-size:1.25rem;margin:0 0 1rem}label{display:block;margin:.75rem 0 .25rem;font-size:.9rem}
input[type=text]{width:100%;box-sizing:border-box;padding:.5rem;font-size:1.25rem;letter-spacing:.15em;text-transform:uppercase}
button{margin-top:1rem;width:100%;padding:.6rem;font-size:1rem;cursor:pointer}
.row{display:flex;gap:.75rem}.row form{flex:1}
.err{color:#b00020;margin:.5rem 0}.sub{color:#555;font-size:.9rem}
.code{font-family:ui-monospace,monospace;font-size:1.5rem;letter-spacing:.15em;text-align:center;background:#f4f5f7;padding:.5rem;border-radius:4px;margin:.5rem 0}
.warn{background:#fff4e5;border:1px solid #f0b95b;padding:.6rem;border-radius:4px;font-size:.9rem;margin:1rem 0}
dl{font-size:.9rem;margin:.5rem 0}dt{color:#555;margin-top:.4rem}dd{margin:0;word-break:break-word}
ul{margin:.25rem 0 .5rem;padding-left:1.2rem;font-size:.95rem}
.deny{background:#fff;border:1px solid #888}
</style></head><body><main>
<h1>{{.Title}}</h1>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
{{if eq .Mode "entry"}}
<p class="sub">Enter the code shown on your device.</p>
<form method="post" action="{{.Action}}" autocomplete="off">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label for="uc">Code</label><input id="uc" type="text" name="user_code" value="{{.UserCode}}" autocomplete="off" autocapitalize="characters" spellcheck="false" autofocus required maxlength="32" placeholder="XXXX-XXXX">
<button type="submit">Continue</button></form>
{{else if eq .Mode "approve"}}
<p><strong>{{.Client}}</strong> wants to sign in to {{.Realm}} as <strong>{{.User}}</strong>.</p>
<div class="code" aria-label="Code on your device">{{.UserCode}}</div>
<p class="sub">Make sure this is the code your device shows. It would be allowed to:</p>
<ul>{{range .Scopes}}<li>{{.}}</li>{{end}}</ul>
<dl><dt>Request came from</dt><dd>{{.IP}}</dd>
<dt>Device / software</dt><dd>{{.UA}}</dd>
<dt>Requested</dt><dd>{{.When}} ({{.Ago}})</dd></dl>
<p class="warn"><strong>Only approve if you started this on your own device.</strong> If you did not, deny it: someone may be trying to get into your account.</p>
<div class="row">
<form method="post" action="{{.Action}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="user_code" value="{{.UserCode}}"><input type="hidden" name="decision" value="approve"><button type="submit">Approve</button></form>
<form method="post" action="{{.Action}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="user_code" value="{{.UserCode}}"><input type="hidden" name="decision" value="deny"><button type="submit" class="deny">Deny</button></form>
</div>
{{else}}
{{if .Approved}}<p>You approved the sign-in. You can close this window and go back to your device.</p>
{{else}}<p>You denied the sign-in. Nothing was shared with the device. You can close this window.</p>{{end}}
{{end}}
</main></body></html>`))

func (p *Provider) deviceRender(w http.ResponseWriter, rl core.Realm, status int, v deviceView) {
	nonce := randToken(16)
	v.Nonce = nonce
	v.Realm = rl.DisplayName
	if v.Realm == "" {
		v.Realm = rl.Name
	}
	v.Action = p.deviceURL(rl.Name)
	if v.Mode != "done" {
		csrf := p.newCSRF(rl.Name)
		v.CSRF = csrf
		// #nosec G124 -- HttpOnly and SameSite are set; Secure follows p.secure (config-driven, off only for plain-HTTP dev installs)
		http.SetCookie(w, &http.Cookie{Name: deviceCSRFCookie, Value: csrf, Path: "/realms/" + rl.Name + "/device",
			HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(csrfTTL.Seconds())})
	}
	p.pageHeaders(w, nonce)
	w.WriteHeader(status)
	_ = deviceTmpl.Execute(w, v)
}

func (p *Provider) deviceEntry(w http.ResponseWriter, rl core.Realm, status int, msg, prefill string) {
	p.deviceRender(w, rl, status, deviceView{Title: "Connect a device", Mode: "entry", Error: msg, UserCode: prefill})
}

func (p *Provider) deviceApprovePage(w http.ResponseWriter, rl core.Realm, d core.DeviceCode, cl core.Client, u core.User, norm string) {
	name := cl.Name
	if name == "" {
		name = cl.ClientID
	}
	var scopes []string
	for _, s := range strings.Fields(d.Scope) {
		if w, ok := scopeWords[s]; ok {
			scopes = append(scopes, w)
		}
	}
	ua := d.RequestUA
	if ua == "" {
		ua = "unknown"
	} else if len(ua) > 100 {
		ua = ua[:100] + "..."
	}
	ip := d.RequestIP
	if ip == "" {
		ip = "unknown"
	}
	ago := p.now().Sub(d.CreatedAt).Round(time.Minute)
	agoS := "just now"
	if ago >= time.Minute {
		agoS = fmt.Sprintf("%d min ago", int(ago.Minutes()))
	}
	p.deviceRender(w, rl, http.StatusOK, deviceView{Title: "Approve this device?", Mode: "approve",
		UserCode: displayUserCode(norm), Client: name, User: u.Username, Scopes: scopes, IP: ip, UA: ua,
		When: d.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"), Ago: agoS})
}

func (p *Provider) deviceUnavailable(w http.ResponseWriter, r *http.Request) (core.Realm, core.DeviceStore, bool) {
	rl, ok := p.realm(r.Context(), r.PathValue("realm"))
	if !ok {
		p.errorPage(w, http.StatusNotFound, "Unknown realm.")
		return rl, nil, false
	}
	ds, ok := p.deviceStore()
	if !ok {
		p.errorPage(w, http.StatusNotImplemented, "Device sign-in is not available.")
		return rl, nil, false
	}
	return rl, ds, true
}

// deviceVerify serves GET and POST /realms/{realm}/device: enter or confirm
// the user code, then (once signed in) approve or deny it.
func (p *Provider) deviceVerify(w http.ResponseWriter, r *http.Request) {
	rl, ds, ok := p.deviceUnavailable(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		raw := r.URL.Query().Get("user_code")
		if raw == "" {
			p.deviceEntry(w, rl, http.StatusOK, "", "")
			return
		}
		p.deviceStart(w, r, rl, ds, raw)
		return
	}
	if err := r.ParseForm(); err != nil {
		p.errorPage(w, http.StatusBadRequest, "Invalid request.")
		return
	}
	form := r.PostForm.Get("csrf")
	ck, err := r.Cookie(deviceCSRFCookie)
	if err != nil || form == "" || !hmac.Equal([]byte(ck.Value), []byte(form)) || !p.checkCSRF(rl.Name, form) {
		p.cfg.Obs.Login(rl.Name, "csrf")
		p.errorPage(w, http.StatusForbidden, "Your session expired or the request was invalid. Go back and try again.")
		return
	}
	switch r.PostForm.Get("decision") {
	case "":
		p.deviceStart(w, r, rl, ds, r.PostForm.Get("user_code"))
	case "approve", "deny":
		p.deviceDecide(w, r, rl, ds, r.PostForm.Get("user_code"), r.PostForm.Get("decision") == "approve")
	default:
		p.errorPage(w, http.StatusBadRequest, "Invalid request.")
	}
}

// deviceStart handles a submitted user code: validate it, make sure the
// visitor is signed in (through the normal login if not) and show the
// approval page.
func (p *Provider) deviceStart(w http.ResponseWriter, r *http.Request, rl core.Realm, ds core.DeviceStore, raw string) {
	d, norm, found, tooMany, unavail := p.lookupUserCode(r, rl, ds, raw)
	switch {
	case unavail:
		p.errorPage(w, http.StatusServiceUnavailable, "Temporary error. Try again.")
		return
	case tooMany:
		w.Header().Set("Retry-After", "600")
		p.errorPage(w, http.StatusTooManyRequests, "Too many attempts. Wait a few minutes and try again.")
		return
	case !found:
		p.deviceEntry(w, rl, http.StatusBadRequest, deviceNotValid, "")
		return
	}
	cl, ok := p.deviceClient(r.Context(), d)
	if !ok {
		p.deviceEntry(w, rl, http.StatusBadRequest, deviceNotValid, "")
		return
	}
	_, u, signedIn := p.deviceSessionUser(w, r, rl)
	if !signedIn {
		p.deviceLogin(w, r, rl, norm)
		return
	}
	p.deviceApprovePage(w, rl, d, cl, u, norm)
}

// deviceLogin sends the browser through the ordinary authorization endpoint as
// the built-in device-login client. The code it gets back is never exchanged
// (the PKCE verifier does not exist); the point is completeLogin, which runs
// every login rule and sets the SSO session cookie.
func (p *Provider) deviceLogin(w http.ResponseWriter, r *http.Request, rl core.Realm, norm string) {
	verifier := randToken(32)
	sum := sha256.Sum256([]byte(verifier)) // verifier is discarded: the code is unredeemable
	q := url.Values{
		"client_id":             {deviceClientID},
		"response_type":         {"code"},
		"redirect_uri":          {p.deviceURL(rl.Name) + "/continue"},
		"scope":                 {"openid"},
		"state":                 {p.signPending(rl.Name, "", deviceStatePurpose, norm, 15*time.Minute)},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	noStore(w)
	http.Redirect(w, r, p.endpoint(rl.Name, "auth")+"?"+q.Encode(), http.StatusSeeOther)
}

// deviceContinue is where the login redirect lands. It reads the SSO session
// the login created and never touches the authorization code.
func (p *Provider) deviceContinue(w http.ResponseWriter, r *http.Request) {
	rl, ds, ok := p.deviceUnavailable(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	if code := q.Get("code"); code != "" {
		// Hygiene only: drop the unusable code now instead of at expiry.
		_, _ = p.cfg.Store.ConsumeAuthCode(r.Context(), HashSecret(code))
	}
	_, norm, valid := p.checkPending(rl.Name, q.Get("state"), deviceStatePurpose)
	if !valid || q.Get("error") != "" {
		p.deviceEntry(w, rl, http.StatusBadRequest, "Sign-in did not complete. Enter the code from your device to start again.", "")
		return
	}
	_, u, signedIn := p.deviceSessionUser(w, r, rl)
	if !signedIn {
		p.deviceEntry(w, rl, http.StatusUnauthorized, "Sign-in did not complete. Enter the code from your device to start again.", "")
		return
	}
	d, norm, found, tooMany, unavail := p.lookupUserCode(r, rl, ds, norm)
	switch {
	case unavail:
		p.errorPage(w, http.StatusServiceUnavailable, "Temporary error. Try again.")
	case tooMany:
		w.Header().Set("Retry-After", "600")
		p.errorPage(w, http.StatusTooManyRequests, "Too many attempts. Wait a few minutes and try again.")
	case !found:
		p.deviceEntry(w, rl, http.StatusBadRequest, deviceNotValid, "")
	default:
		cl, ok := p.deviceClient(r.Context(), d)
		if !ok {
			p.deviceEntry(w, rl, http.StatusBadRequest, deviceNotValid, "")
			return
		}
		p.deviceApprovePage(w, rl, d, cl, u, norm)
	}
}

// deviceDecide applies the user's Approve or Deny (CSRF already checked).
func (p *Provider) deviceDecide(w http.ResponseWriter, r *http.Request, rl core.Realm, ds core.DeviceStore, raw string, approve bool) {
	ctx := r.Context()
	d, norm, found, tooMany, unavail := p.lookupUserCode(r, rl, ds, raw)
	switch {
	case unavail:
		p.errorPage(w, http.StatusServiceUnavailable, "Temporary error. Try again.")
		return
	case tooMany:
		w.Header().Set("Retry-After", "600")
		p.errorPage(w, http.StatusTooManyRequests, "Too many attempts. Wait a few minutes and try again.")
		return
	case !found:
		p.deviceEntry(w, rl, http.StatusBadRequest, deviceNotValid, "")
		return
	}
	cl, ok := p.deviceClient(ctx, d)
	if !ok {
		p.deviceEntry(w, rl, http.StatusBadRequest, deviceNotValid, "")
		return
	}
	s, u, signedIn := p.deviceSessionUser(w, r, rl)
	if !signedIn {
		p.deviceLogin(w, r, rl, norm) // session ended meanwhile: sign in again
		return
	}
	ip := p.clientIP(r)
	dec := core.DeviceDecision{}
	if approve {
		// The device's client becomes part of the session so ending it also
		// notifies (back-channel logout) and revokes what the device receives.
		if err := p.cfg.Store.AddSessionClient(ctx, rl.Name, s.ID, cl.ClientID); err != nil {
			p.cfg.Logger.Error("oidc: record device client in session", "err", err)
			p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
			return
		}
		dec = core.DeviceDecision{Approve: true, UserID: u.ID, SessionID: s.ID, AuthTime: s.AuthTime}
	}
	if _, err := ds.DecideDeviceCode(ctx, rl.Name, userCodeHash(norm), p.now(), dec); err != nil {
		if errors.Is(err, idp.ErrNotFound) { // decided or expired in the meantime
			p.deviceEntry(w, rl, http.StatusBadRequest, deviceNotValid, "")
			return
		}
		p.cfg.Logger.Error("oidc: decide device code", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return
	}
	typ := "DEVICE_DENY"
	if approve {
		typ = "DEVICE_APPROVE"
	}
	p.event(ctx, rl, typ, u.ID, cl.ClientID, ip, "")
	title := "Device denied"
	if approve {
		title = "Device approved"
	}
	p.deviceRender(w, rl, http.StatusOK, deviceView{Title: title, Mode: "done", Approved: approve})
}
