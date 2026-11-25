// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

const csrfCookie = "haven_csrf"

var knownScopes = []string{"openid", "profile", "email", "roles", "offline_access"}

type authzReq struct {
	realm     core.Realm
	client    core.Client
	redirect  string
	state     string
	scope     string
	nonce     string
	challenge string
	resources []string            // RFC 8707, canonical and allow-listed (resources.go)
	acr       core.ACRRequirement // acr_values / claims acr (authn.go)
	limited   bool                // set by the consent screen: claims follow the granted scopes
}

func filterScope(s string) string {
	var out []string
	for _, f := range strings.Fields(s) {
		if slices.Contains(knownScopes, f) && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return strings.Join(out, " ")
}

func validChallenge(c string) bool {
	if len(c) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(c)
	return err == nil
}

func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var fapiOK bool
	if r, q, fapiOK = p.fapiAuthorize(w, r, q); !fapiOK { // fapi.go: PAR / JAR / RAR / dpop_jkt
		return
	}
	name := r.PathValue("realm")
	rl, ok := p.realm(r.Context(), name)
	if !ok {
		p.errorPage(w, http.StatusNotFound, "Unknown realm.")
		return
	}
	cl, err := p.authorizeClientFor(r, name, q.Get("client_id")) // cimd.go: kill switch + metadata-document clients, then authorizeClient (device.go)
	if err != nil || !cl.Enabled || !cl.AuthCodeFlow {
		p.errorPage(w, http.StatusBadRequest, "Invalid client.")
		return
	}
	ru := q.Get("redirect_uri")
	if ru == "" || !slices.Contains(cl.RedirectURIs, ru) || !safeRedirect(ru) {
		p.errorPage(w, http.StatusBadRequest, "Invalid redirect URI.")
		return
	}
	// From here on, errors go back to the (now trusted) redirect URI.
	state := q.Get("state")
	fail := func(code, desc string) { p.redirectErr(w, r, ru, state, name, code, desc) }

	if state == "" {
		fail("invalid_request", "state is required")
		return
	}
	if q.Get("response_type") != "code" {
		fail("unsupported_response_type", "only response_type=code is supported")
		return
	}
	if m := q.Get("response_mode"); m != "" && m != "query" {
		fail("invalid_request", "only response_mode=query is supported")
		return
	}
	if q.Get("request") != "" {
		fail("request_not_supported", "request objects are not supported")
		return
	}
	if q.Get("request_uri") != "" {
		fail("request_uri_not_supported", "request_uri is not supported")
		return
	}
	ch, meth := q.Get("code_challenge"), q.Get("code_challenge_method")
	if ch == "" {
		if cl.Public || cl.RequirePKCE {
			fail("invalid_request", "code_challenge is required")
			return
		}
	} else {
		if meth != "S256" {
			fail("invalid_request", "code_challenge_method must be S256")
			return
		}
		if !validChallenge(ch) {
			fail("invalid_request", "malformed code_challenge")
			return
		}
	}
	ar := &authzReq{realm: rl, client: cl, redirect: ru, state: state, challenge: ch,
		scope: filterScope(q.Get("scope")), nonce: q.Get("nonce")}
	if len(ar.nonce) > 512 {
		fail("invalid_request", "nonce too long")
		return
	}
	res, rerr := p.authzResources(name, cl.ClientID, q["resource"])
	if rerr != nil {
		fail("invalid_target", rerr.Error())
		return
	}
	ar.resources = res
	prompts := strings.Fields(q.Get("prompt"))
	promptNone, promptLogin := slices.Contains(prompts, "none"), slices.Contains(prompts, "login")
	if promptNone && promptLogin {
		fail("invalid_request", "prompt=none cannot be combined with login")
		return
	}
	maxAge := int64(-1) // -1: not requested
	if q.Has("max_age") {
		n, err := strconv.ParseInt(q.Get("max_age"), 10, 64)
		if err != nil || n < 0 {
			fail("invalid_request", "max_age must be a non-negative integer")
			return
		}
		maxAge = n
	}
	req, aerr := parseACRRequest(q) // authn.go
	if aerr != nil {
		fail("invalid_request", aerr.Error())
		return
	}
	if code, desc := p.acrPossible(r.Context(), name, req); code != "" {
		fail(code, desc)
		return
	}
	ar.acr = req

	if r.Method == http.MethodGet {
		// SSO reuse comes only after every redirect_uri / PKCE / parameter
		// check above, so it cannot weaken them.
		if !promptLogin && p.ssoReuse(w, r, ar, maxAge) {
			return
		}
		if promptNone {
			fail("login_required", "interactive login is required")
			return
		}
		p.loginPage(w, r, ar, "", "")
		return
	}
	if promptNone {
		fail("login_required", "interactive login is required")
		return
	}
	p.login(w, r, ar)
}

// ssoReuse issues a code from the browser's live SSO session without showing
// the login form. It reports whether it wrote a response. A session whose user
// is gone or disabled is ended and treated as no session.
func (p *Provider) ssoReuse(w http.ResponseWriter, r *http.Request, ar *authzReq, maxAge int64) bool {
	rl := ar.realm
	s, ok := p.currentSession(r, rl)
	if !ok {
		return false
	}
	ctx := r.Context()
	u, err := p.cfg.Store.GetUser(ctx, rl.Name, s.UserID)
	if err != nil || !u.Enabled {
		if err == nil || errors.Is(err, idp.ErrNotFound) {
			_, _ = p.sessions().End(ctx, rl.Name, s.ID)
			p.clearSSOCookie(w, rl.Name)
		} else {
			p.cfg.Logger.Error("oidc: load sso user", "err", err)
		}
		return false
	}
	if rl.EmailVerificationRequired && !u.EmailVerified {
		return false
	}
	if maxAge >= 0 && (maxAge == 0 || p.now().Sub(s.AuthTime) > time.Duration(maxAge)*time.Second) {
		return false
	}
	if p.stepUpBlocksSSO(r, ar, u, s) { // stepup.go: risk policy asks for a real login
		return false
	}
	if !p.acrMetBySession(ctx, ar, s) { // authn.go: a stronger login is demanded
		return false
	}
	p.touchSession(r, rl, s)
	p.issueCode(w, r, ar, u, s, "sso")
	return true
}

// issueCode records the client in the session, stores an authorization code
// bound to it and redirects back to the client.
func (p *Provider) issueCode(w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User, s core.Session, detail string) {
	ctx := r.Context()
	rl := ar.realm
	// The one gate every code passes: the session must meet the demanded
	// authentication level, whichever path led here (authn.go).
	authn, met, err := p.sessionGrant(ctx, rl.Name, s.ID, s.AuthTime, ar.acr)
	if err != nil {
		p.cfg.Logger.Error("oidc: authentication context", "err", err)
		p.redirectErr(w, r, ar.redirect, ar.state, rl.Name, "server_error", "could not issue code")
		return
	}
	if !met {
		p.acrUnmet(w, r, ar, u.ID, "session_too_weak")
		return
	}
	if consentGateHook != nil && consentGateHook(p, w, r, ar, u, s, detail) { // consent.go
		return
	}
	authn.Limited = ar.limited
	if err := p.cfg.Store.AddSessionClient(ctx, rl.Name, s.ID, ar.client.ClientID); err != nil {
		p.cfg.Logger.Error("oidc: record session client", "err", err)
		p.redirectErr(w, r, ar.redirect, ar.state, rl.Name, "server_error", "could not issue code")
		return
	}
	code := randToken(32) + encodeSuffix(ar.resources, authn) // the code carries the granted resources and authentication context
	if !p.fapiBindCode(w, r, ar, HashSecret(code)) {          // fapi.go: authorization_details, dpop_jkt, single-use login context
		return
	}
	err = p.cfg.Store.PutAuthCode(ctx, core.AuthCode{
		CodeHash: HashSecret(code), Realm: rl.Name, ClientID: ar.client.ClientID, UserID: u.ID,
		RedirectURI: ar.redirect, Scope: ar.scope, Nonce: ar.nonce,
		CodeChallenge: ar.challenge, ChallengeMeth: methFor(ar.challenge),
		AuthTime: s.AuthTime, SessionID: s.ID, ExpiresAt: p.now().Add(p.cfg.CodeTTL),
	})
	if err != nil {
		p.cfg.Logger.Error("oidc: store auth code", "err", err)
		p.redirectErr(w, r, ar.redirect, ar.state, rl.Name, "server_error", "could not issue code")
		return
	}
	p.cfg.Obs.Login(rl.Name, "success")
	p.event(ctx, rl, "LOGIN", u.ID, ar.client.ClientID, p.clientIP(r), detail)
	// Expire the CSRF cookie (harmless when none was set).
	// #nosec G124 -- expiry cookie (MaxAge -1, empty value): deleted by name and path, its flags carry no data; Secure would follow p.secure
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: "/realms/" + rl.Name + oidcPath + "/auth", MaxAge: -1})
	p.redirectWith(w, r, ar.redirect, url.Values{"code": {code}, "state": {ar.state}}, rl.Name)
}

func safeRedirect(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "javascript", "data", "vbscript", "file", "blob":
		return false
	}
	return true
}

func (p *Provider) redirectErr(w http.ResponseWriter, r *http.Request, ru, state, realm, code, desc string) {
	p.redirectWith(w, r, ru, url.Values{"error": {code}, "error_description": {desc}, "state": {state}}, realm)
}

func (p *Provider) redirectWith(w http.ResponseWriter, r *http.Request, ru string, v url.Values, realm string) {
	u, err := url.Parse(ru)
	if err != nil {
		p.errorPage(w, http.StatusBadRequest, "Invalid redirect URI.")
		return
	}
	q := u.Query()
	for k, vs := range v {
		if len(vs) > 0 && vs[0] != "" {
			q.Set(k, vs[0])
		}
	}
	q.Set("iss", p.issuer(realm))
	u.RawQuery = q.Encode()
	noStore(w)
	http.Redirect(w, r, u.String(), http.StatusFound) // #nosec G710 -- u is the client redirect_uri, already matched against the client registered URIs
}

// ---- CSRF ----

func (p *Provider) csrfMAC(realm, payload string) string {
	m := hmac.New(sha256.New, p.csrfKey)
	m.Write([]byte("csrf|" + realm + "|" + payload))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (p *Provider) newCSRF(realm string) string {
	payload := strconv.FormatInt(p.now().Add(csrfTTL).Unix(), 10) + "." + randToken(16)
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + p.csrfMAC(realm, payload)
}

func (p *Provider) checkCSRF(realm, tok string) bool {
	enc, mac, ok := strings.Cut(tok, ".")
	if !ok {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return false
	}
	payload := string(raw)
	if !hmac.Equal([]byte(mac), []byte(p.csrfMAC(realm, payload))) {
		return false
	}
	expStr, _, _ := strings.Cut(payload, ".")
	exp, err := strconv.ParseInt(expStr, 10, 64)
	return err == nil && p.now().Unix() <= exp
}

// ---- pages ----

func (p *Provider) pageHeaders(w http.ResponseWriter, nonce string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
	h.Set("X-Frame-Options", "DENY")
	// No form-action: browsers apply it to the post-login redirect to the
	// client, which would break every flow.
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; base-uri 'none'; frame-ancestors 'none'")
}

var pageTmpl = template.Must(template.New("page").Parse(withTheme(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<!--theme--></head><body><main>
{{if .Login}}<!--hero:lock-->{{else if eq .Form "forgot"}}<!--hero:envelope-->{{else if eq .Form "reset"}}<!--hero:lock-->{{else if .Form}}<!--hero:envelope-->{{else}}<!--hero:compass-->{{end}}
{{if .Login}}<h1>Sign in to {{.Realm}}</h1>
<p class="sub">to continue to {{.Client}}</p>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}" autocomplete="on">
<input type="hidden" name="csrf" value="{{.CSRF}}">
<label for="u">Username or email</label><input id="u" name="username" value="{{.Username}}" autocomplete="username" autofocus required maxlength="256">
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required maxlength="1024">
<button type="submit">Sign in</button></form>
{{if .Passkey}}{{template "passkey" .}}{{end}}
{{if .ForgotURL}}<p class="sub"><a href="{{.ForgotURL}}">Forgot your password?</a></p>{{end}}
{{range .Providers}}<a class="fed" href="{{.URL}}">Continue with {{.Name}}</a>
{{end}}
{{else if .Form}}<h1>{{.Title}}</h1>
{{if .Message}}<p class="sub">{{.Message}}</p>{{end}}
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
{{if eq .Form "forgot"}}<label for="u">Username or email</label><input id="u" name="username" autocomplete="username" autofocus required maxlength="256">
<button type="submit">Send reset link</button>
{{else if eq .Form "reset"}}<input type="hidden" name="token" value="{{.Token}}">
<label for="p">New password</label><input id="p" name="password" type="password" autocomplete="new-password" autofocus required maxlength="1024">
<label for="c">Repeat new password</label><input id="c" name="confirm" type="password" autocomplete="new-password" required maxlength="1024">
<button type="submit">Set password</button>
{{else}}<input type="hidden" name="token" value="{{.Token}}">
<button type="submit">Confirm email address</button>{{end}}
</form>
{{else}}<h1>{{.Title}}</h1><p>{{.Message}}</p>{{end}}
</main></body></html>`)))

type pageData struct {
	Title, Nonce, Realm, Client, Error, Username, CSRF, Action, Message string
	Token, Form, ForgotURL                                              string
	Login                                                               bool
	Passkey                                                             *PasskeyLogin // set by passkeys.go via loginPageHook
	Providers                                                           []fedButton   // federation.go
}

func (p *Provider) errorPage(w http.ResponseWriter, status int, msg string) {
	p.simplePage(w, status, "Error", msg)
}

func (p *Provider) simplePage(w http.ResponseWriter, status int, title, msg string) {
	nonce := randToken(16)
	p.pageHeaders(w, nonce)
	w.WriteHeader(status)
	_ = pageTmpl.Execute(w, pageData{Title: title, Nonce: nonce, Message: msg})
}

func (p *Provider) loginPage(w http.ResponseWriter, r *http.Request, ar *authzReq, errMsg, username string) {
	csrf := p.newCSRF(ar.realm.Name)
	// #nosec G124 -- HttpOnly and SameSite are set; Secure follows p.secure (config-driven, off only for plain-HTTP dev installs)
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: csrf, Path: "/realms/" + ar.realm.Name + oidcPath + "/auth",
		HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(csrfTTL.Seconds())})
	nonce := randToken(16)
	p.pageHeaders(w, nonce)
	disp := ar.realm.DisplayName
	if disp == "" {
		disp = ar.realm.Name
	}
	cn := ar.client.Name
	if cn == "" {
		cn = ar.client.ClientID
	}
	pd := pageData{Title: "Sign in", Nonce: nonce, Login: true, Realm: disp, Client: cn,
		Error: errMsg, Username: username, CSRF: csrf, ForgotURL: p.forgotURL(ar.realm.Name),
		Action: r.URL.Path + "?" + r.URL.RawQuery, Providers: p.loginProviders(r, ar.realm)}
	if loginPageHook != nil {
		loginPageHook(p, w, ar, nonce, &pd) // passkeys: adds the button and its nonce'd script
	}
	w.WriteHeader(http.StatusOK)
	_ = pageTmpl.Execute(w, pd)
}

// ---- login ----

func (p *Provider) dummy() string {
	p.dummyOnce.Do(func() {
		h, err := p.cfg.Hasher.Hash(randToken(16))
		if err != nil {
			h = ""
		}
		p.dummyHash = h
	})
	return p.dummyHash
}

const badCreds = "Invalid username or password"

func (p *Provider) login(w http.ResponseWriter, r *http.Request, ar *authzReq) {
	if err := r.ParseForm(); err != nil {
		p.errorPage(w, http.StatusBadRequest, "Invalid request.")
		return
	}
	rl := ar.realm
	form := r.PostForm.Get("csrf")
	ck, err := r.Cookie(csrfCookie)
	if err != nil || form == "" || !hmac.Equal([]byte(ck.Value), []byte(form)) || !p.checkCSRF(rl.Name, form) {
		p.cfg.Obs.Login(rl.Name, "csrf")
		p.errorPage(w, http.StatusForbidden, "Your session expired or the request was invalid. Go back and try again.")
		return
	}
	// Follow-up posts of extra steps (CSRF already verified above).
	for _, h := range authContinueHooks {
		if h.fn(p, w, r, ar) {
			return
		}
	}
	ctx := r.Context()
	ip := p.clientIP(r)
	username := strings.TrimSpace(r.PostForm.Get("username"))
	password := r.PostForm.Get("password")
	if username == "" || password == "" || len(username) > 256 || len(password) > 1024 {
		p.cfg.Obs.Login(rl.Name, "bad_credentials")
		p.loginPage(w, r, ar, badCreds, username)
		return
	}
	fail := func(u core.User, why, result string) {
		p.cfg.Obs.Login(rl.Name, result)
		p.event(ctx, rl, "LOGIN_ERROR", u.ID, ar.client.ClientID, ip, why)
		p.loginPage(w, r, ar, badCreds, username)
	}

	u, err := p.cfg.Store.GetUserByUsername(ctx, rl.Name, username)
	if err != nil {
		if !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: load user", "err", err)
			p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
			return
		}
		p.cfg.Hasher.Verify(password, p.dummy())
		fail(core.User{}, "user_not_found", "bad_credentials")
		return
	}
	now := p.now()
	encoded := u.PasswordHash
	if encoded == "" {
		encoded = p.dummy()
	}
	good, rehash := p.cfg.Hasher.Verify(password, encoded)
	if u.PasswordHash == "" {
		good = false
	}
	locked := !u.LockedUntil.IsZero() && now.Before(u.LockedUntil)
	if rl.BruteForceProtection && locked {
		fail(u, "user_temporarily_disabled", "locked")
		return
	}
	if !good {
		if rl.BruteForceProtection {
			if !u.LockedUntil.IsZero() { // lock elapsed: start a fresh count
				u.FailedLogins, u.LockedUntil = 0, time.Time{}
			}
			u.FailedLogins++
			if u.FailedLogins >= lockThreshold {
				u.LockedUntil = now.Add(lockDuration)
			}
			if err := p.cfg.Store.UpdateUser(ctx, u); err != nil {
				p.cfg.Logger.Error("oidc: record failed login", "err", err)
			}
			if u.FailedLogins >= lockThreshold {
				p.cfg.Obs.Lockout(rl.Name)
			}
		}
		fail(u, "invalid_credentials", "bad_credentials")
		return
	}
	if !u.Enabled {
		fail(u, "user_disabled", "disabled")
		return
	}
	if rl.EmailVerificationRequired && !u.EmailVerified {
		p.cfg.Obs.Login(rl.Name, "unverified")
		p.event(ctx, rl, "LOGIN_ERROR", u.ID, ar.client.ClientID, ip, "email_not_verified")
		msg := "Your email address has not been verified. Verify it before signing in."
		if p.sendAsync(rl, u, core.ActionVerifyEmail) {
			msg = "Your email address has not been verified. We sent a verification link to the address on file: open it, then sign in."
		}
		p.loginPage(w, r, ar, msg, username)
		return
	}
	if rehash || u.FailedLogins != 0 || !u.LockedUntil.IsZero() {
		if rehash {
			if h, err := p.cfg.Hasher.Hash(password); err == nil {
				u.PasswordHash = h
			}
		}
		u.FailedLogins, u.LockedUntil = 0, time.Time{}
		if err := p.cfg.Store.UpdateUser(ctx, u); err != nil {
			p.cfg.Logger.Error("oidc: update user after login", "err", err)
		}
	}

	// Extra authentication steps (second factors...). A hook that needs the
	// user to do something renders its page and returns true; it finishes the
	// login later with p.completeLogin from an authContinueHook.
	for _, h := range authStepHooks {
		if h.fn(p, w, r, ar, u) {
			return
		}
	}
	p.completeLogin(w, r, ar, u, "")
}

// completeLogin is where every interactive login ends: all required factors
// have been satisfied, so start the SSO session and issue the code.
func (p *Provider) completeLogin(w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User, detail string) {
	sess, err := p.startSession(w, r, ar.realm, u)
	if err != nil {
		p.cfg.Logger.Error("oidc: start session", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return
	}
	if err := p.recordAuthn(r.Context(), ar.realm.Name, sess.ID, detail); err != nil { // authn.go
		p.cfg.Logger.Error("oidc: record authentication methods", "err", err)
		_, _ = p.sessions().End(r.Context(), ar.realm.Name, sess.ID)
		p.clearSSOCookie(w, ar.realm.Name)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return
	}
	if afterLoginHook != nil { // stepup.go: remember the device
		afterLoginHook(p, w, r, ar, u)
	}
	p.issueCode(w, r, ar, u, sess, detail)
}

func methFor(ch string) string {
	if ch == "" {
		return ""
	}
	return "S256"
}
