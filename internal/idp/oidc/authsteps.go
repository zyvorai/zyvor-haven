// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Extra authentication steps (second factors, passkeys, step-up...).
//
//   - authStepHooks run after the password, enabled and email checks of an
//     interactive login. A hook that needs something more from the user renders
//     a page (stepPage) and returns true. It must NOT issue a code itself.
//   - authContinueHooks run at the start of every POST to /auth after the CSRF
//     check, before the password is read. A hook recognises its own form fields
//     (for example "mfa_token"), validates them, and either re-renders its page
//     with an error or calls p.completeLogin. It returns true when it handled
//     the request.
//
// A silent SSO re-login never runs these: the session already represents a
// fully authenticated user.
type (
	authStepHook     func(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User) (handled bool)
	authContinueHook func(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq) (handled bool)
)

// Step ordering. A user is challenged by the FIRST step that applies to them,
// so the order decides which factor they actually get. Lower runs first.
// Passkeys (phishing resistant) go before TOTP: a user who has both is asked
// for the passkey, because a phished one-time code must not be enough.
const (
	authOrderPasskey = 50
	authOrderDefault = 100 // TOTP and anything not ordered explicitly
)

type orderedStep struct {
	order int
	fn    authStepHook
}

type orderedContinue struct {
	order int
	fn    authContinueHook
}

var (
	authStepHooks     []orderedStep
	authContinueHooks []orderedContinue
)

// registerAuthStep registers at the default order.
func registerAuthStep(step authStepHook, cont authContinueHook) {
	registerAuthStepAt(authOrderDefault, step, cont)
}

// registerAuthStepAt registers at an explicit order. Equal orders keep their
// registration order.
func registerAuthStepAt(order int, step authStepHook, cont authContinueHook) {
	if step != nil {
		i := len(authStepHooks)
		for i > 0 && authStepHooks[i-1].order > order {
			i--
		}
		authStepHooks = append(authStepHooks, orderedStep{})
		copy(authStepHooks[i+1:], authStepHooks[i:])
		authStepHooks[i] = orderedStep{order, step}
	}
	if cont != nil {
		i := len(authContinueHooks)
		for i > 0 && authContinueHooks[i-1].order > order {
			i--
		}
		authContinueHooks = append(authContinueHooks, orderedContinue{})
		copy(authContinueHooks[i+1:], authContinueHooks[i:])
		authContinueHooks[i] = orderedContinue{order, cont}
	}
}

// ---- pending proofs ----

// signPending returns a short-lived HMAC-signed token proving that a prior
// step succeeded for (realm, user, purpose), carrying an optional payload.
// It is NOT a session and grants nothing on its own: the continue hook must
// still verify the second factor. The same key as the CSRF tokens is used with
// a distinct domain separator.
func (p *Provider) signPending(realm, userID, purpose, payload string, ttl time.Duration) string {
	exp := strconv.FormatInt(p.now().Add(ttl).Unix(), 10)
	body := strings.Join([]string{exp, userID, purpose, payload}, "\x1f")
	return base64.RawURLEncoding.EncodeToString([]byte(body)) + "." + p.pendingMAC(realm, body)
}

// checkPending verifies a token made by signPending for the same realm and
// purpose and returns its user id and payload.
func (p *Provider) checkPending(realm, tok, purpose string) (userID, payload string, ok bool) {
	enc, mac, found := strings.Cut(tok, ".")
	if !found || len(tok) > 2048 {
		return "", "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", "", false
	}
	body := string(raw)
	if !hmac.Equal([]byte(mac), []byte(p.pendingMAC(realm, body))) {
		return "", "", false
	}
	parts := strings.SplitN(body, "\x1f", 4)
	if len(parts) != 4 || parts[2] != purpose {
		return "", "", false
	}
	exp, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || p.now().Unix() > exp {
		return "", "", false
	}
	return parts[1], parts[3], true
}

func (p *Provider) pendingMAC(realm, body string) string {
	m := hmac.New(sha256.New, p.csrfKey)
	m.Write([]byte("pending|" + realm + "|" + body))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

// ---- step pages ----

// StepData is what a step page template sees.
type StepData struct {
	Title, Nonce, CSRF, Action, Realm, Client, Error string
	Data                                             any // feature-specific
}

const stepLayout = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<!--theme--></head><body><main>
<!--hero-->
<h1>{{.Title}}</h1>
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
{{template "body" .}}
</main></body></html>`

var (
	stepMu    sync.Mutex
	stepCache = map[string]*template.Template{}
)

func stepTemplate(body string) *template.Template {
	stepMu.Lock()
	defer stepMu.Unlock()
	if t, ok := stepCache[body]; ok {
		return t
	}
	t := template.Must(template.Must(template.New("step").Parse(withTheme(strings.Replace(stepLayout, "<!--hero-->", "<!--hero:"+heroForBody(body)+"-->", 1)))).Parse(`{{define "body"}}` + body + `{{end}}`))
	stepCache[body] = t
	return t
}

// stepPage renders a page of the login flow: fresh CSRF token and cookie
// (scoped to the /auth path like the login form), nonce'd CSP, no-store. The
// form must POST to {{.Action}} (the original /auth URL, so the authorization
// request survives) and include <input type="hidden" name="csrf" value="{{.CSRF}}">.
// body is trusted static template text, never user input.
func (p *Provider) stepPage(w http.ResponseWriter, r *http.Request, ar *authzReq, status int, title, errMsg, body string, data any) {
	csrf := p.newCSRF(ar.realm.Name)
	// #nosec G124 -- HttpOnly and SameSite are set; Secure follows p.secure (config-driven, off only for plain-HTTP dev installs)
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: csrf, Path: "/realms/" + ar.realm.Name + oidcPath + "/auth",
		HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(csrfTTL.Seconds())})
	nonce := randToken(16)
	p.pageHeaders(w, nonce)
	// Step pages may carry one inline script (WebAuthn), but only with this
	// response's nonce; everything else stays blocked.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; script-src 'nonce-"+nonce+"'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
	disp := ar.realm.DisplayName
	if disp == "" {
		disp = ar.realm.Name
	}
	cn := ar.client.Name
	if cn == "" {
		cn = ar.client.ClientID
	}
	w.WriteHeader(status)
	_ = stepTemplate(body).Execute(w, StepData{Title: title, Nonce: nonce, CSRF: csrf, Realm: disp, Client: cn,
		Error: errMsg, Action: r.URL.Path + "?" + r.URL.RawQuery, Data: data})
}
