// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"html/template"
	"net/http"
	"net/url"
	"slices"

	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/core"
)

func (p *Provider) logoutPath(realm string) string { return "/realms/" + realm + oidcPath + "/logout" }

var logoutTmpl = template.Must(template.New("logout").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign out</title>
<style nonce="{{.Nonce}}">
body{font-family:system-ui,sans-serif;background:#f4f5f7;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
main{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.15);width:min(22rem,90vw)}
h1{font-size:1.25rem;margin:0 0 1rem}
button{margin-top:1rem;width:100%;padding:.6rem;font-size:1rem;cursor:pointer}
</style></head><body><main>
<h1>Sign out of {{.Realm}}?</h1>
<form method="post" action="{{.Action}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
{{range .Hidden}}<input type="hidden" name="{{.K}}" value="{{.V}}">
{{end}}<button type="submit">Sign out</button></form>
</main></body></html>`))

type hiddenField struct{ K, V string }

// verifyHint validates an id_token_hint for logout. Signature, alg pinning,
// issuer and realm are always enforced; only expiry is waived, because ID
// tokens are short-lived and are usually stale by the time a user signs out.
func (p *Provider) verifyHint(r *http.Request, realm, hint string) (core.Claims, bool) {
	var c core.Claims
	var err error
	if ev, ok := p.cfg.Signer.(core.ExpiredVerifier); ok {
		c, err = ev.VerifyAllowExpired(r.Context(), realm, hint)
	} else {
		c, err = p.cfg.Signer.Verify(r.Context(), realm, hint)
	}
	if err != nil || claimStr(c, "iss") != p.issuer(realm) || claimStr(c, "typ") != "ID" ||
		claimStr(c, "sub") == "" || claimStr(c, "azp") == "" {
		return nil, false
	}
	return c, true
}

// cookieSession returns the session behind the SSO cookie even when it has
// expired: ending an already expired session is fine and tidies it up.
func (p *Provider) cookieSession(r *http.Request, realm string) (core.Session, bool) {
	ck, err := r.Cookie(ssoCookie)
	if err != nil || ck.Value == "" || len(ck.Value) > 256 {
		return core.Session{}, false
	}
	s, err := p.cfg.Store.GetSessionByCookie(r.Context(), realm, actions.Hash(ck.Value))
	if err != nil {
		return core.Session{}, false
	}
	return s, true
}

// logout implements OIDC RP-Initiated Logout 1.0 on GET and POST.
//
// A request carrying a valid id_token_hint is authenticated enough to act
// directly. Without one the browser's own session is only ended after an
// explicit, CSRF-protected confirmation, so a third-party page cannot log
// users out by embedding the URL (logout CSRF).
func (p *Provider) logout(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("realm")
	rl, ok := p.realm(r.Context(), name)
	if !ok {
		p.errorPage(w, http.StatusNotFound, "Unknown realm.")
		return
	}
	if err := r.ParseForm(); err != nil {
		p.errorPage(w, http.StatusBadRequest, "Invalid request.")
		return
	}
	get := func(k string) string {
		if v := r.PostForm.Get(k); v != "" {
			return v
		}
		return r.URL.Query().Get(k)
	}
	hint, ru, clientID, state := get("id_token_hint"), get("post_logout_redirect_uri"), get("client_id"), get("state")
	ip := p.clientIP(r)
	reject := func(status int, msg, detail string) {
		p.event(r.Context(), rl, "LOGOUT_ERROR", "", clientID, ip, detail)
		p.errorPage(w, status, msg)
	}

	var hc core.Claims
	if hint != "" {
		c, ok := p.verifyHint(r, name, hint)
		if !ok {
			reject(http.StatusBadRequest, "Invalid logout request.", "invalid id_token_hint")
			return
		}
		if clientID != "" && clientID != claimStr(c, "azp") {
			reject(http.StatusBadRequest, "Invalid logout request.", "client_id does not match id_token_hint")
			return
		}
		hc, clientID = c, claimStr(c, "azp")
	}

	// Validate the redirect up front so a bad one is never carried through
	// the confirmation page.
	var redirect *url.URL
	if ru != "" {
		if clientID == "" {
			reject(http.StatusBadRequest, "Invalid logout request.", "post_logout_redirect_uri without client")
			return
		}
		cl, err := p.cfg.Store.GetClientByClientID(r.Context(), name, clientID)
		if err != nil || !cl.Enabled || !slices.Contains(cl.RedirectURIs, ru) || !safeRedirect(ru) {
			reject(http.StatusBadRequest, "Invalid post-logout redirect URI.", "unregistered post_logout_redirect_uri")
			return
		}
		u, err := url.Parse(ru)
		if err != nil {
			reject(http.StatusBadRequest, "Invalid post-logout redirect URI.", "unparsable post_logout_redirect_uri")
			return
		}
		if state != "" {
			q := u.Query()
			q.Set("state", state)
			u.RawQuery = q.Encode()
		}
		redirect = u
	}

	cs, haveCookie := p.cookieSession(r, name)
	switch {
	case hc != nil:
		p.logoutWithHint(w, r, rl, hc, cs, haveCookie, ip)
	case haveCookie:
		if r.Method != http.MethodPost {
			p.logoutConfirm(w, rl, ru, clientID, state)
			return
		}
		if !p.checkActionCSRF(r, name) {
			p.event(r.Context(), rl, "LOGOUT_ERROR", cs.UserID, clientID, ip, "csrf check failed")
			p.errorPage(w, http.StatusForbidden, "This sign-out request could not be verified. Go back and try again.")
			return
		}
		p.endAndLog(r, rl, cs.ID, cs.UserID, clientID, ip, "confirmed")
		p.clearSSOCookie(w, name)
		p.clearLogoutCSRF(w, name)
	default:
		// No session in this browser: already signed out.
		p.clearSSOCookie(w, name)
	}

	if redirect != nil {
		noStore(w)
		http.Redirect(w, r, redirect.String(), http.StatusFound)
		return
	}
	p.simplePage(w, http.StatusOK, "Signed out", "You have been signed out.")
}

// logoutWithHint ends the session named by a verified id_token_hint and, when
// it belongs to the same user, the browser's cookie session.
func (p *Provider) logoutWithHint(w http.ResponseWriter, r *http.Request, rl core.Realm, hc core.Claims,
	cs core.Session, haveCookie bool, ip string) {
	sub, azp, sid := claimStr(hc, "sub"), claimStr(hc, "azp"), claimStr(hc, "sid")
	if sid != "" {
		// The hint's sid only counts when the session belongs to the hint's
		// subject: a token for one user never ends another user's session.
		if s, err := p.cfg.Store.GetSession(r.Context(), rl.Name, sid); err == nil && s.UserID == sub {
			p.endAndLog(r, rl, sid, sub, azp, ip, "id_token_hint")
		}
	}
	if haveCookie && cs.UserID == sub {
		if cs.ID != sid {
			p.endAndLog(r, rl, cs.ID, sub, azp, ip, "id_token_hint cookie session")
		}
		p.clearSSOCookie(w, rl.Name)
	}
}

// endAndLog ends one session through the sessions service and records LOGOUT
// only when this call actually ended it, so replays leave no trace.
func (p *Provider) endAndLog(r *http.Request, rl core.Realm, sid, userID, clientID, ip, how string) {
	if _, err := p.sessions().End(r.Context(), rl.Name, sid); err != nil {
		return
	}
	p.event(r.Context(), rl, "LOGOUT", userID, clientID, ip, how)
}

func (p *Provider) logoutConfirm(w http.ResponseWriter, rl core.Realm, ru, clientID, state string) {
	csrf := p.newCSRF(rl.Name)
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: csrf, Path: p.logoutPath(rl.Name),
		HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(csrfTTL.Seconds())})
	var hidden []hiddenField
	for _, f := range []hiddenField{{"post_logout_redirect_uri", ru}, {"client_id", clientID}, {"state", state}} {
		if f.V != "" {
			hidden = append(hidden, f)
		}
	}
	nonce := randToken(16)
	p.pageHeaders(w, nonce)
	disp := rl.DisplayName
	if disp == "" {
		disp = rl.Name
	}
	w.WriteHeader(http.StatusOK)
	_ = logoutTmpl.Execute(w, struct {
		Nonce, Realm, CSRF, Action string
		Hidden                     []hiddenField
	}{nonce, disp, csrf, p.logoutPath(rl.Name), hidden})
}

func (p *Provider) clearLogoutCSRF(w http.ResponseWriter, realm string) {
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: p.logoutPath(realm), MaxAge: -1})
}
