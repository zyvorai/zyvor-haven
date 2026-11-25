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

var logoutTmpl = template.Must(template.New("logout").Parse(withTheme(`<!doctype html>
<html<!--loc-->><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.L.T "Sign out"}}</title>
<!--theme--></head><body><main>
<!--hero:door-->
<h1>{{.L.T "Sign out of %s?" .Realm}}</h1>
<form method="post" action="{{.Action}}">
<input type="hidden" name="csrf" value="{{.CSRF}}">
{{range .Hidden}}<input type="hidden" name="{{.K}}" value="{{.V}}">
{{end}}<button type="submit">{{.L.T "Sign out"}}</button></form>
</main></body></html>`)))

type hiddenField struct{ K, V string }

type logoutView struct {
	Nonce, Realm, CSRF, Action string
	Hidden                     []hiddenField
	L                          Loc // ui.go
}

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
	// The session of THIS browser, when this request ended it: only then are
	// its applications told through the browser (front-channel logout), so a
	// stolen id_token_hint never reveals them.
	var browser *core.Session
	switch {
	case hc != nil:
		browser = p.logoutWithHint(w, r, rl, hc, cs, haveCookie, ip)
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
		if s, ended := p.endAndLog(r, rl, cs.ID, cs.UserID, clientID, ip, "confirmed"); ended {
			browser = &s
		}
		p.clearSSOCookie(w, name)
		p.clearLogoutCSRF(w, name)
	default:
		// No session in this browser: already signed out.
		p.clearSSOCookie(w, name)
	}

	if browser != nil {
		next := ""
		if redirect != nil {
			next = redirect.String()
		}
		if p.frontchannelLogout(w, r, rl, *browser, next) { // frontchannel.go
			return
		}
	}
	if redirect != nil {
		noStore(w)
		http.Redirect(w, r, redirect.String(), http.StatusFound)
		return
	}
	p.simplePage(w, http.StatusOK, "Signed out", "You have been signed out.")
}

// logoutWithHint ends the session named by a verified id_token_hint and, when
// it belongs to the same user, the browser's cookie session. It returns the
// cookie session if this call ended it.
func (p *Provider) logoutWithHint(w http.ResponseWriter, r *http.Request, rl core.Realm, hc core.Claims,
	cs core.Session, haveCookie bool, ip string) (browser *core.Session) {
	sub, azp, sid := claimStr(hc, "sub"), claimStr(hc, "azp"), claimStr(hc, "sid")
	own := haveCookie && cs.UserID == sub
	if sid != "" {
		// The hint's sid only counts when the session belongs to the hint's
		// subject: a token for one user never ends another user's session.
		if s, err := p.cfg.Store.GetSession(r.Context(), rl.Name, sid); err == nil && s.UserID == sub {
			if ended, ok := p.endAndLog(r, rl, sid, sub, azp, ip, "id_token_hint"); ok && own && cs.ID == sid {
				browser = &ended
			}
		}
	}
	if own {
		if cs.ID != sid {
			if ended, ok := p.endAndLog(r, rl, cs.ID, sub, azp, ip, "id_token_hint cookie session"); ok {
				browser = &ended
			}
		}
		p.clearSSOCookie(w, rl.Name)
	}
	return browser
}

// endAndLog ends one session through the sessions service and records LOGOUT
// only when this call actually ended it, so replays leave no trace.
func (p *Provider) endAndLog(r *http.Request, rl core.Realm, sid, userID, clientID, ip, how string) (core.Session, bool) {
	s, err := p.sessions().End(r.Context(), rl.Name, sid)
	if err != nil {
		return core.Session{}, false
	}
	p.event(r.Context(), rl, "LOGOUT", userID, clientID, ip, how)
	return s, true
}

func (p *Provider) logoutConfirm(w http.ResponseWriter, rl core.Realm, ru, clientID, state string) {
	csrf := p.newCSRF(rl.Name)
	// #nosec G124 -- HttpOnly and SameSite are set; Secure follows p.secure (config-driven, off only for plain-HTTP dev installs)
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
	l := p.loc(w)
	w.WriteHeader(http.StatusOK)
	_ = logoutTmpl.Execute(w, logoutView{Nonce: nonce, Realm: l.RealmName(rl), CSRF: csrf,
		Action: keepUILocales(w, p.logoutPath(rl.Name)), Hidden: hidden, L: l})
}

func (p *Provider) clearLogoutCSRF(w http.ResponseWriter, realm string) {
	// #nosec G124 -- expiry cookie (MaxAge -1, empty value): deleted by name and path, its flags carry no data; Secure would follow p.secure
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: "", Path: p.logoutPath(realm), MaxAge: -1})
}
