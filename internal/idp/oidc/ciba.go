// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/mail"
)

// OpenID Connect Client-Initiated Backchannel Authentication (CIBA), poll mode.
// See docs/ciba.md.
//
// The client (an AI agent, a service) calls the backchannel authentication
// endpoint with a login_hint. The user is NOT told through the response:
// they get an email (the existing mail sender, no new transport) with a link
// to an approval page. The page is behind the ordinary login (every login
// rule, second factor and step-up policy runs, and a fresh sign-in is
// required), shows who is asking for what, and the user approves or denies.
// The client polls the token endpoint with the auth_req_id.
//
// Authentication of the approving user is not implemented here: as in the
// device flow, the browser goes through /auth as the built-in pseudo client
// cibaClientID (prompt=login) and this file only reads the SSO session that
// the login created.

const (
	cibaGrant    = "urn:openid:params:grant-type:ciba"
	cibaClientID = "haven-ciba" // built-in pseudo client, see authorizeClient

	cibaDefaultTTL = 120 * time.Second
	cibaMaxTTL     = 600 * time.Second
	cibaInterval   = 5 // seconds

	// The approver must have signed in this recently (an approval is a
	// sensitive act; a day-old SSO session is not enough).
	cibaAuthFresh = 5 * time.Minute

	cibaMaxHint     = 256
	cibaMaxBinding  = 128 // runes
	cibaMaxResource = 5
	cibaMaxURILen   = 256

	cibaCSRFCookie   = "haven_ciba_csrf"
	cibaStatePurpose = "ciba-login"

	// Limits on guessable or abusable operations (fixed window, shared across
	// replicas, see hitLimit).
	cibaStartPerIP     = 60 // backchannel requests per IP per window
	cibaPerHint        = 5  // requests per (client, login_hint) per window
	cibaMailPerUser    = 5  // approval emails per user per window, all clients
	cibaLookupPerIP    = 30 // approval page loads per IP per window
	cibaLookupPerRealm = 600
)

func init() {
	registerFeature(func(p *Provider, mux *http.ServeMux) {
		r := "/realms/{realm}"
		mux.HandleFunc("POST "+r+oidcPath+"/ext/ciba/auth", p.cibaAuthorize)
		mux.HandleFunc("GET "+r+"/ciba/approve", p.cibaApprove)
		mux.HandleFunc("POST "+r+"/ciba/approve", p.cibaApprove)
		mux.HandleFunc("GET "+r+"/ciba/continue", p.cibaContinue)
	})
	registerDiscovery(func(p *Provider, realm string, doc map[string]any) {
		if !p.cibaAvailable() {
			return
		}
		doc["backchannel_authentication_endpoint"] = p.endpoint(realm, "ext/ciba/auth")
		doc["backchannel_token_delivery_modes_supported"] = []string{"poll"}
		doc["backchannel_user_code_parameter_supported"] = false
		if g, ok := doc["grant_types_supported"].([]string); ok {
			doc["grant_types_supported"] = append(slices.Clone(g), cibaGrant)
		}
	})
	registerGrant(cibaGrant, (*Provider).grantCIBA)
}

func (p *Provider) cibaStore() (core.CIBAStore, bool) {
	return core.StoreAs[core.CIBAStore](p.cfg.Store)
}

// cibaAvailable: the store supports CIBA and email can be sent (without mail
// the approver could never be told, so the feature is off).
func (p *Provider) cibaAvailable() bool {
	_, ok := p.cibaStore()
	return ok && p.actionsOn()
}

// cibaLoginClient is the built-in pseudo client used for the approver's login.
// It exists only here (never in the store, so the token endpoint does not know
// it) and only while CIBA is available.
func (p *Provider) cibaLoginClient(realm string) (core.Client, error) {
	if !p.cibaAvailable() {
		return core.Client{}, idp.ErrNotFound
	}
	return core.Client{Realm: realm, ClientID: cibaClientID, Name: "Haven approval login", Enabled: true,
		Public: true, AuthCodeFlow: true, RequirePKCE: true,
		RedirectURIs: []string{p.cibaURL(realm) + "/continue"}}, nil
}

func (p *Provider) cibaURL(realm string) string { return p.issuer(realm) + "/ciba" }

// cibaClientOK reports whether cl may use CIBA right now: enabled, confidential
// and opted in.
func (p *Provider) cibaClientOK(ctx context.Context, cs core.CIBAStore, cl core.Client) (bool, error) {
	if !cl.Enabled || cl.Public || cl.ID == "" {
		return false, nil
	}
	return cs.CIBAClientEnabled(ctx, cl.Realm, cl.ID)
}

func (p *Provider) cibaError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// cibaText cleans a string that is shown to a human: it rejects control and
// format characters (newlines, bidi overrides) outright.
func cibaText(s string, max int) (string, bool) {
	s = strings.TrimSpace(s)
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > max {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			return "", false
		}
	}
	return s, true
}

// cibaDisplay is cibaText for values that are not the caller's to reject
// (client names): control characters are dropped and the length is capped.
func cibaDisplay(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == ' ' || r == ' ' {
			continue
		}
		if n++; n > max {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// validResource accepts an RFC 8707 resource indicator: an absolute http(s)
// URI without fragment.
func validResource(s string) bool {
	if s == "" || len(s) > cibaMaxURILen {
		return false
	}
	if t, ok := cibaText(s, cibaMaxURILen); !ok || t != s {
		return false
	}
	u, err := url.Parse(s)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.Fragment == "" && u.User == nil
}

// ---- backchannel authentication endpoint ----

func (p *Provider) cibaAuthorize(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("realm")
	rl, ok := p.realm(r.Context(), name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "realm_not_found"})
		return
	}
	cs, ok := p.cibaStore()
	if !ok || !p.actionsOn() {
		p.cibaError(w, http.StatusNotImplemented, "feature_unavailable", "backchannel authentication is not available")
		return
	}
	if err := r.ParseForm(); err != nil {
		p.cibaError(w, http.StatusBadRequest, "invalid_request", "malformed body")
		return
	}
	noStore(w)
	ctx := r.Context()
	ip := p.clientIP(r)
	allowed, err := p.hitLimit(ctx, "cibastart", name, ip, cibaStartPerIP)
	if err != nil {
		p.cfg.Logger.Error("oidc: ciba rate limit", "err", err)
		p.cibaError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "try again later")
		return
	}
	if !allowed {
		p.cibaError(w, http.StatusTooManyRequests, "slow_down", "too many backchannel authentication requests")
		return
	}

	cl, _, basic, terr := p.authClient(r, name)
	if terr != nil {
		p.event(ctx, rl, "CIBA_AUTH_REQUEST_ERROR", "", r.PostForm.Get("client_id"), ip, terr.code)
		p.writeTokenErr(w, terr, basic)
		return
	}
	on, err := p.cibaClientOK(ctx, cs, cl)
	if err != nil {
		p.cfg.Logger.Error("oidc: ciba client opt-in", "err", err)
		p.cibaError(w, http.StatusInternalServerError, "server_error", "temporary error")
		return
	}
	if !on { // not opted in, or a public client
		p.event(ctx, rl, "CIBA_AUTH_REQUEST_ERROR", "", cl.ClientID, ip, "unauthorized_client")
		p.cibaError(w, http.StatusBadRequest, "unauthorized_client", "client may not use backchannel authentication")
		return
	}
	bad := func(code, desc string) {
		p.event(ctx, rl, "CIBA_AUTH_REQUEST_ERROR", "", cl.ClientID, ip, code)
		p.cibaError(w, http.StatusBadRequest, code, desc)
	}
	// Exactly one hint, and only the kind we support.
	if r.PostForm.Get("login_hint_token") != "" || r.PostForm.Get("id_token_hint") != "" {
		bad("invalid_request", "only login_hint is supported")
		return
	}
	if r.PostForm.Get("user_code") != "" {
		bad("invalid_request", "user_code is not supported")
		return
	}
	if r.PostForm.Get("request") != "" || r.PostForm.Get("request_uri") != "" {
		bad("invalid_request", "signed requests are not supported")
		return
	}
	hint := strings.TrimSpace(r.PostForm.Get("login_hint"))
	if hint == "" || len(hint) > cibaMaxHint || !utf8.ValidString(hint) {
		bad("invalid_request", "login_hint is required")
		return
	}
	scope := strings.Fields(r.PostForm.Get("scope"))
	for _, s := range scope {
		if !slices.Contains(knownScopes, s) || s == "offline_access" { // no refresh tokens: every action is approved afresh
			bad("invalid_scope", "unknown or unsupported scope")
			return
		}
	}
	if !slices.Contains(scope, "openid") {
		bad("invalid_scope", "scope must include openid")
		return
	}
	sc := filterScope(strings.Join(scope, " "))
	binding, bok := cibaText(r.PostForm.Get("binding_message"), cibaMaxBinding)
	if !bok {
		bad("invalid_binding_message", "binding_message is too long or contains control characters")
		return
	}
	resources := r.PostForm["resource"]
	if len(resources) > cibaMaxResource {
		bad("invalid_target", "too many resource parameters")
		return
	}
	for _, res := range resources {
		if !validResource(res) {
			bad("invalid_target", "resource must be an absolute http(s) URI without fragment")
			return
		}
	}
	resources = dedupe(resources)
	ttl := cibaDefaultTTL
	if v := r.PostForm.Get("requested_expiry"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > int(cibaMaxTTL.Seconds()) {
			bad("invalid_request", fmt.Sprintf("requested_expiry must be between 1 and %d seconds", int(cibaMaxTTL.Seconds())))
			return
		}
		ttl = time.Duration(n) * time.Second
	}

	// Per (client, hint) limit, applied to every hint alike: whether the hint
	// names a real user must not change the answer.
	ok, err = p.hitLimit(ctx, "cibahint", name, cl.ClientID+"|"+strings.ToLower(hint), cibaPerHint)
	if err != nil {
		p.cfg.Logger.Error("oidc: ciba hint rate limit", "err", err)
		p.cibaError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "try again later")
		return
	}
	if !ok {
		p.cibaError(w, http.StatusTooManyRequests, "slow_down", "too many requests for this login_hint")
		return
	}

	u, resolved, rerr := p.cibaResolve(ctx, rl, hint)
	if rerr != nil {
		p.cfg.Logger.Error("oidc: ciba resolve login_hint", "err", rerr)
		p.cibaError(w, http.StatusInternalServerError, "server_error", "temporary error")
		return
	}

	now := p.now()
	_, _ = cs.PurgeExpiredCIBA(ctx, now) // housekeeping; expired rows are harmless anyway
	authReq, approval := randToken(32), randToken(32)
	row := core.CIBARequest{
		AuthReqHash: HashSecret(authReq), ApprovalHash: HashSecret(approval), Realm: name, ClientID: cl.ClientID,
		Scope: sc, Binding: binding, Resources: resources, Status: core.CIBAPending, RequestIP: ip,
		Interval: cibaInterval, CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	if resolved {
		row.UserID = u.ID
	}
	if err := cs.PutCIBARequest(ctx, row); err != nil { // a collision of 256-bit tokens is a bug, not a retry
		p.cfg.Logger.Error("oidc: store ciba request", "err", err)
		p.cibaError(w, http.StatusInternalServerError, "server_error", "temporary error")
		return
	}
	if resolved {
		p.cibaNotify(rl, cl, u, row, approval)
	}
	p.event(ctx, rl, "CIBA_AUTH_REQUEST", row.UserID, cl.ClientID, ip, fmt.Sprintf("scope=%s resolved=%v", sc, resolved))
	writeJSON(w, http.StatusOK, map[string]any{
		"auth_req_id": authReq,
		"expires_in":  int(ttl.Seconds()),
		"interval":    cibaInterval,
	})
}

func dedupe(in []string) []string {
	var out []string
	for _, s := range in {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// cibaResolve maps a login_hint (username, or email address) to the user the
// request is for. resolved=false covers unknown, ambiguous, disabled and
// unreachable users alike; the caller must answer the same in every case.
func (p *Provider) cibaResolve(ctx context.Context, rl core.Realm, hint string) (u core.User, resolved bool, err error) {
	u, err = p.cfg.Store.GetUserByUsername(ctx, rl.Name, hint)
	if err != nil {
		if !errors.Is(err, idp.ErrNotFound) {
			return core.User{}, false, err
		}
		u = core.User{}
		if strings.Contains(hint, "@") {
			us, err := p.usersWithEmail(ctx, rl.Name, hint)
			if err != nil {
				return core.User{}, false, err
			}
			if len(us) == 1 {
				u = us[0]
			}
		}
	}
	if u.ID == "" || !u.Enabled || strings.TrimSpace(u.Email) == "" || strings.ContainsAny(u.Email, "\r\n") ||
		(rl.EmailVerificationRequired && !u.EmailVerified) {
		return core.User{}, false, nil
	}
	return u, true, nil
}

// cibaNotify emails the approval link in the background, so the response (and
// its timing) does not depend on the user or on the mail system.
func (p *Provider) cibaNotify(rl core.Realm, cl core.Client, u core.User, row core.CIBARequest, approval string) {
	p.bg.Add(1)
	go func() {
		defer p.bg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), mailTimeout)
		defer cancel()
		ok, err := p.hitLimit(ctx, "cibamail", rl.Name, u.ID, cibaMailPerUser)
		if err != nil || !ok {
			p.cfg.Logger.Info("oidc: ciba approval email suppressed by rate limit", "realm", rl.Name)
			return
		}
		disp := rl.DisplayName
		if disp == "" {
			disp = rl.Name
		}
		name := cibaDisplay(cl.Name, 80)
		if name == "" {
			name = cibaDisplay(cl.ClientID, 80)
		}
		link := p.cibaURL(rl.Name) + "/approve?req=" + url.QueryEscape(approval)
		var b strings.Builder
		fmt.Fprintf(&b, "%s is asking for your approval to act on your behalf in %s.\n\n", name, disp)
		if row.Binding != "" {
			fmt.Fprintf(&b, "Message from the application (Haven cannot verify it): %q\n\n", row.Binding)
		}
		fmt.Fprintf(&b, "Access requested: %s\n", row.Scope)
		for _, res := range row.Resources {
			fmt.Fprintf(&b, "Resource: %s\n", res)
		}
		mins := max(1, int(row.ExpiresAt.Sub(row.CreatedAt)/time.Minute))
		fmt.Fprintf(&b, "\nReview and approve or deny it here (you will be asked to sign in):\n\n%s\n\n", link)
		fmt.Fprintf(&b, "This request expires in %d minute(s). If you were not expecting it, do not approve it; you can open the link and press Deny.\n", mins)
		msg := mail.Message{To: strings.TrimSpace(u.Email), Subject: "Approval request from " + name, Text: b.String()}
		if err := p.cfg.Actions.Mailer.Send(ctx, msg); err != nil {
			p.cfg.Logger.Error("oidc: ciba approval email failed", "realm", rl.Name, "err", err)
		}
	}()
}

// ---- token endpoint grant ----

func (p *Provider) grantCIBA(r *http.Request, rl core.Realm, cl core.Client, confidential bool) (map[string]any, *tokenErr) {
	ctx := r.Context()
	cs, ok := p.cibaStore()
	if !ok || !p.actionsOn() {
		return nil, &tokenErr{http.StatusNotImplemented, "feature_unavailable", "backchannel authentication is not available"}
	}
	if !confidential {
		return nil, oerr("unauthorized_client", "client may not use this grant")
	}
	on, err := p.cibaClientOK(ctx, cs, cl)
	if err != nil {
		p.cfg.Logger.Error("oidc: ciba client opt-in", "err", err)
		return nil, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	if !on {
		return nil, oerr("unauthorized_client", "client may not use this grant")
	}
	id := r.PostForm.Get("auth_req_id")
	if id == "" || len(id) > 256 {
		return nil, oerr("invalid_request", "auth_req_id is required")
	}
	hash := HashSecret(id)
	now := p.now()
	// Unknown ids and ids of another client or realm look identical.
	bad := oerr("invalid_grant", "invalid auth_req_id")
	d, tooFast, err := cs.PollCIBA(ctx, rl.Name, cl.ClientID, hash, now)
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return nil, bad
		}
		p.cfg.Logger.Error("oidc: poll ciba", "err", err)
		return nil, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	if !now.Before(d.ExpiresAt) {
		return nil, oerr("expired_token", "the auth_req_id has expired")
	}
	if tooFast {
		return nil, oerr("slow_down", fmt.Sprintf("polling too fast; interval is now %d seconds", d.Interval))
	}
	switch d.Status {
	case core.CIBAPending:
		return nil, oerr("authorization_pending", "the user has not decided yet")
	case core.CIBADenied:
		return nil, oerr("access_denied", "the user denied the request")
	case core.CIBAApproved:
	default:
		return nil, bad
	}
	// Single use: whoever deletes the row issues the tokens.
	d, err = cs.ConsumeCIBA(ctx, rl.Name, cl.ClientID, hash, now)
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return nil, bad
		}
		p.cfg.Logger.Error("oidc: consume ciba", "err", err)
		return nil, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	u, err := p.cfg.Store.GetUser(ctx, rl.Name, d.UserID)
	if err != nil || d.UserID == "" || !u.Enabled {
		return nil, bad
	}
	if d.SessionID == "" || !p.sessionAlive(r, rl.Name, d.SessionID) {
		return nil, bad
	}
	// No refresh token (issueRefresh=false): a CIBA client asks again, and the
	// user approves again, for the next action.
	resp, terr := p.issue(r, rl, cl, u, d.Scope, "", d.AuthTime, randToken(16), "", false, cibaGrant, d.SessionID, true)
	if terr != nil {
		return nil, terr
	}
	p.event(ctx, rl, "CIBA_TOKEN", u.ID, cl.ClientID, p.clientIP(r), "")
	return resp, nil
}

// ---- approval UI ----

const cibaNotValid = "This request is not valid, has expired, or was already answered."

type cibaView struct {
	Title, Nonce, Realm, CSRF, Action, Token string
	Mode                                     string // approve | done
	Client, User, Binding                    string
	Scopes, Resources                        []string
	IP, When, Ago                            string
	Approved                                 bool
}

var cibaTmpl = template.Must(template.New("ciba").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
<style nonce="{{.Nonce}}">
body{font-family:system-ui,sans-serif;background:#f4f5f7;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center}
main{background:#fff;padding:2rem;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.15);width:min(28rem,92vw)}
h1{font-size:1.25rem;margin:0 0 1rem}
button{margin-top:1rem;width:100%;padding:.6rem;font-size:1rem;cursor:pointer}
.row{display:flex;gap:.75rem}.row form{flex:1}.sub{color:#555;font-size:.9rem}
.warn{background:#fff4e5;border:1px solid #f0b95b;padding:.6rem;border-radius:4px;font-size:.9rem;margin:1rem 0}
blockquote{margin:.5rem 0;padding:.5rem .75rem;border-left:4px solid #888;background:#f4f5f7;word-break:break-word}
dl{font-size:.9rem;margin:.5rem 0}dt{color:#555;margin-top:.4rem}dd{margin:0;word-break:break-word}
ul{margin:.25rem 0 .5rem;padding-left:1.2rem;font-size:.95rem;word-break:break-word}
.deny{background:#fff;border:1px solid #888}
</style></head><body><main>
<h1>{{.Title}}</h1>
{{if eq .Mode "approve"}}
<p><strong>{{.Client}}</strong> is asking to act for <strong>{{.User}}</strong> in {{.Realm}}.</p>
{{if .Binding}}<p class="sub">Message from the application (Haven cannot verify it):</p><blockquote>{{.Binding}}</blockquote>{{end}}
<p class="sub">If you approve, it will be able to:</p>
<ul>{{range .Scopes}}<li>{{.}}</li>{{end}}</ul>
{{if .Resources}}<p class="sub">It says it wants to use these resources:</p><ul>{{range .Resources}}<li>{{.}}</li>{{end}}</ul>{{end}}
<dl><dt>Request came from</dt><dd>{{.IP}}</dd>
<dt>Requested</dt><dd>{{.When}} ({{.Ago}})</dd></dl>
<p class="warn"><strong>Only approve if you (or an agent you set up) just asked for this.</strong> If you did not, deny it: someone may be trying to use your account.</p>
<div class="row">
<form method="post" action="{{.Action}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="req" value="{{.Token}}"><input type="hidden" name="decision" value="approve"><button type="submit">Approve</button></form>
<form method="post" action="{{.Action}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="req" value="{{.Token}}"><input type="hidden" name="decision" value="deny"><button type="submit" class="deny">Deny</button></form>
</div>
{{else}}
{{if .Approved}}<p>You approved the request. You can close this window.</p>
{{else}}<p>You denied the request. Nothing was shared. You can close this window.</p>{{end}}
{{end}}
</main></body></html>`))

func (p *Provider) cibaRender(w http.ResponseWriter, rl core.Realm, status int, v cibaView) {
	nonce := randToken(16)
	v.Nonce = nonce
	v.Realm = rl.DisplayName
	if v.Realm == "" {
		v.Realm = rl.Name
	}
	v.Action = p.cibaURL(rl.Name) + "/approve"
	if v.Mode == "approve" {
		csrf := p.newCSRF(rl.Name)
		v.CSRF = csrf
		// #nosec G124 -- HttpOnly and SameSite are set; Secure follows p.secure (config-driven, off only for plain-HTTP dev installs)
		http.SetCookie(w, &http.Cookie{Name: cibaCSRFCookie, Value: csrf, Path: "/realms/" + rl.Name + "/ciba",
			HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(csrfTTL.Seconds())})
	}
	p.pageHeaders(w, nonce)
	w.WriteHeader(status)
	_ = cibaTmpl.Execute(w, v)
}

func (p *Provider) cibaRealm(w http.ResponseWriter, r *http.Request) (core.Realm, core.CIBAStore, bool) {
	rl, ok := p.realm(r.Context(), r.PathValue("realm"))
	if !ok {
		p.errorPage(w, http.StatusNotFound, "Unknown realm.")
		return rl, nil, false
	}
	cs, ok := p.cibaStore()
	if !ok || !p.actionsOn() {
		p.errorPage(w, http.StatusNotImplemented, "This kind of approval is not available.")
		return rl, nil, false
	}
	return rl, cs, true
}

// cibaLoad applies the lookup rate limits and loads the pending request behind
// an approval token, plus its client. It writes the error response itself and
// reports whether the caller may go on. Unknown, expired, decided and
// unaddressable requests are one and the same answer.
func (p *Provider) cibaLoad(w http.ResponseWriter, r *http.Request, rl core.Realm, cs core.CIBAStore, token string) (core.CIBARequest, core.Client, bool) {
	ctx := r.Context()
	ip := p.clientIP(r)
	for _, l := range []struct {
		ip  string
		max int
	}{{ip, cibaLookupPerIP}, {"", cibaLookupPerRealm}} {
		ok, err := p.hitLimit(ctx, "cibaapr", rl.Name, l.ip, l.max)
		if err != nil {
			p.cfg.Logger.Error("oidc: ciba lookup rate limit", "err", err)
			p.errorPage(w, http.StatusServiceUnavailable, "Temporary error. Try again.")
			return core.CIBARequest{}, core.Client{}, false
		}
		if !ok {
			w.Header().Set("Retry-After", "600")
			p.errorPage(w, http.StatusTooManyRequests, "Too many attempts. Wait a few minutes and try again.")
			return core.CIBARequest{}, core.Client{}, false
		}
	}
	notValid := func() (core.CIBARequest, core.Client, bool) {
		p.errorPage(w, http.StatusBadRequest, cibaNotValid)
		return core.CIBARequest{}, core.Client{}, false
	}
	if token == "" || len(token) > 256 {
		return notValid()
	}
	row, err := cs.GetCIBAByApproval(ctx, rl.Name, HashSecret(token))
	if err != nil {
		if !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: ciba lookup", "err", err)
			p.errorPage(w, http.StatusServiceUnavailable, "Temporary error. Try again.")
			return core.CIBARequest{}, core.Client{}, false
		}
		return notValid()
	}
	if row.UserID == "" || row.Status != core.CIBAPending || !p.now().Before(row.ExpiresAt) {
		return notValid()
	}
	cl, err := p.cfg.Store.GetClientByClientID(ctx, rl.Name, row.ClientID)
	if err != nil {
		return notValid()
	}
	if on, err := p.cibaClientOK(ctx, cs, cl); err != nil || !on {
		return notValid()
	}
	return row, cl, true
}

// cibaApprover returns the signed-in user when they are the addressee and
// signed in recently enough to decide.
func (p *Provider) cibaApprover(w http.ResponseWriter, r *http.Request, rl core.Realm, row core.CIBARequest) (core.Session, core.User, bool, bool) {
	s, u, signedIn := p.deviceSessionUser(w, r, rl)
	if !signedIn {
		return s, u, false, false
	}
	if u.ID != row.UserID {
		return s, u, false, true // wrong account
	}
	if p.now().Sub(s.AuthTime) > cibaAuthFresh {
		return s, u, false, false // stale: sign in again
	}
	return s, u, true, false
}

// cibaLogin sends the browser through the ordinary authorization endpoint with
// prompt=login, as the built-in approval client. The code that comes back is
// never exchanged (the PKCE verifier does not exist); the point is
// completeLogin, which runs every login rule, factor and step-up policy (with
// the request's real scope, so "sensitive scope" policies apply) and starts a
// fresh SSO session.
func (p *Provider) cibaLogin(w http.ResponseWriter, r *http.Request, rl core.Realm, row core.CIBARequest, token string) {
	verifier := randToken(32)
	sum := sha256.Sum256([]byte(verifier)) // discarded: the code is unredeemable
	q := url.Values{
		"client_id":             {cibaClientID},
		"response_type":         {"code"},
		"redirect_uri":          {p.cibaURL(rl.Name) + "/continue"},
		"scope":                 {row.Scope},
		"prompt":                {"login"},
		"state":                 {p.signPending(rl.Name, "", cibaStatePurpose, token, 15*time.Minute)},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	noStore(w)
	http.Redirect(w, r, p.endpoint(rl.Name, "auth")+"?"+q.Encode(), http.StatusSeeOther)
}

func (p *Provider) cibaApprovePage(w http.ResponseWriter, rl core.Realm, row core.CIBARequest, cl core.Client, u core.User, token string) {
	name := cibaDisplay(cl.Name, 80)
	if name == "" {
		name = cibaDisplay(cl.ClientID, 80)
	}
	var scopes []string
	for _, s := range strings.Fields(row.Scope) {
		if w, ok := scopeWords[s]; ok {
			scopes = append(scopes, w)
		}
	}
	ago := p.now().Sub(row.CreatedAt).Round(time.Minute)
	agoS := "just now"
	if ago >= time.Minute {
		agoS = fmt.Sprintf("%d min ago", int(ago.Minutes()))
	}
	ip := row.RequestIP
	if ip == "" {
		ip = "unknown"
	}
	p.cibaRender(w, rl, http.StatusOK, cibaView{Title: "Approve this request?", Mode: "approve", Token: token,
		Client: name, User: u.Username, Binding: row.Binding, Scopes: scopes, Resources: row.Resources, IP: ip,
		When: row.CreatedAt.UTC().Format("2006-01-02 15:04:05 UTC"), Ago: agoS})
}

// cibaApprove serves GET (show) and POST (decide) /realms/{realm}/ciba/approve.
func (p *Provider) cibaApprove(w http.ResponseWriter, r *http.Request) {
	rl, cs, ok := p.cibaRealm(w, r)
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		p.cibaShow(w, r, rl, cs, r.URL.Query().Get("req"), false)
		return
	}
	if err := r.ParseForm(); err != nil {
		p.errorPage(w, http.StatusBadRequest, "Invalid request.")
		return
	}
	form := r.PostForm.Get("csrf")
	ck, err := r.Cookie(cibaCSRFCookie)
	if err != nil || form == "" || !hmac.Equal([]byte(ck.Value), []byte(form)) || !p.checkCSRF(rl.Name, form) {
		p.cfg.Obs.Login(rl.Name, "csrf")
		p.errorPage(w, http.StatusForbidden, "Your session expired or the request was invalid. Open the link from your email again.")
		return
	}
	dec := r.PostForm.Get("decision")
	if dec != "approve" && dec != "deny" {
		p.errorPage(w, http.StatusBadRequest, "Invalid request.")
		return
	}
	token := r.PostForm.Get("req")
	row, cl, ok := p.cibaLoad(w, r, rl, cs, token)
	if !ok {
		return
	}
	s, u, fresh, wrong := p.cibaApprover(w, r, rl, row)
	if wrong {
		p.errorPage(w, http.StatusForbidden, "This request is not addressed to the account you are signed in with.")
		return
	}
	if !fresh {
		p.cibaLogin(w, r, rl, row, token) // session ended or went stale meanwhile
		return
	}
	approve := dec == "approve"
	d := core.CIBADecision{}
	if approve {
		// The client becomes part of the session so ending it also notifies
		// (back-channel logout) and revokes what the client received.
		if err := p.cfg.Store.AddSessionClient(r.Context(), rl.Name, s.ID, cl.ClientID); err != nil {
			p.cfg.Logger.Error("oidc: record ciba client in session", "err", err)
			p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
			return
		}
		d = core.CIBADecision{Approve: true, SessionID: s.ID, AuthTime: s.AuthTime}
	}
	if _, err := cs.DecideCIBA(r.Context(), rl.Name, HashSecret(token), u.ID, p.now(), d); err != nil {
		if errors.Is(err, idp.ErrNotFound) { // decided or expired in the meantime
			p.errorPage(w, http.StatusBadRequest, cibaNotValid)
			return
		}
		p.cfg.Logger.Error("oidc: decide ciba", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return
	}
	typ, title := "CIBA_DENY", "Request denied"
	if approve {
		typ, title = "CIBA_APPROVE", "Request approved"
	}
	p.event(r.Context(), rl, typ, u.ID, cl.ClientID, p.clientIP(r), "")
	p.cibaRender(w, rl, http.StatusOK, cibaView{Title: title, Mode: "done", Approved: approve})
}

// cibaShow shows the approval page, sending the browser through login first
// when it has no fresh session of the addressee. afterLogin is true on the
// landing page of that login: a second round of login is then an error, not
// another redirect (no loops).
func (p *Provider) cibaShow(w http.ResponseWriter, r *http.Request, rl core.Realm, cs core.CIBAStore, token string, afterLogin bool) {
	row, cl, ok := p.cibaLoad(w, r, rl, cs, token)
	if !ok {
		return
	}
	_, u, fresh, wrong := p.cibaApprover(w, r, rl, row)
	switch {
	case wrong:
		p.errorPage(w, http.StatusForbidden, "This request is not addressed to the account you signed in with. Sign in as the account that received the email.")
	case !fresh && afterLogin:
		p.errorPage(w, http.StatusUnauthorized, "Sign-in did not complete. Open the link from your email again.")
	case !fresh:
		p.cibaLogin(w, r, rl, row, token)
	default:
		p.cibaApprovePage(w, rl, row, cl, u, token)
	}
}

// cibaContinue is where the login redirect lands. It reads the SSO session the
// login created and never touches the authorization code.
func (p *Provider) cibaContinue(w http.ResponseWriter, r *http.Request) {
	rl, cs, ok := p.cibaRealm(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	if code := q.Get("code"); code != "" {
		// Hygiene only: drop the unusable code now instead of at expiry.
		_, _ = p.cfg.Store.ConsumeAuthCode(r.Context(), HashSecret(code))
	}
	_, token, valid := p.checkPending(rl.Name, q.Get("state"), cibaStatePurpose)
	if !valid || q.Get("error") != "" {
		p.errorPage(w, http.StatusBadRequest, "Sign-in did not complete. Open the link from your email again.")
		return
	}
	p.cibaShow(w, r, rl, cs, token, true)
}
