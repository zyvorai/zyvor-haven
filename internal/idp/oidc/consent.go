// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// The consent screen. Every authorization of a third-party client (CIMD,
// dynamically registered, or any client the realm policy names) ends here
// before a code is issued:
//
//   - issueCode calls consentGateHook. It either lets the code through (no
//     consent needed, or a remembered grant still covers the request) or renders
//     the consent page.
//   - The page posts back to the original /auth URL, so the whole authorization
//     request (client, redirect URI, PKCE, scope) is re-validated from scratch;
//     consentContinue (an authContinueHook) handles the decision after the CSRF
//     check that login() already did.
//
// Nothing the page shows or accepts is trusted: names are escaped, the
// redirect URI is the exactly-registered one, and the decision is bound to the
// SSO session of the logged-in user.

const (
	consentProofTTL = 10 * time.Minute
	consentLimit    = 60 // decisions per user and window
	consentWindow   = time.Minute
)

type consentDoneKey struct{}

// consentGateHook is set below; issueCode (authorize.go) calls it first.
var consentGateHook func(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User, s core.Session, detail string) bool

func init() {
	consentGateHook = (*Provider).consentGate
	registerAuthStep(nil, consentContinue)
	registerFeature(func(p *Provider, mux *http.ServeMux) {
		mux.HandleFunc("GET /realms/{realm}/account/consents", p.accountConsents)
		mux.HandleFunc("POST /realms/{realm}/account/consents", p.accountConsents)
	})
	registerDiscovery(func(p *Provider, realm string, doc map[string]any) {
		cs, ok := p.consentStore()
		if !ok {
			return
		}
		doc["prompt_values_supported"] = []string{"none", "login", "consent"}
		if pol, err := p.consentPolicy(context.Background(), cs, realm); err == nil && pol.CIMDEnabled {
			doc["client_id_metadata_document_supported"] = true
		}
	})
}

func (p *Provider) consentStore() (core.ConsentStore, bool) {
	return core.StoreAs[core.ConsentStore](p.cfg.Store)
}

// ---- who needs consent ----

type consentSubject struct {
	kind string // "cimd" | "dcr" | "configured"
	name string
	uri  string
	fp   string
}

// consentSubjectOf reports whether the client must be shown at the consent
// screen. ok=false: no consent needed. CIMD and dynamically registered clients
// always need it; others only when the realm policy says so.
func (p *Provider) consentSubjectOf(ctx context.Context, cs core.ConsentStore, pol core.ConsentPolicy, cl core.Client) (s consentSubject, ok bool, err error) {
	if cl.ClientID == deviceClientID {
		return s, false, nil // the device page has its own approval step
	}
	s.fp = core.ClientFingerprint(cl.ClientID, cl.Name, cl.RedirectURIs)
	s.name = cl.Name
	if s.name == "" {
		s.name = cl.ClientID
	}
	if cc, e := cs.GetConsentClient(ctx, cl.Realm, cl.ClientID); e == nil {
		s.kind, s.uri = "cimd", cc.ClientURI
		return s, true, nil
	} else if !errors.Is(e, idp.ErrNotFound) {
		return s, false, e
	}
	if dc, have := core.StoreAs[core.DCRStore](p.cfg.Store); have {
		if rc, e := dc.GetRegisteredClient(ctx, cl.Realm, cl.ClientID); e == nil {
			s.kind, s.uri = "dcr", rc.ClientURI
			return s, true, nil
		} else if !errors.Is(e, idp.ErrNotFound) {
			return s, false, e
		}
	}
	if pol.RequireAll && !slices.Contains(pol.SkipClients, cl.ClientID) {
		s.kind = "configured"
		return s, true, nil
	}
	return s, false, nil
}

// consentResources are the resources of the request as the consent screen shows
// and records them: the canonical, allow-listed set (resources.go) that the
// issued tokens are bound to, sorted.
func consentResources(ar *authzReq) []string {
	out := slices.Clone(ar.resources)
	slices.Sort(out)
	return out
}

// scopeOpenID cannot be unticked: without it there is no sign-in at all.
const scopeOpenID = "openid"

// grantedScopes is the requested scope narrowed to what the posted form ticked.
// ok is false when the form names a scope that was not requested.
func grantedScopes(requested string, ticked []string) (granted, declined []string, ok bool) {
	req := strings.Fields(requested)
	for _, t := range ticked {
		if !slices.Contains(req, t) {
			return nil, nil, false
		}
	}
	for _, s := range req {
		if s == scopeOpenID || slices.Contains(ticked, s) {
			granted = append(granted, s)
		} else {
			declined = append(declined, s)
		}
	}
	return granted, declined, true
}

func sortedScopes(scope string) []string {
	s := strings.Fields(scope)
	sort.Strings(s)
	return s
}

// consentDigest binds the decision to what the page showed.
func consentDigest(fp string, scopes, resources []string) string {
	h := sha256.New()
	for _, part := range [][]string{{fp}, scopes, resources} {
		h.Write([]byte(strings.Join(part, "\x1f")))
		h.Write([]byte{0x1e})
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// ---- gate ----

func (p *Provider) consentGate(w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User, s core.Session, detail string) bool {
	cs, on := p.consentStore()
	if !on || r.Context().Value(consentDoneKey{}) != nil {
		return false
	}
	ctx, rl := r.Context(), ar.realm
	fail := func(code, desc string) bool {
		p.redirectErr(w, r, ar.redirect, ar.state, rl.Name, code, desc)
		return true
	}
	pol, err := p.consentPolicy(ctx, cs, rl.Name)
	if err != nil {
		p.cfg.Logger.Error("oidc: consent policy", "err", err)
		return fail("server_error", "could not check consent")
	}
	subj, need, err := p.consentSubjectOf(ctx, cs, pol, ar.client)
	if err != nil {
		p.cfg.Logger.Error("oidc: consent subject", "err", err)
		return fail("server_error", "could not check consent")
	}
	if !need {
		return false
	}
	ar.limited = true // the tokens carry what the user consented to, no more
	if _, err := cs.GetConsentBlock(ctx, rl.Name, ar.client.ClientID); err == nil {
		return fail("access_denied", "this application has been blocked")
	} else if !errors.Is(err, idp.ErrNotFound) {
		return fail("server_error", "could not check consent")
	}
	resources := consentResources(ar)
	scopes := sortedScopes(ar.scope)
	prompts := strings.Fields(r.URL.Query().Get("prompt"))
	remember := subj.kind != "cimd" || pol.RememberCIMD
	if remember && !slices.Contains(prompts, "consent") {
		g, err := cs.GetActiveConsentGrant(ctx, rl.Name, u.ID, ar.client.ClientID, p.now())
		if err == nil && g.Fingerprint == subj.fp && g.Covers(scopes, resources) {
			return false // already consented, nothing changed
		}
		if err != nil && !errors.Is(err, idp.ErrNotFound) {
			return fail("server_error", "could not check consent")
		}
	}
	if slices.Contains(prompts, "none") {
		return fail("consent_required", "user consent is required")
	}
	p.consentPage(w, r, ar, u, s, subj, scopes, resources, "", http.StatusOK)
	return true
}

// ---- page ----

type scopeInfo struct {
	Name, Desc string
	Required   bool
}

type consentView struct {
	ClientName, ClientID, ClientURI, Redirect, Note, Proof string
	Scopes                                                 []scopeInfo
	Resources                                              []string
	AccountURL                                             string
}

var scopeDesc = map[string]string{
	"openid":         "confirm who you are",
	"profile":        "read your name and username",
	"email":          "read your email address",
	"roles":          "read your roles in this realm",
	"offline_access": "keep access after you sign out (until you revoke it)",
}

const consentBody = `{{with .Data}}<p><strong>{{.ClientName}}</strong> is asking to access your account.</p>
<p class="sub">{{.Note}}</p>
<p class="sub">Application identifier:<br><code>{{.ClientID}}</code></p>
{{if .ClientURI}}<p class="sub">Website it claims (not verified):<br><code>{{.ClientURI}}</code></p>{{end}}
<p class="sub">If you allow, your browser returns to:<br><code>{{.Redirect}}</code></p>
{{if .Resources}}<p class="sub">For these services (the access tokens are valid there):</p><ul>{{range .Resources}}<li><code>{{.}}</code></li>{{end}}</ul>{{end}}
<p class="sub">You can review and revoke this later on your account page: <code>{{.AccountURL}}</code></p>
<form method="post" action="{{$.Action}}"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="consent_proof" value="{{.Proof}}">
<p class="sub">It will be able to (untick anything you do not want to allow):</p>
<ul>{{range .Scopes}}<li><label class="check"><input type="checkbox" name="consent_scope" value="{{.Name}}" checked{{if .Required}} disabled{{end}}><span><code>{{.Name}}</code>: {{.Desc}}{{if .Required}} (required){{end}}</span></label></li>{{end}}</ul>
<button type="submit" name="consent_decision" value="allow">Allow</button>
<button type="submit" name="consent_decision" value="deny" class="secondary">Deny</button></form>{{end}}`

func (p *Provider) consentPage(w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User, s core.Session, subj consentSubject, scopes, resources []string, errMsg string, status int) {
	rl := ar.realm
	csrf := p.newCSRF(rl.Name)
	// #nosec G124 -- HttpOnly and SameSite are set; Secure follows p.secure (config-driven, off only for plain-HTTP dev installs)
	http.SetCookie(w, &http.Cookie{Name: csrfCookie, Value: csrf, Path: "/realms/" + rl.Name + oidcPath + "/auth",
		HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(csrfTTL.Seconds())})
	nonce := randToken(16)
	p.pageHeaders(w, nonce) // nonce'd style-src only, no script, frame-ancestors none, X-Frame-Options DENY
	// The proof says: this page was rendered for this user in this SSO session
	// for exactly this client and request. A decision without it is refused, so
	// posting straight to /auth with a stolen SSO cookie cannot skip the checks
	// ssoReuse applies (max_age, step-up, prompt=login).
	digest := consentDigest(subj.fp, scopes, resources)
	v := consentView{ClientName: subj.name, ClientID: ar.client.ClientID, ClientURI: subj.uri, Redirect: ar.redirect,
		Resources: resources, Proof: p.signPending(rl.Name, u.ID, "consent", s.ID+"|"+digest, consentProofTTL),
		AccountURL: p.base + "/realms/" + rl.Name + "/account/consents"}
	switch subj.kind {
	case "cimd":
		v.Note = "This application identifies itself with a web address. Anyone can publish such a document, so continue only if you just started this from that application."
	case "dcr":
		v.Note = "This application registered itself automatically. Your administrator has not reviewed it."
	default:
		v.Note = "Your administrator requires you to approve this application."
	}
	for _, s := range scopes {
		d := scopeDesc[s]
		if d == "" {
			d = "use this permission"
		}
		v.Scopes = append(v.Scopes, scopeInfo{s, d, s == scopeOpenID})
	}
	disp := rl.DisplayName
	if disp == "" {
		disp = rl.Name
	}
	w.WriteHeader(status)
	_ = stepTemplate(consentBody).Execute(w, StepData{Title: "Allow access to " + disp, Nonce: nonce, CSRF: csrf, Realm: disp,
		Client: subj.name, Error: errMsg, Action: r.URL.Path + "?" + r.URL.RawQuery, Data: v})
}

// ---- decision ----

func (p *Provider) consentLimited(ctx context.Context, realm, userID string) (denied bool) {
	sum := sha256.Sum256([]byte("consent|" + realm + "|" + userID))
	ok, err := p.cfg.Store.HitRateLimit(ctx, hex.EncodeToString(sum[:]), p.now(), consentWindow, consentLimit)
	if err != nil {
		p.cfg.Logger.Error("oidc: consent rate limit", "err", err)
		return true
	}
	return !ok
}

// consentContinue handles the consent form posted to /auth. CSRF was verified
// by login() before the continue hooks run.
func consentContinue(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq) bool {
	decision := r.PostForm.Get("consent_decision")
	if decision == "" {
		return false
	}
	cs, on := p.consentStore()
	if !on {
		p.errorPage(w, http.StatusNotFound, "Not found.")
		return true
	}
	ctx, rl := r.Context(), ar.realm
	expired := func() bool {
		p.errorPage(w, http.StatusForbidden, "Your session expired. Start again from the application.")
		return true
	}
	sess, ok := p.currentSession(r, rl)
	if !ok {
		return expired()
	}
	u, err := p.cfg.Store.GetUser(ctx, rl.Name, sess.UserID)
	if err != nil || !u.Enabled || (rl.EmailVerificationRequired && !u.EmailVerified) {
		if err != nil && !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: consent load user", "err", err)
		}
		return expired()
	}
	pol, err := p.consentPolicy(ctx, cs, rl.Name)
	if err != nil {
		p.cfg.Logger.Error("oidc: consent policy", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return true
	}
	subj, need, err := p.consentSubjectOf(ctx, cs, pol, ar.client)
	if err != nil {
		p.cfg.Logger.Error("oidc: consent subject", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return true
	}
	// The proof comes first: only a page the gate rendered for this user and
	// session can lead to a decision.
	proofUser, proofPayload, proofOK := p.checkPending(rl.Name, r.PostForm.Get("consent_proof"), "consent")
	sessID, proofDigest, _ := strings.Cut(proofPayload, "|")
	if !proofOK || proofUser != u.ID || sessID != sess.ID {
		return expired()
	}
	if !need { // policy changed meanwhile: nothing to decide, start over
		p.errorPage(w, http.StatusConflict, "This request changed. Start again from the application.")
		return true
	}
	if _, err := cs.GetConsentBlock(ctx, rl.Name, ar.client.ClientID); err == nil {
		p.redirectErr(w, r, ar.redirect, ar.state, rl.Name, "access_denied", "this application has been blocked")
		return true
	}
	resources := consentResources(ar)
	scopes := sortedScopes(ar.scope)
	if p.consentLimited(ctx, rl.Name, u.ID) {
		p.errorPage(w, http.StatusTooManyRequests, "Too many attempts. Wait a minute and try again.")
		return true
	}
	// The decision must be for what the page showed: if the client's identity
	// or the request changed in between, show the page again.
	if proofDigest != consentDigest(subj.fp, scopes, resources) {
		p.consentPage(w, r, ar, u, sess, subj, scopes, resources, "The application's details changed. Review them and decide again.", http.StatusConflict)
		return true
	}
	rc := core.ConsentReceipt{Realm: rl.Name, Time: p.now(), UserID: u.ID, ClientID: ar.client.ClientID, ClientName: subj.name,
		Scopes: scopes, Resources: resources, Actor: u.ID}
	switch decision {
	case "deny":
		rc.Type = core.ReceiptDeny
		if _, err := cs.AppendConsentReceipt(ctx, rc); err != nil {
			p.cfg.Logger.Error("oidc: consent receipt", "err", err)
		}
		p.event(ctx, rl, "CONSENT_DENY", u.ID, ar.client.ClientID, p.clientIP(r), strings.Join(scopes, " "))
		p.redirectErr(w, r, ar.redirect, ar.state, rl.Name, "access_denied", "the user denied the request")
	case "allow":
		now := p.now()
		kept, declined, ok := grantedScopes(ar.scope, r.PostForm["consent_scope"])
		if !ok {
			p.errorPage(w, http.StatusBadRequest, "Invalid request.")
			return true
		}
		if len(kept) == 0 && len(declined) > 0 {
			p.consentPage(w, r, ar, u, sess, subj, scopes, resources, "Tick at least one permission, or press Deny.", http.StatusOK)
			return true
		}
		// Withdrawing a scope that was allowed before also ends the refresh
		// tokens that still carry it.
		if old, err := cs.GetActiveConsentGrant(ctx, rl.Name, u.ID, ar.client.ClientID, now); err == nil {
			if slices.ContainsFunc(declined, func(s string) bool { return slices.Contains(old.Scopes, s) }) {
				if _, err := cs.RevokeClientRefreshTokens(ctx, rl.Name, ar.client.ClientID, u.ID); err != nil {
					p.cfg.Logger.Error("oidc: consent withdraw scope", "err", err)
					p.redirectErr(w, r, ar.redirect, ar.state, rl.Name, "server_error", "could not record consent")
					return true
				}
			}
		} else if !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: consent load grant", "err", err)
			p.redirectErr(w, r, ar.redirect, ar.state, rl.Name, "server_error", "could not record consent")
			return true
		}
		// From here the request is for the granted subset only.
		ar.scope, ar.limited = strings.Join(kept, " "), true
		scopes = sortedScopes(ar.scope)
		rc.Scopes = scopes
		if len(declined) > 0 {
			rc.Detail = "declined: " + strings.Join(declined, " ")
		}
		g, err := cs.PutConsentGrant(ctx, core.ConsentGrant{Realm: rl.Name, UserID: u.ID, ClientID: ar.client.ClientID,
			ClientName: subj.name, Scopes: scopes, Resources: resources, Fingerprint: subj.fp, CreatedAt: now,
			ExpiresAt: now.Add(pol.GrantTTL())}, now)
		if err == nil {
			rc.Type = core.ReceiptGrant
			_, err = cs.AppendConsentReceipt(ctx, rc)
			if err != nil { // no receipt, no grant: fail closed
				_, _ = cs.RevokeConsentGrant(ctx, rl.Name, g.ID, "system", now)
			}
		}
		if err != nil {
			p.cfg.Logger.Error("oidc: consent grant", "err", err)
			p.redirectErr(w, r, ar.redirect, ar.state, rl.Name, "server_error", "could not record consent")
			return true
		}
		p.event(ctx, rl, "CONSENT_GRANT", u.ID, ar.client.ClientID, p.clientIP(r), strings.Join(scopes, " "))
		p.issueCode(w, r.WithContext(context.WithValue(ctx, consentDoneKey{}, true)), ar, u, sess, "consent")
	default:
		p.errorPage(w, http.StatusBadRequest, "Invalid request.")
	}
	return true
}

// ---- account page ----

type consentGrantRow struct {
	ID, ClientName, ClientID, Scopes, Resources string
	Granted, Expires                            string
}

type consentHistoryRow struct{ When, Type, Client, Scopes, By string }

type consentAcct struct {
	Info    string
	Grants  []consentGrantRow
	History []consentHistoryRow
}

const consentAcctBody = `{{with .Data}}{{if .Info}}<p class="sub">{{.Info}}</p>{{end}}
{{if not .Grants}}<p>No applications currently have remembered access to your account.</p>{{end}}
{{range .Grants}}<div class="item"><p><strong>{{.ClientName}}</strong><br><code>{{.ClientID}}</code><br>
<span class="sub">Scopes: {{.Scopes}}{{if .Resources}}<br>Services: {{.Resources}}{{end}}<br>Allowed {{.Granted}}, expires {{.Expires}}</span></p>
<form method="post" action="{{$.Action}}"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="action" value="revoke"><input type="hidden" name="grant_id" value="{{.ID}}">
<button type="submit" class="secondary">Revoke access</button></form></div>{{end}}
{{if .History}}<p class="sub"><strong>Recent activity</strong></p><ul>{{range .History}}<li class="sub">{{.When}}: {{.Type}} {{.Client}}{{if .Scopes}} ({{.Scopes}}){{end}}{{if .By}} by {{.By}}{{end}}</li>{{end}}</ul>{{end}}{{end}}`

func (p *Provider) accountConsents(w http.ResponseWriter, r *http.Request) {
	rl, ok := p.realm(r.Context(), r.PathValue("realm"))
	if !ok {
		p.errorPage(w, http.StatusNotFound, "Unknown realm.")
		return
	}
	cs, on := p.consentStore()
	if !on {
		p.errorPage(w, http.StatusNotFound, "Not found.")
		return
	}
	sess, ok := p.currentSession(r, rl)
	if !ok {
		p.errorPage(w, http.StatusUnauthorized, "Sign in first, then open this page again.")
		return
	}
	ctx := r.Context()
	u, err := p.cfg.Store.GetUser(ctx, rl.Name, sess.UserID)
	if err != nil || !u.Enabled {
		if err != nil && !isNotFound(err) {
			p.cfg.Logger.Error("oidc: consent account load user", "err", err)
		}
		p.errorPage(w, http.StatusForbidden, "Sign in first, then open this page again.")
		return
	}
	path := "/realms/" + rl.Name + "/account/consents"
	show := func(status int, info, errMsg string) {
		grants, err := cs.ListConsentGrants(ctx, rl.Name, u.ID, "", false, p.now(), 100)
		if err != nil {
			p.cfg.Logger.Error("oidc: list consent grants", "err", err)
			p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
			return
		}
		d := consentAcct{Info: info}
		for _, g := range grants {
			d.Grants = append(d.Grants, consentGrantRow{ID: g.ID, ClientName: g.ClientName, ClientID: g.ClientID,
				Scopes: strings.Join(g.Scopes, " "), Resources: strings.Join(g.Resources, " "),
				Granted: g.UpdatedAt.UTC().Format("2006-01-02 15:04 MST"), Expires: g.ExpiresAt.UTC().Format("2006-01-02")})
		}
		if all, err := cs.ListConsentReceipts(ctx, rl.Name, u.ID, 0, 0); err == nil {
			slices.Reverse(all)
			for i, rc := range all {
				if i == 10 {
					break
				}
				by := ""
				if rc.Actor != u.ID {
					by = rc.Actor
				}
				d.History = append(d.History, consentHistoryRow{When: rc.Time.UTC().Format("2006-01-02 15:04 MST"), Type: rc.Type,
					Client: rc.ClientName, Scopes: strings.Join(rc.Scopes, " "), By: by})
			}
		}
		p.mfaPage(w, r, rl, path, status, "Applications with access", errMsg, consentAcctBody, d)
	}
	if r.Method == http.MethodGet {
		show(http.StatusOK, "", "")
		return
	}
	if err := r.ParseForm(); err != nil {
		p.errorPage(w, http.StatusBadRequest, "Invalid request.")
		return
	}
	if !p.checkFormCSRF(r, rl.Name) {
		p.errorPage(w, http.StatusForbidden, "Your session expired or the request was invalid. Go back and try again.")
		return
	}
	if r.PostForm.Get("action") != "revoke" {
		show(http.StatusBadRequest, "", "Unknown action.")
		return
	}
	if p.consentLimited(ctx, rl.Name, u.ID) {
		p.errorPage(w, http.StatusTooManyRequests, "Too many attempts. Wait a minute and try again.")
		return
	}
	g, err := cs.GetConsentGrant(ctx, rl.Name, r.PostForm.Get("grant_id"))
	if err != nil || g.UserID != u.ID { // someone else's grant looks like a missing one
		show(http.StatusNotFound, "", "That access was not found.")
		return
	}
	if _, err := core.RevokeConsent(ctx, cs, g, u.ID, p.now()); err != nil && !errors.Is(err, idp.ErrConflict) {
		p.cfg.Logger.Error("oidc: revoke consent", "err", err)
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		return
	}
	p.event(ctx, rl, "CONSENT_REVOKE", u.ID, g.ClientID, p.clientIP(r), "by user")
	show(http.StatusOK, "Access revoked: "+g.ClientName+" can no longer refresh its tokens. Access tokens it already holds expire within minutes.", "")
}
