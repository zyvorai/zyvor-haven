// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/safehttp"
	"github.com/zyvorai/haven/internal/idp/upstream"
)

// Identity brokering: "Sign in with <upstream OIDC provider>".
//
//	GET .../broker/{alias}/login?<original /auth query>
//	    validates the original authorization request, stores a single-use
//	    login state (only hashes of the state and of a browser-binding cookie),
//	    and redirects to the upstream authorization endpoint with PKCE S256 and
//	    a nonce.
//	GET .../broker/{alias}/endpoint?code&state
//	    checks the state (single use) and the binding cookie, exchanges the code,
//	    fully validates the ID token, resolves the local user and finishes with
//	    completeLogin exactly like a password login.
//
// The feature is off (404) when the store has no core.FedStore.

const (
	fedCookie        = "haven_fed"
	fedStateTTL      = 10 * time.Minute
	fedLoginWindow   = 5 * time.Minute
	fedLoginLimit    = 30
	fedMaxQuery      = 4096
	fedMaxEmail      = 320
	fedMaxUsername   = 64
	fedUsernameTries = 50
)

// federatedRunsAuthSteps makes federated logins run the local second-factor
// hooks (authStepHooks). Off: the upstream provider already authenticated the
// user. Kept as a switch so a realm/provider option can enable it later.
const federatedRunsAuthSteps = false

func init() {
	registerFeature(func(p *Provider, mux *http.ServeMux) {
		if p.cfg.Federation == nil {
			p.cfg.Federation = upstream.NewManager(safehttp.Options{}, p.cfg.Clock)
		}
		b := "/realms/{realm}/broker/{alias}"
		mux.HandleFunc("GET "+b+"/login", p.brokerLogin)
		mux.HandleFunc("GET "+b+"/endpoint", p.brokerEndpoint)
	})
}

func (p *Provider) fedStore() (core.FedStore, bool) { return core.StoreAs[core.FedStore](p.cfg.Store) }

// fedButton is one "Continue with ..." entry on the login page.
type fedButton struct{ Name, URL string }

// loginProviders lists the enabled providers of the realm for the login page.
// Errors and a missing store show no buttons.
func (p *Provider) loginProviders(r *http.Request, rl core.Realm) []fedButton {
	fs, ok := p.fedStore()
	if !ok {
		return nil
	}
	ps, err := fs.ListFedProviders(r.Context(), rl.Name)
	if err != nil {
		p.cfg.Logger.Error("oidc: list identity providers", "err", err)
		return nil
	}
	var out []fedButton
	for _, fp := range ps {
		if !fp.Enabled {
			continue
		}
		out = append(out, fedButton{Name: fp.DisplayName,
			URL: "/realms/" + rl.Name + "/broker/" + fp.Alias + "/login?" + r.URL.RawQuery})
	}
	return out
}

func (p *Provider) brokerFail(w http.ResponseWriter, rl core.Realm, r *http.Request, clientID, alias, kind string, status int, msg string) {
	p.cfg.Obs.Login(rl.Name, "federated_error")
	p.cfg.Logger.Warn("oidc: federated login failed", "realm", rl.Name, "alias", alias, "kind", kind)
	p.event(r.Context(), rl, "LOGIN_ERROR", "", clientID, p.clientIP(r), "federated:"+alias+":"+kind)
	noStore(w)
	p.simplePage(w, status, "Sign-in failed", msg)
}

const (
	msgUnavailable = "The external sign-in provider could not be reached or rejected the request. Close this page and try again from the application."
	msgExpired     = "Your sign-in request expired or was not started in this browser. Close this page and start again from the application."
)

func fedKey(purpose, realm, ip string) string {
	h := sha256.Sum256([]byte(purpose + "|" + realm + "|" + ip))
	return hex.EncodeToString(h[:])
}

// parseAuthzQuery re-validates an original authorization request exactly as
// /auth does (client, exact redirect URI, state, response_type, PKCE rules)
// and returns the request, or a message for the error page.
func (p *Provider) parseAuthzQuery(ctx context.Context, rl core.Realm, q url.Values) (*authzReq, string) {
	cl, err := p.cfg.Store.GetClientByClientID(ctx, rl.Name, q.Get("client_id"))
	if err != nil || !cl.Enabled || !cl.AuthCodeFlow {
		return nil, "Invalid client."
	}
	ru := q.Get("redirect_uri")
	if ru == "" || !slices.Contains(cl.RedirectURIs, ru) || !safeRedirect(ru) {
		return nil, "Invalid redirect URI."
	}
	if q.Get("state") == "" || q.Get("response_type") != "code" || q.Get("request") != "" || q.Get("request_uri") != "" {
		return nil, "Invalid authorization request."
	}
	if m := q.Get("response_mode"); m != "" && m != "query" {
		return nil, "Invalid authorization request."
	}
	ch, meth := q.Get("code_challenge"), q.Get("code_challenge_method")
	if ch == "" {
		if cl.Public || cl.RequirePKCE {
			return nil, "Invalid authorization request."
		}
	} else if meth != "S256" || !validChallenge(ch) {
		return nil, "Invalid authorization request."
	}
	ar := &authzReq{realm: rl, client: cl, redirect: ru, state: q.Get("state"), challenge: ch,
		scope: filterScope(q.Get("scope")), nonce: q.Get("nonce")}
	if len(ar.nonce) > 512 {
		return nil, "Invalid authorization request."
	}
	return ar, ""
}

// fedVerifier derives the PKCE verifier from the state with the server key, so
// no secret is stored. (Replicas need the same CSRFKey, as for the login form.)
func (p *Provider) fedVerifier(realm, alias, state string) string {
	m := hmac.New(sha256.New, p.csrfKey)
	m.Write([]byte("fed-pkce|" + realm + "|" + alias + "|" + state))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (p *Provider) fedRedirectURI(realm, alias string) string {
	return p.base + "/realms/" + realm + "/broker/" + alias + "/endpoint"
}

func (p *Provider) fedCookiePath(realm string) string { return "/realms/" + realm + "/broker" }

// fedProvider loads an enabled provider and its spec.
func (p *Provider) fedProvider(ctx context.Context, fs core.FedStore, realm, alias string) (core.FedProvider, upstream.Spec, bool) {
	fp, err := fs.GetFedProvider(ctx, realm, alias)
	if err != nil || !fp.Enabled {
		return fp, upstream.Spec{}, false
	}
	spec, _, err := upstream.ParseConfig(fp.ProviderType, fp.Config, p.cfg.Federation.AllowPrivate())
	if err != nil {
		p.cfg.Logger.Error("oidc: stored identity provider config is invalid", "realm", realm, "alias", alias)
		return fp, upstream.Spec{}, false
	}
	return fp, spec, true
}

func (p *Provider) brokerLogin(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	realm, alias := r.PathValue("realm"), r.PathValue("alias")
	rl, ok := p.realm(r.Context(), realm)
	fs, haveStore := p.fedStore()
	if !ok || !haveStore {
		p.errorPage(w, http.StatusNotFound, "Unknown realm.")
		return
	}
	if len(r.URL.RawQuery) > fedMaxQuery {
		p.errorPage(w, http.StatusBadRequest, "Invalid authorization request.")
		return
	}
	ar, msg := p.parseAuthzQuery(r.Context(), rl, r.URL.Query())
	if ar == nil {
		p.errorPage(w, http.StatusBadRequest, msg)
		return
	}
	_, spec, ok := p.fedProvider(r.Context(), fs, realm, alias)
	if !ok {
		p.errorPage(w, http.StatusNotFound, "This sign-in option is not available.")
		return
	}
	allowed, err := p.cfg.Store.HitRateLimit(r.Context(), fedKey("fedlogin", realm, p.clientIP(r)), p.now(), fedLoginWindow, fedLoginLimit)
	if err != nil {
		p.cfg.Logger.Error("oidc: federation rate limit store error; treating as limited", "err", err)
	}
	if err != nil || !allowed {
		p.errorPage(w, http.StatusTooManyRequests, "Too many sign-in attempts. Wait a few minutes and try again.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	disc, err := p.cfg.Federation.Discover(ctx, spec)
	if err != nil {
		p.brokerFail(w, rl, r, ar.client.ClientID, alias, upstreamKind(err), http.StatusBadGateway, msgUnavailable)
		return
	}

	state, nonce := randToken(32), randToken(24)
	browser := p.fedBrowserToken(r, rl.Name)
	err = fs.PutFedState(r.Context(), core.FedLoginState{
		StateHash: HashSecret(state), Realm: rl.Name, Alias: alias, BrowserHash: HashSecret(browser),
		Nonce: nonce, AuthQuery: r.URL.RawQuery, ExpiresAt: p.now().Add(fedStateTTL),
	})
	if err != nil {
		p.cfg.Logger.Error("oidc: store federation state", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return
	}
	ch := sha256.Sum256([]byte(p.fedVerifier(rl.Name, alias, state)))
	dest, err := upstream.AuthURL(spec, disc, p.fedRedirectURI(rl.Name, alias), state, nonce, base64.RawURLEncoding.EncodeToString(ch[:]))
	if err != nil {
		p.errorPage(w, http.StatusBadGateway, msgUnavailable)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: fedCookie, Value: browser, Path: p.fedCookiePath(rl.Name),
		HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteLaxMode, MaxAge: int(fedStateTTL.Seconds())})
	http.Redirect(w, r, dest, http.StatusFound)
}

// fedBrowserToken returns the browser-binding token: the existing cookie when
// it is well formed (so parallel tabs keep working), else a fresh one.
func (p *Provider) fedBrowserToken(r *http.Request, realm string) string {
	if ck, err := r.Cookie(fedCookie); err == nil && len(ck.Value) == 43 {
		if _, err := base64.RawURLEncoding.DecodeString(ck.Value); err == nil {
			return ck.Value
		}
	}
	return randToken(32)
}

func upstreamKind(err error) string {
	var ue *upstream.Error
	if errors.As(err, &ue) {
		return ue.Kind
	}
	return "error"
}

func (p *Provider) brokerEndpoint(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	realm, alias := r.PathValue("realm"), r.PathValue("alias")
	rl, ok := p.realm(r.Context(), realm)
	fs, haveStore := p.fedStore()
	if !ok || !haveStore {
		p.errorPage(w, http.StatusNotFound, "Unknown realm.")
		return
	}
	q := r.URL.Query()
	state := q.Get("state")
	if state == "" || len(state) > 200 {
		p.brokerFail(w, rl, r, "", alias, "no_state", http.StatusBadRequest, msgExpired)
		return
	}
	// Single use: the state is burned by the first request that presents it,
	// whatever happens next.
	st, err := fs.ConsumeFedState(r.Context(), HashSecret(state))
	if err != nil {
		p.brokerFail(w, rl, r, "", alias, "unknown_state", http.StatusBadRequest, msgExpired)
		return
	}
	if st.Realm != rl.Name || st.Alias != alias || !p.now().Before(st.ExpiresAt) {
		p.brokerFail(w, rl, r, "", alias, "state_mismatch", http.StatusBadRequest, msgExpired)
		return
	}
	ck, err := r.Cookie(fedCookie)
	if err != nil || ck.Value == "" || subtle.ConstantTimeCompare([]byte(HashSecret(ck.Value)), []byte(st.BrowserHash)) != 1 {
		p.cfg.Obs.Login(rl.Name, "csrf")
		p.brokerFail(w, rl, r, "", alias, "browser_mismatch", http.StatusBadRequest, msgExpired)
		return
	}
	authQ, err := url.ParseQuery(st.AuthQuery)
	if err != nil {
		p.brokerFail(w, rl, r, "", alias, "bad_query", http.StatusBadRequest, msgExpired)
		return
	}
	ar, msg := p.parseAuthzQuery(r.Context(), rl, authQ)
	if ar == nil {
		p.errorPage(w, http.StatusBadRequest, msg)
		return
	}
	cid := ar.client.ClientID
	fp, spec, ok := p.fedProvider(r.Context(), fs, realm, alias)
	if !ok {
		p.brokerFail(w, rl, r, cid, alias, "provider_unavailable", http.StatusNotFound, "This sign-in option is not available.")
		return
	}
	if q.Get("error") != "" {
		// The upstream refused (for example the user cancelled). Nothing from the
		// response is echoed.
		p.brokerFail(w, rl, r, cid, alias, "upstream_denied", http.StatusForbidden, "Sign-in with "+fp.DisplayName+" was cancelled or denied.")
		return
	}
	code := q.Get("code")
	if code == "" || len(code) > 4096 {
		p.brokerFail(w, rl, r, cid, alias, "no_code", http.StatusBadRequest, msgUnavailable)
		return
	}
	secret := ""
	if fp.ClientSecretSealed != "" {
		if p.cfg.SecretBox == nil {
			p.brokerFail(w, rl, r, cid, alias, "no_secret_key", http.StatusServiceUnavailable, msgUnavailable)
			return
		}
		b, err := p.cfg.SecretBox.Open(fp.ClientSecretSealed, "idp|"+rl.Name+"|"+alias)
		if err != nil {
			p.brokerFail(w, rl, r, cid, alias, "secret_unreadable", http.StatusServiceUnavailable, msgUnavailable)
			return
		}
		secret = string(b)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	disc, err := p.cfg.Federation.Discover(ctx, spec)
	if err != nil {
		p.brokerFail(w, rl, r, cid, alias, upstreamKind(err), http.StatusBadGateway, msgUnavailable)
		return
	}
	idTok, err := p.cfg.Federation.Exchange(ctx, spec, disc, secret, code, p.fedRedirectURI(rl.Name, alias), p.fedVerifier(rl.Name, alias, state))
	if err != nil {
		p.brokerFail(w, rl, r, cid, alias, upstreamKind(err), http.StatusBadGateway, msgUnavailable)
		return
	}
	claims, err := p.cfg.Federation.VerifyIDToken(ctx, spec, disc, idTok, st.Nonce)
	if err != nil {
		p.brokerFail(w, rl, r, cid, alias, upstreamKind(err), http.StatusBadGateway, msgUnavailable)
		return
	}

	u, link, why := p.fedResolve(r.Context(), rl, fp, spec, claims)
	if why != "" {
		switch why {
		case "disabled":
			p.cfg.Obs.Login(rl.Name, "disabled")
			p.brokerFail(w, rl, r, cid, alias, why, http.StatusForbidden, "Your account is disabled.")
		case "no_account":
			p.brokerFail(w, rl, r, cid, alias, why, http.StatusForbidden, "No account is linked to this "+fp.DisplayName+" identity, and new accounts are not created automatically. Ask an administrator.")
		case "email_exists":
			p.brokerFail(w, rl, r, cid, alias, why, http.StatusForbidden, "An account with this email address already exists but cannot be linked automatically. Sign in with your existing method or ask an administrator to link it.")
		case "link_conflict":
			p.brokerFail(w, rl, r, cid, alias, why, http.StatusForbidden, "This account is already linked to a different "+fp.DisplayName+" identity. Ask an administrator.")
		default:
			p.brokerFail(w, rl, r, cid, alias, why, http.StatusInternalServerError, "Temporary error. Try again.")
		}
		return
	}
	if err := p.fedSyncRoles(r.Context(), rl, spec, &u, link, claims); err != nil {
		p.cfg.Logger.Error("oidc: federated role sync", "err", err)
		p.brokerFail(w, rl, r, cid, alias, "role_sync", http.StatusInternalServerError, "Temporary error. Try again.")
		return
	}
	if rl.EmailVerificationRequired && !u.EmailVerified {
		msg := "Your email address has not been verified. Verify it before signing in."
		if p.sendAsync(rl, u, core.ActionVerifyEmail) {
			msg = "Your email address has not been verified. We sent a verification link to the address on file: open it, then sign in again."
		}
		p.brokerFail(w, rl, r, cid, alias, "email_not_verified", http.StatusForbidden, msg)
		return
	}
	if federatedRunsAuthSteps {
		for _, h := range authStepHooks {
			if h(p, w, r, ar, u) {
				return
			}
		}
	}
	p.completeLogin(w, r, ar, u, "federated:"+alias)
}

// fedResolve maps validated claims to a local user. It returns a short reason
// code when the login must be refused ("" = ok).
func (p *Provider) fedResolve(ctx context.Context, rl core.Realm, fp core.FedProvider, spec upstream.Spec, claims upstream.Claims) (core.User, core.FedLink, string) {
	fs, _ := p.fedStore()
	sub := upstream.Subject(spec, claims)
	email := strings.ToLower(strings.TrimSpace(claims.Str("email")))
	if len(email) > fedMaxEmail || strings.ContainsAny(email, "\x00\r\n\t ") {
		email = ""
	}
	// An address counts as proven only if the provider is configured to be
	// trusted for it AND the upstream says it verified it.
	trusted := fp.TrustEmail && upstream.EmailVerified(spec, claims) && email != ""

	link, err := fs.GetFedLink(ctx, rl.Name, fp.Alias, sub)
	switch {
	case err == nil:
		u, err := p.cfg.Store.GetUser(ctx, rl.Name, link.UserID)
		if err == nil {
			if !u.Enabled {
				return u, link, "disabled"
			}
			return u, link, ""
		}
		if !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: load federated user", "err", err)
			return core.User{}, link, "store"
		}
		// The user is gone (a store without cascading deletes): the link is dead.
		_ = fs.DeleteFedLink(ctx, rl.Name, fp.Alias, link.UserID)
	case !errors.Is(err, idp.ErrNotFound):
		p.cfg.Logger.Error("oidc: load federated link", "err", err)
		return core.User{}, link, "store"
	}

	// No link yet. Does a local account already own this email address?
	var same []core.User
	if email != "" {
		same, err = p.usersWithEmail(ctx, rl.Name, email)
		if err != nil {
			p.cfg.Logger.Error("oidc: look up users by email", "err", err)
			return core.User{}, link, "store"
		}
	}
	if len(same) > 0 {
		// Linking to an existing account is the account-takeover vector of
		// identity brokering: only when explicitly enabled, the provider is
		// trusted for email, the upstream verified the address, exactly one
		// account matches and that account has no link for this provider yet.
		if !(spec.LinkByEmail && trusted && len(same) == 1) {
			return core.User{}, link, "email_exists"
		}
		u := same[0]
		ls, err := fs.ListFedLinksByUser(ctx, rl.Name, u.ID)
		if err != nil {
			return core.User{}, link, "store"
		}
		for _, l := range ls {
			if l.Alias == fp.Alias {
				return core.User{}, link, "link_conflict"
			}
		}
		if !u.Enabled {
			return u, link, "disabled"
		}
		nl := core.FedLink{Realm: rl.Name, Alias: fp.Alias, Subject: sub, UserID: u.ID, CreatedAt: p.now(), LastLoginAt: p.now()}
		if err := fs.CreateFedLink(ctx, nl); err != nil {
			if errors.Is(err, idp.ErrConflict) {
				return core.User{}, link, "link_conflict"
			}
			return core.User{}, link, "store"
		}
		return u, nl, ""
	}
	if !spec.AutoCreate {
		return core.User{}, link, "no_account"
	}
	return p.fedCreateUser(ctx, rl, fp, spec, claims, sub, email, trusted)
}

// usersWithEmail returns the local users whose email equals addr
// (case-insensitive). The store has no email index, so it scans the search
// results in pages, capped.
func (p *Provider) usersWithEmail(ctx context.Context, realm, addr string) ([]core.User, error) {
	var out []core.User
	const page = 200
	for off := 0; off < 20000; off += page {
		us, err := p.cfg.Store.ListUsers(ctx, realm, addr, off, page)
		if err != nil {
			return nil, err
		}
		for _, u := range us {
			if strings.EqualFold(strings.TrimSpace(u.Email), addr) {
				out = append(out, u)
			}
		}
		if len(us) < page {
			break
		}
	}
	return out, nil
}

func sanitizeUsername(s string) string {
	var b strings.Builder
	for _, c := range strings.ToLower(strings.TrimSpace(s)) {
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-', c == '@', c == '+':
			b.WriteRune(c)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if len(out) > fedMaxUsername-8 {
		out = out[:fedMaxUsername-8]
	}
	return out
}

func (p *Provider) fedCreateUser(ctx context.Context, rl core.Realm, fp core.FedProvider, spec upstream.Spec, claims upstream.Claims, sub, email string, trusted bool) (core.User, core.FedLink, string) {
	fs, _ := p.fedStore()
	base := sanitizeUsername(claims.Str(spec.UsernameClaim))
	if base == "" && email != "" {
		base = sanitizeUsername(strings.SplitN(email, "@", 2)[0])
	}
	if base == "" {
		base = "user"
	}
	first, last := claims.Str("given_name"), claims.Str("family_name")
	for _, s := range []*string{&first, &last} {
		if len(*s) > 255 || hasControl(*s) {
			*s = ""
		}
	}
	for i := 0; i < fedUsernameTries+5; i++ {
		name := base
		switch {
		case i == 0:
		case i <= fedUsernameTries:
			name = base + strconv.Itoa(i+1)
		default:
			name = base + "-" + strings.ToLower(randToken(5))
		}
		u := core.User{Realm: rl.Name, Username: name, Email: email, FirstName: first, LastName: last,
			Enabled: true, EmailVerified: trusted}
		err := p.cfg.Store.CreateUser(ctx, u)
		if errors.Is(err, idp.ErrConflict) {
			continue
		}
		if err != nil {
			p.cfg.Logger.Error("oidc: create federated user", "err", err)
			return core.User{}, core.FedLink{}, "store"
		}
		stored, err := p.cfg.Store.GetUserByUsername(ctx, rl.Name, name)
		if err != nil {
			return core.User{}, core.FedLink{}, "store"
		}
		nl := core.FedLink{Realm: rl.Name, Alias: fp.Alias, Subject: sub, UserID: stored.ID, CreatedAt: p.now(), LastLoginAt: p.now()}
		if err := fs.CreateFedLink(ctx, nl); err != nil {
			// Lost a race with a concurrent first login of the same identity:
			// drop our duplicate and use the winner's.
			_ = p.cfg.Store.DeleteUser(ctx, rl.Name, stored.ID)
			if errors.Is(err, idp.ErrConflict) {
				if l, err := fs.GetFedLink(ctx, rl.Name, fp.Alias, sub); err == nil {
					if w, err := p.cfg.Store.GetUser(ctx, rl.Name, l.UserID); err == nil {
						if !w.Enabled {
							return w, l, "disabled"
						}
						return w, l, ""
					}
				}
			}
			return core.User{}, core.FedLink{}, "store"
		}
		return stored, nl, ""
	}
	return core.User{}, core.FedLink{}, "username_exhausted"
}

func hasControl(s string) bool {
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return true
		}
	}
	return false
}

// fedSyncRoles applies the provider's claim-to-role mappings and records the
// login time. Roles that do not exist in the realm are skipped. Mode "import"
// only adds. Mode "sync" also removes roles federation itself added earlier
// (recorded in link.MappedRoles) that the mappings no longer grant. A role an
// administrator assigned is never recorded as mapped, so it is never removed.
func (p *Provider) fedSyncRoles(ctx context.Context, rl core.Realm, spec upstream.Spec, u *core.User, link core.FedLink, claims upstream.Claims) error {
	fs, _ := p.fedStore()
	mapped := slices.Clone(link.MappedRoles)
	changed := false
	if len(spec.Rules) > 0 {
		desired := upstream.MapRoles(spec.Rules, claims)
		if len(desired) > 0 {
			known, err := p.cfg.Store.ListRoles(ctx, rl.Name)
			if err != nil {
				return err
			}
			exists := map[string]bool{}
			for _, r := range known {
				exists[r.Name] = true
			}
			for _, name := range desired {
				if exists[name] && !slices.Contains(u.Roles, name) {
					u.Roles = append(u.Roles, name)
					if !slices.Contains(mapped, name) {
						mapped = append(mapped, name)
					}
					changed = true
				}
			}
		}
		if spec.RoleSync == upstream.SyncForce {
			var keep []string
			for _, name := range mapped {
				if slices.Contains(desired, name) {
					keep = append(keep, name)
					continue
				}
				if i := slices.Index(u.Roles, name); i >= 0 {
					u.Roles = slices.Delete(slices.Clone(u.Roles), i, i+1)
					changed = true
				}
			}
			mapped = keep
		}
	}
	if changed {
		if err := p.cfg.Store.UpdateUser(ctx, *u); err != nil {
			return err
		}
	}
	slices.Sort(mapped)
	link.MappedRoles, link.LastLoginAt = mapped, p.now()
	return fs.UpdateFedLink(ctx, link)
}
