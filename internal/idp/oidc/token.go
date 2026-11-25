// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

type tokenErr struct {
	status int
	code   string
	desc   string
}

func (e *tokenErr) Error() string { return e.code }

func oerr(code, desc string) *tokenErr { return &tokenErr{http.StatusBadRequest, code, desc} }

func (p *Provider) writeTokenErr(w http.ResponseWriter, e *tokenErr, basic bool) {
	if e.status == http.StatusUnauthorized && basic {
		w.Header().Set("WWW-Authenticate", `Basic realm="haven-idp", charset="UTF-8"`)
	}
	writeJSON(w, e.status, map[string]string{"error": e.code, "error_description": e.desc})
}

// authClient authenticates the calling client from Basic or POST credentials.
// Public clients identify with client_id only. The returned bool reports
// whether the client authenticated with a secret.
// grantLabel bounds the grant label to the known grant types.
func grantLabel(g string) string {
	switch g {
	case "authorization_code", "refresh_token", "client_credentials":
		return g
	}
	return "other"
}

// tokenFail records a token endpoint error and writes it.
func (p *Provider) tokenFail(w http.ResponseWriter, e *tokenErr, basic bool, realm, grant string) {
	p.cfg.Obs.TokenError(realm, grant, e.code)
	p.writeTokenErr(w, e, basic)
}

func (p *Provider) authClient(r *http.Request, realm string) (core.Client, bool, bool, *tokenErr) {
	id, secret, basic := r.BasicAuth()
	if basic {
		var err error
		if id, err = url.QueryUnescape(id); err != nil {
			return core.Client{}, false, true, &tokenErr{http.StatusUnauthorized, "invalid_client", "bad client credentials"}
		}
		if secret, err = url.QueryUnescape(secret); err != nil {
			return core.Client{}, false, true, &tokenErr{http.StatusUnauthorized, "invalid_client", "bad client credentials"}
		}
		if r.PostForm.Get("client_secret") != "" {
			return core.Client{}, false, true, oerr("invalid_request", "multiple client authentication methods")
		}
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	bad := &tokenErr{http.StatusUnauthorized, "invalid_client", "client authentication failed"}
	if id == "" {
		return core.Client{}, false, basic, bad
	}
	cl, err := p.cfg.Store.GetClientByClientID(r.Context(), realm, id)
	if err != nil {
		secretEq(secret, HashSecret("x")) // keep timing similar
		return core.Client{}, false, basic, bad
	}
	if !cl.Enabled {
		return core.Client{}, false, basic, bad
	}
	if cl.Public {
		if secret != "" {
			return core.Client{}, false, basic, bad
		}
		return cl, false, basic, nil
	}
	if !secretEq(secret, cl.SecretHash) {
		return core.Client{}, false, basic, bad
	}
	return cl, true, basic, nil
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("realm")
	rl, ok := p.realm(r.Context(), name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "realm_not_found"})
		return
	}
	if err := r.ParseForm(); err != nil {
		p.tokenFail(w, oerr("invalid_request", "malformed body"), false, rl.Name, "other")
		return
	}
	grant := grantLabel(r.PostForm.Get("grant_type"))
	cl, confidential, basic, terr := p.authClient(r, name)
	if terr != nil {
		p.tokenFail(w, terr, basic, rl.Name, grant)
		return
	}
	if r, terr = p.dpopToken(w, r, rl); terr != nil { // DPoP (dpop.go): validate the proof
		p.tokenFail(w, terr, basic, rl.Name, grant)
		return
	}
	if r, terr = p.fapiToken(w, r, rl, cl); terr != nil { // fapi.go: require DPoP, dpop_jkt, authorization_details
		p.tokenFail(w, terr, basic, rl.Name, grant)
		return
	}
	var resp map[string]any
	switch g := r.PostForm.Get("grant_type"); g {
	case "authorization_code":
		resp, terr = p.grantCode(r, rl, cl)
	case "refresh_token":
		resp, terr = p.grantRefresh(r, rl, cl)
	case "client_credentials":
		resp, terr = p.grantClientCreds(r, rl, cl, confidential)
	default:
		if h, ok := grantHooks[g]; ok {
			resp, terr = h(p, r, rl, cl, confidential)
		} else {
			terr = oerr("unsupported_grant_type", "grant_type not supported")
		}
	}
	if terr == nil {
		terr = p.dpopTokenDone(w, r, rl, cl, resp) // DPoP: bind the refresh token
	}
	if terr == nil {
		terr = p.fapiTokenDone(r, rl, cl, resp) // fapi.go: report and bind authorization_details
	}
	if terr != nil {
		p.tokenFail(w, terr, basic, rl.Name, grant)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (p *Provider) grantCode(r *http.Request, rl core.Realm, cl core.Client) (map[string]any, *tokenErr) {
	ctx := r.Context()
	if !cl.AuthCodeFlow {
		return nil, oerr("unauthorized_client", "client may not use this grant")
	}
	code := r.PostForm.Get("code")
	if code == "" {
		return nil, oerr("invalid_request", "code is required")
	}
	hash := HashSecret(code)
	ac, err := p.cfg.Store.ConsumeAuthCode(ctx, hash)
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			p.revokeForReplayedCode(r, rl.Name, hash)
			return nil, oerr("invalid_grant", "invalid or expired code")
		}
		p.cfg.Logger.Error("oidc: consume code", "err", err)
		return nil, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	bad := oerr("invalid_grant", "invalid or expired code")
	if ac.Realm != rl.Name || ac.ClientID != cl.ClientID || !p.now().Before(ac.ExpiresAt) {
		return nil, bad
	}
	if subtle.ConstantTimeCompare([]byte(r.PostForm.Get("redirect_uri")), []byte(ac.RedirectURI)) != 1 {
		return nil, oerr("invalid_grant", "redirect_uri mismatch")
	}
	if ac.CodeChallenge != "" {
		v := r.PostForm.Get("code_verifier")
		if len(v) < 43 || len(v) > 128 || ac.ChallengeMeth != "S256" {
			return nil, oerr("invalid_grant", "PKCE verification failed")
		}
		sum := sha256.Sum256([]byte(v))
		got := base64.RawURLEncoding.EncodeToString(sum[:])
		if subtle.ConstantTimeCompare([]byte(got), []byte(ac.CodeChallenge)) != 1 {
			return nil, oerr("invalid_grant", "PKCE verification failed")
		}
	} else if cl.Public || cl.RequirePKCE {
		return nil, bad
	}
	u, err := p.cfg.Store.GetUser(ctx, rl.Name, ac.UserID)
	if err != nil || !u.Enabled {
		return nil, bad
	}
	// A code issued in an SSO session is worthless once that session is over
	// (logout between redirect and exchange).
	if ac.SessionID != "" && !p.sessionAlive(r, rl.Name, ac.SessionID) {
		return nil, bad
	}
	granted, rok := decodeResources(code) // resources.go: the set carried by the code string
	if !rok {
		return nil, bad
	}
	aud, kept, terr := p.resolveResources(r, rl, cl, granted, false)
	if terr != nil {
		return nil, terr
	}
	r = withResources(r, aud, kept)
	family := randToken(16)
	resp, terr := p.issue(r, rl, cl, u, ac.Scope, ac.Nonce, ac.AuthTime, family, "", true, "authorization_code", ac.SessionID, ac.SessionID != "")
	if terr != nil {
		return nil, terr
	}
	p.rememberCode(hash, family, ac.ExpiresAt)
	return resp, nil
}

func (p *Provider) rememberCode(hash, family string, exp time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	// Keep the memory of a code only as long as a replay is plausible.
	exp = exp.Add(24 * time.Hour)
	if len(p.codeFams) >= 10000 {
		for k, v := range p.codeFams {
			if now.After(v.expires) {
				delete(p.codeFams, k)
			}
		}
		for k := range p.codeFams {
			if len(p.codeFams) < 10000 {
				break
			}
			delete(p.codeFams, k)
		}
	}
	p.codeFams[hash] = codeFam{family: family, expires: exp}
}

func (p *Provider) revokeForReplayedCode(r *http.Request, realm, hash string) {
	p.mu.Lock()
	cf, ok := p.codeFams[hash]
	if ok {
		delete(p.codeFams, hash)
	}
	p.mu.Unlock()
	if ok && p.now().Before(cf.expires) {
		p.cfg.Obs.CodeReplay(realm)
		if err := p.cfg.Store.RevokeRefreshFamily(r.Context(), cf.family); err != nil {
			p.cfg.Logger.Error("oidc: revoke family on code replay", "err", err)
		}
	}
}

func (p *Provider) grantRefresh(r *http.Request, rl core.Realm, cl core.Client) (map[string]any, *tokenErr) {
	ctx := r.Context()
	if !cl.AuthCodeFlow && !cl.DeviceFlow { // device-flow clients refresh the tokens they were given
		return nil, oerr("unauthorized_client", "client may not use this grant")
	}
	raw := r.PostForm.Get("refresh_token")
	if raw == "" {
		return nil, oerr("invalid_request", "refresh_token is required")
	}
	hash := HashSecret(raw)
	bad := oerr("invalid_grant", "invalid refresh token")
	rt, err := p.cfg.Store.GetRefreshToken(ctx, hash)
	if err != nil {
		if !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: load refresh token", "err", err)
		}
		return nil, bad
	}
	if rt.Realm != rl.Name || rt.ClientID != cl.ClientID || rt.Revoked || !p.now().Before(rt.ExpiresAt) || rt.UserID == "" {
		return nil, bad
	}
	if rt.Used {
		p.refreshReuse(r, rl.Name, rt.FamilyID)
		return nil, bad
	}
	// Online refresh tokens live and die with their SSO session; offline ones
	// outlive it (but their access tokens then carry no sid).
	sidLive := false
	if rt.SessionID != "" {
		sidLive = p.sessionAlive(r, rl.Name, rt.SessionID)
		if !sidLive && !slices.Contains(strings.Fields(rt.Scope), "offline_access") {
			p.revokeFamily(r, rt.FamilyID)
			return nil, bad
		}
	}
	scope := rt.Scope
	if s := r.PostForm.Get("scope"); s != "" {
		for _, f := range strings.Fields(s) {
			if !slices.Contains(strings.Fields(rt.Scope), f) {
				return nil, oerr("invalid_scope", "scope exceeds the original grant")
			}
		}
		scope = filterScope(s)
	}
	u, err := p.cfg.Store.GetUser(ctx, rl.Name, rt.UserID)
	if err != nil || !u.Enabled {
		return nil, bad
	}
	granted, rok := decodeResources(raw) // resources.go
	if !rok {
		return nil, bad
	}
	aud, kept, terr := p.resolveResources(r, rl, cl, granted, false)
	if terr != nil {
		return nil, terr
	}
	r = withResources(r, aud, kept)
	newRefresh := ""
	if rl.RefreshTokenRotation {
		if err := p.cfg.Store.MarkRefreshUsed(ctx, hash); err != nil {
			if errors.Is(err, idp.ErrConflict) {
				p.refreshReuse(r, rl.Name, rt.FamilyID)
				return nil, bad
			}
			p.cfg.Logger.Error("oidc: mark refresh used", "err", err)
			return nil, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
		}
	} else {
		newRefresh = raw
	}
	resp, terr := p.issue(r, rl, cl, u, scope, "", time.Time{}, rt.FamilyID, newRefresh, newRefresh == "", "refresh_token", rt.SessionID, sidLive)
	if terr != nil {
		return nil, terr
	}
	if sidLive {
		p.touchSession(r, rl, core.Session{ID: rt.SessionID})
	}
	if newRefresh != "" {
		resp["refresh_token"] = newRefresh
		resp["refresh_expires_in"] = int(rt.ExpiresAt.Sub(p.now()).Seconds())
	}
	return resp, nil
}

// refreshReuse reports a reused refresh token and revokes its family.
func (p *Provider) refreshReuse(r *http.Request, realm, family string) {
	p.cfg.Obs.RefreshReuse(realm)
	p.revokeFamily(r, family)
}

func (p *Provider) revokeFamily(r *http.Request, family string) {
	if err := p.cfg.Store.RevokeRefreshFamily(r.Context(), family); err != nil {
		p.cfg.Logger.Error("oidc: revoke refresh family", "err", err)
	}
}

func (p *Provider) grantClientCreds(r *http.Request, rl core.Realm, cl core.Client, confidential bool) (map[string]any, *tokenErr) {
	if !confidential || cl.Public || !cl.ServiceAccount {
		return nil, oerr("unauthorized_client", "client may not use this grant")
	}
	if err := p.ensureKey(r.Context(), rl.Name); err != nil {
		p.cfg.Logger.Error("oidc: ensure key", "err", err)
		return nil, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	scope := filterScope(strings.ReplaceAll(r.PostForm.Get("scope"), "offline_access", ""))
	scope = strings.Join(slices.DeleteFunc(strings.Fields(scope), func(s string) bool { return s == "openid" }), " ")
	aud, _, terr := p.resolveResources(r, rl, cl, nil, true) // resources.go
	if terr != nil {
		return nil, terr
	}
	now := p.now()
	ttl := rl.AccessTokenTTL
	if ttl <= 0 {
		ttl = defaultAccess
	}
	claims := core.Claims{
		"iss": p.issuer(rl.Name), "sub": "service-account-" + cl.ClientID, "aud": audClaim(cl.ClientID, aud),
		"azp": cl.ClientID, "exp": now.Add(ttl).Unix(), "iat": now.Unix(), "jti": randToken(16),
		"typ": "Bearer", "scope": scope, "client_id": cl.ClientID,
		"realm_access": map[string]any{"roles": []string{}},
	}
	dpopBindClaims(r.Context(), claims)
	at, err := p.cfg.Signer.Sign(r.Context(), rl.Name, claims)
	if err != nil {
		p.cfg.Logger.Error("oidc: sign access token", "err", err)
		return nil, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	p.cfg.Obs.TokenIssued(rl.Name, "client_credentials", "access")
	resp := map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": int(ttl.Seconds()), "scope": scope}
	dpopTokenType(r.Context(), resp)
	return resp, nil
}

// issue builds the token response for a user. When newFamily is true a
// refresh token may be issued (and stored) in family.
func (p *Provider) issue(r *http.Request, rl core.Realm, cl core.Client, u core.User, scope, nonce string,
	authTime time.Time, family, _ string, issueRefresh bool, grant, sid string, sidLive bool) (map[string]any, *tokenErr) {
	ctx := r.Context()
	if err := p.ensureKey(ctx, rl.Name); err != nil {
		p.cfg.Logger.Error("oidc: ensure key", "err", err)
		return nil, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	now := p.now()
	ttl := rl.AccessTokenTTL
	if ttl <= 0 {
		ttl = defaultAccess
	}
	scopes := strings.Fields(scope)
	roles := p.effectiveRoles(ctx, rl, u) // permanent roles + active time-boxed grants
	iss := p.issuer(rl.Name)
	rg := resourcesOf(ctx) // resources.go: RFC 8707 audience / refresh-carried set
	atClaims := core.Claims{
		"iss": iss, "sub": u.ID, "aud": audClaim(cl.ClientID, rg.aud), "azp": cl.ClientID,
		"exp": now.Add(ttl).Unix(), "iat": now.Unix(), "jti": randToken(16),
		"typ": "Bearer", "scope": scope, "preferred_username": u.Username,
		"realm_access": map[string]any{"roles": roles},
	}
	if sid != "" && sidLive {
		atClaims["sid"] = sid
	}
	dpopBindClaims(ctx, atClaims)
	fapiBindClaims(ctx, atClaims)
	at, err := p.cfg.Signer.Sign(ctx, rl.Name, atClaims)
	if err != nil {
		p.cfg.Logger.Error("oidc: sign access token", "err", err)
		return nil, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	resp := map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": int(ttl.Seconds()), "scope": scope}
	dpopTokenType(ctx, resp)

	if slices.Contains(scopes, "openid") {
		sum := sha256.Sum256([]byte(at))
		idc := core.Claims{
			"iss": iss, "sub": u.ID, "aud": cl.ClientID, "azp": cl.ClientID,
			"exp": now.Add(ttl).Unix(), "iat": now.Unix(), "typ": "ID",
			"at_hash":            base64.RawURLEncoding.EncodeToString(sum[:16]),
			"preferred_username": u.Username,
		}
		if sid != "" && sidLive {
			idc["sid"] = sid
		}
		if !authTime.IsZero() {
			idc["auth_time"] = authTime.Unix()
		}
		if nonce != "" {
			idc["nonce"] = nonce
		}
		if slices.Contains(scopes, "email") {
			idc["email"], idc["email_verified"] = u.Email, u.EmailVerified
		}
		if slices.Contains(scopes, "profile") {
			idc["given_name"], idc["family_name"] = u.FirstName, u.LastName
			idc["name"] = strings.TrimSpace(u.FirstName + " " + u.LastName)
		}
		p.addGroupsClaim(rl.Name, cl, u, scopes, idc) // groupsclaim.go: opted-in clients that were granted "groups"
		idt, err := p.cfg.Signer.Sign(ctx, rl.Name, idc)
		if err != nil {
			p.cfg.Logger.Error("oidc: sign id token", "err", err)
			return nil, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
		}
		resp["id_token"] = idt
	}

	issuedRefresh := false
	if issueRefresh && (slices.Contains(scopes, "offline_access") || rl.RefreshTokenTTL > 0) {
		rtl := rl.RefreshTokenTTL
		if rtl <= 0 {
			rtl = defaultRefresh
		}
		raw := randToken(32) + encodeResources(rg.granted)
		err := p.cfg.Store.PutRefreshToken(ctx, core.RefreshToken{
			TokenHash: HashSecret(raw), FamilyID: family, Realm: rl.Name, ClientID: cl.ClientID,
			UserID: u.ID, SessionID: sid, Scope: scope, ExpiresAt: now.Add(rtl), CreatedAt: now,
		})
		if err != nil {
			p.cfg.Logger.Error("oidc: store refresh token", "err", err)
			return nil, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
		}
		resp["refresh_token"] = raw
		resp["refresh_expires_in"] = int(rtl.Seconds())
		issuedRefresh = true
	}
	// Report only once everything was issued successfully.
	p.cfg.Obs.TokenIssued(rl.Name, grant, "access")
	if _, ok := resp["id_token"]; ok {
		p.cfg.Obs.TokenIssued(rl.Name, grant, "id")
	}
	if issuedRefresh {
		p.cfg.Obs.TokenIssued(rl.Name, grant, "refresh")
	}
	return resp, nil
}
