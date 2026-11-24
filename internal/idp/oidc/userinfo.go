// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func claimStr(c core.Claims, k string) string {
	s, _ := c[k].(string)
	return s
}

func claimNum(c core.Claims, k string) (int64, bool) {
	switch v := c[k].(type) {
	case float64:
		return int64(v), true
	case int64:
		return v, true
	case int:
		return int64(v), true
	case json.Number:
		n, err := v.Int64()
		return n, err == nil
	}
	return 0, false
}

func claimHasAud(c core.Claims, want string) bool {
	switch v := c["aud"].(type) {
	case string:
		return v == want
	case []string:
		return slices.Contains(v, want)
	case []any:
		for _, a := range v {
			if s, _ := a.(string); s == want {
				return true
			}
		}
	}
	return false
}

// verifyAccess checks signature, issuer, expiry, token type and that the
// audience is a client of the realm.
func (p *Provider) verifyAccess(r *http.Request, realm, tok string) (core.Claims, bool) {
	c, err := p.cfg.Signer.Verify(r.Context(), realm, tok)
	if err != nil {
		return nil, false
	}
	exp, ok := claimNum(c, "exp")
	if !ok || !p.now().Before(unix(exp)) {
		return nil, false
	}
	if claimStr(c, "iss") != p.issuer(realm) || claimStr(c, "typ") != "Bearer" {
		return nil, false
	}
	azp := claimStr(c, "azp")
	if azp == "" || !claimHasAud(c, azp) {
		return nil, false
	}
	cl, err := p.cfg.Store.GetClientByClientID(r.Context(), realm, azp)
	if err != nil || !cl.Enabled {
		return nil, false
	}
	// A token bound to an SSO session dies with it. Tokens without sid
	// (client_credentials, pre-SSO tokens) are unaffected.
	if sid := claimStr(c, "sid"); sid != "" && !p.sessionAlive(r, realm, sid) {
		return nil, false
	}
	return c, true
}

func (p *Provider) bearerErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="`+code+`"`)
	writeJSON(w, status, map[string]string{"error": code})
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("realm")
	if _, ok := p.realm(r.Context(), name); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "realm_not_found"})
		return
	}
	h := r.Header.Get("Authorization")
	scheme, tok, _ := strings.Cut(h, " ")
	if !(strings.EqualFold(scheme, "Bearer") || strings.EqualFold(scheme, "DPoP")) || strings.TrimSpace(tok) == "" {
		p.bearerErr(w, http.StatusUnauthorized, "invalid_request")
		return
	}
	tok = strings.TrimSpace(tok)
	c, ok := p.verifyAccess(r, name, tok)
	if !ok {
		p.bearerErr(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	if !p.dpopResource(w, r, name, c, scheme, tok, p.endpoint(name, "userinfo")) { // sender constraint (dpop.go)
		return
	}
	scopes := strings.Fields(claimStr(c, "scope"))
	if !slices.Contains(scopes, "openid") {
		p.bearerErr(w, http.StatusForbidden, "insufficient_scope")
		return
	}
	u, err := p.cfg.Store.GetUser(r.Context(), name, claimStr(c, "sub"))
	if err != nil || !u.Enabled {
		p.bearerErr(w, http.StatusUnauthorized, "invalid_token")
		return
	}
	out := map[string]any{"sub": u.ID, "preferred_username": u.Username}
	if slices.Contains(scopes, "email") {
		out["email"], out["email_verified"] = u.Email, u.EmailVerified
	}
	if slices.Contains(scopes, "profile") {
		out["given_name"], out["family_name"] = u.FirstName, u.LastName
		out["name"] = strings.TrimSpace(u.FirstName + " " + u.LastName)
	}
	writeJSON(w, http.StatusOK, out)
}

func (p *Provider) revoke(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("realm")
	if _, ok := p.realm(r.Context(), name); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "realm_not_found"})
		return
	}
	if err := r.ParseForm(); err != nil {
		p.writeTokenErr(w, oerr("invalid_request", "malformed body"), false)
		return
	}
	cl, _, basic, terr := p.authClient(r, name)
	if terr != nil {
		p.writeTokenErr(w, terr, basic)
		return
	}
	if tok := r.PostForm.Get("token"); tok != "" {
		rt, err := p.cfg.Store.GetRefreshToken(r.Context(), HashSecret(tok))
		if err == nil && rt.Realm == name && rt.ClientID == cl.ClientID {
			p.revokeFamily(r, rt.FamilyID)
		} else if err != nil && !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: revoke lookup", "err", err)
		}
	}
	// RFC 7009: success even for unknown tokens. Access tokens are
	// stateless and simply expire.
	noStore(w)
	w.WriteHeader(http.StatusOK)
}

func (p *Provider) introspect(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("realm")
	if _, ok := p.realm(r.Context(), name); !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "realm_not_found"})
		return
	}
	if err := r.ParseForm(); err != nil {
		p.writeTokenErr(w, oerr("invalid_request", "malformed body"), false)
		return
	}
	cl, confidential, basic, terr := p.authClient(r, name)
	if terr == nil && !confidential {
		terr = &tokenErr{http.StatusUnauthorized, "invalid_client", "client authentication required"}
	}
	if terr != nil {
		p.writeTokenErr(w, terr, basic)
		return
	}
	inactive := map[string]any{"active": false}
	tok := r.PostForm.Get("token")
	if tok == "" {
		writeJSON(w, http.StatusOK, inactive)
		return
	}
	if strings.Count(tok, ".") == 2 {
		c, ok := p.verifyAccess(r, name, tok)
		if !ok {
			writeJSON(w, http.StatusOK, inactive)
			return
		}
		out := map[string]any{"active": true, "token_type": "Bearer", "client_id": claimStr(c, "azp"),
			"scope": claimStr(c, "scope"), "sub": claimStr(c, "sub"), "iss": claimStr(c, "iss"),
			"aud": c["aud"], "jti": claimStr(c, "jti"), "username": claimStr(c, "preferred_username")}
		if cnf, ok := c["cnf"]; ok { // DPoP-bound: the resource server checks the proof against cnf.jkt
			out["cnf"], out["token_type"] = cnf, "DPoP"
		}
		if v, ok := claimNum(c, "exp"); ok {
			out["exp"] = v
		}
		if v, ok := claimNum(c, "iat"); ok {
			out["iat"] = v
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	rt, err := p.cfg.Store.GetRefreshToken(r.Context(), HashSecret(tok))
	if err != nil || rt.Realm != name || rt.Revoked || rt.Used || !p.now().Before(rt.ExpiresAt) {
		writeJSON(w, http.StatusOK, inactive)
		return
	}
	_ = cl
	cnf, cerr := p.dpopRefreshCnf(r.Context(), tok)
	if cerr != nil { // cannot tell whether it is key-bound: fail closed
		p.cfg.Logger.Error("oidc: introspect dpop binding", "err", cerr)
		writeJSON(w, http.StatusOK, inactive)
		return
	}
	out := map[string]any{"active": true, "token_type": "refresh_token", "client_id": rt.ClientID,
		"scope": rt.Scope, "sub": rt.UserID, "exp": rt.ExpiresAt.Unix(), "iat": rt.CreatedAt.Unix(),
		"iss": p.issuer(name)}
	if cnf != nil {
		out["cnf"] = cnf
	}
	writeJSON(w, http.StatusOK, out)
}

func unix(n int64) time.Time { return time.Unix(n, 0) }
