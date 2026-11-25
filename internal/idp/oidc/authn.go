// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// Authentication context (amr, acr, auth_time) and step-up (RFC 9470). See
// docs/step-up-acr.md.
//
//   - completeLogin records what actually happened (amr) against the new SSO
//     session. Nothing else ever writes that record, so a silent SSO re-login,
//     a device approval or a CIBA approval reports the original login.
//   - issueCode derives the acr from that record with the realm's ladder and
//     refuses to issue a code when the request demanded more. It is the one
//     gate every code passes, whatever path led to it.
//   - The context travels inside the code and refresh token strings (see
//     encodeSuffix), whose sha256 is all that is stored: it cannot be altered.
//   - Code redemption and refresh re-check it against the CURRENT ladder and
//     refuse when it no longer holds. They never raise it.

const (
	// authOrderACR runs after the fallback and risk step-up steps and before
	// the passkey and TOTP challenges.
	authOrderACR = 30

	errUnmetACR = "unmet_authentication_requirements"
	msgUnmetACR = "the requested authentication level cannot be met"

	maxACRValues  = 10
	maxClaimsLen  = 4096
	maxACRBytes   = 1024 // all requested values together: they ride in token strings
	maxAuthnBytes = 8192 // decoded token context (JSON may escape each value byte sixfold)
)

func init() {
	registerAuthStepAt(authOrderACR, acrStep, nil)
	registerDiscovery(func(p *Provider, realm string, doc map[string]any) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pol, on, err := p.acrPolicy(ctx, realm)
		if err != nil {
			p.cfg.Logger.Error("oidc: acr policy", "err", err)
			return
		}
		if !on {
			return
		}
		vals := make([]string, len(pol.Levels))
		for i, l := range pol.Levels {
			vals[i] = l.Value
		}
		doc["acr_values_supported"] = vals
		// Only the "acr" member of the claims parameter is honoured.
		doc["claims_parameter_supported"] = true
		if c, ok := doc["claims_supported"].([]string); ok {
			doc["claims_supported"] = append(slices.Clone(c), "acr", "amr")
		}
	})
}

// grantAuthn is the authentication context of one grant.
type grantAuthn struct {
	ACR      string     `json:"a,omitempty"`
	AMR      []string   `json:"m,omitempty"`
	AuthTime int64      `json:"t,omitempty"`
	Req      [][]string `json:"r,omitempty"` // what the authorization request demanded
	// Limited marks a grant that went through the consent screen: the tokens
	// carry roles and the user name only when the scopes granted cover them.
	Limited bool `json:"l,omitempty"`
}

func (g grantAuthn) zero() bool {
	return g.ACR == "" && len(g.AMR) == 0 && g.AuthTime == 0 && len(g.Req) == 0 && !g.Limited
}

func (g grantAuthn) requirement() core.ACRRequirement { return core.ACRRequirement{Sets: g.Req} }

// claims adds auth_time, acr and amr to token claims.
func (g grantAuthn) claims(c map[string]any) {
	if g.AuthTime != 0 {
		c["auth_time"] = g.AuthTime
	}
	if g.ACR != "" {
		c["acr"] = g.ACR
	}
	if len(g.AMR) > 0 {
		c["amr"] = g.AMR
	}
}

func (g grantAuthn) encode() string {
	if g.zero() {
		return ""
	}
	b, err := json.Marshal(g)
	if err != nil { // only strings, ints and bools
		panic("oidc: encode grant context: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// encodeSuffix is what follows the random part of a code, refresh token or
// CIBA handle: "" , "~<resources>" or "~[<resources>]~<context>".
func encodeSuffix(res []string, g grantAuthn) string {
	enc := g.encode()
	if enc == "" {
		return encodeResources(res)
	}
	r := encodeResources(res)
	if r == "" {
		r = resSep
	}
	return r + resSep + enc
}

// decodeAuthn reads the context out of a token string the store already
// recognised. ok is false for a malformed one.
func decodeAuthn(tok string) (g grantAuthn, ok bool) {
	parts := strings.Split(tok, resSep)
	switch {
	case len(parts) < 3:
		return g, true
	case len(parts) > 3 || parts[2] == "" || len(parts[2]) > base64.RawURLEncoding.EncodedLen(maxAuthnBytes):
		return g, false
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || json.Unmarshal(b, &g) != nil {
		return grantAuthn{}, false
	}
	return g, true
}

type authnCtxKey struct{}
type uvCtxKey struct{}

func withAuthn(r *http.Request, g grantAuthn) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), authnCtxKey{}, g))
}

func authnOf(ctx context.Context) grantAuthn {
	g, _ := ctx.Value(authnCtxKey{}).(grantAuthn)
	return g
}

// acrPolicy is the realm's ladder. on is false when the store cannot keep
// authentication context: the feature is then off.
func (p *Provider) acrPolicy(ctx context.Context, realm string) (pol core.ACRPolicy, on bool, err error) {
	st, ok := core.StoreAs[core.AuthnStore](p.cfg.Store)
	if !ok {
		return pol, false, nil
	}
	pol, err = st.GetACRPolicy(ctx, realm)
	if errors.Is(err, idp.ErrNotFound) {
		return core.DefaultACRPolicy(), true, nil
	}
	if err != nil {
		return core.ACRPolicy{}, true, err
	}
	return pol, true, nil
}

// amrOf lists the methods behind a completeLogin detail. uv is whether the
// passkey assertion reported user verification. An unknown detail yields
// nothing, which reaches no level.
func amrOf(detail string, uv bool) []string {
	passkey := func(first []string, mfa bool) []string {
		m := append(first, core.AMRWebAuthn, core.AMRUser)
		if uv {
			m = append(m, core.AMRUV)
		}
		if mfa {
			m = append(m, core.AMRMFA)
		}
		return m
	}
	switch {
	case detail == "": // the password step was the whole login
		return []string{core.AMRPassword}
	case detail == "totp":
		return []string{core.AMRPassword, core.AMROTP, core.AMRMFA}
	case detail == "recovery":
		return []string{core.AMRPassword, core.AMRRecovery, core.AMRMFA}
	case detail == "passkey": // passwordless: two factors only if the user was verified
		return passkey(nil, uv)
	case detail == "passkey_2fa":
		return passkey([]string{core.AMRPassword}, true)
	case strings.HasPrefix(detail, "federated:"):
		return []string{core.AMRFederated}
	}
	return nil
}

// recordAuthn stores the methods of a login against its new session.
func (p *Provider) recordAuthn(ctx context.Context, realm, sessionID, detail string) error {
	st, ok := core.StoreAs[core.AuthnStore](p.cfg.Store)
	if !ok {
		return nil
	}
	uv, _ := ctx.Value(uvCtxKey{}).(bool)
	return st.PutSessionAuthn(ctx, core.SessionAuthn{Realm: realm, SessionID: sessionID, AMR: amrOf(detail, uv)})
}

// loginMeetsACR checks a completed sign-in against the demand before any
// session exists. It reports whether the caller may go on; otherwise it has
// answered. issueCode checks the stored session again.
func (p *Provider) loginMeetsACR(w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User, detail string) bool {
	if ar.acr.Empty() {
		return true
	}
	pol, on, err := p.acrPolicy(r.Context(), ar.realm.Name)
	if err != nil {
		p.cfg.Logger.Error("oidc: acr policy", "err", err)
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		return false
	}
	if on {
		uv, _ := r.Context().Value(uvCtxKey{}).(bool)
		if _, met := pol.Select(amrOf(detail, uv), ar.acr); met {
			return true
		}
	}
	p.acrUnmet(w, r, ar, u.ID, "login_too_weak")
	return false
}

// sessionGrant is the context tokens of session sid carry for a request that
// demands req. met=false: the session does not satisfy req.
func (p *Provider) sessionGrant(ctx context.Context, realm, sid string, authTime time.Time, req core.ACRRequirement) (g grantAuthn, met bool, err error) {
	pol, on, err := p.acrPolicy(ctx, realm)
	if err != nil {
		return g, false, err
	}
	if !on {
		return g, req.Empty(), nil
	}
	st, _ := core.StoreAs[core.AuthnStore](p.cfg.Store)
	rec, err := st.GetSessionAuthn(ctx, realm, sid)
	if err != nil && !errors.Is(err, idp.ErrNotFound) { // not found: a session from before the feature
		return g, false, err
	}
	acr, met := pol.Select(rec.AMR, req)
	if !met {
		return grantAuthn{}, false, nil
	}
	g = grantAuthn{ACR: acr, AMR: rec.AMR, Req: req.Sets}
	if !authTime.IsZero() {
		g.AuthTime = authTime.Unix()
	}
	return g, true, nil
}

// recheckGrant verifies a grant read back from a code or refresh token against
// the ladder as it is now. A level that no longer holds ends the grant's
// usefulness: the client has to send the user through /auth again. The level is
// never recomputed upwards, and never silently lowered.
func (p *Provider) recheckGrant(ctx context.Context, rl core.Realm, g grantAuthn) *tokenErr {
	if g.ACR == "" && len(g.Req) == 0 {
		return nil // nothing is claimed, nothing was demanded
	}
	pol, on, err := p.acrPolicy(ctx, rl.Name)
	if err != nil {
		p.cfg.Logger.Error("oidc: acr policy", "err", err)
		return &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	if on {
		_, met := pol.Select(g.AMR, g.requirement())
		if met && (g.ACR == "" || pol.Meets(g.AMR, g.ACR)) {
			return nil
		}
	}
	return oerr("invalid_grant", "the authentication level of this grant no longer satisfies the realm policy; sign in again")
}

// copyAuthnClaims copies the named claims of a verified token to a response.
func copyAuthnClaims(out map[string]any, c core.Claims, names ...string) {
	for _, n := range names {
		if v, ok := c[n]; ok {
			out[n] = v
		}
	}
}

// ---- request parameters ----

var errACRParam = errors.New("invalid acr request")

func validRequestedACR(vals []string) bool {
	return len(vals) <= maxACRValues && !slices.ContainsFunc(vals, func(v string) bool { return !core.ValidACRValue(v) })
}

// parseACRValues reads the acr_values parameter (space separated, in order of
// preference). Duplicated parameters are refused: one of them would be ignored.
func parseACRValues(q url.Values) ([]string, error) {
	if len(q["acr_values"]) > 1 {
		return nil, errors.New("acr_values must not be repeated")
	}
	raw := q.Get("acr_values")
	if len(raw) > maxACRBytes {
		return nil, errors.New("acr_values is too long")
	}
	vals := strings.Fields(raw)
	if !validRequestedACR(vals) {
		return nil, errors.New("acr_values has too many or malformed values")
	}
	return vals, nil
}

// parseACRRequest turns acr_values and the "acr" member of the claims
// parameter into a requirement. Whatever names an acr value is binding
// (RFC 9470 section 5), essential or not; "essential": true without values
// demands that some level is reached.
func parseACRRequest(q url.Values) (core.ACRRequirement, error) {
	var req core.ACRRequirement
	if len(q["claims"]) > 1 {
		return req, errors.New("claims must not be repeated")
	}
	if raw := q.Get("claims"); raw != "" {
		if len(raw) > maxClaimsLen {
			return req, errors.New("claims is too long")
		}
		var top map[string]json.RawMessage
		if json.Unmarshal([]byte(raw), &top) != nil || top == nil || hasDupKeys([]byte(raw)) {
			return req, errors.New("claims must be a JSON object without duplicate members")
		}
		// id_token first: its value is the one the acr claim must report.
		for _, target := range []string{"id_token", "userinfo", "access_token"} {
			set, has, err := claimsACR(top[target])
			if err != nil {
				return core.ACRRequirement{}, errors.New("claims." + target + " is malformed")
			}
			if has {
				req.Sets = append(req.Sets, set)
			}
		}
	}
	vals, err := parseACRValues(q)
	if err != nil {
		return core.ACRRequirement{}, err
	}
	if len(vals) > 0 {
		req.Sets = append(req.Sets, vals)
	}
	n := 0
	for _, s := range req.Sets {
		for _, v := range s {
			n += len(v)
		}
	}
	if n > maxACRBytes {
		return core.ACRRequirement{}, errors.New("too many requested acr values")
	}
	return req, nil
}

// claimsACR reads one claims target. has reports that it demands something.
func claimsACR(raw json.RawMessage) (set []string, has bool, err error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, false, nil
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil {
		return nil, false, errACRParam
	}
	acr, ok := members["acr"]
	if !ok || string(acr) == "null" {
		return nil, false, nil
	}
	var spec map[string]json.RawMessage
	if json.Unmarshal(acr, &spec) != nil {
		return nil, false, errACRParam
	}
	essential := false
	if e, ok := spec["essential"]; ok && json.Unmarshal(e, &essential) != nil {
		return nil, false, errACRParam
	}
	v, hasValue := spec["value"]
	vs, hasValues := spec["values"]
	switch {
	case hasValue && hasValues:
		return nil, false, errACRParam
	case hasValue:
		var s string
		if json.Unmarshal(v, &s) != nil || s == "" {
			return nil, false, errACRParam
		}
		set = []string{s}
	case hasValues:
		if json.Unmarshal(vs, &set) != nil || len(set) == 0 {
			return nil, false, errACRParam
		}
	default:
		return nil, essential, nil
	}
	if !validRequestedACR(set) {
		return nil, false, errACRParam
	}
	return set, true, nil
}

// acrPossible checks, before anyone is asked to sign in, that some login could
// meet req. It returns an OAuth error code and description, or "".
func (p *Provider) acrPossible(ctx context.Context, realm string, req core.ACRRequirement) (code, desc string) {
	if req.Empty() {
		return "", ""
	}
	pol, on, err := p.acrPolicy(ctx, realm)
	if err != nil {
		p.cfg.Logger.Error("oidc: acr policy", "err", err)
		return "server_error", "could not check the authentication requirements"
	}
	if !on || !pol.Satisfiable(req) {
		return errUnmetACR, msgUnmetACR
	}
	return "", ""
}

// acrMetBySession reports whether the session may be reused for the request.
// Errors answer no.
func (p *Provider) acrMetBySession(ctx context.Context, ar *authzReq, s core.Session) bool {
	if ar.acr.Empty() {
		return true
	}
	_, met, err := p.sessionGrant(ctx, ar.realm.Name, s.ID, s.AuthTime, ar.acr)
	if err != nil {
		p.cfg.Logger.Error("oidc: session authentication context", "err", err)
		return false
	}
	return met
}

func (p *Provider) acrUnmet(w http.ResponseWriter, r *http.Request, ar *authzReq, userID, why string) {
	p.event(r.Context(), ar.realm, "LOGIN_ERROR", userID, ar.client.ClientID, p.clientIP(r), "acr_unmet:"+why)
	p.redirectErr(w, r, ar.redirect, ar.state, ar.realm.Name, errUnmetACR, msgUnmetACR)
}

// acrStep runs after the password step when the request demands a level the
// password alone does not reach. It lets the user's second factor step run if
// that factor can reach it, enrolls one when the realm allows that and the user
// has none, and otherwise fails the request. It never issues a code; issueCode
// verifies the outcome in every case.
func acrStep(p *Provider, w http.ResponseWriter, r *http.Request, ar *authzReq, u core.User) bool {
	if ar.acr.Empty() {
		return false
	}
	ctx := r.Context()
	fail := func(msg string, err error) bool {
		p.cfg.Logger.Error("oidc: "+msg, "err", err)
		p.errorPage(w, http.StatusInternalServerError, mfaTemporary)
		return true
	}
	pol, on, err := p.acrPolicy(ctx, ar.realm.Name)
	if err != nil {
		return fail("acr policy", err)
	}
	unmet := func(why string) bool {
		p.acrUnmet(w, r, ar, u.ID, why)
		return true
	}
	if !on {
		return unmet("unavailable")
	}
	reaches := func(m ...string) bool {
		_, ok := pol.Select(m, ar.acr)
		return ok
	}
	if reaches(core.AMRPassword) {
		return false
	}
	// Whether the account has a passkey does not depend on the relying party
	// being usable: a misconfiguration must not let someone who knows only the
	// password add another authenticator.
	var hasPasskey, hasTOTP bool
	if st, ok := core.StoreAs[core.PasskeyStore](p.cfg.Store); ok {
		creds, err := st.ListPasskeys(ctx, ar.realm.Name, u.ID)
		if err != nil {
			return fail("acr list passkeys", err)
		}
		hasPasskey = len(creds) > 0
	}
	_, _, passkeysUsable := p.passkeys()
	mst, mfaOn := p.mfaStore()
	if mfaOn {
		c, err := mst.GetTOTP(ctx, ar.realm.Name, u.ID)
		if err != nil && !errors.Is(err, idp.ErrNotFound) {
			return fail("acr load totp", err)
		}
		hasTOTP = err == nil && c.Confirmed
	}
	totpReaches := reaches(core.AMRPassword, core.AMROTP, core.AMRMFA)
	switch {
	case hasPasskey && passkeysUsable:
		// The passkey step challenges this user. TOTP is deliberately not
		// substituted: a request parameter must not pick a weaker factor.
		if reaches(core.AMRPassword, core.AMRWebAuthn, core.AMRUser, core.AMRUV, core.AMRMFA) {
			return false
		}
		return unmet("factor_too_weak")
	case hasTOTP:
		if totpReaches || reaches(core.AMRPassword, core.AMRRecovery, core.AMRMFA) {
			return false
		}
		return unmet("factor_too_weak")
	case !hasPasskey && mfaOn && totpReaches:
		// Only for a user with no second factor at all.
		mpol, err := mst.GetMFAPolicy(ctx, ar.realm.Name)
		if err != nil {
			return fail("acr mfa policy", err)
		}
		if mpol.RequireMFA {
			return false // the two-step verification step enrolls everyone anyway
		}
		if !pol.EnrollOnStepUp {
			break
		}
		seed, err := p.newEnrollment(r, mst, ar.realm.Name, u.ID)
		if err != nil {
			return fail("acr start enrollment", err)
		}
		p.enrollPage(w, r, ar, u, seed, http.StatusOK, "")
		return true
	}
	return unmet("no_suitable_factor")
}
