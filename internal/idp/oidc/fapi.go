// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto/subtle"
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

// FAPI 2.0 building blocks: PAR (RFC 9126), JAR (RFC 9101), RAR (RFC 9396),
// per-client require-PAR / require-DPoP, and dpop_jkt at the authorization
// endpoint. See docs/fapi-par-jar-rar.md for exactly what is and is not met.
//
// Everything fails closed: a store without core.FAPIStore turns the feature
// off (PAR answers 501, request/request_uri/authorization_details/dpop_jkt at
// /auth are refused), and a store error while checking a client's settings
// refuses the request instead of assuming defaults.

const (
	parURIPrefix = "urn:ietf:params:oauth:request_uri:"
	parTTL       = 60 * time.Second
	fapiCtxTTL   = 10 * time.Minute // how long a login may take after the request_uri was redeemed
	parRateLimit = 120              // /par calls per client address per 10 minutes
	fapiCtxParam = "fapi_ctx"
)

func init() {
	registerFeature(func(p *Provider, mux *http.ServeMux) {
		mux.HandleFunc("POST /realms/{realm}"+oidcPath+"/par", p.par)
	})
	registerDiscovery(func(p *Provider, realm string, doc map[string]any) {
		if _, ok := p.fapiStore(); !ok {
			return
		}
		doc["pushed_authorization_request_endpoint"] = p.endpoint(realm, "par")
		doc["require_pushed_authorization_requests"] = false // a per-client setting, not realm-wide
		doc["request_parameter_supported"] = true
		doc["request_uri_parameter_supported"] = true // PAR request_uris only; no remote fetch
		doc["require_request_uri_registration"] = false
		doc["request_object_signing_alg_values_supported"] = jarAlgs
		doc["authorization_details_supported"] = true
	})
}

func (p *Provider) fapiStore() (core.FAPIStore, bool) {
	return core.StoreAs[core.FAPIStore](p.cfg.Store)
}

// fapiAuthz is what an authorization request asks for beyond the basics; it
// travels in the request context to issueCode, which binds it to the code.
type fapiAuthz struct{ details, jkt, ctxHash string }

type fapiCtxKey struct{}
type fapiDetailsKey struct{}

func fapiAuthzOf(ctx context.Context) fapiAuthz {
	a, _ := ctx.Value(fapiCtxKey{}).(fapiAuthz)
	return a
}

// fapiTokenDetails is the authorization_details granted to the tokens of the
// current token request ("" = none).
func fapiTokenDetails(ctx context.Context) string {
	s, _ := ctx.Value(fapiDetailsKey{}).(string)
	return s
}

func (p *Provider) clientFAPI(ctx context.Context, st core.FAPIStore, realm string, cl core.Client) (core.ClientFAPI, error) {
	if cl.ID == "" { // the built-in device-login client has no settings
		return core.ClientFAPI{}, nil
	}
	cfg, err := st.GetClientFAPI(ctx, realm, cl.ID)
	if errors.Is(err, idp.ErrNotFound) {
		return core.ClientFAPI{}, nil
	}
	return cfg, err
}

// ---- POST /par ----

func (p *Provider) parFail(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

func (p *Provider) par(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("realm")
	ctx := r.Context()
	rl, ok := p.realm(ctx, name)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "realm_not_found"})
		return
	}
	st, ok := p.fapiStore()
	if !ok {
		p.parFail(w, http.StatusNotImplemented, "feature_unavailable", "pushed authorization requests are not available")
		return
	}
	if err := r.ParseForm(); err != nil {
		p.parFail(w, http.StatusBadRequest, "invalid_request", "malformed body")
		return
	}
	allowed, err := p.hitLimit(ctx, "par", name, p.clientIP(r), parRateLimit)
	if err != nil {
		p.cfg.Logger.Error("oidc: par rate limit", "err", err)
		p.parFail(w, http.StatusInternalServerError, "server_error", "temporary error")
		return
	}
	if !allowed {
		p.parFail(w, http.StatusTooManyRequests, "invalid_request", "too many requests")
		return
	}
	// Client authentication is required: a pushed request is a credential-like
	// reference, so it is only created for a client that proved who it is.
	cl, confidential, basic, terr := p.authClient(r, name)
	if terr == nil && !confidential {
		terr = &tokenErr{http.StatusUnauthorized, "invalid_client", "client authentication required"}
	}
	if terr != nil {
		p.writeTokenErr(w, terr, basic)
		return
	}
	if !cl.AuthCodeFlow {
		p.parFail(w, http.StatusBadRequest, "unauthorized_client", "client may not use the authorization code flow")
		return
	}
	if r.PostForm.Has("request_uri") {
		p.parFail(w, http.StatusBadRequest, "invalid_request", "request_uri must not be sent to the PAR endpoint")
		return
	}
	cfg, err := p.clientFAPI(ctx, st, name, cl)
	if err != nil {
		p.cfg.Logger.Error("oidc: par client settings", "err", err)
		p.parFail(w, http.StatusInternalServerError, "server_error", "temporary error")
		return
	}

	var params map[string]string
	if obj := r.PostForm.Get("request"); obj != "" {
		params, err = verifyRequestObject(obj, cfg.JWKS, cl.ClientID, p.issuer(name), p.now())
		if err != nil {
			p.event(ctx, rl, "PAR_ERROR", "", cl.ClientID, p.clientIP(r), "invalid_request_object")
			p.parFail(w, http.StatusBadRequest, "invalid_request_object", "the request object is invalid")
			return
		}
	} else {
		if cfg.RequireSignedRequest {
			p.parFail(w, http.StatusBadRequest, "invalid_request", "this client must send a signed request object")
			return
		}
		params = map[string]string{}
		for _, k := range jarParams {
			if v := r.PostForm.Get(k); v != "" {
				if len(v) > jarMaxValue {
					p.parFail(w, http.StatusBadRequest, "invalid_request", "parameter too long")
					return
				}
				params[k] = v
			}
		}
	}
	if ru := params["redirect_uri"]; ru == "" || !slices.Contains(cl.RedirectURIs, ru) || !safeRedirect(ru) {
		p.parFail(w, http.StatusBadRequest, "invalid_request", "invalid redirect_uri")
		return
	}
	if params["response_type"] != "code" {
		p.parFail(w, http.StatusBadRequest, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	// DPoP at PAR (RFC 9449, section 10.1): a proof binds the request to its key.
	if len(r.Header.Values("DPoP")) > 0 {
		pr, derr := p.checkDPoP(r, name, p.endpoint(name, "par"), "")
		if derr != nil {
			te := derr.tokenErr(w)
			p.parFail(w, te.status, te.code, te.desc)
			return
		}
		if j := params["dpop_jkt"]; j != "" && subtle.ConstantTimeCompare([]byte(j), []byte(pr.jkt)) != 1 {
			p.parFail(w, http.StatusBadRequest, "invalid_dpop_proof", "dpop_jkt does not match the proof key")
			return
		}
		params["dpop_jkt"] = pr.jkt
	}
	if d, code, msg := fapiCheckExtras(params["authorization_details"], params["dpop_jkt"], cfg); code != "" {
		p.parFail(w, http.StatusBadRequest, code, msg)
		return
	} else if d != "" {
		params["authorization_details"] = d
	}

	body, err := json.Marshal(params)
	if err != nil {
		p.parFail(w, http.StatusInternalServerError, "server_error", "temporary error")
		return
	}
	uri := parURIPrefix + randToken(32)
	err = st.PutFAPIRequest(ctx, core.FAPIRequest{Kind: core.FAPIKindPAR, IDHash: HashSecret(uri), Realm: name,
		ClientID: cl.ClientID, Params: string(body), ExpiresAt: p.now().Add(parTTL)})
	if err != nil {
		p.cfg.Logger.Error("oidc: store par", "err", err)
		p.parFail(w, http.StatusInternalServerError, "server_error", "temporary error")
		return
	}
	p.event(ctx, rl, "PAR", "", cl.ClientID, p.clientIP(r), "")
	writeJSON(w, http.StatusCreated, map[string]any{"request_uri": uri, "expires_in": int(parTTL.Seconds())})
}

// fapiCheckExtras validates authorization_details against the client's allowed
// types and dpop_jkt for shape. It returns the canonical details.
func fapiCheckExtras(details, jkt string, cfg core.ClientFAPI) (canonical, code, msg string) {
	if details != "" {
		c, err := validateAuthzDetails(details, cfg.AuthzDetailTypes)
		if err != nil {
			return "", "invalid_authorization_details", "authorization_details is malformed or contains a type this client may not request"
		}
		canonical = c
	}
	if jkt != "" && !validChallenge(jkt) { // a base64url SHA-256 thumbprint has the same shape
		return "", "invalid_request", "dpop_jkt must be a JWK SHA-256 thumbprint"
	}
	return canonical, "", ""
}

// ---- GET/POST /auth ----

// fapiAuthorize runs at the top of the authorization endpoint. It turns a
// request_uri (PAR), a request object (JAR) or a login context into the
// ordinary parameter set the rest of authorize() works with, enforces the
// client's require-PAR / signed-request settings, validates
// authorization_details and dpop_jkt, and hands them to issueCode through the
// request context. ok=false means the response was written.
func (p *Provider) fapiAuthorize(w http.ResponseWriter, r *http.Request, q url.Values) (*http.Request, url.Values, bool) {
	ctx := r.Context()
	name := r.PathValue("realm")
	extras := q.Has("authorization_details") || q.Has("dpop_jkt") || q.Has(fapiCtxParam)
	st, have := p.fapiStore()
	if !have {
		if extras { // would be silently ignored: refuse instead
			p.errorPage(w, http.StatusBadRequest, "This request uses a feature that is not available.")
			return r, q, false
		}
		return r, q, true // request / request_uri are refused by authorize() itself
	}
	rl, ok := p.realm(ctx, name)
	if !ok {
		return r, q, true
	}
	cl, err := p.authorizeClient(ctx, name, q.Get("client_id"))
	if err != nil || !cl.Enabled || !cl.AuthCodeFlow {
		return r, q, true // authorize() reports the invalid client
	}
	cfg, err := p.clientFAPI(ctx, st, name, cl)
	if err != nil {
		p.cfg.Logger.Error("oidc: client fapi settings", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return r, q, false
	}
	reqURI, obj, handle := q.Get("request_uri"), q.Get("request"), q.Get(fapiCtxParam)
	n := 0
	for _, s := range []string{reqURI, obj, handle} {
		if s != "" {
			n++
		}
	}
	if n > 1 {
		p.errorPage(w, http.StatusBadRequest, "Invalid authorization request.")
		return r, q, false
	}
	badReq := func() (*http.Request, url.Values, bool) {
		p.errorPage(w, http.StatusBadRequest, "Invalid or expired authorization request.")
		return r, q, false
	}

	var params map[string]string
	var ctxHash string // the login context this request continues from, spent when the code is issued
	switch {
	case reqURI != "":
		if !strings.HasPrefix(reqURI, parURIPrefix) || len(reqURI) > 256 {
			return badReq()
		}
		rec, err := st.ConsumeFAPIRequest(ctx, name, core.FAPIKindPAR, HashSecret(reqURI), p.now())
		if err != nil {
			if !errors.Is(err, idp.ErrNotFound) {
				p.cfg.Logger.Error("oidc: consume par", "err", err)
			}
			return badReq()
		}
		if rec.ClientID != cl.ClientID || json.Unmarshal([]byte(rec.Params), &params) != nil {
			return badReq()
		}
		// The request_uri is single use. The login that follows continues from a
		// context handle that only works for this client and expires quickly.
		h := randToken(32)
		err = st.PutFAPIRequest(ctx, core.FAPIRequest{Kind: core.FAPIKindCtx, IDHash: HashSecret(h), Realm: name,
			ClientID: cl.ClientID, Params: rec.Params, ExpiresAt: p.now().Add(fapiCtxTTL)})
		if err != nil {
			p.cfg.Logger.Error("oidc: store login context", "err", err)
			p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
			return r, q, false
		}
		next := url.Values{"client_id": {cl.ClientID}, fapiCtxParam: {h}}
		if r.Method == http.MethodGet {
			noStore(w)
			http.Redirect(w, r, r.URL.Path+"?"+next.Encode(), http.StatusFound)
			return r, q, false
		}
		u := *r.URL
		u.RawQuery = next.Encode()
		r = r.WithContext(ctx)
		r.URL = &u
		ctxHash = HashSecret(h)
	case handle != "":
		rec, err := st.GetFAPIRequest(ctx, name, core.FAPIKindCtx, HashSecret(handle), p.now())
		if err != nil {
			if !errors.Is(err, idp.ErrNotFound) {
				p.cfg.Logger.Error("oidc: load login context", "err", err)
			}
			return badReq()
		}
		if rec.ClientID != cl.ClientID || json.Unmarshal([]byte(rec.Params), &params) != nil {
			return badReq()
		}
		ctxHash = HashSecret(handle)
	case obj != "":
		if cfg.RequirePAR {
			p.errorPage(w, http.StatusBadRequest, "This client must use pushed authorization requests.")
			return r, q, false
		}
		params, err = verifyRequestObject(obj, cfg.JWKS, cl.ClientID, p.issuer(name), p.now())
		if err != nil {
			p.event(ctx, rl, "LOGIN_ERROR", "", cl.ClientID, p.clientIP(r), "invalid_request_object")
			p.errorPage(w, http.StatusBadRequest, "The request object is invalid.")
			return r, q, false
		}
	default:
		if cfg.RequirePAR || cfg.RequireSignedRequest {
			p.errorPage(w, http.StatusBadRequest, "This client must send a pushed or signed authorization request.")
			return r, q, false
		}
	}

	var out url.Values
	if params == nil { // plain request: the query is the request
		out = q
	} else {
		out = url.Values{"client_id": {cl.ClientID}}
		for _, k := range jarParams {
			if v := params[k]; v != "" {
				out.Set(k, v)
			}
		}
	}
	d, code, msg := fapiCheckExtras(out.Get("authorization_details"), out.Get("dpop_jkt"), cfg)
	if code != "" {
		ru, state := out.Get("redirect_uri"), out.Get("state")
		if ru != "" && state != "" && slices.Contains(cl.RedirectURIs, ru) && safeRedirect(ru) {
			p.redirectErr(w, r, ru, state, name, code, msg)
		} else {
			p.errorPage(w, http.StatusBadRequest, "Invalid authorization request.")
		}
		return r, out, false
	}
	if a := (fapiAuthz{details: d, jkt: out.Get("dpop_jkt"), ctxHash: ctxHash}); a != (fapiAuthz{}) {
		r = r.WithContext(context.WithValue(r.Context(), fapiCtxKey{}, a))
	}
	return r, out, true
}

// fapiBindCode stores the extras of the request next to the code. It returns
// false after answering the client when they cannot be stored (the code is not
// issued, so a request is never downgraded to one without them).
func (p *Provider) fapiBindCode(w http.ResponseWriter, r *http.Request, ar *authzReq, codeHash string) bool {
	a := fapiAuthzOf(r.Context())
	if a == (fapiAuthz{}) {
		return true
	}
	st, ok := p.fapiStore()
	var err error
	if ok && a.ctxHash != "" {
		// Spend the login context: a pushed request yields one code, however
		// often the browser URL is replayed. A concurrent second use loses.
		_, err = st.ConsumeFAPIRequest(r.Context(), ar.realm.Name, core.FAPIKindCtx, a.ctxHash, p.now())
	}
	if ok && err == nil && (a.details != "" || a.jkt != "") {
		err = st.PutFAPIBinding(r.Context(), core.FAPIBinding{Kind: core.FAPIKindCode, KeyHash: codeHash, Realm: ar.realm.Name,
			ClientID: ar.client.ClientID, Details: a.details, DPoPJKT: a.jkt, ExpiresAt: p.now().Add(p.cfg.CodeTTL + time.Minute)})
	}
	if !ok || err != nil {
		if err != nil {
			p.cfg.Logger.Error("oidc: bind code extras", "err", err)
		}
		p.redirectErr(w, r, ar.redirect, ar.state, ar.realm.Name, "server_error", "could not issue code")
		return false
	}
	return true
}

// fapiParseCheck is the guard for the entry points that rebuild an
// authorization request from a query (identity brokering): they know nothing
// of request objects, contexts or bound extras, so anything that needs them is
// refused rather than silently stripped. It returns a message to show, or "".
func (p *Provider) fapiParseCheck(ctx context.Context, rl core.Realm, cl core.Client, q url.Values) string {
	if q.Has("authorization_details") || q.Has("dpop_jkt") || q.Has(fapiCtxParam) {
		return "Invalid authorization request."
	}
	st, ok := p.fapiStore()
	if !ok {
		return ""
	}
	cfg, err := p.clientFAPI(ctx, st, rl.Name, cl)
	if err != nil || cfg.RequirePAR || cfg.RequireSignedRequest {
		return "Invalid authorization request."
	}
	return ""
}

// ---- token endpoint ----

// fapiToken runs at the token endpoint after DPoP proof validation. It
// enforces require-DPoP, checks the code's dpop_jkt, and loads the
// authorization_details the tokens must carry.
func (p *Provider) fapiToken(w http.ResponseWriter, r *http.Request, rl core.Realm, cl core.Client) (*http.Request, *tokenErr) {
	if r.PostForm.Has("authorization_details") {
		return r, oerr("invalid_request", "authorization_details is only accepted at the authorization endpoint")
	}
	st, ok := p.fapiStore()
	if !ok {
		return r, nil
	}
	ctx := r.Context()
	cfg, err := p.clientFAPI(ctx, st, rl.Name, cl)
	if err != nil {
		p.cfg.Logger.Error("oidc: token client settings", "err", err)
		return r, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	jkt := dpopJKT(ctx)
	if cfg.RequireDPoP && jkt == "" {
		return r, badProof("this client requires DPoP").tokenErr(w)
	}
	var kind, key string
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		kind, key = core.FAPIKindCode, r.PostForm.Get("code")
	case "refresh_token":
		kind, key = core.FAPIKindRefresh, r.PostForm.Get("refresh_token")
	}
	if key == "" {
		return r, nil
	}
	b, err := st.GetFAPIBinding(ctx, kind, HashSecret(key), p.now())
	switch {
	case errors.Is(err, idp.ErrNotFound):
		return r, nil
	case err != nil:
		p.cfg.Logger.Error("oidc: load binding", "err", err)
		return r, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	if b.Realm != rl.Name || b.ClientID != cl.ClientID {
		return r, nil // the grant itself refuses a code or token of another client
	}
	if b.DPoPJKT != "" {
		if jkt == "" {
			return r, badProof("this authorization code is bound to a DPoP key: a proof is required").tokenErr(w)
		}
		if subtle.ConstantTimeCompare([]byte(b.DPoPJKT), []byte(jkt)) != 1 {
			return r, badProof("the proof key does not match dpop_jkt").tokenErr(w)
		}
	}
	if b.Details != "" {
		r = r.WithContext(context.WithValue(ctx, fapiDetailsKey{}, b.Details))
	}
	return r, nil
}

// fapiTokenDone runs after a successful grant: it reports authorization_details
// in the response and binds them to the refresh token so a refreshed access
// token carries them too. A binding that cannot be stored fails the request.
func (p *Provider) fapiTokenDone(r *http.Request, rl core.Realm, cl core.Client, resp map[string]any) *tokenErr {
	d := fapiTokenDetails(r.Context())
	if d == "" {
		return nil
	}
	resp["authorization_details"] = json.RawMessage(d)
	rt, _ := resp["refresh_token"].(string)
	if rt == "" {
		return nil
	}
	ttl := defaultRefresh
	if n, ok := resp["refresh_expires_in"].(int); ok && n > 0 {
		ttl = time.Duration(n) * time.Second
	}
	st, ok := p.fapiStore()
	var err error
	if ok {
		err = st.PutFAPIBinding(r.Context(), core.FAPIBinding{Kind: core.FAPIKindRefresh, KeyHash: HashSecret(rt), Realm: rl.Name,
			ClientID: cl.ClientID, Details: d, ExpiresAt: p.now().Add(ttl + time.Hour)})
	}
	if !ok || err != nil {
		if err != nil {
			p.cfg.Logger.Error("oidc: bind refresh details", "err", err)
		}
		delete(resp, "refresh_token")
		delete(resp, "refresh_expires_in")
		return &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	return nil
}

// fapiBindClaims puts authorization_details into access token claims.
func fapiBindClaims(ctx context.Context, claims core.Claims) {
	if d := fapiTokenDetails(ctx); d != "" {
		claims["authorization_details"] = json.RawMessage(d)
	}
}

// fapiRefreshDetails returns the authorization_details bound to a refresh
// token for introspection (nil = none; an error means "cannot tell").
func (p *Provider) fapiRefreshDetails(ctx context.Context, rawToken string) (json.RawMessage, error) {
	st, ok := p.fapiStore()
	if !ok {
		return nil, nil
	}
	b, err := st.GetFAPIBinding(ctx, core.FAPIKindRefresh, HashSecret(rawToken), p.now())
	if errors.Is(err, idp.ErrNotFound) {
		return nil, nil
	}
	if err != nil || b.Details == "" {
		return nil, err
	}
	return json.RawMessage(b.Details), nil
}
