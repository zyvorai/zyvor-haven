// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// OAuth 2.0 Dynamic Client Registration (RFC 7591) and Client Registration
// Management (RFC 7592). Registration needs an admin-issued initial access
// token; there is deliberately no anonymous mode. Management is authenticated
// by the per-client registration access token only.

const (
	dcrPath         = "/clients-registrations/openid-connect"
	dcrMaxBody      = 16 << 10
	dcrMaxRedirects = 10
	dcrMaxURILen    = 2048
	dcrRegisterMax  = 20 // registrations (incl. failed auth) per IP per minute
	dcrManageMax    = 60 // management calls per IP per minute
	dcrWindow       = time.Minute
)

var dcrClientIDRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func init() {
	registerFeature(func(p *Provider, mux *http.ServeMux) {
		base := "/realms/{realm}" + dcrPath
		mux.HandleFunc("POST "+base, p.dcrRegister)
		mux.HandleFunc("GET "+base+"/{clientId}", p.dcrRead)
		mux.HandleFunc("PUT "+base+"/{clientId}", p.dcrUpdate)
		mux.HandleFunc("DELETE "+base+"/{clientId}", p.dcrDelete)
	})
	registerDiscovery(func(p *Provider, realm string, doc map[string]any) {
		if _, ok := core.StoreAs[core.DCRStore](p.cfg.Store); ok {
			doc["registration_endpoint"] = p.issuer(realm) + dcrPath
		}
	})
}

// ---- errors ----

type dcrErr struct {
	status int
	code   string
	desc   string // fixed text: never built from request data
}

func metaErr(desc string) *dcrErr {
	return &dcrErr{http.StatusBadRequest, "invalid_client_metadata", desc}
}
func uriErr(desc string) *dcrErr { return &dcrErr{http.StatusBadRequest, "invalid_redirect_uri", desc} }

func writeDCRErr(w http.ResponseWriter, e *dcrErr) {
	if e.status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}
	writeJSON(w, e.status, map[string]string{"error": e.code, "error_description": e.desc})
}

var errInvalidToken = &dcrErr{http.StatusUnauthorized, "invalid_token", "the access token is missing, invalid, expired or exhausted"}

// ---- metadata ----

type dcrMeta struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	RegistrationAccessToken string   `json:"registration_access_token"`
	SoftwareStatement       string   `json:"software_statement"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	ApplicationType         string   `json:"application_type"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	BackchannelLogoutURI    string   `json:"backchannel_logout_uri"`
	FrontchannelLogoutURI   string   `json:"frontchannel_logout_uri"`
	Contacts                []string `json:"contacts"`
	LogoURI                 string   `json:"logo_uri"`
	ClientURI               string   `json:"client_uri"`
	PolicyURI               string   `json:"policy_uri"`
	TosURI                  string   `json:"tos_uri"`
	dcrAuthMeta                      // client authentication (clientauth_dcr.go)
}

// dcrNormalized is validated metadata mapped onto the core types.
type dcrNormalized struct {
	client core.Client
	reg    core.RegisteredClient
	// frontchannel is the validated frontchannel_logout_uri, stored beside
	// the client (core.FrontchannelStore).
	frontchannel string
	auth         *core.ClientAuth // nil = no per-client authentication settings
}

func dcrReadMeta(w http.ResponseWriter, r *http.Request) (dcrMeta, *dcrErr) {
	var m dcrMeta
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, dcrMaxBody))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return m, &dcrErr{http.StatusRequestEntityTooLarge, "invalid_client_metadata", "request body too large"}
		}
		return m, metaErr("could not read the request body")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&m); err != nil || dec.More() {
		return m, metaErr("the body must be one JSON object with correctly typed metadata")
	}
	return m, nil
}

// dcrValidate applies every registration rule. Descriptions never echo input.
func dcrValidate(m dcrMeta, allowed []string) (dcrNormalized, *dcrErr) {
	var n dcrNormalized
	if m.SoftwareStatement != "" {
		return n, &dcrErr{http.StatusBadRequest, "invalid_software_statement", "software statements are not supported"}
	}
	if !dcrText(m.ClientName, 255) {
		return n, metaErr("client_name is too long or contains control characters")
	}
	app := m.ApplicationType
	if app == "" {
		app = "web"
	}
	if app != "web" && app != "native" {
		return n, metaErr("application_type must be web or native")
	}
	method := m.TokenEndpointAuthMethod
	if method == "" {
		method = "client_secret_basic"
	}
	if !slices.Contains(dcrAuthMethods, method) {
		return n, metaErr("token_endpoint_auth_method must be none, client_secret_basic, client_secret_post, private_key_jwt, tls_client_auth or self_signed_tls_client_auth")
	}
	public := method == "none"
	auth, aerr := dcrClientAuth(m.dcrAuthMeta, method)
	if aerr != nil {
		return n, aerr
	}
	n.auth = auth

	grants := m.GrantTypes
	if len(grants) == 0 {
		grants = []string{"authorization_code"}
	}
	var gs []string
	for _, g := range grants {
		if !slices.Contains(core.DCRGrantTypes, g) && g != core.DCRDeviceGrant {
			return n, metaErr("grant_types may only contain authorization_code, refresh_token, client_credentials and the device_code grant")
		}
		if !slices.Contains(allowed, g) {
			return n, metaErr("a requested grant type is not allowed by this realm's registration policy")
		}
		if !slices.Contains(gs, g) {
			gs = append(gs, g)
		}
	}
	hasCode, hasRefresh, hasCC := slices.Contains(gs, "authorization_code"), slices.Contains(gs, "refresh_token"), slices.Contains(gs, "client_credentials")
	hasDevice := slices.Contains(gs, core.DCRDeviceGrant)
	if hasRefresh && !hasCode && !hasDevice {
		return n, metaErr("refresh_token requires authorization_code or the device_code grant")
	}
	if !hasCode && !hasCC && !hasDevice {
		return n, metaErr("grant_types needs authorization_code, client_credentials or the device_code grant")
	}
	if hasDevice && hasCC { // a service account has no user to approve a device
		return n, metaErr("the device_code grant cannot be combined with client_credentials")
	}
	if public && hasCC {
		return n, metaErr("a public client (token_endpoint_auth_method none) cannot use client_credentials")
	}
	if len(m.ResponseTypes) > 0 {
		for _, rt := range m.ResponseTypes {
			if rt != "code" {
				return n, metaErr("response_types may only contain code")
			}
		}
	}
	if hasCode && len(m.ResponseTypes) > 0 && !slices.Contains(m.ResponseTypes, "code") {
		return n, metaErr("authorization_code requires the code response type")
	}
	if !hasCode && len(m.ResponseTypes) > 0 {
		return n, metaErr("response_types code requires the authorization_code grant")
	}

	if len(m.RedirectURIs) > dcrMaxRedirects {
		return n, uriErr("too many redirect_uris")
	}
	var uris []string
	for _, u := range m.RedirectURIs {
		if !dcrRedirectOK(u, app) {
			return n, uriErr("a redirect URI is not allowed")
		}
		if !slices.Contains(uris, u) {
			uris = append(uris, u)
		}
	}
	if hasCode && len(uris) == 0 {
		return n, uriErr("redirect_uris is required for the authorization_code grant")
	}

	scope := m.Scope
	if scope == "" {
		scope = "openid profile email"
	}
	var sc []string
	for _, s := range strings.Fields(scope) {
		if !slices.Contains(knownScopes, s) {
			return n, metaErr("scope may only contain openid, profile, email, roles and offline_access")
		}
		if !slices.Contains(sc, s) {
			sc = append(sc, s)
		}
	}
	if len(sc) == 0 {
		return n, metaErr("scope is empty")
	}
	if slices.Contains(sc, "offline_access") && !hasRefresh {
		return n, metaErr("offline_access requires the refresh_token grant")
	}

	if m.BackchannelLogoutURI != "" {
		if err := idp.ValidateLogoutURI(m.BackchannelLogoutURI); err != nil {
			return n, metaErr("backchannel_logout_uri is not acceptable")
		}
	}
	if m.FrontchannelLogoutURI != "" {
		if _, err := idp.FrontchannelOrigin(m.FrontchannelLogoutURI, uris); err != nil {
			return n, metaErr("frontchannel_logout_uri is not acceptable: " + err.Error()) // fixed texts, no input echoed
		}
	}
	if len(m.Contacts) > 10 {
		return n, metaErr("too many contacts")
	}
	for _, c := range m.Contacts {
		if c == "" || !dcrText(c, 254) {
			return n, metaErr("a contact is empty, too long or contains control characters")
		}
	}
	for _, u := range []string{m.LogoURI, m.ClientURI, m.PolicyURI, m.TosURI} {
		if u != "" && !dcrMetaURL(u) {
			return n, metaErr("logo_uri, client_uri, policy_uri and tos_uri must be https URLs (http for loopback)")
		}
	}

	n.client = core.Client{
		Name: m.ClientName, Enabled: true, Public: public, RedirectURIs: uris,
		AuthCodeFlow: hasCode, ServiceAccount: hasCC, DeviceFlow: hasDevice,
		// Every code-flow client must use PKCE S256, confidential or not.
		RequirePKCE:          hasCode,
		BackchannelLogoutURI: m.BackchannelLogoutURI,
	}
	n.frontchannel = m.FrontchannelLogoutURI
	n.reg = core.RegisteredClient{
		ApplicationType: app, TokenAuthMethod: method, Scope: strings.Join(sc, " "), GrantTypes: gs,
		Contacts: m.Contacts, LogoURI: m.LogoURI, ClientURI: m.ClientURI, PolicyURI: m.PolicyURI, TosURI: m.TosURI,
	}
	return n, nil
}

func dcrText(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0) {
			return false
		}
	}
	return true
}

func dcrLoopback(h string) bool {
	if strings.EqualFold(h, "localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

var dcrSchemeRE = regexp.MustCompile(`^[a-z][a-z0-9+.-]*$`)

// dcrRedirectOK is the Admin API redirect rule (no wildcards, no fragments,
// length cap, no javascript:/data:/vbscript:/file:/blob:) made stricter: http
// only for loopback, no userinfo, and custom schemes only for native apps and
// only reverse-domain style (they must contain a dot).
func dcrRedirectOK(raw, app string) bool {
	if raw == "" || len(raw) > dcrMaxURILen || !dcrText(raw, dcrMaxURILen) ||
		strings.ContainsAny(raw, "*#\\") || strings.TrimSpace(raw) != raw {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Fragment != "" || u.User != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "javascript", "data", "vbscript", "file", "blob":
		return false
	case "https":
		return u.Hostname() != ""
	case "http":
		return u.Hostname() != "" && dcrLoopback(u.Hostname())
	}
	return app == "native" && dcrSchemeRE.MatchString(u.Scheme) && strings.Contains(u.Scheme, ".")
}

func dcrMetaURL(raw string) bool {
	if len(raw) > dcrMaxURILen || !dcrText(raw, dcrMaxURILen) {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Hostname() == "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return true
	case "http":
		return dcrLoopback(u.Hostname())
	}
	return false
}

// ---- shared plumbing ----

func (p *Provider) dcrStore(w http.ResponseWriter) (core.DCRStore, bool) {
	st, ok := core.StoreAs[core.DCRStore](p.cfg.Store)
	if !ok {
		writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "feature_unavailable"})
	}
	return st, ok
}

// dcrLimit counts one hit for (purpose, realm, ip) and fails closed.
func (p *Provider) dcrLimit(w http.ResponseWriter, r *http.Request, realm, purpose string, max int) bool {
	sum := sha256.Sum256([]byte(purpose + "|" + realm + "|" + p.clientIP(r)))
	ok, err := p.cfg.Store.HitRateLimit(r.Context(), hex.EncodeToString(sum[:]), p.now(), dcrWindow, max)
	if err != nil {
		p.cfg.Logger.Error("oidc: dcr rate limit", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "temporarily_unavailable"})
		return false
	}
	if !ok {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too_many_requests",
			"error_description": "too many registration requests, retry later"})
		return false
	}
	return true
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		return ""
	}
	t := strings.TrimSpace(h[7:])
	if len(t) > 512 || strings.ContainsAny(t, " \t") {
		return ""
	}
	return t
}

func (p *Provider) dcrEvent(r *http.Request, rl core.Realm, typ, clientID, detail string) {
	p.event(r.Context(), rl, typ, "", clientID, p.clientIP(r), detail)
}

// dcrLiveCount counts DCR clients that still exist as the very same client
// (a deleted client, or a reused client_id, does not count).
func (p *Provider) dcrLive(r *http.Request, st core.DCRStore, realm string) ([]core.RegisteredClient, error) {
	rows, err := st.ListRegisteredClients(r.Context(), realm)
	if err != nil {
		return nil, err
	}
	cs, err := p.cfg.Store.ListClients(r.Context(), realm)
	if err != nil {
		return nil, err
	}
	ids := make(map[string]string, len(cs))
	for _, c := range cs {
		ids[c.ClientID] = c.ID
	}
	out := rows[:0]
	for _, rc := range rows {
		if id, ok := ids[rc.ClientID]; ok && id == rc.ClientUUID {
			out = append(out, rc)
		}
	}
	return out, nil
}

func (p *Provider) dcrPolicy(r *http.Request, st core.DCRStore, realm string) (core.RegistrationPolicy, error) {
	pol, err := st.GetRegistrationPolicy(r.Context(), realm)
	if errors.Is(err, idp.ErrNotFound) {
		return core.RegistrationPolicy{Realm: realm, MaxClients: core.DCRDefaultMaxClients,
			AllowedGrantTypes: slices.Clone(core.DCRGrantTypes)}, nil
	}
	if len(pol.AllowedGrantTypes) == 0 {
		pol.AllowedGrantTypes = slices.Clone(core.DCRGrantTypes)
	}
	return pol, err
}

func (p *Provider) dcrView(rl core.Realm, cl core.Client, rc core.RegisteredClient) map[string]any {
	v := map[string]any{
		"client_id":                  cl.ClientID,
		"client_id_issued_at":        cl.CreatedAt.Unix(),
		"registration_client_uri":    p.issuer(rl.Name) + dcrPath + "/" + cl.ClientID,
		"redirect_uris":              nonNil(cl.RedirectURIs),
		"grant_types":                nonNil(rc.GrantTypes),
		"response_types":             []string{},
		"token_endpoint_auth_method": rc.TokenAuthMethod,
		"application_type":           rc.ApplicationType,
		"scope":                      rc.Scope,
	}
	if cl.AuthCodeFlow {
		v["response_types"] = []string{"code"}
	}
	for k, s := range map[string]string{"client_name": cl.Name, "backchannel_logout_uri": cl.BackchannelLogoutURI,
		"logo_uri": rc.LogoURI, "client_uri": rc.ClientURI, "policy_uri": rc.PolicyURI, "tos_uri": rc.TosURI} {
		if s != "" {
			v[k] = s
		}
	}
	if len(rc.Contacts) > 0 {
		v["contacts"] = rc.Contacts
	}
	return v
}

// dcrFrontchannelSupported refuses a frontchannel_logout_uri the store cannot
// keep, rather than dropping it silently.
func (p *Provider) dcrFrontchannelSupported(n dcrNormalized) *dcrErr {
	if _, ok := core.StoreAs[core.FrontchannelStore](p.cfg.Store); !ok && n.frontchannel != "" {
		return metaErr("frontchannel_logout_uri is not supported by this server")
	}
	return nil
}

// dcrSetFrontchannel replaces the client's URI ("" removes it).
func (p *Provider) dcrSetFrontchannel(ctx context.Context, realm, clientUUID, uri string) error {
	st, ok := core.StoreAs[core.FrontchannelStore](p.cfg.Store)
	if !ok {
		return nil
	}
	return st.SetFrontchannelLogoutURI(ctx, realm, clientUUID, uri)
}

func (p *Provider) dcrViewFrontchannel(ctx context.Context, v map[string]any, realm string, cl core.Client) {
	st, ok := core.StoreAs[core.FrontchannelStore](p.cfg.Store)
	if !ok {
		return
	}
	uri, err := st.FrontchannelLogoutURI(ctx, realm, cl.ID)
	if err != nil {
		p.cfg.Logger.Error("oidc: dcr front-channel logout uri", "err", err)
		return
	}
	if uri != "" {
		v["frontchannel_logout_uri"] = uri
		v["frontchannel_logout_session_required"] = true // iss and sid are always sent
	}
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ---- POST: register ----

func (p *Provider) dcrRegister(w http.ResponseWriter, r *http.Request) {
	rl, ok := p.realm(r.Context(), r.PathValue("realm"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "realm_not_found"})
		return
	}
	st, ok := p.dcrStore(w)
	if !ok {
		return
	}
	if !p.dcrLimit(w, r, rl.Name, "dcr", dcrRegisterMax) {
		return
	}
	ctx := r.Context()
	tok := bearerToken(r)
	if tok == "" {
		p.dcrEvent(r, rl, "CLIENT_REGISTER_ERROR", "", "invalid_token")
		writeDCRErr(w, errInvalidToken)
		return
	}
	iat, err := st.ConsumeInitialAccessToken(ctx, rl.Name, HashSecret(tok), p.now())
	if err != nil || iat.CreatedAt.Before(rl.CreatedAt) { // token older than the realm: realm was recreated
		if err != nil && !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: dcr consume token", "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
			return
		}
		p.dcrEvent(r, rl, "CLIENT_REGISTER_ERROR", "", "invalid_token")
		writeDCRErr(w, errInvalidToken)
		return
	}
	// From here the token's registration is spent; give it back unless a
	// client was actually created.
	created := false
	defer func() {
		if !created {
			if err := st.RefundInitialAccessToken(ctx, rl.Name, iat.ID); err != nil {
				p.cfg.Logger.Error("oidc: dcr refund token", "err", err)
			}
		}
	}()
	fail := func(e *dcrErr) {
		p.dcrEvent(r, rl, "CLIENT_REGISTER_ERROR", "", e.code)
		writeDCRErr(w, e)
	}
	srvFail := func(what string, err error) {
		p.cfg.Logger.Error("oidc: dcr "+what, "err", err)
		p.dcrEvent(r, rl, "CLIENT_REGISTER_ERROR", "", "server_error")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
	}

	meta, merr := dcrReadMeta(w, r)
	if merr != nil {
		fail(merr)
		return
	}
	pol, err := p.dcrPolicy(r, st, rl.Name)
	if err != nil {
		srvFail("policy", err)
		return
	}
	n, verr := dcrValidate(meta, pol.AllowedGrantTypes)
	if verr == nil {
		verr = p.dcrFrontchannelSupported(n)
	}
	if verr == nil {
		verr = p.dcrAuthAvailable(n.auth)
	}
	if verr != nil {
		fail(verr)
		return
	}
	capErr := &dcrErr{http.StatusForbidden, "access_denied", "this realm has reached its limit of dynamically registered clients"}
	live, err := p.dcrLive(r, st, rl.Name)
	if err != nil {
		srvFail("count", err)
		return
	}
	if len(live) >= pol.MaxClients {
		fail(capErr)
		return
	}

	var secret string
	cl := n.client
	cl.Realm = rl.Name
	cl.CreatedAt = p.now().UTC()
	if !cl.Public && !core.StrongClientAuth(n.reg.TokenAuthMethod) { // key and certificate clients get no secret
		secret = randToken(32)
		cl.SecretHash = HashSecret(secret)
	}
	regTok := "hrat_" + randToken(32)
	for attempt := 0; ; attempt++ {
		cl.ClientID = "hc_" + randToken(16) // 22 URL-safe characters
		err = p.cfg.Store.CreateClient(ctx, cl)
		if !errors.Is(err, idp.ErrConflict) || attempt >= 3 {
			break
		}
	}
	if err != nil {
		srvFail("create client", err)
		return
	}
	stored, err := p.cfg.Store.GetClientByClientID(ctx, rl.Name, cl.ClientID)
	if err != nil {
		srvFail("reload client", err)
		return
	}
	rc := n.reg
	rc.Realm, rc.ClientID, rc.ClientUUID = rl.Name, stored.ClientID, stored.ID
	rc.RegTokenHash, rc.CreatedVia, rc.InitialTokenID = HashSecret(regTok), core.DCRCreatedVia, iat.ID
	rc.CreatedAt, rc.UpdatedAt = stored.CreatedAt, stored.CreatedAt
	rollback := func() { _ = p.cfg.Store.DeleteClient(ctx, rl.Name, stored.ID) }
	if n.auth != nil {
		if err := p.dcrApplyAuth(ctx, rl.Name, stored, n.auth); err != nil {
			rollback()
			srvFail("store client authentication", err)
			return
		}
	}
	if err := st.PutRegisteredClient(ctx, rc); err != nil {
		rollback()
		srvFail("store registration", err)
		return
	}
	// Strict cap check after the fact: concurrent registrations may all have
	// passed the pre-check, so over the cap everyone over it backs out.
	if live, err = p.dcrLive(r, st, rl.Name); err != nil || len(live) > pol.MaxClients {
		_ = st.DeleteRegisteredClient(ctx, rl.Name, stored.ClientID)
		rollback()
		if err != nil {
			srvFail("recount", err)
			return
		}
		fail(capErr)
		return
	}
	if err := p.dcrSetFrontchannel(ctx, rl.Name, stored.ID, n.frontchannel); err != nil {
		_ = st.DeleteRegisteredClient(ctx, rl.Name, stored.ClientID)
		rollback()
		srvFail("store front-channel logout uri", err)
		return
	}
	created = true

	v := p.dcrView(rl, stored, rc)
	p.dcrViewFrontchannel(ctx, v, rl.Name, stored)
	dcrAuthView(v, n.auth)
	v["registration_access_token"] = regTok
	if secret != "" {
		v["client_secret"] = secret
		v["client_secret_expires_at"] = 0
	}
	method := "public"
	if !stored.Public {
		method = "confidential"
	}
	p.dcrEvent(r, rl, "CLIENT_REGISTER", stored.ClientID, "type="+method+" app="+rc.ApplicationType+" iat="+iat.ID)
	writeJSON(w, http.StatusCreated, v)
}

// ---- management (RFC 7592) ----

// dcrManage authenticates a management call with the registration access
// token of exactly this client. Every failure is the same 401, so nothing
// tells apart an unknown client, an admin-created client (never manageable
// here) and a wrong token.
func (p *Provider) dcrManage(w http.ResponseWriter, r *http.Request) (core.Realm, core.DCRStore, core.RegisteredClient, core.Client, bool) {
	var zrc core.RegisteredClient
	rl, ok := p.realm(r.Context(), r.PathValue("realm"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "realm_not_found"})
		return rl, nil, zrc, core.Client{}, false
	}
	st, ok := p.dcrStore(w)
	if !ok {
		return rl, nil, zrc, core.Client{}, false
	}
	if !p.dcrLimit(w, r, rl.Name, "dcr-manage", dcrManageMax) {
		return rl, nil, zrc, core.Client{}, false
	}
	deny := func() (core.Realm, core.DCRStore, core.RegisteredClient, core.Client, bool) {
		p.dcrEvent(r, rl, "CLIENT_REGISTER_ERROR", "", "manage invalid_token")
		writeDCRErr(w, errInvalidToken)
		return rl, nil, zrc, core.Client{}, false
	}
	tok, id := bearerToken(r), r.PathValue("clientId")
	if !dcrClientIDRE.MatchString(id) {
		return deny()
	}
	rc, err := st.GetRegisteredClient(r.Context(), rl.Name, id)
	if err != nil {
		secretEq(tok, HashSecret("x")) // similar timing for unknown clients
		if !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: dcr load registration", "err", err)
		}
		return deny()
	}
	if tok == "" || !secretEq(tok, rc.RegTokenHash) {
		return deny()
	}
	cl, err := p.cfg.Store.GetClientByClientID(r.Context(), rl.Name, id)
	if err != nil || cl.ID != rc.ClientUUID {
		return deny()
	}
	return rl, st, rc, cl, true
}

func (p *Provider) dcrRead(w http.ResponseWriter, r *http.Request) {
	rl, _, rc, cl, ok := p.dcrManage(w, r)
	if !ok {
		return
	}
	v := p.dcrView(rl, cl, rc)
	p.dcrViewFrontchannel(r.Context(), v, rl.Name, cl)
	cur, found, err := p.clientAuthConfig(r.Context(), rl.Name, cl)
	if err != nil {
		p.cfg.Logger.Error("oidc: dcr client authentication", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if found {
		dcrAuthView(v, &cur)
	}
	writeJSON(w, http.StatusOK, v)
}

// dcrUpdate replaces the client's metadata (RFC 7592 section 2.2). Nothing is
// rotated: the client secret and the registration access token stay as they
// are and are not returned again. The client cannot switch between public and
// confidential, and an administrator's disabled flag is kept.
func (p *Provider) dcrUpdate(w http.ResponseWriter, r *http.Request) {
	rl, st, rc, cl, ok := p.dcrManage(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	fail := func(e *dcrErr) {
		p.dcrEvent(r, rl, "CLIENT_REGISTER_ERROR", cl.ClientID, "update "+e.code)
		writeDCRErr(w, e)
	}
	meta, merr := dcrReadMeta(w, r)
	if merr != nil {
		fail(merr)
		return
	}
	if (meta.ClientID != "" && meta.ClientID != cl.ClientID) || meta.ClientSecret != "" || meta.RegistrationAccessToken != "" {
		fail(metaErr("client_id, client_secret and registration_access_token cannot be changed"))
		return
	}
	pol, err := p.dcrPolicy(r, st, rl.Name)
	if err != nil {
		p.cfg.Logger.Error("oidc: dcr policy", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	n, verr := dcrValidate(meta, pol.AllowedGrantTypes)
	if verr == nil {
		verr = p.dcrFrontchannelSupported(n)
	}
	if verr != nil {
		fail(verr)
		return
	}
	if n.client.Public != cl.Public {
		fail(metaErr("the client cannot switch between public and confidential"))
		return
	}
	cur, found, err := p.clientAuthConfig(ctx, rl.Name, cl)
	if err != nil {
		p.cfg.Logger.Error("oidc: dcr client authentication", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if found && core.StrongClientAuth(cur.Method) && !core.StrongClientAuth(n.reg.TokenAuthMethod) {
		fail(metaErr("a client that authenticates with a key or certificate cannot switch to a secret"))
		return
	}
	if found && cur.CertBoundTokens && (n.auth == nil || !n.auth.CertBoundTokens) {
		fail(metaErr("certificate-bound access tokens cannot be switched off through registration management"))
		return
	}
	if e := p.dcrAuthAvailable(n.auth); e != nil {
		fail(e)
		return
	}
	next := cl
	next.Name, next.RedirectURIs, next.AuthCodeFlow, next.ServiceAccount = n.client.Name, n.client.RedirectURIs, n.client.AuthCodeFlow, n.client.ServiceAccount
	next.DeviceFlow = n.client.DeviceFlow
	next.RequirePKCE, next.BackchannelLogoutURI = n.client.RequirePKCE, n.client.BackchannelLogoutURI
	if core.StrongClientAuth(n.reg.TokenAuthMethod) {
		next.SecretHash = "" // no secret is left behind to fall back to
	}
	// Settings first: if the next write fails the stricter method already holds.
	if err := p.dcrApplyAuth(ctx, rl.Name, cl, n.auth); err != nil {
		p.cfg.Logger.Error("oidc: dcr update client authentication", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := p.cfg.Store.UpdateClient(ctx, next); err != nil {
		p.cfg.Logger.Error("oidc: dcr update client", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := p.dcrSetFrontchannel(ctx, rl.Name, cl.ID, n.frontchannel); err != nil {
		p.cfg.Logger.Error("oidc: dcr update front-channel logout uri", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	rc.ApplicationType, rc.TokenAuthMethod, rc.Scope, rc.GrantTypes = n.reg.ApplicationType, n.reg.TokenAuthMethod, n.reg.Scope, n.reg.GrantTypes
	rc.Contacts, rc.LogoURI, rc.ClientURI, rc.PolicyURI, rc.TosURI = n.reg.Contacts, n.reg.LogoURI, n.reg.ClientURI, n.reg.PolicyURI, n.reg.TosURI
	rc.UpdatedAt = p.now().UTC()
	if err := st.UpdateRegisteredClient(ctx, rc); err != nil {
		p.cfg.Logger.Error("oidc: dcr update registration", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	p.dcrEvent(r, rl, "CLIENT_UPDATE_REGISTRATION", cl.ClientID, "")
	v := p.dcrView(rl, next, rc)
	p.dcrViewFrontchannel(ctx, v, rl.Name, next)
	dcrAuthView(v, n.auth)
	writeJSON(w, http.StatusOK, v)
}

// dcrDelete removes the client and its registration record. Codes and tokens
// already issued die with the client lookup (every grant re-reads the client).
func (p *Provider) dcrDelete(w http.ResponseWriter, r *http.Request) {
	rl, st, _, cl, ok := p.dcrManage(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := p.cfg.Store.DeleteClient(ctx, rl.Name, cl.ID); err != nil && !errors.Is(err, idp.ErrNotFound) {
		p.cfg.Logger.Error("oidc: dcr delete client", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	if err := st.DeleteRegisteredClient(ctx, rl.Name, cl.ClientID); err != nil && !errors.Is(err, idp.ErrNotFound) {
		p.cfg.Logger.Error("oidc: dcr delete registration", "err", err)
	}
	p.dcrEvent(r, rl, "CLIENT_DELETE_REGISTRATION", cl.ClientID, "")
	noStore(w)
	w.WriteHeader(http.StatusNoContent)
}
