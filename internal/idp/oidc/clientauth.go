// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/safehttp"
)

// Client authentication with a per-client method. See
// docs/client-authentication.md.
//
// Every endpoint that authenticates a client goes through authClient
// (token.go), which hands over to this file in two cases: the request carries
// a client assertion, or the client has a core.ClientAuth configuration. A
// configured method is the ONLY way that client authenticates: a client set to
// private_key_jwt or mutual TLS is refused with a secret (right or wrong), with
// nothing but its client_id, and even if an administrator later marks it
// public. A store error refuses the request instead of assuming "no method".

const (
	clientAssertionRate = 3000 // accepted assertions per client and address per 10 minutes
	caMaxDN             = 1024
)

func (p *Provider) clientAuthStore() (core.ClientAuthStore, bool) {
	return core.StoreAs[core.ClientAuthStore](p.cfg.Store)
}

// clientAuthConfig returns the client's configuration; found=false means it
// has none (or the store cannot hold any).
func (p *Provider) clientAuthConfig(ctx context.Context, realm string, cl core.Client) (cfg core.ClientAuth, found bool, err error) {
	st, ok := p.clientAuthStore()
	if !ok || cl.ID == "" {
		return core.ClientAuth{}, false, nil
	}
	cfg, err = st.GetClientAuth(ctx, realm, cl.ID)
	if errors.Is(err, idp.ErrNotFound) {
		return core.ClientAuth{}, false, nil
	}
	if err != nil {
		return core.ClientAuth{}, false, err
	}
	return cfg, true, nil
}

func badClient() *tokenErr {
	return &tokenErr{http.StatusUnauthorized, "invalid_client", "client authentication failed"}
}

// clientAuthFailed logs why (a fixed label, never credential material) and
// returns the one opaque answer the caller sees.
func (p *Provider) clientAuthFailed(realm, clientID, method, reason string) *tokenErr {
	p.cfg.Logger.Info("oidc: client authentication failed", "realm", realm, "client", clientID, "method", method, "reason", reason)
	return badClient()
}

// authConfigured authenticates a client that has a configured method, from a
// request without a client assertion.
func (p *Provider) authConfigured(r *http.Request, realm string, cl core.Client, cfg core.ClientAuth, secret string, basic bool) (core.Client, bool, bool, *tokenErr) {
	deny := func(reason string) (core.Client, bool, bool, *tokenErr) {
		return core.Client{}, false, basic, p.clientAuthFailed(realm, cl.ClientID, cfg.Method, reason)
	}
	switch cfg.Method {
	case core.AuthMethodSecretBasic, core.AuthMethodSecretPost:
		if cl.Public || basic != (cfg.Method == core.AuthMethodSecretBasic) {
			return deny("wrong_method")
		}
		if !secretEq(secret, cl.SecretHash) {
			return deny("bad_secret")
		}
		return cl, true, basic, nil
	case core.AuthMethodNone:
		if !cl.Public || basic || secret != "" {
			return deny("wrong_method")
		}
		return cl, false, basic, nil
	case core.AuthMethodTLS, core.AuthMethodSelfSignedTLS:
		// No other credential may travel with the certificate.
		if basic || r.Header.Get("Authorization") != "" || r.PostForm.Has("client_secret") {
			return deny("wrong_method")
		}
		if reason := p.verifyClientCert(r, cfg); reason != "" {
			return deny(reason)
		}
		return cl, true, false, nil
	}
	// private_key_jwt without an assertion, or a method this build does not know.
	return deny("wrong_method")
}

// authAssertion authenticates a request that carries a client assertion
// (private_key_jwt).
func (p *Provider) authAssertion(r *http.Request, realm string) (core.Client, bool, bool, *tokenErr) {
	fail := func(clientID, reason string) (core.Client, bool, bool, *tokenErr) {
		return core.Client{}, false, false, p.clientAuthFailed(realm, clientID, core.AuthMethodPrivateKeyJWT, reason)
	}
	server := func(what string, err error) (core.Client, bool, bool, *tokenErr) {
		p.cfg.Logger.Error("oidc: client assertion "+what, "err", err)
		return core.Client{}, false, false, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	if r.Header.Get("Authorization") != "" || r.PostForm.Has("client_secret") {
		return core.Client{}, false, false, oerr("invalid_request", "multiple client authentication methods")
	}
	types, raws := r.PostForm["client_assertion_type"], r.PostForm["client_assertion"]
	if len(types) != 1 || types[0] != clientAssertionType || len(raws) != 1 {
		return fail("", "assertion_parameters")
	}
	a, err := parseAssertion(raws[0])
	if err != nil {
		return fail("", err.Error())
	}
	// sub only selects which client's keys to try; nothing is trusted before
	// the signature verifies against them.
	id := a.str("sub")
	if id == "" || len(id) > cimdMaxURL {
		return fail("", "no_subject")
	}
	if ids := r.PostForm["client_id"]; len(ids) > 1 || (len(ids) == 1 && ids[0] != id) {
		return fail("", "client_id_mismatch")
	}
	st, ok := p.clientAuthStore()
	if !ok {
		return fail("", "unavailable")
	}
	ctx := r.Context()
	cl, err := p.cfg.Store.GetClientByClientID(ctx, realm, id)
	if err != nil {
		if !errors.Is(err, idp.ErrNotFound) {
			return server("client", err)
		}
		return fail("", "unknown_client")
	}
	if !cl.Enabled {
		return fail(cl.ClientID, "disabled")
	}
	cfg, found, err := p.clientAuthConfig(ctx, realm, cl)
	if err != nil {
		return server("settings", err)
	}
	if !found || cfg.Method != core.AuthMethodPrivateKeyJWT {
		return fail(cl.ClientID, "wrong_method")
	}
	if cfg.SigningAlg != "" && cfg.SigningAlg != a.alg {
		return fail(cl.ClientID, "wrong_alg")
	}
	keys, err := p.clientKeys(ctx, cfg, func(k []clientKey) bool { return len(a.candidates(k)) > 0 })
	if err != nil {
		p.cfg.Logger.Info("oidc: client keys unavailable", "realm", realm, "client", cl.ClientID, "err", err)
		return fail(cl.ClientID, "keys_unavailable")
	}
	if !a.verify(keys) {
		return fail(cl.ClientID, "bad_signature_or_key")
	}
	// RFC 7523 / OIDC Core 9 (and RFC 9126 section 2, CIBA 7.1): the audience
	// is this server: its issuer, the token endpoint, or the endpoint called.
	auds := []string{p.issuer(realm), p.endpoint(realm, "token"), p.base + r.URL.Path}
	jti, exp, err := a.checkClaims(cl.ClientID, auds, p.now())
	if err != nil {
		return fail(cl.ClientID, err.Error())
	}
	allowed, err := p.hitLimit(ctx, "clientassert", realm, cl.ID+"|"+p.clientIP(r), clientAssertionRate)
	if err != nil {
		return server("rate limit", err)
	}
	if !allowed {
		return core.Client{}, false, false, &tokenErr{http.StatusTooManyRequests, "invalid_request", "too many requests"}
	}
	// Single use. Remembered until the assertion can no longer be accepted.
	sum := sha256.Sum256([]byte(cl.ID + "|" + jti))
	switch err := st.RememberClientAssertion(ctx, realm, hex.EncodeToString(sum[:]), p.now(), exp.Add(caSkew+caSkew)); {
	case err == nil:
	case errors.Is(err, idp.ErrConflict):
		return fail(cl.ClientID, "replay")
	default:
		return server("replay cache", err)
	}
	return cl, true, false, nil
}

// ---- configuration validation (Admin API and dynamic registration) ----

var caDNSNameRE = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(\.[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?)*$`)

func caPrintable(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

// ValidateClientAuth checks a client authentication configuration for a client
// that is public or not, and returns it normalised. allowPrivate permits an
// http jwks_uri on loopback (dev only). Errors are fixed text and never repeat
// key material.
func ValidateClientAuth(c core.ClientAuth, public, allowPrivate bool) (core.ClientAuth, error) {
	e := func(msg string) (core.ClientAuth, error) { return core.ClientAuth{}, errors.New(msg) }
	methods := []string{core.AuthMethodNone, core.AuthMethodSecretBasic, core.AuthMethodSecretPost,
		core.AuthMethodPrivateKeyJWT, core.AuthMethodTLS, core.AuthMethodSelfSignedTLS}
	if !slices.Contains(methods, c.Method) {
		return e("method must be one of " + strings.Join(methods, ", "))
	}
	if public != (c.Method == core.AuthMethodNone) {
		return e("method none is for public clients; every other method needs a confidential client")
	}
	if public && c.CertBoundTokens {
		return e("certificate-bound tokens need a confidential client (refresh tokens of public clients are not certificate-bound)")
	}
	usesKeys := c.Method == core.AuthMethodPrivateKeyJWT || c.Method == core.AuthMethodSelfSignedTLS
	if !usesKeys && (c.JWKS != "" || c.JWKSURI != "") {
		return e("jwks and jwks_uri belong to private_key_jwt and self_signed_tls_client_auth only")
	}
	if c.Method != core.AuthMethodPrivateKeyJWT && c.SigningAlg != "" {
		return e("a signing algorithm belongs to private_key_jwt only")
	}
	tlsFields := 0
	for _, v := range []string{c.TLSSubjectDN, c.TLSSANDNS, c.TLSSANURI, c.TLSSANIP, c.TLSSANEmail} {
		if v != "" {
			tlsFields++
		}
	}
	if c.Method == core.AuthMethodTLS {
		if tlsFields != 1 {
			return e("tls_client_auth needs exactly one of the subject DN or a SAN (DNS, URI, IP or email)")
		}
		switch {
		case c.TLSSubjectDN != "" && !caPrintable(c.TLSSubjectDN, caMaxDN):
			return e("the subject DN is not acceptable")
		case c.TLSSANDNS != "" && (len(c.TLSSANDNS) > 253 || !caDNSNameRE.MatchString(c.TLSSANDNS)):
			return e("the DNS SAN must be a host name without wildcards")
		case c.TLSSANURI != "" && (!caPrintable(c.TLSSANURI, jwksMaxURI) || !strings.Contains(c.TLSSANURI, ":") || strings.ContainsAny(c.TLSSANURI, " *")):
			return e("the URI SAN must be an absolute URI")
		case c.TLSSANEmail != "" && (!caPrintable(c.TLSSANEmail, 254) || strings.Count(c.TLSSANEmail, "@") != 1 ||
			strings.HasPrefix(c.TLSSANEmail, "@") || strings.HasSuffix(c.TLSSANEmail, "@") || strings.ContainsAny(c.TLSSANEmail, " *")):
			return e("the email SAN must be an address")
		case c.TLSSANIP != "":
			ip, err := netip.ParseAddr(c.TLSSANIP)
			if err != nil || ip.Zone() != "" {
				return e("the IP SAN must be an IP address")
			}
			c.TLSSANIP = ip.Unmap().String()
		}
	} else if tlsFields != 0 {
		return e("a certificate subject or SAN belongs to tls_client_auth only")
	}
	if c.SigningAlg != "" && !slices.Contains(clientAssertionAlgs, c.SigningAlg) {
		return e("the signing algorithm must be one of " + strings.Join(clientAssertionAlgs, ", "))
	}
	if usesKeys {
		if (c.JWKS == "") == (c.JWKSURI == "") {
			return e(c.Method + " needs exactly one of jwks and jwks_uri")
		}
		if c.JWKSURI != "" {
			if _, err := safehttp.ValidateURL(c.JWKSURI, allowPrivate, "jwks_uri", jwksMaxURI); err != nil {
				return core.ClientAuth{}, err
			}
			return c, nil
		}
		keys, private, err := parseClientJWKS([]byte(c.JWKS))
		if err != nil {
			return e("jwks is not a usable JWKS document")
		}
		if private {
			return e("jwks must contain public keys only")
		}
		usable := slices.ContainsFunc(keys, func(k clientKey) bool {
			if c.Method == core.AuthMethodSelfSignedTLS {
				return k.cert != nil
			}
			return k.pub != nil
		})
		if !usable {
			if c.Method == core.AuthMethodSelfSignedTLS {
				return e("jwks needs at least one key with an x5c certificate")
			}
			return e("jwks needs at least one usable signing key (EC P-256, RSA 2048-8192 bits, or Ed25519)")
		}
	}
	return c, nil
}

// ---- discovery ----

func init() {
	registerDiscovery(func(p *Provider, _ string, doc map[string]any) {
		if _, ok := p.clientAuthStore(); !ok {
			return
		}
		extra := []string{core.AuthMethodPrivateKeyJWT}
		mtls := p.cfg.MTLS.Enabled()
		if mtls {
			if p.cfg.MTLS.Roots != nil {
				extra = append(extra, core.AuthMethodTLS)
			}
			extra = append(extra, core.AuthMethodSelfSignedTLS)
			doc["tls_client_certificate_bound_access_tokens"] = true
		}
		for _, ep := range []string{"token_endpoint", "introspection_endpoint", "revocation_endpoint"} {
			if m, ok := doc[ep+"_auth_methods_supported"].([]string); ok {
				doc[ep+"_auth_methods_supported"] = append(slices.Clone(m), extra...)
				doc[ep+"_auth_signing_alg_values_supported"] = clientAssertionAlgs
			}
		}
	})
}
