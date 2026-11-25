// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Dynamic client registration of strong client authentication (RFC 7591
// metadata, RFC 8705 section 2). A registration that asks for a key or
// certificate method gets no client secret, and RFC 7592 updates cannot move
// such a client back to a secret.

// dcrAuthMeta is the registration metadata of client authentication.
type dcrAuthMeta struct {
	JWKS                        json.RawMessage `json:"jwks"`
	JWKSURI                     string          `json:"jwks_uri"`
	TokenEndpointAuthSigningAlg string          `json:"token_endpoint_auth_signing_alg"`
	TLSSubjectDN                string          `json:"tls_client_auth_subject_dn"`
	TLSSANDNS                   string          `json:"tls_client_auth_san_dns"`
	TLSSANURI                   string          `json:"tls_client_auth_san_uri"`
	TLSSANIP                    string          `json:"tls_client_auth_san_ip"`
	TLSSANEmail                 string          `json:"tls_client_auth_san_email"`
	CertBoundTokens             bool            `json:"tls_client_certificate_bound_access_tokens"`
}

var dcrAuthMethods = []string{core.AuthMethodNone, core.AuthMethodSecretBasic, core.AuthMethodSecretPost,
	core.AuthMethodPrivateKeyJWT, core.AuthMethodTLS, core.AuthMethodSelfSignedTLS}

// dcrClientAuth turns the metadata into the configuration to store, or nil
// when the client needs none (secret or public, no certificate binding: key
// metadata is then ignored, as before).
func dcrClientAuth(m dcrAuthMeta, method string) (*core.ClientAuth, *dcrErr) {
	if !core.StrongClientAuth(method) && !m.CertBoundTokens {
		return nil, nil
	}
	c := core.ClientAuth{Method: method, CertBoundTokens: m.CertBoundTokens}
	if core.StrongClientAuth(method) {
		if t := bytes.TrimSpace(m.JWKS); len(t) > 0 && !bytes.Equal(t, []byte("null")) {
			c.JWKS = string(t)
		}
		c.JWKSURI, c.SigningAlg = m.JWKSURI, m.TokenEndpointAuthSigningAlg
		c.TLSSubjectDN, c.TLSSANDNS, c.TLSSANURI = m.TLSSubjectDN, m.TLSSANDNS, m.TLSSANURI
		c.TLSSANIP, c.TLSSANEmail = m.TLSSANIP, m.TLSSANEmail
	}
	// Registration never accepts an http jwks_uri, not even on loopback.
	c, err := ValidateClientAuth(c, method == core.AuthMethodNone, false)
	if err != nil {
		return nil, metaErr("the client authentication metadata (jwks or jwks_uri, signing algorithm, certificate subject, certificate binding) is not acceptable for this token_endpoint_auth_method")
	}
	return &c, nil
}

// dcrAuthAvailable refuses a method this deployment cannot enforce.
func (p *Provider) dcrAuthAvailable(a *core.ClientAuth) *dcrErr {
	if a == nil {
		return nil
	}
	_, ok := p.clientAuthStore()
	needTLS := a.Method == core.AuthMethodTLS || a.Method == core.AuthMethodSelfSignedTLS || a.CertBoundTokens
	if !ok || (needTLS && !p.cfg.MTLS.Enabled()) || (a.Method == core.AuthMethodTLS && p.cfg.MTLS.Roots == nil) {
		return metaErr("this server does not support the requested client authentication")
	}
	return nil
}

// dcrApplyAuth stores (or removes) the configuration of a registered client.
func (p *Provider) dcrApplyAuth(ctx context.Context, realm string, cl core.Client, a *core.ClientAuth) error {
	st, ok := p.clientAuthStore()
	if !ok {
		if a == nil {
			return nil
		}
		return errors.New("no client authentication store")
	}
	if a == nil {
		return st.DeleteClientAuth(ctx, realm, cl.ID)
	}
	c := *a
	c.Realm, c.ClientRef = realm, cl.ID
	return st.PutClientAuth(ctx, c)
}

// dcrAuthView adds the configuration to a registration response.
func dcrAuthView(v map[string]any, a *core.ClientAuth) {
	if a == nil || !slices.Contains(dcrAuthMethods, a.Method) {
		return
	}
	v["token_endpoint_auth_method"] = a.Method
	if a.JWKS != "" {
		v["jwks"] = json.RawMessage(a.JWKS)
	}
	for k, s := range map[string]string{"jwks_uri": a.JWKSURI, "token_endpoint_auth_signing_alg": a.SigningAlg,
		"tls_client_auth_subject_dn": a.TLSSubjectDN, "tls_client_auth_san_dns": a.TLSSANDNS,
		"tls_client_auth_san_uri": a.TLSSANURI, "tls_client_auth_san_ip": a.TLSSANIP, "tls_client_auth_san_email": a.TLSSANEmail} {
		if s != "" {
			v[k] = s
		}
	}
	if a.CertBoundTokens {
		v["tls_client_certificate_bound_access_tokens"] = true
	}
}
