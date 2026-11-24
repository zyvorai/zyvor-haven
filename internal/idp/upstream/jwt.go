// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package upstream

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/zyvorai/haven/internal/idp/safehttp"
)

// Workload JWT verification: validates a platform-issued token (for example a
// Kubernetes projected service-account token) against explicitly configured
// keys. Unlike an ID token there is no nonce and no client_id; the caller pins
// issuer, audience and subject exactly.

const maxWorkloadJWT = 16 << 10

// JWTSpec says what a workload JWT must look like to be accepted. Every field
// except the key source is mandatory and compared exactly.
type JWTSpec struct {
	Issuer   string
	Audience string
	Subject  string
	// Exactly one key source: a JWKS URL (fetched through the SSRF-safe client
	// and cached) or an inline JWKS document.
	JWKSURI    string
	StaticJWKS string
}

// ParseStaticJWKS validates an inline JWKS document and returns how many
// usable keys it holds (0 with an error when none).
func ParseStaticJWKS(raw string) (int, error) {
	keys, err := parseJWKSDoc([]byte(raw))
	return len(keys), err
}

func parseJWKSDoc(raw []byte) ([]jwk, error) {
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, errors.New("not a JWKS document")
	}
	if len(doc.Keys) > maxJWKSKeys {
		doc.Keys = doc.Keys[:maxJWKSKeys]
	}
	var ok []jwk
	for _, k := range doc.Keys {
		if k.parse() {
			ok = append(ok, k)
		}
	}
	if len(ok) == 0 {
		return nil, errors.New("no usable keys (RSA >= 2048 bits or P-256 EC, use sig)")
	}
	return ok, nil
}

func pickKey(keys []jwk, alg, kid string) (any, bool) {
	var match []jwk
	for _, k := range keys {
		if k.Alg != "" && k.Alg != alg {
			continue
		}
		if (alg == "ES256") != (k.Kty == "EC") {
			continue
		}
		if kid != "" && k.Kid != kid {
			continue
		}
		match = append(match, k)
	}
	if len(match) == 1 || (kid != "" && len(match) > 0) {
		return match[0].pub, true
	}
	return nil, false
}

// VerifyJWT fully validates raw: size, structure, algorithm allowlist
// (RS256/PS256/ES256 only), signature against the configured keys, iss, aud,
// sub (all exact), and exp (required), iat/nbf with 60 s skew. Failure kinds
// are stable and secret-free; the caller must not distinguish them to the
// remote party.
func (m *Manager) VerifyJWT(ctx context.Context, s JWTSpec, raw string) (Claims, error) {
	if s.Issuer == "" || s.Audience == "" || s.Subject == "" || (s.JWKSURI == "") == (s.StaticJWKS == "") {
		return nil, fail("bad_spec", nil)
	}
	if len(raw) == 0 || len(raw) > maxWorkloadJWT {
		return nil, fail("bad_token", nil)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fail("bad_token", nil)
	}
	hdrB, err1 := base64.RawURLEncoding.DecodeString(parts[0])
	payB, err2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, err3 := base64.RawURLEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, fail("bad_token", nil)
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hdrB, &hdr); err != nil {
		return nil, fail("bad_token", nil)
	}
	if !allowedAlgs[hdr.Alg] {
		return nil, fail("bad_alg", nil)
	}
	var key any
	if s.StaticJWKS != "" {
		keys, err := parseJWKSDoc([]byte(s.StaticJWKS))
		if err != nil {
			return nil, fail("bad_jwks", err)
		}
		var ok bool
		if key, ok = pickKey(keys, hdr.Alg, hdr.Kid); !ok {
			return nil, fail("unknown_key", nil)
		}
	} else {
		if _, err := safehttp.ValidateURL(s.JWKSURI, m.allowPrivate, "jwks url", maxURL); err != nil {
			return nil, fail("bad_url", err)
		}
		var err error
		if key, err = m.selectKey(ctx, s.JWKSURI, hdr.Alg, hdr.Kid); err != nil {
			return nil, err
		}
	}
	if !verifySig(hdr.Alg, key, []byte(parts[0]+"."+parts[1]), sig) {
		return nil, fail("bad_signature", nil)
	}
	dec := json.NewDecoder(bytes.NewReader(payB))
	dec.UseNumber()
	var c Claims
	if err := dec.Decode(&c); err != nil {
		return nil, fail("bad_token", nil)
	}
	if err := m.checkWorkloadClaims(s, c); err != nil {
		return nil, err
	}
	return c, nil
}

func (m *Manager) checkWorkloadClaims(s JWTSpec, c Claims) error {
	now := m.now()
	if iss, _ := c["iss"].(string); subtle.ConstantTimeCompare([]byte(iss), []byte(s.Issuer)) != 1 || iss == "" {
		return fail("issuer_mismatch", nil)
	}
	if !audOK(c["aud"], s.Audience) {
		return fail("bad_audience", nil)
	}
	if sub, _ := c["sub"].(string); subtle.ConstantTimeCompare([]byte(sub), []byte(s.Subject)) != 1 || sub == "" {
		return fail("bad_subject", nil)
	}
	exp, hasExp, okExp := numClaim(c, "exp")
	iat, hasIat, okIat := numClaim(c, "iat")
	nbf, hasNbf, okNbf := numClaim(c, "nbf")
	if !okExp || !okIat || !okNbf || !hasExp {
		return fail("bad_time", nil)
	}
	if !now.Before(exp.Add(Skew)) {
		return fail("expired", nil)
	}
	if (hasIat && iat.After(now.Add(Skew))) || (hasNbf && nbf.After(now.Add(Skew))) {
		return fail("bad_time", nil)
	}
	return nil
}
