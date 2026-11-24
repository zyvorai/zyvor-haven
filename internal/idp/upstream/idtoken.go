// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package upstream

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"time"
)

// Clock skew tolerated on exp, iat and nbf.
const Skew = 60 * time.Second

const maxIDToken = 16 << 10

// Only these signature algorithms are accepted. "none" and every HMAC
// algorithm are refused by construction: the key type must match the
// algorithm family, and a symmetric algorithm has no key to match.
var allowedAlgs = map[string]bool{"RS256": true, "PS256": true, "ES256": true}

// Claims are the verified ID token claims.
type Claims map[string]any

// Str returns a string claim ("" when absent or not a string).
func (c Claims) Str(name string) string {
	s, _ := c[name].(string)
	return s
}

// Bool returns a boolean claim, accepting the strings "true"/"1" some
// providers send. Absent or anything else is false.
func (c Claims) Bool(name string) bool {
	switch v := c[name].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	}
	return false
}

// VerifyIDToken fully validates an ID token: structure, algorithm allowlist,
// signature against the provider's JWKS (kid selection, one refresh on an
// unknown kid), iss, aud (+azp), exp/iat/nbf with skew, and nonce. For a
// multi-tenant Microsoft provider the issuer is matched against the token's
// tid claim.
func (m *Manager) VerifyIDToken(ctx context.Context, s Spec, d *Discovery, raw, nonce string) (Claims, error) {
	if len(raw) == 0 || len(raw) > maxIDToken {
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
	signed := []byte(parts[0] + "." + parts[1])

	key, err := m.selectKey(ctx, d.JWKSURI, hdr.Alg, hdr.Kid)
	if err != nil {
		return nil, err
	}
	if !verifySig(hdr.Alg, key, signed, sig) {
		return nil, fail("bad_signature", nil)
	}

	dec := json.NewDecoder(bytes.NewReader(payB))
	dec.UseNumber()
	var claims Claims
	if err := dec.Decode(&claims); err != nil {
		return nil, fail("bad_token", nil)
	}
	if err := m.checkClaims(s, claims, nonce); err != nil {
		return nil, err
	}
	return claims, nil
}

func (m *Manager) selectKey(ctx context.Context, jwksURI, alg, kid string) (any, error) {
	for attempt := 0; attempt < 2; attempt++ {
		keys, err := m.keys(ctx, jwksURI, attempt == 1)
		if err != nil {
			return nil, err
		}
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
		// Without a kid the key is only unambiguous when exactly one fits.
		if len(match) == 1 || (kid != "" && len(match) > 0) {
			return match[0].pub, nil
		}
	}
	return nil, fail("unknown_key", nil)
}

func verifySig(alg string, pub any, signed, sig []byte) bool {
	h := sha256.Sum256(signed)
	switch alg {
	case "RS256":
		k, ok := pub.(*rsa.PublicKey)
		return ok && rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil
	case "PS256":
		k, ok := pub.(*rsa.PublicKey)
		return ok && rsa.VerifyPSS(k, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	case "ES256":
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || len(sig) != 64 {
			return false
		}
		return ecdsa.Verify(k, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	}
	return false
}

func numClaim(c Claims, name string) (time.Time, bool, bool) {
	v, ok := c[name]
	if !ok {
		return time.Time{}, false, true
	}
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, true, false
	}
	f, err := n.Float64()
	if err != nil || f < 0 || f > 1e12 {
		return time.Time{}, true, false
	}
	return time.Unix(int64(f), 0), true, true
}

func (m *Manager) checkClaims(s Spec, c Claims, nonce string) error {
	now := m.now()
	iss, _ := c["iss"].(string)
	want := s.Issuer
	if s.MultiTenant() {
		tid, _ := c["tid"].(string)
		if !guidRE.MatchString(tid) {
			return fail("issuer_mismatch", errors.New("missing tid"))
		}
		want = strings.Replace(s.Issuer, microsoftTenantTpl, strings.ToLower(tid), 1)
		iss = strings.ToLower(iss)
	}
	if iss == "" || !(iss == want || (s.Type == TypeGoogle && iss == "accounts.google.com")) {
		return fail("issuer_mismatch", nil)
	}
	if !audOK(c["aud"], s.ClientID) {
		return fail("bad_audience", nil)
	}
	if azp, present := c["azp"]; present {
		if a, _ := azp.(string); a != s.ClientID {
			return fail("bad_audience", errors.New("azp"))
		}
	} else if aud, isList := c["aud"].([]any); isList && len(aud) > 1 {
		return fail("bad_audience", errors.New("multiple audiences without azp"))
	}
	exp, hasExp, okExp := numClaim(c, "exp")
	iat, hasIat, okIat := numClaim(c, "iat")
	nbf, hasNbf, okNbf := numClaim(c, "nbf")
	if !okExp || !okIat || !okNbf || !hasExp || !hasIat {
		return fail("bad_time", nil)
	}
	if !now.Before(exp.Add(Skew)) {
		return fail("expired", nil)
	}
	if iat.After(now.Add(Skew)) || (hasNbf && nbf.After(now.Add(Skew))) {
		return fail("bad_time", nil)
	}
	got, _ := c["nonce"].(string)
	if nonce == "" || subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return fail("bad_nonce", nil)
	}
	sub, _ := c["sub"].(string)
	if sub == "" || len(sub) > 255 {
		return fail("bad_subject", nil)
	}
	if s.HostedDomain != "" && !strings.EqualFold(Claims(c).Str("hd"), s.HostedDomain) {
		return fail("wrong_hosted_domain", nil)
	}
	return nil
}

func audOK(aud any, clientID string) bool {
	switch a := aud.(type) {
	case string:
		return a == clientID
	case []any:
		for _, x := range a {
			if s, ok := x.(string); ok && s == clientID {
				return true
			}
		}
	}
	return false
}

// EmailVerified reports whether the upstream vouches for the email address.
// Standard providers send email_verified. Microsoft Entra ID does not: its
// optional xms_edov claim ("email domain owner verified") is used instead,
// and without it the address is treated as unverified.
func EmailVerified(s Spec, c Claims) bool {
	if s.Type == TypeMicrosoft {
		return c.Bool("xms_edov")
	}
	return c.Bool("email_verified")
}

// Subject is the stable account key: the upstream sub, qualified with the
// tenant for a multi-tenant Microsoft provider.
func Subject(s Spec, c Claims) string {
	sub := c.Str("sub")
	if s.MultiTenant() {
		return strings.ToLower(c.Str("tid")) + "/" + sub
	}
	return sub
}
