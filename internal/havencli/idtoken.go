// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package havencli

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// decodeClaims splits a compact JWT and decodes header and payload. It does
// NOT check anything: callers must not trust the result until verified.
func decodeClaims(raw string) (header, claims map[string]any, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("not a compact JWT")
	}
	for i, dst := range []*map[string]any{&header, &claims} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			return nil, nil, errors.New("JWT is not base64url")
		}
		if err := json.Unmarshal(b, dst); err != nil {
			return nil, nil, errors.New("JWT part is not JSON")
		}
	}
	return header, claims, nil
}

func claimStr(m map[string]any, k string) string { s, _ := m[k].(string); return s }

func claimTime(m map[string]any, k string) time.Time {
	f, ok := m[k].(float64)
	if !ok || f <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(f), 0)
}

func audContains(claims map[string]any, clientID string) bool {
	switch a := claims["aud"].(type) {
	case string:
		return a == clientID
	case []any:
		for _, v := range a {
			if s, _ := v.(string); s == clientID {
				return true
			}
		}
	}
	return false
}

// checkIDTokenClaims validates iss, aud (+azp), exp. There is no nonce check:
// the device flow has no nonce parameter, so haven never sends one and a
// nonce claim, if the server adds one, has nothing to be compared with.
func checkIDTokenClaims(claims map[string]any, issuer, clientID string, now time.Time) error {
	if claimStr(claims, "iss") != issuer {
		return errors.New("ID token iss does not match the issuer")
	}
	if !audContains(claims, clientID) {
		return errors.New("ID token aud does not contain this client_id")
	}
	if azp := claimStr(claims, "azp"); azp != "" && azp != clientID {
		return errors.New("ID token azp is not this client_id")
	}
	exp := claimTime(claims, "exp")
	if exp.IsZero() {
		return errors.New("ID token has no exp")
	}
	if now.After(exp.Add(60 * time.Second)) {
		return errors.New("ID token is already expired")
	}
	return nil
}

func b64int(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) == 0 {
		return nil, errors.New("bad base64url")
	}
	return new(big.Int).SetBytes(b), nil
}

// verifySignature checks an RS256 or ES256 JWT against the key set. Every
// other alg (none, HS*, ...) is refused.
func verifySignature(raw string, keys []jwk) (string, error) {
	parts := strings.Split(raw, ".")
	hdr, _, err := decodeClaims(raw)
	if err != nil {
		return "", err
	}
	alg := claimStr(hdr, "alg")
	kid := claimStr(hdr, "kid")
	if alg != "ES256" && alg != "RS256" {
		return "", fmt.Errorf("unsupported ID token alg %q (only ES256 and RS256)", clean(alg, 16))
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", errors.New("bad signature encoding")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	tried := false
	for _, k := range keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if kid != "" && k.Kid != kid {
			continue
		}
		switch {
		case alg == "ES256" && k.Kty == "EC" && k.Crv == "P-256":
			x, ex := b64int(k.X)
			y, ey := b64int(k.Y)
			if ex != nil || ey != nil || len(sig) != 64 {
				continue
			}
			if x.BitLen() > 256 || y.BitLen() > 256 {
				continue
			}
			pt := make([]byte, 65) // SEC 1 uncompressed point; parsing checks it is on the curve
			pt[0] = 4
			x.FillBytes(pt[1:33])
			y.FillBytes(pt[33:])
			pub, perr := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), pt)
			if perr != nil {
				continue
			}
			tried = true
			if ecdsa.Verify(pub, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
				return alg, nil
			}
		case alg == "RS256" && k.Kty == "RSA":
			n, en := b64int(k.N)
			e, ee := b64int(k.E)
			if en != nil || ee != nil || n.BitLen() < 2048 || !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
				continue
			}
			tried = true
			if rsa.VerifyPKCS1v15(&rsa.PublicKey{N: n, E: int(e.Int64())}, crypto.SHA256, digest[:], sig) == nil {
				return alg, nil
			}
		}
	}
	if !tried {
		return "", errors.New("no matching signing key in the issuer's JWKS")
	}
	return "", errors.New("ID token signature is invalid")
}

func (c *oidc) fetchJWKS(ctx context.Context, uri string) ([]jwk, error) {
	st, b, err := c.get(ctx, uri, "")
	if err != nil {
		return nil, fmt.Errorf("fetching JWKS: %w", err)
	}
	if st != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint answered HTTP %d", st)
	}
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(b, &set); err != nil {
		return nil, errors.New("JWKS is not valid JSON")
	}
	return set.Keys, nil
}

// idResult is a validated (or merely decoded) ID token.
type idResult struct {
	Claims   map[string]any
	Verified bool   // signature checked against the issuer's JWKS
	Alg      string // set when Verified
	Note     string // why not verified
}

// checkIDToken validates claims and, when the discovery document has a
// jwks_uri, the signature. A failed signature is an error; a provider with no
// jwks_uri yields Verified=false with a note (the token came straight from the
// token endpoint over TLS, which OIDC Core 3.1.3.7 accepts, but we say so).
func (c *oidc) checkIDToken(ctx context.Context, d *discovery, raw, clientID string, now time.Time) (*idResult, error) {
	_, claims, err := decodeClaims(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid ID token: %w", err)
	}
	if err := checkIDTokenClaims(claims, c.issuer.String(), clientID, now); err != nil {
		return nil, err
	}
	res := &idResult{Claims: claims}
	if d.JWKSURI == "" {
		res.Note = "issuer publishes no jwks_uri"
		return res, nil
	}
	keys, err := c.fetchJWKS(ctx, d.JWKSURI)
	if err != nil {
		return nil, err
	}
	alg, err := verifySignature(raw, keys)
	if err != nil {
		return nil, err
	}
	res.Verified, res.Alg = true, alg
	return res, nil
}
