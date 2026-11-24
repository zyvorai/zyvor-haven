// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strconv"
	"strings"
	"time"
)

// JAR: signed request objects (RFC 9101). Only ES256 and PS256 are accepted
// (the algorithms FAPI 2.0 allows); "none", HS* and RS256 are refused. The
// verification key comes only from the client's registered inline JWKS, never
// from the object (jwk, jku, x5u headers are ignored) and never from the
// network.

const (
	jarMaxSize     = 32 << 10
	jarMaxLifetime = time.Hour // exp - nbf
	jarSkew        = 60 * time.Second
	jarMaxValue    = 8 << 10 // bytes of any one parameter
)

var jarAlgs = []string{"ES256", "PS256"}

// jarParams are the request object members that become authorization request
// parameters. Anything else in the object is dropped.
var jarParams = []string{"redirect_uri", "response_type", "scope", "state", "nonce", "code_challenge",
	"code_challenge_method", "response_mode", "prompt", "max_age", "authorization_details", "dpop_jkt"}

var errJAR = errors.New("invalid request object")

type jarKey struct {
	kid, alg string
	pub      any // *ecdsa.PublicKey | *rsa.PublicKey
}

// parseJARKeys reads the usable public keys of an inline JWKS: EC P-256 and
// RSA 2048..8192 bits, use sig (or unset). Private members make a key unusable
// (a registered private key is a mistake we do not paper over).
func parseJARKeys(raw string) ([]jarKey, error) {
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	if len(raw) == 0 || len(raw) > 64<<10 || json.Unmarshal([]byte(raw), &doc) != nil {
		return nil, errJAR
	}
	if len(doc.Keys) > 20 {
		doc.Keys = doc.Keys[:20]
	}
	var out []jarKey
	for _, k := range doc.Keys {
		str := func(n string) string { s, _ := k[n].(string); return s }
		if u := str("use"); u != "" && u != "sig" {
			continue
		}
		private := false
		for _, m := range []string{"d", "p", "q", "dp", "dq", "qi", "oth", "k"} {
			if _, has := k[m]; has {
				private = true
			}
		}
		if private {
			continue
		}
		jk := jarKey{kid: str("kid"), alg: str("alg")}
		switch str("kty") {
		case "EC":
			x, e1 := base64.RawURLEncoding.DecodeString(str("x"))
			y, e2 := base64.RawURLEncoding.DecodeString(str("y"))
			if str("crv") != "P-256" || e1 != nil || e2 != nil || len(x) != 32 || len(y) != 32 {
				continue
			}
			pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
				continue
			}
			jk.pub = pub
		case "RSA":
			nb, e1 := base64.RawURLEncoding.DecodeString(str("n"))
			eb, e2 := base64.RawURLEncoding.DecodeString(str("e"))
			if e1 != nil || e2 != nil || len(nb) == 0 || nb[0] == 0 || len(eb) == 0 || len(eb) > 4 {
				continue
			}
			n, e := new(big.Int).SetBytes(nb), int(new(big.Int).SetBytes(eb).Int64())
			if n.BitLen() < 2048 || n.BitLen() > 8192 || e < 3 || e%2 == 0 {
				continue
			}
			jk.pub = &rsa.PublicKey{N: n, E: e}
		default:
			continue
		}
		out = append(out, jk)
	}
	if len(out) == 0 {
		return nil, errJAR
	}
	return out, nil
}

// ValidateJARKeys tells the Admin API whether a JWKS can verify request objects.
func ValidateJARKeys(raw string) error { _, err := parseJARKeys(raw); return err }

func verifyJARSig(alg string, pub any, signed, sig []byte) bool {
	h := sha256.Sum256(signed)
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if alg != "ES256" || len(sig) != 64 {
			return false
		}
		return ecdsa.Verify(k, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
	case *rsa.PublicKey:
		return alg == "PS256" && rsa.VerifyPSS(k, crypto.SHA256, h[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}) == nil
	}
	return false
}

// verifyRequestObject validates a signed request object for clientID and
// returns the authorization request parameters it carries. Every failure is
// the same opaque errJAR: the caller must not tell the remote party why.
func verifyRequestObject(raw, jwks, clientID, issuer string, now time.Time) (map[string]string, error) {
	if len(raw) == 0 || len(raw) > jarMaxSize {
		return nil, errJAR
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errJAR
	}
	hb, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	pb, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	sig, e3 := base64.RawURLEncoding.DecodeString(parts[2])
	if e1 != nil || e2 != nil || e3 != nil {
		return nil, errJAR
	}
	var hdr struct {
		Alg  string          `json:"alg"`
		Kid  string          `json:"kid"`
		Typ  string          `json:"typ"`
		Crit json.RawMessage `json:"crit"`
	}
	if json.Unmarshal(hb, &hdr) != nil || len(hdr.Crit) != 0 {
		return nil, errJAR
	}
	if hdr.Typ != "" && !strings.EqualFold(hdr.Typ, "oauth-authz-req+jwt") {
		return nil, errJAR
	}
	algOK := false
	for _, a := range jarAlgs {
		algOK = algOK || a == hdr.Alg
	}
	if !algOK {
		return nil, errJAR // includes "none"
	}
	keys, err := parseJARKeys(jwks)
	if err != nil {
		return nil, errJAR
	}
	var cands []jarKey
	for _, k := range keys {
		if _, isEC := k.pub.(*ecdsa.PublicKey); isEC != (hdr.Alg == "ES256") {
			continue
		}
		if k.alg != "" && k.alg != hdr.Alg {
			continue
		}
		if hdr.Kid != "" && k.kid != hdr.Kid {
			continue
		}
		cands = append(cands, k)
	}
	if len(cands) == 0 || (hdr.Kid == "" && len(cands) != 1) {
		return nil, errJAR
	}
	signed := []byte(parts[0] + "." + parts[1])
	valid := false
	for _, k := range cands {
		valid = valid || verifyJARSig(hdr.Alg, k.pub, signed, sig)
	}
	if !valid {
		return nil, errJAR
	}

	dec := json.NewDecoder(bytes.NewReader(pb))
	dec.UseNumber()
	var c map[string]any
	if dec.Decode(&c) != nil || c == nil {
		return nil, errJAR
	}
	if hasDupKeys(pb) {
		return nil, errJAR
	}
	if iss, _ := c["iss"].(string); iss != clientID || iss == "" {
		return nil, errJAR
	}
	if cid, has := c["client_id"]; has && cid != clientID {
		return nil, errJAR
	}
	if !audHas(c["aud"], issuer) {
		return nil, errJAR
	}
	exp, ok1 := jarTime(c["exp"])
	nbf, ok2 := jarTime(c["nbf"])
	if !ok1 || !ok2 { // both are required: an object must have a bounded lifetime
		return nil, errJAR
	}
	if !now.Before(exp.Add(jarSkew)) || nbf.After(now.Add(jarSkew)) || exp.Sub(nbf) > jarMaxLifetime || !exp.After(nbf) {
		return nil, errJAR
	}
	if _, has := c["request"]; has {
		return nil, errJAR
	}
	if _, has := c["request_uri"]; has {
		return nil, errJAR
	}
	out := map[string]string{}
	for _, k := range jarParams {
		v, has := c[k]
		if !has {
			continue
		}
		var s string
		switch t := v.(type) {
		case string:
			s = t
		case json.Number:
			if k != "max_age" {
				return nil, errJAR
			}
			s = t.String()
		case []any:
			if k != "authorization_details" {
				return nil, errJAR
			}
			b, err := json.Marshal(t)
			if err != nil {
				return nil, errJAR
			}
			s = string(b)
		default:
			return nil, errJAR
		}
		if len(s) > jarMaxValue {
			return nil, errJAR
		}
		out[k] = s
	}
	return out, nil
}

func jarTime(v any) (time.Time, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return time.Time{}, false
	}
	f, err := strconv.ParseFloat(n.String(), 64)
	if err != nil || f < 0 || f > 1e11 {
		return time.Time{}, false
	}
	return time.Unix(int64(f), 0), true
}

func audHas(v any, want string) bool {
	switch a := v.(type) {
	case string:
		return a == want
	case []any:
		for _, x := range a {
			if s, _ := x.(string); s == want {
				return true
			}
		}
	}
	return false
}
