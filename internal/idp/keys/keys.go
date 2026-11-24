// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package keys implements core.Signer: ES256 JWTs over a core.Store.
//
// Claims returned by Verify are decoded with json.Decoder.UseNumber, so every
// JSON number is a json.Number (never float64).
package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

const (
	maxTokenSize = 16 << 10
	leeway       = 30 * time.Second
	cacheTTL     = 5 * time.Second
	algES256     = "ES256"
)

// ErrInvalidToken is wrapped by every Verify failure.
var ErrInvalidToken = errors.New("keys: invalid token")

func bad(msg string) error { return fmt.Errorf("%w: %s", ErrInvalidToken, msg) }

// Options configures a Signer.
type Options struct {
	Clock    func() time.Time // default time.Now
	KeyGrace time.Duration    // how long a rotated key stays published; default 24h
}

type parsed struct {
	key core.SigningKey
	pub *ecdsa.PublicKey
	prv *ecdsa.PrivateKey // nil if the PEM could not be parsed
}

type cacheEntry struct {
	at   time.Time
	keys []parsed
}

type signer struct {
	store core.Store
	clock func() time.Time
	grace time.Duration

	mu    sync.Mutex // serializes key creation
	cmu   sync.RWMutex
	cache map[string]cacheEntry
}

// New returns a core.Signer backed by store.
func New(store core.Store, opts Options) core.Signer {
	if opts.Clock == nil {
		opts.Clock = time.Now
	}
	if opts.KeyGrace <= 0 {
		opts.KeyGrace = 24 * time.Hour
	}
	return &signer{store: store, clock: opts.Clock, grace: opts.KeyGrace, cache: map[string]cacheEntry{}}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func pad32(n *big.Int) []byte { return n.FillBytes(make([]byte, 32)) }

// thumbprint computes the RFC 7638 thumbprint of an EC P-256 public key.
func thumbprint(pub *ecdsa.PublicKey) string {
	s := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`, b64(pad32(pub.X)), b64(pad32(pub.Y)))
	h := sha256.Sum256([]byte(s))
	return b64(h[:])
}

type jwk struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func newKey(realm string, now time.Time) (core.SigningKey, error) {
	prv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return core.SigningKey{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(prv)
	if err != nil {
		return core.SigningKey{}, err
	}
	kid := thumbprint(&prv.PublicKey)
	pj, err := json.Marshal(jwk{"EC", "P-256", "sig", algES256, kid, b64(pad32(prv.X)), b64(pad32(prv.Y))})
	if err != nil {
		return core.SigningKey{}, err
	}
	return core.SigningKey{
		KID: kid, Realm: realm, Alg: algES256,
		PrivatePEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}),
		PublicJWK:  pj, Active: true, CreatedAt: now,
	}, nil
}

func parseKey(k core.SigningKey) (parsed, error) {
	var j jwk
	if err := json.Unmarshal(k.PublicJWK, &j); err != nil {
		return parsed{}, err
	}
	if j.Kty != "EC" || j.Crv != "P-256" {
		return parsed{}, errors.New("unsupported jwk")
	}
	xb, err1 := base64.RawURLEncoding.DecodeString(j.X)
	yb, err2 := base64.RawURLEncoding.DecodeString(j.Y)
	if err1 != nil || err2 != nil || len(xb) != 32 || len(yb) != 32 {
		return parsed{}, errors.New("bad jwk coordinates")
	}
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return parsed{}, errors.New("point not on curve")
	}
	p := parsed{key: k, pub: pub}
	if blk, _ := pem.Decode(k.PrivatePEM); blk != nil {
		if pk, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
			if e, ok := pk.(*ecdsa.PrivateKey); ok {
				p.prv = e
			}
		}
	}
	return p, nil
}

func (s *signer) invalidate(realm string) {
	s.cmu.Lock()
	delete(s.cache, realm)
	s.cmu.Unlock()
}

// load returns the realm's unexpired keys, active first, using the cache.
func (s *signer) load(ctx context.Context, realm string) ([]parsed, error) {
	now := s.clock()
	s.cmu.RLock()
	e, ok := s.cache[realm]
	s.cmu.RUnlock()
	if !ok || now.Sub(e.at) > cacheTTL || now.Before(e.at) {
		list, err := s.store.ListSigningKeys(ctx, realm)
		if err != nil {
			return nil, err
		}
		e = cacheEntry{at: now}
		for _, k := range list {
			if k.Alg != "" && k.Alg != algES256 {
				continue
			}
			if p, err := parseKey(k); err == nil {
				e.keys = append(e.keys, p)
			}
		}
		s.cmu.Lock()
		s.cache[realm] = e
		s.cmu.Unlock()
	}
	out := make([]parsed, 0, len(e.keys))
	for _, p := range e.keys {
		if p.key.NotAfter.IsZero() || now.Before(p.key.NotAfter) {
			out = append(out, p)
		}
	}
	return out, nil
}

func activeOf(ks []parsed) *parsed {
	for i := range ks {
		if ks[i].key.Active && ks[i].prv != nil {
			return &ks[i]
		}
	}
	return nil
}

func (s *signer) EnsureKey(ctx context.Context, realm string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidate(realm)
	ks, err := s.load(ctx, realm)
	if err != nil {
		return err
	}
	if activeOf(ks) != nil {
		return nil
	}
	return s.create(ctx, realm, nil)
}

func (s *signer) create(ctx context.Context, realm string, old []parsed) error {
	defer s.invalidate(realm)
	now := s.clock()
	for _, o := range old {
		if !o.key.Active {
			continue
		}
		k := o.key
		k.Active = false
		k.NotAfter = now.Add(s.grace)
		if err := s.store.PutSigningKey(ctx, k); err != nil {
			return err
		}
	}
	nk, err := newKey(realm, now)
	if err != nil {
		return err
	}
	if err := s.store.PutSigningKey(ctx, nk); err != nil {
		// The store allows one active key per realm. A conflict means another
		// replica created (or rotated to) its own active key a moment ago: the
		// realm now has the key we wanted, so there is nothing left to do.
		// Checking "is there a key?" in memory cannot stop that race; the store can.
		if errors.Is(err, idp.ErrConflict) {
			return nil
		}
		return err
	}
	return nil
}

func (s *signer) Rotate(ctx context.Context, realm string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.invalidate(realm)
	ks, err := s.load(ctx, realm)
	if err != nil {
		return err
	}
	return s.create(ctx, realm, ks)
}

func (s *signer) Sign(ctx context.Context, realm string, claims core.Claims) (string, error) {
	ks, err := s.load(ctx, realm)
	if err != nil {
		return "", err
	}
	a := activeOf(ks)
	if a == nil {
		return "", errors.New("keys: no active signing key for realm")
	}
	hdr, _ := json.Marshal(map[string]string{"alg": algES256, "typ": "JWT", "kid": a.key.KID})
	pl, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	in := b64(hdr) + "." + b64(pl)
	h := sha256.Sum256([]byte(in))
	r, sv, err := ecdsa.Sign(rand.Reader, a.prv, h[:])
	if err != nil {
		return "", err
	}
	return in + "." + b64(append(pad32(r), pad32(sv)...)), nil
}

func numeric(v any) (float64, bool, error) {
	if v == nil {
		return 0, false, nil
	}
	n, ok := v.(json.Number)
	if !ok {
		return 0, false, errors.New("not a number")
	}
	f, err := n.Float64()
	return f, true, err
}

func (s *signer) Verify(ctx context.Context, realm, token string) (core.Claims, error) {
	return s.verify(ctx, realm, token, false)
}

// VerifyAllowExpired implements core.ExpiredVerifier: like Verify but an
// elapsed exp is tolerated. Signature, alg pinning, kid and nbf still apply.
func (s *signer) VerifyAllowExpired(ctx context.Context, realm, token string) (core.Claims, error) {
	return s.verify(ctx, realm, token, true)
}

func (s *signer) verify(ctx context.Context, realm, token string, allowExpired bool) (core.Claims, error) {
	if len(token) > maxTokenSize {
		return nil, bad("token too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, bad("malformed")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, bad("header encoding")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return nil, bad("header json")
	}
	if hdr.Alg != algES256 {
		return nil, bad("unsupported alg")
	}
	if hdr.Kid == "" {
		return nil, bad("missing kid")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, bad("signature")
	}
	ks, err := s.load(ctx, realm)
	if err != nil {
		return nil, err
	}
	var key *parsed
	for i := range ks {
		if ks[i].key.KID == hdr.Kid {
			key = &ks[i]
			break
		}
	}
	if key == nil {
		return nil, bad("unknown kid")
	}
	h := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(key.pub, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, bad("signature mismatch")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, bad("payload encoding")
	}
	dec := json.NewDecoder(strings.NewReader(string(pb)))
	dec.UseNumber()
	var claims core.Claims
	if err := dec.Decode(&claims); err != nil || claims == nil {
		return nil, bad("payload json")
	}
	now := s.clock()
	exp, hasExp, err := numeric(claims["exp"])
	if err != nil {
		return nil, bad("exp")
	}
	if hasExp && !allowExpired && now.After(time.Unix(0, int64(exp*1e9)).Add(leeway)) {
		return nil, bad("expired")
	}
	nbf, hasNbf, err := numeric(claims["nbf"])
	if err != nil {
		return nil, bad("nbf")
	}
	if hasNbf && now.Add(leeway).Before(time.Unix(0, int64(nbf*1e9))) {
		return nil, bad("not yet valid")
	}
	return claims, nil
}

func (s *signer) JWKS(ctx context.Context, realm string) ([]byte, error) {
	ks, err := s.load(ctx, realm)
	if err != nil {
		return nil, err
	}
	set := struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: []json.RawMessage{}}
	for _, k := range ks {
		set.Keys = append(set.Keys, json.RawMessage(k.key.PublicJWK))
	}
	return json.Marshal(set)
}
