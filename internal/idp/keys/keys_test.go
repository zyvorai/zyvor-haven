// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package keys

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

type fakeStore struct {
	core.Store
	mu   sync.Mutex
	keys map[string][]core.SigningKey
}

func newStore() *fakeStore { return &fakeStore{keys: map[string][]core.SigningKey{}} }

func (f *fakeStore) PutSigningKey(_ context.Context, k core.SigningKey) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	l := f.keys[k.Realm]
	for i := range l {
		if l[i].KID == k.KID {
			l[i] = k
			return nil
		}
	}
	f.keys[k.Realm] = append(l, k)
	return nil
}

func (f *fakeStore) ListSigningKeys(_ context.Context, realm string) ([]core.SigningKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]core.SigningKey(nil), f.keys[realm]...)
	// active first
	for i := range out {
		if out[i].Active {
			out[0], out[i] = out[i], out[0]
		}
	}
	return out, nil
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func setup(t *testing.T) (core.Signer, *fakeStore, *clock) {
	t.Helper()
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	st := newStore()
	s := New(st, Options{Clock: clk.now, KeyGrace: time.Hour})
	if err := s.EnsureKey(context.Background(), "r"); err != nil {
		t.Fatal(err)
	}
	return s, st, clk
}

func claimsAt(clk *clock, ttl time.Duration) core.Claims {
	return core.Claims{"sub": "u1", "exp": clk.now().Add(ttl).Unix(), "iat": clk.now().Unix()}
}

func b64d(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignVerify(t *testing.T) {
	ctx := context.Background()
	s, _, clk := setup(t)
	tok, err := s.Sign(ctx, "r", claimsAt(clk, time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	c, err := s.Verify(ctx, "r", tok)
	if err != nil {
		t.Fatal(err)
	}
	if c["sub"] != "u1" {
		t.Fatalf("claims %v", c)
	}
	if _, ok := c["exp"].(json.Number); !ok {
		t.Fatalf("exp type %T", c["exp"])
	}
	if err := s.EnsureKey(ctx, "r"); err != nil {
		t.Fatal(err)
	}
	if raw, _ := s.JWKS(ctx, "r"); strings.Count(string(raw), `"kid"`) != 1 {
		t.Fatalf("EnsureKey created extra key: %s", raw)
	}
	if _, err := s.Sign(ctx, "nokeys", nil); err == nil {
		t.Fatal("sign without key succeeded")
	}
}

func TestVerifyRejections(t *testing.T) {
	ctx := context.Background()
	s, _, clk := setup(t)
	good, _ := s.Sign(ctx, "r", claimsAt(clk, time.Minute))
	p := strings.Split(good, ".")
	hdr := func(m map[string]any) string {
		b, _ := json.Marshal(m)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	var kid string
	var h map[string]any
	json.Unmarshal(b64d(t, p[0]), &h)
	kid = h["kid"].(string)

	flip := []byte(p[2])
	if flip[5] == 'A' {
		flip[5] = 'B'
	} else {
		flip[5] = 'A'
	}
	sign := func(c core.Claims) string { tok, _ := s.Sign(ctx, "r", c); return tok }

	tests := map[string]string{
		"tampered sig":     p[0] + "." + p[1] + "." + string(flip),
		"tampered payload": p[0] + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin"}`)) + "." + p[2],
		"alg none":         hdr(map[string]any{"alg": "none", "typ": "JWT", "kid": kid}) + "." + p[1] + ".",
		"alg none+sig":     hdr(map[string]any{"alg": "none", "kid": kid}) + "." + p[1] + "." + p[2],
		"alg HS256":        hdr(map[string]any{"alg": "HS256", "kid": kid}) + "." + p[1] + "." + p[2],
		"alg lowercase":    hdr(map[string]any{"alg": "es256", "kid": kid}) + "." + p[1] + "." + p[2],
		"missing kid":      hdr(map[string]any{"alg": "ES256"}) + "." + p[1] + "." + p[2],
		"wrong kid":        hdr(map[string]any{"alg": "ES256", "kid": "nope"}) + "." + p[1] + "." + p[2],
		"expired":          sign(claimsAt(clk, -time.Hour)),
		"not yet valid":    sign(core.Claims{"nbf": clk.now().Add(time.Hour).Unix()}),
		"bad exp type":     sign(core.Claims{"exp": "soon"}),
		"short sig":        p[0] + "." + p[1] + "." + p[2][:20],
		"two parts":        p[0] + "." + p[1],
		"empty":            "",
		"oversized":        good + strings.Repeat("A", 17<<10),
		"junk":             "a.b.c",
	}
	for name, tok := range tests {
		_, err := s.Verify(ctx, "r", tok)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("%s: err not ErrInvalidToken: %v", name, err)
		}
	}
	if _, err := s.Verify(ctx, "other", good); err == nil {
		t.Error("token verified in other realm")
	}
	// leeway: expired 10s ago is still fine, nbf 10s ahead is fine
	if _, err := s.Verify(ctx, "r", sign(core.Claims{"exp": clk.now().Add(-10 * time.Second).Unix(), "nbf": clk.now().Add(10 * time.Second).Unix()})); err != nil {
		t.Errorf("leeway: %v", err)
	}
}

func TestRotationGrace(t *testing.T) {
	ctx := context.Background()
	s, _, clk := setup(t)
	old, _ := s.Sign(ctx, "r", core.Claims{"sub": "old"})
	if err := s.Rotate(ctx, "r"); err != nil {
		t.Fatal(err)
	}
	newTok, _ := s.Sign(ctx, "r", core.Claims{"sub": "new"})
	kidOf := func(tok string) string {
		var h struct{ Kid string }
		json.Unmarshal(b64d(t, strings.Split(tok, ".")[0]), &h)
		return h.Kid
	}
	if kidOf(old) == kidOf(newTok) {
		t.Fatal("sign did not switch to new key")
	}
	for _, tok := range []string{old, newTok} {
		if _, err := s.Verify(ctx, "r", tok); err != nil {
			t.Fatalf("within grace: %v", err)
		}
	}
	raw, _ := s.JWKS(ctx, "r")
	var set struct{ Keys []map[string]string }
	json.Unmarshal(raw, &set)
	if len(set.Keys) != 2 {
		t.Fatalf("jwks keys: %d", len(set.Keys))
	}
	clk.add(2 * time.Hour)
	if _, err := s.Verify(ctx, "r", old); err == nil {
		t.Fatal("old key verifies after grace")
	}
	if _, err := s.Verify(ctx, "r", newTok); err != nil {
		t.Fatalf("new key: %v", err)
	}
	raw, _ = s.JWKS(ctx, "r")
	set.Keys = nil
	json.Unmarshal(raw, &set)
	if len(set.Keys) != 1 {
		t.Fatalf("jwks after grace: %d", len(set.Keys))
	}
}

// TestJWKSIndependentVerify verifies tokens using only the published JWK and
// stdlib, and checks the kid is the RFC 7638 thumbprint.
func TestJWKSIndependentVerify(t *testing.T) {
	ctx := context.Background()
	s, st, clk := setup(t)
	s.Rotate(ctx, "r")
	raw, err := s.JWKS(ctx, "r")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"d"`) || strings.Contains(string(raw), "PRIVATE") {
		t.Fatal("private material in JWKS")
	}
	var set struct {
		Keys []struct{ Kty, Crv, Use, Alg, Kid, X, Y string }
	}
	if err := json.Unmarshal(raw, &set); err != nil {
		t.Fatal(err)
	}
	pubs := map[string]*ecdsa.PublicKey{}
	for _, k := range set.Keys {
		if k.Kty != "EC" || k.Crv != "P-256" || k.Use != "sig" || k.Alg != "ES256" {
			t.Fatalf("jwk %+v", k)
		}
		x, y := new(big.Int).SetBytes(b64d(t, k.X)), new(big.Int).SetBytes(b64d(t, k.Y))
		sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + k.X + `","y":"` + k.Y + `"}`))
		if k.Kid != base64.RawURLEncoding.EncodeToString(sum[:]) {
			t.Fatal("kid is not RFC 7638 thumbprint")
		}
		pubs[k.Kid] = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	}
	if len(pubs) != 2 {
		t.Fatalf("want 2 keys")
	}
	tok, _ := s.Sign(ctx, "r", claimsAt(clk, time.Minute))
	p := strings.Split(tok, ".")
	var h struct{ Alg, Typ, Kid string }
	json.Unmarshal(b64d(t, p[0]), &h)
	if h.Alg != "ES256" || h.Typ != "JWT" {
		t.Fatalf("header %+v", h)
	}
	sig := b64d(t, p[2])
	d := sha256.Sum256([]byte(p[0] + "." + p[1]))
	if len(sig) != 64 || !ecdsa.Verify(pubs[h.Kid], d[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		t.Fatal("independent verification failed")
	}
	// stored private key is PKCS#8 PEM
	for _, k := range st.keys["r"] {
		if !strings.HasPrefix(string(k.PrivatePEM), "-----BEGIN PRIVATE KEY-----") || k.Alg != "ES256" {
			t.Fatal("stored key format")
		}
	}
}

func TestConcurrent(t *testing.T) {
	ctx := context.Background()
	clk := &clock{t: time.Unix(1_800_000_000, 0)}
	s := New(newStore(), Options{Clock: clk.now})
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.EnsureKey(ctx, "r"); err != nil {
				t.Error(err)
				return
			}
			tok, err := s.Sign(ctx, "r", claimsAt(clk, time.Minute))
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := s.Verify(ctx, "r", tok); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	raw, _ := s.JWKS(ctx, "r")
	if n := strings.Count(string(raw), `"kid"`); n != 1 {
		t.Fatalf("keys after concurrent ensure: %d", n)
	}
}
