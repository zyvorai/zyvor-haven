// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/mail"
	"github.com/zyvorai/haven/internal/idp/safehttp"
)

const (
	issuerR  = idpBase + "/realms/r"
	oidcR    = "/realms/r" + oidcPath
	tokenR   = oidcR + "/token"
	introR   = oidcR + "/token/introspect"
	revokeR  = oidcR + "/revoke"
	parR     = oidcR + "/par"
	cibaR    = oidcR + "/ext/ciba/auth"
	deviceR  = oidcR + "/auth/device"
	userinfR = oidcR + "/userinfo"
)

// ---- keys and assertions ----

type caKey struct {
	kid  string
	priv crypto.Signer
}

func (k caKey) jwk() map[string]any {
	switch pub := k.priv.Public().(type) {
	case *ecdsa.PublicKey:
		b, err := pub.Bytes()
		if err != nil {
			panic(err)
		}
		return map[string]any{"kty": "EC", "crv": "P-256", "kid": k.kid, "use": "sig", "x": b64u(b[1:33]), "y": b64u(b[33:])}
	case *rsa.PublicKey:
		return map[string]any{"kty": "RSA", "kid": k.kid, "n": b64u(pub.N.Bytes()), "e": b64u(big.NewInt(int64(pub.E)).Bytes())}
	case ed25519.PublicKey:
		return map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": k.kid, "x": b64u(pub)}
	}
	panic("key type")
}

func ecKey(t *testing.T, kid string) caKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return caKey{kid, k}
}

func rsaKey(t *testing.T, kid string, bits int) caKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return caKey{kid, k}
}

func edKey(t *testing.T, kid string) caKey {
	t.Helper()
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return caKey{kid, k}
}

func jwksOf(keys ...caKey) string {
	var l []any
	for _, k := range keys {
		l = append(l, k.jwk())
	}
	return mustJSON(map[string]any{"keys": l})
}

func signJWS(t *testing.T, k caKey, alg string, hdr map[string]any, payload []byte) string {
	t.Helper()
	hb, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	signed := b64u(hb) + "." + b64u(payload)
	h := sha256.Sum256([]byte(signed))
	var sig []byte
	switch alg {
	case "ES256", "ES384":
		r, s, err := ecdsa.Sign(rand.Reader, k.priv.(*ecdsa.PrivateKey), h[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = append(padTo(r.Bytes(), 32), padTo(s.Bytes(), 32)...)
	case "PS256":
		sig, err = rsa.SignPSS(rand.Reader, k.priv.(*rsa.PrivateKey), crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "RS256":
		sig, err = rsa.SignPKCS1v15(rand.Reader, k.priv.(*rsa.PrivateKey), crypto.SHA256, h[:])
	case "EdDSA":
		sig = ed25519.Sign(k.priv.(ed25519.PrivateKey), []byte(signed))
	case "HS256":
		m := hmac.New(sha256.New, []byte("s3cret"))
		m.Write([]byte(signed))
		sig = m.Sum(nil)
	case "none":
		sig = []byte("x")
	}
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + b64u(sig)
}

// ---- environment ----

type caEnv struct {
	*denv
	key  caKey
	cl   core.Client // confidential client "svc" configured for private_key_jwt, still holding a secret hash
	jtis atomic.Int64
}

func newCAEnv(t *testing.T, o devOpts) *caEnv {
	t.Helper()
	c := &caEnv{denv: newDEnv(t, o), key: ecKey(t, "k1")}
	c.cl = c.addClient(t, "svc", nil)
	c.configure(t, c.cl, core.ClientAuth{Method: core.AuthMethodPrivateKeyJWT, JWKS: jwksOf(c.key)})
	return c
}

// addClient creates a confidential client that has a secret ("s3cret") and
// every server-to-server flow.
func (c *caEnv) addClient(t *testing.T, id string, mut func(*core.Client)) core.Client {
	t.Helper()
	cl := core.Client{Realm: "r", ClientID: id, Name: id, Enabled: true, SecretHash: HashSecret("s3cret"),
		ServiceAccount: true, DeviceFlow: true, AuthCodeFlow: true, RedirectURIs: []string{cb}}
	if mut != nil {
		mut(&cl)
	}
	if err := c.st.CreateClient(context.Background(), cl); err != nil {
		t.Fatal(err)
	}
	got, err := c.st.GetClientByClientID(context.Background(), "r", id)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func (c *caEnv) configure(t *testing.T, cl core.Client, cfg core.ClientAuth) {
	t.Helper()
	cfg.Realm, cfg.ClientRef = "r", cl.ID
	if err := c.st.PutClientAuth(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
}

type aOpt struct {
	alg    string
	hdr    func(map[string]any)
	claims func(map[string]any)
	raw    []byte // replaces the payload
}

// assertion builds a client assertion for client id signed with k.
func (c *caEnv) assertion(t *testing.T, id string, k caKey, o aOpt) string {
	t.Helper()
	alg := o.alg
	if alg == "" {
		switch k.priv.(type) {
		case *ecdsa.PrivateKey:
			alg = "ES256"
		case *rsa.PrivateKey:
			alg = "PS256"
		default:
			alg = "EdDSA"
		}
	}
	hdr := map[string]any{"alg": alg, "kid": k.kid, "typ": "JWT"}
	if o.hdr != nil {
		o.hdr(hdr)
	}
	c.mu.Lock()
	now := c.now
	c.mu.Unlock()
	cl := map[string]any{"iss": id, "sub": id, "aud": issuerR, "exp": now.Add(time.Minute).Unix(), "iat": now.Unix(),
		"jti": fmt.Sprintf("jti-%d", c.jtis.Add(1))}
	if o.claims != nil {
		o.claims(cl)
	}
	payload, _ := json.Marshal(cl)
	if o.raw != nil {
		payload = o.raw
	}
	return signJWS(t, k, alg, hdr, payload)
}

func withAssertion(form url.Values, a string) url.Values {
	f := url.Values{}
	for k, v := range form {
		f[k] = slices.Clone(v)
	}
	f.Set("client_assertion_type", clientAssertionType)
	f.Set("client_assertion", a)
	return f
}

func (c *caEnv) send(path string, form url.Values, mod ...func(*http.Request)) (int, map[string]any, http.Header) {
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "203.0.113.20:1"
	for _, m := range mod {
		m(req)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out, w.Header()
}

func basicAuth(u, p string) func(*http.Request) {
	return func(r *http.Request) { r.SetBasicAuth(u, p) }
}

var ccForm = url.Values{"grant_type": {"client_credentials"}}

func (c *caEnv) ccWith(a string) (int, map[string]any) {
	code, out, _ := c.send(tokenR, withAssertion(ccForm, a))
	return code, out
}

func wantInvalidClient(t *testing.T, code int, out map[string]any) {
	t.Helper()
	if code != 401 || out["error"] != "invalid_client" || out["access_token"] != nil {
		t.Fatalf("want 401 invalid_client, got %d %v", code, out)
	}
}

// ---- private_key_jwt ----

func TestPrivateKeyJWTAlgorithms(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	ec, rs, ed := ecKey(t, "e"), rsaKey(t, "r", 2048), edKey(t, "d")
	c.configure(t, c.cl, core.ClientAuth{Method: core.AuthMethodPrivateKeyJWT, JWKS: jwksOf(ec, rs, ed)})
	for _, x := range []struct {
		alg string
		k   caKey
	}{{"ES256", ec}, {"PS256", rs}, {"RS256", rs}, {"EdDSA", ed}} {
		for name, aud := range map[string]any{"issuer": issuerR, "token endpoint": idpBase + tokenR, "array": []any{issuerR, idpBase + tokenR}} {
			code, out := c.ccWith(c.assertion(t, "svc", x.k, aOpt{alg: x.alg, claims: func(m map[string]any) { m["aud"] = aud }}))
			if code != 200 || out["access_token"] == nil {
				t.Fatalf("%s %s: %d %v", x.alg, name, code, out)
			}
		}
	}
	// client_id may accompany the assertion when it names the same client.
	f := withAssertion(ccForm, c.assertion(t, "svc", ec, aOpt{}))
	f.Set("client_id", "svc")
	if code, out, _ := c.send(tokenR, f); code != 200 {
		t.Fatalf("with client_id: %d %v", code, out)
	}
	// No kid is fine while exactly one key fits.
	c.configure(t, c.cl, core.ClientAuth{Method: core.AuthMethodPrivateKeyJWT, JWKS: jwksOf(ec, ed)})
	if code, out := c.ccWith(c.assertion(t, "svc", ec, aOpt{hdr: func(h map[string]any) { delete(h, "kid") }})); code != 200 {
		t.Fatalf("no kid: %d %v", code, out)
	}
}

func TestPrivateKeyJWTRejections(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	k := c.key
	other := ecKey(t, "k1") // same kid, not registered
	small := rsaKey(t, "small", 1024)
	rs := rsaKey(t, "rs", 2048)
	k2 := ecKey(t, "k2")
	c.configure(t, c.cl, core.ClientAuth{Method: core.AuthMethodPrivateKeyJWT, JWKS: jwksOf(k, small, rs, k2)})
	now := c.now
	set := func(key string, v any) aOpt {
		return aOpt{claims: func(m map[string]any) {
			if v == nil {
				delete(m, key)
			} else {
				m[key] = v
			}
		}}
	}
	cases := map[string]func() string{
		"alg none":  func() string { return c.assertion(t, "svc", k, aOpt{alg: "none"}) },
		"alg HS256": func() string { return c.assertion(t, "svc", k, aOpt{alg: "HS256"}) },
		"alg ES384": func() string { return c.assertion(t, "svc", k, aOpt{alg: "ES384"}) },
		"RSA 1024":  func() string { return c.assertion(t, "svc", small, aOpt{alg: "RS256"}) },
		"alg/key type": func() string {
			return c.assertion(t, "svc", rs, aOpt{alg: "RS256", hdr: func(h map[string]any) { h["alg"] = "ES256" }})
		},
		"wrong key":   func() string { return c.assertion(t, "svc", other, aOpt{}) },
		"unknown kid": func() string { return c.assertion(t, "svc", k, aOpt{hdr: func(h map[string]any) { h["kid"] = "zz" }}) },
		"no kid, two keys": func() string {
			return c.assertion(t, "svc", k, aOpt{hdr: func(h map[string]any) { delete(h, "kid") }})
		},
		"embedded jwk is ignored": func() string {
			return c.assertion(t, "svc", other, aOpt{hdr: func(h map[string]any) { h["jwk"] = other.jwk() }})
		},
		"crit header": func() string {
			return c.assertion(t, "svc", k, aOpt{hdr: func(h map[string]any) { h["crit"] = []string{"exp"} }})
		},
		"typ of a DPoP proof": func() string {
			return c.assertion(t, "svc", k, aOpt{hdr: func(h map[string]any) { h["typ"] = "dpop+jwt" }})
		},
		"typ of a request object": func() string {
			return c.assertion(t, "svc", k, aOpt{hdr: func(h map[string]any) { h["typ"] = "oauth-authz-req+jwt" }})
		},
		"request object claims": func() string { return c.assertion(t, "svc", k, set("response_type", "code")) },
		"iss differs":           func() string { return c.assertion(t, "svc", k, set("iss", "other")) },
		"iss missing":           func() string { return c.assertion(t, "svc", k, set("iss", nil)) },
		"sub differs":           func() string { return c.assertion(t, "svc", k, set("sub", "app")) },
		"sub missing":           func() string { return c.assertion(t, "svc", k, set("sub", nil)) },
		"aud missing":           func() string { return c.assertion(t, "svc", k, set("aud", nil)) },
		"aud wrong":             func() string { return c.assertion(t, "svc", k, set("aud", "https://evil.example")) },
		"aud other realm":       func() string { return c.assertion(t, "svc", k, set("aud", idpBase+"/realms/other")) },
		"aud prefix":            func() string { return c.assertion(t, "svc", k, set("aud", issuerR+"/")) },
		"aud other endpoint":    func() string { return c.assertion(t, "svc", k, set("aud", idpBase+introR)) },
		"aud also foreign": func() string {
			return c.assertion(t, "svc", k, set("aud", []any{issuerR, "https://evil.example"}))
		},
		"aud empty array": func() string { return c.assertion(t, "svc", k, set("aud", []any{})) },
		"aud number":      func() string { return c.assertion(t, "svc", k, set("aud", 5)) },
		"exp missing":     func() string { return c.assertion(t, "svc", k, set("exp", nil)) },
		"exp string":      func() string { return c.assertion(t, "svc", k, set("exp", "9999999999")) },
		"expired":         func() string { return c.assertion(t, "svc", k, set("exp", now.Add(-2*time.Minute).Unix())) },
		"exp too far":     func() string { return c.assertion(t, "svc", k, set("exp", now.Add(time.Hour).Unix())) },
		"exp too far, no iat": func() string {
			return c.assertion(t, "svc", k, aOpt{claims: func(m map[string]any) {
				delete(m, "iat")
				m["exp"] = now.Add(time.Hour).Unix()
			}})
		},
		"lifetime too long": func() string {
			return c.assertion(t, "svc", k, set("iat", now.Add(-30*time.Minute).Unix()))
		},
		"iat in the future": func() string { return c.assertion(t, "svc", k, set("iat", now.Add(5*time.Minute).Unix())) },
		"nbf in the future": func() string { return c.assertion(t, "svc", k, set("nbf", now.Add(5*time.Minute).Unix())) },
		"nbf not a number":  func() string { return c.assertion(t, "svc", k, set("nbf", "soon")) },
		"jti missing":       func() string { return c.assertion(t, "svc", k, set("jti", nil)) },
		"jti empty":         func() string { return c.assertion(t, "svc", k, set("jti", "")) },
		"jti too long":      func() string { return c.assertion(t, "svc", k, set("jti", strings.Repeat("j", caMaxJTI+1))) },
		"duplicate claim": func() string {
			p := fmt.Sprintf(`{"iss":"svc","sub":"svc","aud":%q,"exp":%d,"jti":"d","aud":%q}`, "https://evil.example", now.Add(time.Minute).Unix(), issuerR)
			return c.assertion(t, "svc", k, aOpt{raw: []byte(p)})
		},
		"trailing data": func() string {
			p := fmt.Sprintf(`{"iss":"svc","sub":"svc","aud":%q,"exp":%d,"jti":"t"} {}`, issuerR, now.Add(time.Minute).Unix())
			return c.assertion(t, "svc", k, aOpt{raw: []byte(p)})
		},
		"unknown client": func() string { return c.assertion(t, "nobody", k, aOpt{}) },
		"not a jwt":      func() string { return "a.b" },
		"empty":          func() string { return "" },
		"oversized":      func() string { return c.assertion(t, "svc", k, set("pad", strings.Repeat("p", caMaxAssertion))) },
		"corrupt signature": func() string {
			a := c.assertion(t, "svc", k, aOpt{})
			i := strings.LastIndex(a, ".") + 4
			r := byte('A')
			if a[i] == 'A' {
				r = 'B'
			}
			return a[:i] + string(r) + a[i+1:]
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			code, out := c.ccWith(mk())
			wantInvalidClient(t, code, out)
		})
	}
	good := func() string { return c.assertion(t, "svc", k, aOpt{}) }
	t.Run("wrong assertion type", func(t *testing.T) {
		f := withAssertion(ccForm, good())
		f.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:saml2-bearer")
		code, out, _ := c.send(tokenR, f)
		wantInvalidClient(t, code, out)
	})
	t.Run("type missing", func(t *testing.T) {
		f := withAssertion(ccForm, good())
		f.Del("client_assertion_type")
		code, out, _ := c.send(tokenR, f)
		wantInvalidClient(t, code, out)
	})
	t.Run("two assertions", func(t *testing.T) {
		f := withAssertion(ccForm, good())
		f.Add("client_assertion", good())
		code, out, _ := c.send(tokenR, f)
		wantInvalidClient(t, code, out)
	})
	t.Run("client_id of another client", func(t *testing.T) {
		f := withAssertion(ccForm, good())
		f.Set("client_id", "app")
		code, out, _ := c.send(tokenR, f)
		wantInvalidClient(t, code, out)
	})
	t.Run("assertion in the query", func(t *testing.T) {
		code, out, _ := c.send(tokenR+"?"+withAssertion(url.Values{"client_id": {"svc"}}, good()).Encode(), ccForm)
		wantInvalidClient(t, code, out)
	})
	for name, mod := range map[string]func(url.Values) func(*http.Request){
		"plus secret": func(f url.Values) func(*http.Request) {
			f.Set("client_secret", "s3cret")
			return func(*http.Request) {}
		},
		"plus basic": func(url.Values) func(*http.Request) { return basicAuth("svc", "s3cret") },
		"plus bearer": func(url.Values) func(*http.Request) {
			return func(r *http.Request) { r.Header.Set("Authorization", "Bearer x") }
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := withAssertion(ccForm, good())
			m := mod(f)
			code, out, _ := c.send(tokenR, f, m)
			if code != 400 || out["error"] != "invalid_request" || out["access_token"] != nil {
				t.Fatalf("%d %v", code, out)
			}
		})
	}
	t.Run("disabled client", func(t *testing.T) {
		x := c.cl
		x.Enabled = false
		if err := c.st.UpdateClient(context.Background(), x); err != nil {
			t.Fatal(err)
		}
		code, out := c.ccWith(good())
		wantInvalidClient(t, code, out)
	})
}

// A client that is not configured for private_key_jwt cannot authenticate with
// an assertion, whatever keys it has elsewhere.
func TestAssertionNeedsTheMethod(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	c.addClient(t, "plainsecret", nil)
	code, out := c.ccWith(c.assertion(t, "plainsecret", c.key, aOpt{}))
	wantInvalidClient(t, code, out)
	fapi, _ := core.StoreAs[core.FAPIStore](c.st)
	cl, _ := c.st.GetClientByClientID(context.Background(), "r", "plainsecret")
	if err := fapi.PutClientFAPI(context.Background(), core.ClientFAPI{Realm: "r", ClientRef: cl.ID, JWKS: jwksOf(c.key)}); err != nil {
		t.Fatal(err)
	}
	code, out = c.ccWith(c.assertion(t, "plainsecret", c.key, aOpt{}))
	wantInvalidClient(t, code, out)
	// A TLS client cannot use one either.
	c.configure(t, cl, core.ClientAuth{Method: core.AuthMethodSelfSignedTLS, JWKS: jwksOf(c.key)})
	code, out = c.ccWith(c.assertion(t, "plainsecret", c.key, aOpt{}))
	wantInvalidClient(t, code, out)
}

func TestPrivateKeyJWTPinnedAlg(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	rs := rsaKey(t, "rs", 2048)
	c.configure(t, c.cl, core.ClientAuth{Method: core.AuthMethodPrivateKeyJWT, JWKS: jwksOf(rs), SigningAlg: "PS256"})
	code, out := c.ccWith(c.assertion(t, "svc", rs, aOpt{alg: "RS256"}))
	wantInvalidClient(t, code, out)
	if code, out := c.ccWith(c.assertion(t, "svc", rs, aOpt{alg: "PS256"})); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
}

func TestClientAssertionReplay(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	a := c.assertion(t, "svc", c.key, aOpt{})
	if code, out := c.ccWith(a); code != 200 {
		t.Fatalf("first: %d %v", code, out)
	}
	code, out := c.ccWith(a)
	wantInvalidClient(t, code, out)
	// Not on another endpoint either.
	code, out, _ = c.send(introR, withAssertion(url.Values{"token": {"x"}}, a))
	wantInvalidClient(t, code, out)
	// A fresh assertion that reuses the jti is the same replay.
	reuse := aOpt{claims: func(m map[string]any) { m["jti"] = "same" }}
	if code, out := c.ccWith(c.assertion(t, "svc", c.key, reuse)); code != 200 {
		t.Fatalf("jti first use: %d %v", code, out)
	}
	code, out = c.ccWith(c.assertion(t, "svc", c.key, reuse))
	wantInvalidClient(t, code, out)
	// Another client may use the same jti.
	two := c.addClient(t, "svc2", nil)
	c.configure(t, two, core.ClientAuth{Method: core.AuthMethodPrivateKeyJWT, JWKS: jwksOf(c.key)})
	if code, out := c.ccWith(c.assertion(t, "svc2", c.key, reuse)); code != 200 {
		t.Fatalf("other client: %d %v", code, out)
	}
	// While the assertion is still acceptable (exp + skew) it stays refused.
	b := c.assertion(t, "svc", c.key, aOpt{})
	if code, _ := c.ccWith(b); code != 200 {
		t.Fatal("b")
	}
	c.advance(time.Minute + caSkew - time.Second)
	code, out = c.ccWith(b)
	wantInvalidClient(t, code, out)
}

func TestClientAssertionReplayConcurrent(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	a := c.assertion(t, "svc", c.key, aOpt{})
	var ok atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if code, _ := c.ccWith(a); code == 200 {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 1 {
		t.Fatalf("%d successes", ok.Load())
	}
}

// A rejected assertion must not use up the jti of the real one.
func TestForgedAssertionDoesNotBurnJTI(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	forger := ecKey(t, "k1")
	jti := aOpt{claims: func(m map[string]any) { m["jti"] = "victim" }}
	code, out := c.ccWith(c.assertion(t, "svc", forger, jti))
	wantInvalidClient(t, code, out)
	if code, out := c.ccWith(c.assertion(t, "svc", c.key, jti)); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
}

type failingCAStore struct {
	core.Store
	core.ClientAuthStore
	get, remember bool
}

func (f failingCAStore) Unwrap() core.Store { return f.Store }
func (f failingCAStore) GetClientAuth(ctx context.Context, realm, ref string) (core.ClientAuth, error) {
	if f.get {
		return core.ClientAuth{}, errors.New("db down")
	}
	return f.ClientAuthStore.GetClientAuth(ctx, realm, ref)
}
func (f failingCAStore) RememberClientAssertion(ctx context.Context, realm, h string, now, exp time.Time) error {
	if f.remember {
		return errors.New("db down")
	}
	return f.ClientAuthStore.RememberClientAssertion(ctx, realm, h, now, exp)
}

func TestClientAuthStoreErrorsFailClosed(t *testing.T) {
	for _, mode := range []string{"settings", "replay"} {
		t.Run(mode, func(t *testing.T) {
			c := newCAEnv(t, devOpts{store: func(s core.Store) core.Store {
				cs, _ := core.StoreAs[core.ClientAuthStore](s)
				return failingCAStore{Store: s, ClientAuthStore: cs, get: mode == "settings", remember: mode == "replay"}
			}})
			code, out := c.ccWith(c.assertion(t, "svc", c.key, aOpt{}))
			if code != 500 || out["access_token"] != nil || strings.Contains(fmt.Sprint(out), "db down") {
				t.Fatalf("%d %v", code, out)
			}
			if mode == "settings" {
				// The secret must not work just because the settings cannot be read.
				code, out, _ := c.send(tokenR, ccForm, basicAuth("svc", "s3cret"))
				if code != 500 || out["access_token"] != nil {
					t.Fatalf("secret fallback on store error: %d %v", code, out)
				}
			}
		})
	}
	t.Run("rate limiter", func(t *testing.T) {
		c := newCAEnv(t, devOpts{store: func(s core.Store) core.Store { return failLimiter{s} }})
		code, out := c.ccWith(c.assertion(t, "svc", c.key, aOpt{}))
		if code != 500 || out["access_token"] != nil {
			t.Fatalf("%d %v", code, out)
		}
	})
}

func TestClientAuthWithoutStoreSupport(t *testing.T) {
	c := newCAEnv(t, devOpts{store: func(s core.Store) core.Store { return struct{ core.Store }{s} }})
	code, out := c.ccWith(c.assertion(t, "svc", c.key, aOpt{}))
	wantInvalidClient(t, code, out)
	w := c.browser().do("GET", "/realms/r/.well-known/openid-configuration", nil)
	if strings.Contains(w.Body.String(), "private_key_jwt") {
		t.Fatal("discovery advertises private_key_jwt without a store")
	}
}

// ---- no fallback, on every endpoint that authenticates clients ----

// allEndpoints is every endpoint that authenticates a client, with a request
// body that gets past authentication when the credentials are good.
func (c *caEnv) allEndpoints(t *testing.T, cl core.Client) map[string]url.Values {
	t.Helper()
	box := mail.NewOutbox(10)
	c.h.cfg.Actions = &actions.Service{Store: c.st, Mailer: box, BaseURL: idpBase}
	t.Cleanup(c.h.bg.Wait)
	cs, _ := core.StoreAs[core.CIBAStore](c.st)
	if err := cs.SetCIBAClient(context.Background(), "r", cl.ID, true); err != nil {
		t.Fatal(err)
	}
	par := pkce()
	return map[string]url.Values{
		tokenR:  ccForm,
		introR:  {"token": {"x"}},
		revokeR: {"token": {"x"}},
		parR:    par,
		cibaR:   {"login_hint": {"alice"}, "scope": {"openid"}},
		deviceR: {"scope": {"openid"}},
	}
}

func okStatus(path string) int {
	if path == parR {
		return 201
	}
	return 200
}

func TestStrongClientNeverFallsBackToSecret(t *testing.T) {
	for _, method := range []string{core.AuthMethodPrivateKeyJWT, core.AuthMethodSelfSignedTLS, core.AuthMethodTLS, "something_new"} {
		for _, public := range []bool{false, true} { // an admin flipping the client to public must not open it
			t.Run(fmt.Sprintf("%s public=%v", method, public), func(t *testing.T) {
				c := newCAEnv(t, devOpts{})
				endpoints := c.allEndpoints(t, c.cl)
				c.configure(t, c.cl, core.ClientAuth{Method: method, JWKS: jwksOf(c.key), TLSSANDNS: "a.example"})
				if public {
					x := c.cl
					x.Public = true
					if err := c.st.UpdateClient(context.Background(), x); err != nil {
						t.Fatal(err)
					}
				}
				withID := func(f url.Values, extra url.Values) url.Values {
					o := url.Values{}
					for k, v := range f {
						o[k] = v
					}
					for k, v := range extra {
						o[k] = v
					}
					return o
				}
				for path, f := range endpoints {
					attempts := map[string]func() (int, map[string]any, http.Header){
						"basic": func() (int, map[string]any, http.Header) { return c.send(path, f, basicAuth("svc", "s3cret")) },
						"post": func() (int, map[string]any, http.Header) {
							return c.send(path, withID(f, url.Values{"client_id": {"svc"}, "client_secret": {"s3cret"}}))
						},
						"client_id only": func() (int, map[string]any, http.Header) {
							return c.send(path, withID(f, url.Values{"client_id": {"svc"}}))
						},
						"empty basic password": func() (int, map[string]any, http.Header) { return c.send(path, f, basicAuth("svc", "")) },
					}
					for name, try := range attempts {
						code, out, _ := try()
						if code != 401 || out["error"] != "invalid_client" {
							t.Errorf("%s %s: %d %v", path, name, code, out)
						}
					}
				}
			})
		}
	}
}

func TestPrivateKeyJWTOnEveryEndpoint(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	for path, f := range c.allEndpoints(t, c.cl) {
		// The issuer, the token endpoint and the endpoint itself are audiences.
		for _, aud := range []string{issuerR, idpBase + tokenR, idpBase + path} {
			a := c.assertion(t, "svc", c.key, aOpt{claims: func(m map[string]any) { m["aud"] = aud }})
			code, out, _ := c.send(path, withAssertion(f, a))
			if code != okStatus(path) {
				t.Errorf("%s aud=%s: %d %v", path, aud, code, out)
			}
			code, out, _ = c.send(path, withAssertion(f, a))
			if code != 401 || out["error"] != "invalid_client" {
				t.Errorf("%s replay: %d %v", path, code, out)
			}
		}
		bad := c.assertion(t, "svc", c.key, aOpt{claims: func(m map[string]any) { m["aud"] = idpBase + userinfR }})
		if code, out, _ := c.send(path, withAssertion(f, bad)); code != 401 {
			t.Errorf("%s foreign endpoint audience: %d %v", path, code, out)
		}
	}
}

func TestPinnedSecretAndNoneMethods(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	post := url.Values{"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"s3cret"}}
	check := func(method string, basicOK, postOK bool) {
		t.Helper()
		c.configure(t, c.cl, core.ClientAuth{Method: method})
		code, out, _ := c.send(tokenR, ccForm, basicAuth("svc", "s3cret"))
		if (code == 200) != basicOK {
			t.Errorf("%s basic: %d %v", method, code, out)
		}
		code, out, _ = c.send(tokenR, post)
		if (code == 200) != postOK {
			t.Errorf("%s post: %d %v", method, code, out)
		}
		code, _, _ = c.send(tokenR, ccForm, basicAuth("svc", "wrong"))
		if code != 401 {
			t.Errorf("%s wrong secret: %d", method, code)
		}
	}
	check(core.AuthMethodSecretBasic, true, false)
	check(core.AuthMethodSecretPost, false, true)
	check(core.AuthMethodNone, false, false) // "none" on a confidential client authenticates nobody
	// A public client pinned to none works, and only without credentials.
	app, _ := c.st.GetClientByClientID(context.Background(), "r", "cli")
	c.configure(t, app, core.ClientAuth{Method: core.AuthMethodNone})
	if code, out, _ := c.send(deviceR, url.Values{"client_id": {"cli"}}); code != 200 {
		t.Errorf("public none: %d %v", code, out)
	}
	if code, _, _ := c.send(deviceR, url.Values{"client_id": {"cli"}, "client_secret": {"x"}}); code != 401 {
		t.Errorf("public none with secret: %d", code)
	}
	// Without any configuration both secret methods keep working.
	c.addClient(t, "legacy", nil)
	if code, out, _ := c.send(tokenR, ccForm, basicAuth("legacy", "s3cret")); code != 200 {
		t.Errorf("legacy basic: %d %v", code, out)
	}
	if code, out, _ := c.send(tokenR, url.Values{"grant_type": {"client_credentials"}, "client_id": {"legacy"}, "client_secret": {"s3cret"}}); code != 200 {
		t.Errorf("legacy post: %d %v", code, out)
	}
}

// ---- jwks_uri ----

type jwksSrv struct {
	srv    *httptest.Server
	hits   atomic.Int32
	mu     sync.Mutex
	body   string
	status int
	loc    string
}

func newJWKSSrv(t *testing.T, body string) *jwksSrv {
	t.Helper()
	s := &jwksSrv{body: body, status: 200}
	s.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/jwks" {
			_, _ = w.Write([]byte(s.get()))
			return
		}
		s.hits.Add(1)
		s.mu.Lock()
		st, loc := s.status, s.loc
		s.mu.Unlock()
		if loc != "" {
			w.Header().Set("Location", loc)
		}
		w.WriteHeader(st)
		_, _ = w.Write([]byte(s.get()))
	}))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *jwksSrv) get() string  { s.mu.Lock(); defer s.mu.Unlock(); return s.body }
func (s *jwksSrv) set(f func()) { s.mu.Lock(); defer s.mu.Unlock(); f() }
func (s *jwksSrv) uri() string  { return s.srv.URL + "/jwks" }

// trust lets the provider reach the loopback test server.
func (c *caEnv) trust(s *jwksSrv) {
	pool := x509.NewCertPool()
	pool.AddCert(s.srv.Certificate())
	c.h.jwksCache().http = safehttp.New(safehttp.Options{AllowPrivate: true, RootCAs: pool, MaxBody: jwksMaxBody, Timeout: jwksTimeout})
}

func TestJWKSURICacheAndRotation(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	s := newJWKSSrv(t, jwksOf(c.key))
	c.trust(s)
	c.configure(t, c.cl, core.ClientAuth{Method: core.AuthMethodPrivateKeyJWT, JWKSURI: s.uri()})
	auth := func(k caKey) int { code, _ := c.ccWith(c.assertion(t, "svc", k, aOpt{})); return code }
	for i := 0; i < 3; i++ {
		if code := auth(c.key); code != 200 {
			t.Fatalf("auth %d: %d", i, code)
		}
	}
	if n := s.hits.Load(); n != 1 {
		t.Fatalf("not cached: %d fetches", n)
	}
	// Unknown key ids cannot make the server hammer the client's URL.
	c.advance(jwksMinGap)
	for i := 0; i < 20; i++ {
		if code := auth(ecKey(t, fmt.Sprintf("random-%d", i))); code != 401 {
			t.Fatalf("unknown kid: %d", code)
		}
	}
	if n := s.hits.Load(); n != 2 {
		t.Fatalf("kid refresh not rate limited: %d fetches", n)
	}
	// Rotation: the new key is picked up once the gap has passed, not before.
	next := ecKey(t, "k2")
	s.set(func() { s.body = jwksOf(next) })
	if code := auth(next); code != 401 {
		t.Fatalf("inside the gap: %d", code)
	}
	c.advance(jwksMinGap)
	if code := auth(next); code != 200 {
		t.Fatalf("after the gap: %d", code)
	}
	if code := auth(c.key); code != 401 {
		t.Fatalf("a removed key must stop working: %d", code)
	}
	if n := s.hits.Load(); n != 3 {
		t.Fatalf("fetches: %d", n)
	}
	// A stale copy is never used: expired cache and a failing server = refused.
	s.set(func() { s.status = 500 })
	c.advance(jwksTTL - time.Second)
	if code := auth(next); code != 200 {
		t.Fatalf("fresh copy: %d", code)
	}
	c.advance(2 * time.Second)
	if code := auth(next); code != 401 {
		t.Fatalf("stale copy used: %d", code)
	}
	before := s.hits.Load()
	for i := 0; i < 10; i++ {
		auth(next)
	}
	if s.hits.Load() != before {
		t.Fatalf("failed fetches are not rate limited: %d", s.hits.Load()-before)
	}
}

func TestJWKSURIFetchRefusals(t *testing.T) {
	cases := map[string]func(s *jwksSrv, good string){
		"not found": func(s *jwksSrv, _ string) { s.status = 404 },
		"redirect": func(s *jwksSrv, _ string) {
			s.status, s.loc = 302, s.srv.URL+"/other" // /other serves the good key set
		},
		"too large": func(s *jwksSrv, good string) { s.body = good[:len(good)-1] + strings.Repeat(" ", jwksMaxBody) + "}" },
		"not json":  func(s *jwksSrv, _ string) { s.body = "<html>" },
		"no keys":   func(s *jwksSrv, _ string) { s.body = `{"keys":[]}` },
		"private keys only": func(s *jwksSrv, good string) {
			s.body = strings.Replace(good, `"kty"`, `"d":"AAAA","kty"`, 1)
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			c := newCAEnv(t, devOpts{})
			good := jwksOf(c.key)
			s := newJWKSSrv(t, good)
			c.trust(s)
			s.set(func() { mut(s, good) })
			c.configure(t, c.cl, core.ClientAuth{Method: core.AuthMethodPrivateKeyJWT, JWKSURI: s.uri()})
			code, out := c.ccWith(c.assertion(t, "svc", c.key, aOpt{}))
			wantInvalidClient(t, code, out)
			if s.hits.Load() != 1 {
				t.Fatalf("fetches: %d", s.hits.Load())
			}
		})
	}
}

// Without the dev switch the real SSRF-safe client refuses a loopback target,
// and an http URL is never fetched.
func TestJWKSURISSRF(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	s := newJWKSSrv(t, jwksOf(c.key))
	pool := x509.NewCertPool()
	pool.AddCert(s.srv.Certificate())
	// The production client (no AllowPrivate), only taught to trust the test CA.
	c.h.jwksCache().http = safehttp.New(safehttp.Options{RootCAs: pool, MaxBody: jwksMaxBody, Timeout: jwksTimeout})
	c.configure(t, c.cl, core.ClientAuth{Method: core.AuthMethodPrivateKeyJWT, JWKSURI: s.uri()})
	code, out := c.ccWith(c.assertion(t, "svc", c.key, aOpt{}))
	wantInvalidClient(t, code, out)
	if s.hits.Load() != 0 {
		t.Fatal("a loopback address was fetched")
	}
	// The default client the provider builds itself is the same.
	d := newCAEnv(t, devOpts{})
	d.configure(t, d.cl, core.ClientAuth{Method: core.AuthMethodPrivateKeyJWT, JWKSURI: s.uri()})
	code, out = d.ccWith(d.assertion(t, "svc", d.key, aOpt{}))
	wantInvalidClient(t, code, out)
	if hc := d.h.jwksCache().http; hc == nil || hc.AllowPrivate {
		t.Fatal("default jwks client lifts the address policy")
	}
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("plain http jwks_uri fetched")
		_, _ = w.Write([]byte(jwksOf(c.key)))
	}))
	defer plain.Close()
	c.configure(t, c.cl, core.ClientAuth{Method: core.AuthMethodPrivateKeyJWT, JWKSURI: plain.URL})
	code, out = c.ccWith(c.assertion(t, "svc", c.key, aOpt{}))
	wantInvalidClient(t, code, out)
}

// ---- configuration validation ----

func TestValidateClientAuth(t *testing.T) {
	k := ecKey(t, "k")
	good := jwksOf(k)
	priv := strings.Replace(good, `"kty"`, `"d":"AAAA","kty"`, 1)
	pj := core.AuthMethodPrivateKeyJWT
	tlsm := core.AuthMethodTLS
	ss := core.AuthMethodSelfSignedTLS
	for name, x := range map[string]struct {
		c      core.ClientAuth
		public bool
		ok     bool
	}{
		"jwt inline":              {core.ClientAuth{Method: pj, JWKS: good}, false, true},
		"jwt uri":                 {core.ClientAuth{Method: pj, JWKSURI: "https://c.example/jwks"}, false, true},
		"jwt both":                {core.ClientAuth{Method: pj, JWKS: good, JWKSURI: "https://c.example/jwks"}, false, false},
		"jwt neither":             {core.ClientAuth{Method: pj}, false, false},
		"jwt http":                {core.ClientAuth{Method: pj, JWKSURI: "http://c.example/jwks"}, false, false},
		"jwt http loopback":       {core.ClientAuth{Method: pj, JWKSURI: "http://127.0.0.1/jwks"}, false, false},
		"jwt userinfo":            {core.ClientAuth{Method: pj, JWKSURI: "https://u:p@c.example/jwks"}, false, false},
		"jwt private":             {core.ClientAuth{Method: pj, JWKS: priv}, false, false},
		"jwt empty set":           {core.ClientAuth{Method: pj, JWKS: `{"keys":[]}`}, false, false},
		"jwt public client":       {core.ClientAuth{Method: pj, JWKS: good}, true, false},
		"jwt alg":                 {core.ClientAuth{Method: pj, JWKS: good, SigningAlg: "ES256"}, false, true},
		"jwt alg none":            {core.ClientAuth{Method: pj, JWKS: good, SigningAlg: "none"}, false, false},
		"jwt alg HS256":           {core.ClientAuth{Method: pj, JWKS: good, SigningAlg: "HS256"}, false, false},
		"jwt with dn":             {core.ClientAuth{Method: pj, JWKS: good, TLSSubjectDN: "CN=a"}, false, false},
		"secret":                  {core.ClientAuth{Method: core.AuthMethodSecretBasic}, false, true},
		"secret bound":            {core.ClientAuth{Method: core.AuthMethodSecretPost, CertBoundTokens: true}, false, true},
		"secret with keys":        {core.ClientAuth{Method: core.AuthMethodSecretBasic, JWKS: good}, false, false},
		"secret public":           {core.ClientAuth{Method: core.AuthMethodSecretBasic}, true, false},
		"none public":             {core.ClientAuth{Method: core.AuthMethodNone}, true, true},
		"none confidential":       {core.ClientAuth{Method: core.AuthMethodNone}, false, false},
		"none bound":              {core.ClientAuth{Method: core.AuthMethodNone, CertBoundTokens: true}, true, false},
		"unknown":                 {core.ClientAuth{Method: "client_secret_jwt"}, false, false},
		"empty":                   {core.ClientAuth{}, false, false},
		"tls dn":                  {core.ClientAuth{Method: tlsm, TLSSubjectDN: "CN=a,O=b"}, false, true},
		"tls nothing":             {core.ClientAuth{Method: tlsm}, false, false},
		"tls two":                 {core.ClientAuth{Method: tlsm, TLSSubjectDN: "CN=a", TLSSANDNS: "a.example"}, false, false},
		"tls dns":                 {core.ClientAuth{Method: tlsm, TLSSANDNS: "a.example"}, false, true},
		"tls dns wildcard":        {core.ClientAuth{Method: tlsm, TLSSANDNS: "*.example"}, false, false},
		"tls uri":                 {core.ClientAuth{Method: tlsm, TLSSANURI: "spiffe://x/y"}, false, true},
		"tls uri relative":        {core.ClientAuth{Method: tlsm, TLSSANURI: "x/y"}, false, false},
		"tls ip":                  {core.ClientAuth{Method: tlsm, TLSSANIP: "2001:DB8::1"}, false, true},
		"tls ip bad":              {core.ClientAuth{Method: tlsm, TLSSANIP: "300.1.1.1"}, false, false},
		"tls email":               {core.ClientAuth{Method: tlsm, TLSSANEmail: "a@b.example"}, false, true},
		"tls email bad":           {core.ClientAuth{Method: tlsm, TLSSANEmail: "b.example"}, false, false},
		"tls with keys":           {core.ClientAuth{Method: tlsm, TLSSANDNS: "a.example", JWKS: good}, false, false},
		"self signed without x5c": {core.ClientAuth{Method: ss, JWKS: good}, false, false},
		"self signed uri":         {core.ClientAuth{Method: ss, JWKSURI: "https://c.example/jwks"}, false, true},
		"self signed alg":         {core.ClientAuth{Method: ss, JWKSURI: "https://c.example/jwks", SigningAlg: "ES256"}, false, false},
	} {
		_, err := ValidateClientAuth(x.c, x.public, false)
		if (err == nil) != x.ok {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	got, err := ValidateClientAuth(core.ClientAuth{Method: tlsm, TLSSANIP: "::ffff:192.0.2.1"}, false, false)
	if err != nil || got.TLSSANIP != "192.0.2.1" {
		t.Errorf("ip normalisation: %q %v", got.TLSSANIP, err)
	}
}

// ---- discovery ----

func TestClientAuthDiscovery(t *testing.T) {
	doc := func(c *caEnv) map[string]any {
		w := c.browser().do("GET", "/realms/r/.well-known/openid-configuration", nil)
		var m map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	list := func(m map[string]any, k string) []string {
		var out []string
		l, _ := m[k].([]any)
		for _, v := range l {
			out = append(out, v.(string))
		}
		return out
	}
	c := newCAEnv(t, devOpts{})
	d := doc(c)
	for _, ep := range []string{"token_endpoint", "introspection_endpoint", "revocation_endpoint"} {
		m := list(d, ep+"_auth_methods_supported")
		if !slices.Contains(m, "private_key_jwt") || !slices.Contains(m, "client_secret_basic") ||
			slices.Contains(m, "tls_client_auth") || slices.Contains(m, "self_signed_tls_client_auth") {
			t.Errorf("%s without mTLS: %v", ep, m)
		}
		if got := list(d, ep+"_auth_signing_alg_values_supported"); !slices.Equal(got, []string{"ES256", "PS256", "RS256", "EdDSA"}) {
			t.Errorf("%s algs: %v", ep, got)
		}
	}
	if d["tls_client_certificate_bound_access_tokens"] != nil {
		t.Error("certificate binding advertised without mTLS")
	}
	c.h.cfg.MTLS = MTLSConfig{Direct: true}
	d = doc(c)
	m := list(d, "token_endpoint_auth_methods_supported")
	if !slices.Contains(m, "self_signed_tls_client_auth") || slices.Contains(m, "tls_client_auth") || d["tls_client_certificate_bound_access_tokens"] != true {
		t.Errorf("direct without CA: %v", d)
	}
	c.h.cfg.MTLS.Roots = x509.NewCertPool()
	if m = list(doc(c), "token_endpoint_auth_methods_supported"); !slices.Contains(m, "tls_client_auth") || len(m) != 6 {
		t.Errorf("direct with CA: %v", m)
	}
}

// ---- dynamic client registration ----

func (c *caEnv) dcr(t *testing.T, method, path, bearer string, body map[string]any) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, "/realms/r/clients-registrations/openid-connect"+path, strings.NewReader(mustJSON(body)))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.RemoteAddr = "203.0.113.30:1"
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, req)
	var out map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func (c *caEnv) iat(t *testing.T) string {
	t.Helper()
	st, _ := core.StoreAs[core.DCRStore](c.st)
	rl, _ := c.st.GetRealm(context.Background(), "r")
	tok := "iat-" + randToken(16)
	if err := st.PutInitialAccessToken(context.Background(), core.InitialAccessToken{Realm: "r", TokenHash: HashSecret(tok),
		Count: 20, Remaining: 20, CreatedAt: rl.CreatedAt.Add(time.Second), ExpiresAt: c.now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestDCRPrivateKeyJWT(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	tok := c.iat(t)
	k := ecKey(t, "d1")
	var jwks map[string]any
	_ = json.Unmarshal([]byte(jwksOf(k)), &jwks)
	meta := map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks": jwks, "grant_types": []string{"client_credentials"}}
	code, out := c.dcr(t, "POST", "", tok, meta)
	if code != 201 {
		t.Fatalf("register: %d %v", code, out)
	}
	if out["client_secret"] != nil || out["token_endpoint_auth_method"] != "private_key_jwt" || out["jwks"] == nil {
		t.Fatalf("response: %v", out)
	}
	id, reg := out["client_id"].(string), out["registration_access_token"].(string)
	cl, _ := c.st.GetClientByClientID(context.Background(), "r", id)
	if cl.SecretHash != "" || cl.Public {
		t.Fatalf("client: %+v", cl)
	}
	if code, o := c.ccWith(c.assertion(t, id, k, aOpt{})); code != 200 {
		t.Fatalf("auth: %d %v", code, o)
	}
	if code, o := c.dcr(t, "GET", "/"+id, reg, nil); code != 200 || o["token_endpoint_auth_method"] != "private_key_jwt" || o["jwks"] == nil {
		t.Fatalf("read: %d %v", code, o)
	}
	// No way back to a secret, nor to nothing.
	for _, m := range []string{"client_secret_basic", "client_secret_post", "", "none"} {
		code, o := c.dcr(t, "PUT", "/"+id, reg, map[string]any{"token_endpoint_auth_method": m, "grant_types": []string{"client_credentials"}})
		if code != 400 {
			t.Fatalf("downgrade to %q: %d %v", m, code, o)
		}
	}
	// Key rotation through RFC 7592.
	k2 := ecKey(t, "d2")
	var jwks2 map[string]any
	_ = json.Unmarshal([]byte(jwksOf(k2)), &jwks2)
	meta["jwks"] = jwks2
	if code, o := c.dcr(t, "PUT", "/"+id, reg, meta); code != 200 {
		t.Fatalf("rotate: %d %v", code, o)
	}
	code, o := c.ccWith(c.assertion(t, id, k, aOpt{}))
	wantInvalidClient(t, code, o)
	if code, o := c.ccWith(c.assertion(t, id, k2, aOpt{})); code != 200 {
		t.Fatalf("new key: %d %v", code, o)
	}
}

func TestDCRSecretClientUpgrade(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	tok := c.iat(t)
	code, out := c.dcr(t, "POST", "", tok, map[string]any{"grant_types": []string{"client_credentials"}})
	if code != 201 {
		t.Fatalf("%d %v", code, out)
	}
	id, secret, reg := out["client_id"].(string), out["client_secret"].(string), out["registration_access_token"].(string)
	var jwks map[string]any
	_ = json.Unmarshal([]byte(jwksOf(c.key)), &jwks)
	code, o := c.dcr(t, "PUT", "/"+id, reg, map[string]any{"token_endpoint_auth_method": "private_key_jwt", "jwks": jwks,
		"grant_types": []string{"client_credentials"}})
	if code != 200 {
		t.Fatalf("upgrade: %d %v", code, o)
	}
	cl, _ := c.st.GetClientByClientID(context.Background(), "r", id)
	if cl.SecretHash != "" {
		t.Fatal("secret hash kept after upgrading")
	}
	code, o, _ = c.send(tokenR, ccForm, basicAuth(id, secret))
	wantInvalidClient(t, code, o)
	if code, o := c.ccWith(c.assertion(t, id, c.key, aOpt{})); code != 200 {
		t.Fatalf("%d %v", code, o)
	}
}

// Certificate binding cannot be dropped by the holder of the registration
// token, whoever switched it on.
func TestDCRKeepsCertificateBinding(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	c.h.cfg.MTLS = MTLSConfig{Direct: true}
	tok := c.iat(t)
	meta := map[string]any{"grant_types": []string{"client_credentials"}, "tls_client_certificate_bound_access_tokens": true}
	code, out := c.dcr(t, "POST", "", tok, meta)
	if code != 201 || out["client_secret"] == nil || out["tls_client_certificate_bound_access_tokens"] != true {
		t.Fatalf("register: %d %v", code, out)
	}
	id, reg := out["client_id"].(string), out["registration_access_token"].(string)
	if code, o := c.dcr(t, "PUT", "/"+id, reg, map[string]any{"grant_types": []string{"client_credentials"}}); code != 400 {
		t.Fatalf("dropping the binding: %d %v", code, o)
	}
	if code, o := c.dcr(t, "PUT", "/"+id, reg, meta); code != 200 {
		t.Fatalf("keeping it: %d %v", code, o)
	}
	// Still enforced: no certificate, no token.
	code, o, _ := c.send(tokenR, ccForm, basicAuth(id, out["client_secret"].(string)))
	if code != 400 || o["access_token"] != nil {
		t.Fatalf("unbound token: %d %v", code, o)
	}
}

func TestDCRClientAuthRefusals(t *testing.T) {
	c := newCAEnv(t, devOpts{})
	tok := c.iat(t)
	var jwks, priv map[string]any
	_ = json.Unmarshal([]byte(jwksOf(c.key)), &jwks)
	_ = json.Unmarshal([]byte(strings.Replace(jwksOf(c.key), `"kty"`, `"d":"AAAA","kty"`, 1)), &priv)
	pj := "private_key_jwt"
	for name, m := range map[string]map[string]any{
		"no keys":               {"token_endpoint_auth_method": pj},
		"private keys":          {"token_endpoint_auth_method": pj, "jwks": priv},
		"both":                  {"token_endpoint_auth_method": pj, "jwks": jwks, "jwks_uri": "https://c.example/k"},
		"http jwks_uri":         {"token_endpoint_auth_method": pj, "jwks_uri": "http://127.0.0.1/k"},
		"jwks_uri wrong type":   {"token_endpoint_auth_method": pj, "jwks_uri": 7},
		"bad alg":               {"token_endpoint_auth_method": pj, "jwks": jwks, "token_endpoint_auth_signing_alg": "HS256"},
		"tls with mtls off":     {"token_endpoint_auth_method": "tls_client_auth", "tls_client_auth_san_dns": "a.example"},
		"self with mtls off":    {"token_endpoint_auth_method": "self_signed_tls_client_auth", "jwks_uri": "https://c.example/k"},
		"binding with mtls off": {"tls_client_certificate_bound_access_tokens": true},
		"client_secret_jwt":     {"token_endpoint_auth_method": "client_secret_jwt"},
		"public binding":        {"token_endpoint_auth_method": "none", "tls_client_certificate_bound_access_tokens": true},
	} {
		if m["grant_types"] == nil && m["token_endpoint_auth_method"] != "none" {
			m["grant_types"] = []string{"client_credentials"}
		} else {
			m["redirect_uris"] = []string{cb}
		}
		if code, out := c.dcr(t, "POST", "", tok, m); code != 400 || out["error"] != "invalid_client_metadata" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	tls := map[string]any{"token_endpoint_auth_method": "tls_client_auth", "tls_client_auth_san_dns": "a.example", "grant_types": []string{"client_credentials"}}
	c.h.cfg.MTLS = MTLSConfig{Direct: true}
	if code, out := c.dcr(t, "POST", "", tok, tls); code != 400 {
		t.Errorf("tls without CA: %d %v", code, out)
	}
	c.h.cfg.MTLS.Roots = x509.NewCertPool()
	code, out := c.dcr(t, "POST", "", tok, tls)
	if code != 201 || out["client_secret"] != nil || out["tls_client_auth_san_dns"] != "a.example" {
		t.Errorf("tls with CA: %d %v", code, out)
	}
}
