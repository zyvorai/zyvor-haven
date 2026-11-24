// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package havencli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIdP is an in-test OIDC provider implementing discovery, the RFC 8628
// device endpoint, the token endpoint (device + refresh grants with refresh
// token rotation), userinfo, revocation and a JWKS. It is NOT the real
// haven-idp; the lead must run the live check after the server side merges.
type fakeIdP struct {
	t   *testing.T
	srv *httptest.Server
	key *ecdsa.PrivateKey

	mu sync.Mutex
	// polls is consumed one entry per device-grant poll: pending, slow_down,
	// denied, expired, ok. When exhausted it repeats the last entry.
	polls          []string
	pollCount      int
	currentRefresh string
	refreshCalls   int
	refreshReuse   int // refresh attempts with a stale token
	refreshDelay   time.Duration
	nextN          int
	revoked        []formVals
	revokeStatus   int
	issued         []string // every token string handed out, for leak scans
	deviceCalls    int
	deviceExpires  int
	deviceInterval int

	// knobs
	issuerOverride  string
	tokenEndpoint   string // override
	deviceEndpoint  string // override
	redirectToken   string // token endpoint 302s here
	hugeToken       bool
	badAud          bool
	badIss          bool
	badSig          bool
	noJWKS          bool
	noIDToken       bool
	accessTTL       int
	idTTL           int
	alwaysInvalidRT bool
	userinfoSub     string
}

type formVals = map[string][]string

func newFake(t *testing.T, useTLS bool) *fakeIdP {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{t: t, key: k, polls: []string{"ok"}, accessTTL: 3600, idTTL: 3600, deviceExpires: 600, deviceInterval: 5, revokeStatus: 200}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("/device", f.device)
	mux.HandleFunc("/token", f.token)
	mux.HandleFunc("/userinfo", f.userinfo)
	mux.HandleFunc("/revoke", f.revoke)
	mux.HandleFunc("/jwks", f.jwks)
	f.srv = httptest.NewUnstartedServer(mux)
	if useTLS {
		f.srv.StartTLS()
	} else {
		f.srv.Start()
	}
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) url() string { return f.srv.URL }

func (f *fakeIdP) caFile(t *testing.T) string {
	p := filepath.Join(t.TempDir(), "ca.pem")
	b := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func (f *fakeIdP) discovery(w http.ResponseWriter, r *http.Request) {
	iss := f.srv.URL
	if f.issuerOverride != "" {
		iss = f.issuerOverride
	}
	tok, dev := f.srv.URL+"/token", f.srv.URL+"/device"
	if f.tokenEndpoint != "" {
		tok = f.tokenEndpoint
	}
	if f.deviceEndpoint != "" {
		dev = f.deviceEndpoint
	}
	d := map[string]any{"issuer": iss, "device_authorization_endpoint": dev, "token_endpoint": tok,
		"userinfo_endpoint": f.srv.URL + "/userinfo", "revocation_endpoint": f.srv.URL + "/revoke"}
	if !f.noJWKS {
		d["jwks_uri"] = f.srv.URL + "/jwks"
	}
	_ = json.NewEncoder(w).Encode(d)
}

func (f *fakeIdP) device(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	f.deviceCalls++
	f.mu.Unlock()
	if r.Form.Get("client_id") == "" {
		jsonErr(w, 400, "invalid_client", "")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"device_code": "DEVCODE-secret", "user_code": "ABCD-EFGH",
		"verification_uri":          f.srv.URL + "/activate",
		"verification_uri_complete": f.srv.URL + "/activate?user_code=ABCD-EFGH",
		"expires_in":                f.deviceExpires, "interval": f.deviceInterval,
	})
}

func jsonErr(w http.ResponseWriter, code int, e, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": e, "error_description": desc})
}

func (f *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	if f.redirectToken != "" {
		http.Redirect(w, r, f.redirectToken, http.StatusTemporaryRedirect)
		return
	}
	if f.hugeToken {
		_, _ = w.Write(bytes.Repeat([]byte("a"), 2<<20))
		return
	}
	_ = r.ParseForm()
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.Form.Get("grant_type") {
	case grantDevice:
		if r.Form.Get("device_code") != "DEVCODE-secret" {
			jsonErr(w, 400, "invalid_grant", "")
			return
		}
		i := f.pollCount
		if i >= len(f.polls) {
			i = len(f.polls) - 1
		}
		f.pollCount++
		switch f.polls[i] {
		case "pending":
			jsonErr(w, 400, "authorization_pending", "")
		case "slow_down":
			jsonErr(w, 400, "slow_down", "")
		case "denied":
			jsonErr(w, 400, "access_denied", "user said no")
		case "expired":
			jsonErr(w, 400, "expired_token", "")
		default:
			f.issueLocked(w, "alice")
		}
	case "refresh_token":
		if f.refreshDelay > 0 {
			f.mu.Unlock()
			time.Sleep(f.refreshDelay)
			f.mu.Lock()
		}
		f.refreshCalls++
		if f.alwaysInvalidRT || r.Form.Get("refresh_token") != f.currentRefresh {
			f.refreshReuse++
			jsonErr(w, 400, "invalid_grant", "refresh token reused or expired")
			return
		}
		f.issueLocked(w, "alice")
	default:
		jsonErr(w, 400, "unsupported_grant_type", "")
	}
}

func (f *fakeIdP) issueLocked(w http.ResponseWriter, user string) {
	f.nextN++
	n := f.nextN
	at, rt := fmt.Sprintf("AT-%d-secretaccess", n), fmt.Sprintf("RT-%d-secretrefresh", n)
	f.currentRefresh = rt
	resp := map[string]any{"access_token": at, "token_type": "Bearer", "refresh_token": rt, "expires_in": f.accessTTL, "scope": "openid"}
	f.issued = append(f.issued, at, rt, "DEVCODE-secret")
	if !f.noIDToken {
		id := f.mintID(user)
		resp["id_token"] = id
		f.issued = append(f.issued, id)
	}
	_ = json.NewEncoder(w).Encode(resp)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (f *fakeIdP) mintID(user string) string {
	iss, aud := f.srv.URL, "haven-cli"
	if f.badIss {
		iss = "https://evil.example"
	}
	if f.badAud {
		aud = "someone-else"
	}
	claims := map[string]any{"iss": iss, "aud": aud, "sub": "sub-123", "preferred_username": user,
		"email": user + "@example.com", "iat": time.Now().Unix(), "exp": time.Now().Add(time.Duration(f.idTTL) * time.Second).Unix()}
	h, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "k1", "typ": "JWT"})
	c, _ := json.Marshal(claims)
	signing := b64(h) + "." + b64(c)
	d := sha256.Sum256([]byte(signing))
	key := f.key
	if f.badSig {
		key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	r, s, _ := ecdsa.Sign(rand.Reader, key, d[:])
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return signing + "." + b64(sig)
}

func (f *fakeIdP) jwks(w http.ResponseWriter, r *http.Request) {
	x, y := f.key.X, f.key.Y
	pad := func(n *big.Int) string { b := make([]byte, 32); n.FillBytes(b); return b64(b) }
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{
		{"kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig", "alg": "ES256", "x": pad(x), "y": pad(y)}}})
}

func (f *fakeIdP) userinfo(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer AT-") {
		jsonErr(w, 401, "invalid_token", "")
		return
	}
	sub := "sub-123"
	if f.userinfoSub != "" {
		sub = f.userinfoSub
	}
	_ = json.NewEncoder(w).Encode(map[string]string{"sub": sub, "preferred_username": "alice", "email": "alice@example.com"})
}

func (f *fakeIdP) revoke(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	f.revoked = append(f.revoked, r.Form)
	f.mu.Unlock()
	w.WriteHeader(f.revokeStatus)
}

// ---- environment helpers ----

type testEnv struct {
	env    *Env
	out    *bytes.Buffer
	errb   *bytes.Buffer
	now    time.Time
	sleeps []time.Duration
	opened []string
	home   string
}

func newEnv(t *testing.T, cfgHome string) *testEnv {
	t.Helper()
	te := &testEnv{out: &bytes.Buffer{}, errb: &bytes.Buffer{}, now: time.Now(), home: cfgHome}
	te.env = &Env{
		Stdout: te.out, Stderr: te.errb,
		Getenv: func(k string) string {
			if k == "XDG_CONFIG_HOME" {
				return cfgHome
			}
			return ""
		},
		UserHomeDir: func() (string, error) { return filepath.Join(cfgHome, "home"), nil },
		Now:         func() time.Time { return te.now },
		Sleep: func(ctx context.Context, d time.Duration) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			te.sleeps = append(te.sleeps, d)
			te.now = te.now.Add(d)
			return nil
		},
		OpenBrowser: func(u string) error { te.opened = append(te.opened, u); return nil },
	}
	return te
}

func (te *testEnv) run(args ...string) int {
	return Run(context.Background(), args, te.env)
}

// seed writes a profile straight into the store.
func seed(t *testing.T, te *testEnv, name string, p *Profile) {
	t.Helper()
	s, err := newStore(te.env)
	if err != nil {
		t.Fatal(err)
	}
	f, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	f.Profiles[name] = p
	if err := s.save(f); err != nil {
		t.Fatal(err)
	}
}

func loadProfile(t *testing.T, te *testEnv, name string) *Profile {
	t.Helper()
	s, _ := newStore(te.env)
	f, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	return f.Profiles[name]
}

// loginArgs logs in against f; cfg dir is te.home.
func loginArgs(f *fakeIdP, extra ...string) []string {
	return append([]string{"login", "--issuer", f.url(), "--client-id", "haven-cli"}, extra...)
}

func mustLogin(t *testing.T, f *fakeIdP, te *testEnv) {
	t.Helper()
	if c := te.run(loginArgs(f)...); c != 0 {
		t.Fatalf("login exit %d: %s", c, te.errb.String())
	}
	te.out.Reset()
	te.errb.Reset()
}

// expireAccess marks the stored access and ID tokens as expired.
func expireAccess(t *testing.T, te *testEnv) {
	t.Helper()
	p := loadProfile(t, te, "default")
	p.AccessExpiry = time.Now().Add(-time.Hour)
	p.IDExpiry = time.Now().Add(-time.Hour)
	seed(t, te, "default", p)
}
