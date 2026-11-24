// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/safehttp"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
	"github.com/zyvorai/haven/internal/idp/upstream"
)

// identFake is the oidc fake store plus real in-memory workload and agent stores.
type identFake struct {
	*fakeStore
	core.WorkloadStore
	core.AgentStore
	rl map[string]int
}

// HitRateLimit is a fixed-window counter that never resets (tests are short).
func (f *identFake) HitRateLimit(_ context.Context, key string, _ time.Time, _ time.Duration, max int) (bool, error) {
	f.fakeStore.mu.Lock()
	defer f.fakeStore.mu.Unlock()
	if f.rl == nil {
		f.rl = map[string]int{}
	}
	f.rl[key]++
	return f.rl[key] <= max, nil
}

const (
	k8sIss = "https://oidc.cluster.example"
	k8sAud = "haven"
	k8sSub = "system:serviceaccount:prod:payments"
)

// signer is a software ES256 key standing in for the cluster's service
// account issuer.
type signer struct {
	key *ecdsa.PrivateKey
	kid string
}

func newSigner(t *testing.T, kid string) *signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &signer{key: k, kid: kid}
}

func (s *signer) jwks() string {
	b := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 32))) }
	return fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","kid":%q,"use":"sig","alg":"ES256","x":%q,"y":%q}]}`,
		s.kid, b(s.key.X), b(s.key.Y))
}

func (s *signer) sign(t *testing.T, alg string, claims map[string]any) string {
	t.Helper()
	hdr, _ := json.Marshal(map[string]any{"alg": alg, "kid": s.kid, "typ": "JWT"})
	pl, _ := json.Marshal(claims)
	in := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl)
	if alg == "none" {
		return in + "."
	}
	h := sha256.Sum256([]byte(in))
	r, sg, err := ecdsa.Sign(rand.Reader, s.key, h[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), sg.FillBytes(make([]byte, 32))...)
	return in + "." + base64.RawURLEncoding.EncodeToString(sig)
}

type idEnv struct {
	*env
	ms  *memstore.Store
	sig *signer
}

func newIDEnv(t *testing.T) *idEnv {
	t.Helper()
	e := newEnv(t, nil)
	ms := memstore.New()
	if err := ms.CreateRealm(context.Background(), core.Realm{Name: "r", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	ie := &idEnv{env: e, ms: ms, sig: newSigner(t, "k1")}
	ie.rebuild(&identFake{fakeStore: e.st, WorkloadStore: ms, AgentStore: ms}, nil)
	return ie
}

func (ie *idEnv) rebuild(st core.Store, mgr *upstream.Manager) {
	clock := func() time.Time { return ie.now }
	ie.h = New(Config{Store: st, Signer: fakeSigner{now: clock}, Hasher: fakeHasher{},
		BaseURL: "https://idp.example", Clock: clock, CSRFKey: []byte("0123456789abcdef0123456789abcdef"),
		Federation: mgr})
}

// workload registers a workload client + identity bound to ie.sig's inline JWKS.
func (ie *idEnv) workload(name string, mut func(*core.WorkloadIdentity)) core.WorkloadIdentity {
	ie.t.Helper()
	cid := "wl-" + name
	ie.st.clients["wl-"+name] = core.Client{ID: "wl-" + name, Realm: "r", ClientID: cid, Name: name, Enabled: true, Public: true}
	w := core.WorkloadIdentity{Realm: "r", Name: name, ClientID: cid, Issuer: k8sIss, JWKS: ie.sig.jwks(), Audience: k8sAud,
		Subject: k8sSub, AllowedScopes: []string{"read", "write"}, TTLSeconds: 600, Enabled: true, CreatedAt: ie.now}
	if mut != nil {
		mut(&w)
	}
	out, err := ie.ms.CreateWorkloadIdentity(context.Background(), w)
	if err != nil {
		ie.t.Fatal(err)
	}
	return out
}

func (ie *idEnv) k8sToken(over map[string]any) string {
	ie.t.Helper()
	c := map[string]any{"iss": k8sIss, "aud": []string{k8sAud}, "sub": k8sSub, "iat": ie.now.Unix(),
		"nbf": ie.now.Unix(), "exp": ie.now.Add(time.Hour).Unix()}
	for k, v := range over {
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
	}
	return ie.sig.sign(ie.t, "ES256", c)
}

func (ie *idEnv) exchangeJWT(client, tok string, extra url.Values) (int, map[string]any) {
	ie.t.Helper()
	f := url.Values{"grant_type": {grantTokenExchange}, "client_id": {client}, "subject_token": {tok}, "subject_token_type": {ttJWT}}
	for k, v := range extra {
		f[k] = v
	}
	code, out, _ := ie.tokenReq(f, "", "")
	return code, out
}

func (ie *idEnv) lastEvent(typ string) (core.Event, bool) {
	for i := len(ie.st.events) - 1; i >= 0; i-- {
		if ie.st.events[i].Type == typ {
			return ie.st.events[i], true
		}
	}
	return core.Event{}, false
}

func wantErr(t *testing.T, code int, out map[string]any, status int, oauth string) {
	t.Helper()
	if code != status || out["error"] != oauth {
		t.Fatalf("got %d %v, want %d %s", code, out, status, oauth)
	}
	if _, has := out["access_token"]; has {
		t.Fatalf("error response carries a token: %v", out)
	}
}

// ---- workload identity ----

func TestWorkloadExchangeIssues(t *testing.T) {
	ie := newIDEnv(t)
	ie.workload("pay", func(w *core.WorkloadIdentity) { w.TTLSeconds = 120 })
	code, out := ie.exchangeJWT("wl-pay", ie.k8sToken(nil), url.Values{"scope": {"read"}})
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if out["token_type"] != "Bearer" || out["issued_token_type"] != ttAccess || out["scope"] != "read" || out["expires_in"] != float64(120) {
		t.Fatalf("response %v", out)
	}
	if _, has := out["refresh_token"]; has {
		t.Fatal("workload tokens get no refresh token")
	}
	c := claimsOf(t, out["access_token"].(string))
	if c["sub"] != "workload-wl-pay" || c["aud"] != "wl-pay" || c["scope"] != "read" ||
		c["workload_subject"] != k8sSub || c["workload_issuer"] != k8sIss || fmt.Sprint(c["realm_access"]) != "map[roles:[]]" {
		t.Fatalf("claims %v", c)
	}
	if c["exp"].(float64)-c["iat"].(float64) != 120 {
		t.Fatalf("ttl %v", c)
	}
	ev, ok := ie.lastEvent("WORKLOAD_TOKEN")
	if !ok || ev.ClientID != "wl-pay" || !strings.Contains(ev.Detail, "workload=pay") {
		t.Fatalf("event %+v", ev)
	}
	// Omitted scope = everything registered for the workload, nothing more.
	_, out = ie.exchangeJWT("wl-pay", ie.k8sToken(nil), nil)
	if out["scope"] != "read write" {
		t.Fatalf("default scope %v", out["scope"])
	}
}

func TestWorkloadJWTBearerGrant(t *testing.T) {
	ie := newIDEnv(t)
	ie.workload("pay", nil)
	f := url.Values{"grant_type": {grantJWTBearer}, "client_id": {"wl-pay"}, "assertion": {ie.k8sToken(nil)}}
	code, out, _ := ie.tokenReq(f, "", "")
	if code != 200 || out["access_token"] == nil {
		t.Fatalf("%d %v", code, out)
	}
	f.Set("assertion", ie.k8sToken(map[string]any{"sub": "system:serviceaccount:prod:evil"}))
	code, out, _ = ie.tokenReq(f, "", "")
	wantErr(t, code, out, 400, "invalid_grant")
	f["assertion"] = []string{"a", "b"}
	code, out, _ = ie.tokenReq(f, "", "")
	wantErr(t, code, out, 400, "invalid_request")
}

func TestWorkloadRejectsBadSubjectTokens(t *testing.T) {
	ie := newIDEnv(t)
	ie.workload("pay", nil)
	other := newSigner(t, "k1") // same kid, different key
	cases := []struct {
		name   string
		tok    func() string
		reason string
	}{
		{"wrong issuer", func() string { return ie.k8sToken(map[string]any{"iss": "https://evil.example"}) }, "issuer_mismatch"},
		{"issuer prefix", func() string { return ie.k8sToken(map[string]any{"iss": k8sIss + "/"}) }, "issuer_mismatch"},
		{"wrong audience", func() string { return ie.k8sToken(map[string]any{"aud": []string{"other"}}) }, "bad_audience"},
		{"audience string wrong", func() string { return ie.k8sToken(map[string]any{"aud": "haven2"}) }, "bad_audience"},
		{"no audience", func() string { return ie.k8sToken(map[string]any{"aud": nil}) }, "bad_audience"},
		{"wrong subject", func() string { return ie.k8sToken(map[string]any{"sub": "system:serviceaccount:prod:other"}) }, "bad_subject"},
		{"subject prefix", func() string { return ie.k8sToken(map[string]any{"sub": k8sSub + "x"}) }, "bad_subject"},
		{"no subject", func() string { return ie.k8sToken(map[string]any{"sub": nil}) }, "bad_subject"},
		{"expired", func() string { return ie.k8sToken(map[string]any{"exp": ie.now.Add(-2 * time.Minute).Unix()}) }, "expired"},
		{"no exp", func() string { return ie.k8sToken(map[string]any{"exp": nil}) }, "bad_time"},
		{"nbf in the future", func() string { return ie.k8sToken(map[string]any{"nbf": ie.now.Add(time.Hour).Unix()}) }, "bad_time"},
		{"wrong key", func() string {
			return other.sign(t, "ES256", map[string]any{"iss": k8sIss, "aud": k8sAud, "sub": k8sSub, "exp": ie.now.Add(time.Hour).Unix()})
		}, "bad_signature"},
		{"alg none", func() string {
			return ie.sig.sign(t, "none", map[string]any{"iss": k8sIss, "aud": k8sAud, "sub": k8sSub, "exp": ie.now.Add(time.Hour).Unix()})
		}, "bad_alg"},
		{"alg HS256", func() string {
			return ie.sig.sign(t, "HS256", map[string]any{"iss": k8sIss, "aud": k8sAud, "sub": k8sSub, "exp": ie.now.Add(time.Hour).Unix()})
		}, "bad_alg"},
		{"unknown kid", func() string {
			s := *ie.sig
			s.kid = "ghost"
			return s.sign(t, "ES256", map[string]any{"iss": k8sIss, "aud": k8sAud, "sub": k8sSub, "exp": ie.now.Add(time.Hour).Unix()})
		}, "unknown_key"},
		{"garbage", func() string { return "not.a.jwt" }, "bad_token"},
		{"two parts", func() string { return "a.b" }, "bad_token"},
		{"huge", func() string { return strings.Repeat("a", 20000) }, "bad_token"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := len(ie.st.events)
			code, out := ie.exchangeJWT("wl-pay", c.tok(), nil)
			wantErr(t, code, out, 400, "invalid_grant")
			if out["error_description"] != "subject token rejected" {
				t.Fatalf("description leaks the reason: %v", out)
			}
			ev := ie.st.events[len(ie.st.events)-1]
			if len(ie.st.events) != before+1 || ev.Type != "WORKLOAD_TOKEN_ERROR" || !strings.HasSuffix(ev.Detail, "reason="+c.reason) {
				t.Fatalf("want reason %s, event %+v", c.reason, ev)
			}
		})
	}
}

func TestWorkloadAcceptsAudienceListContainingOurs(t *testing.T) {
	ie := newIDEnv(t)
	ie.workload("pay", nil)
	code, out := ie.exchangeJWT("wl-pay", ie.k8sToken(map[string]any{"aud": []string{"https://kubernetes.default.svc", k8sAud}}), nil)
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
}

func TestWorkloadClientGate(t *testing.T) {
	ie := newIDEnv(t)
	w := ie.workload("pay", nil)
	tok := ie.k8sToken(nil)
	// A client that has no workload identity.
	ie.st.clients["wl-bare"] = core.Client{ID: "wl-bare", Realm: "r", ClientID: "wl-bare", Enabled: true, Public: true}
	code, out := ie.exchangeJWT("wl-bare", tok, nil)
	wantErr(t, code, out, 400, "unauthorized_client")
	// A different workload pinned to a different subject cannot take this token.
	ie.workload("other", func(x *core.WorkloadIdentity) { x.Subject = "system:serviceaccount:prod:other" })
	code, out = ie.exchangeJWT("wl-other", tok, nil)
	wantErr(t, code, out, 400, "invalid_grant")
	// Turning an interactive flow on for the backing client disables the identity.
	for name, mut := range map[string]func(*core.Client){
		"authcode": func(c *core.Client) { c.AuthCodeFlow = true },
		"device":   func(c *core.Client) { c.DeviceFlow = true },
		"password": func(c *core.Client) { c.PasswordFlow = true },
		"service":  func(c *core.Client) { c.ServiceAccount = true },
	} {
		c := ie.st.clients["wl-pay"]
		orig := c
		mut(&c)
		ie.st.clients["wl-pay"] = c
		code, out = ie.exchangeJWT("wl-pay", tok, nil)
		if code != 400 || out["error"] != "unauthorized_client" {
			t.Fatalf("%s: %d %v", name, code, out)
		}
		ie.st.clients["wl-pay"] = orig
	}
	// A confidential client (static secret) is not a workload client.
	ie.st.clients["wl-pay"] = core.Client{ID: "wl-pay", Realm: "r", ClientID: "wl-pay", Enabled: true, SecretHash: HashSecret("s")}
	f := url.Values{"grant_type": {grantTokenExchange}, "subject_token": {tok}, "subject_token_type": {ttJWT}}
	code, out, _ = ie.tokenReq(f, "wl-pay", "s")
	wantErr(t, code, out, 400, "unauthorized_client")
	ie.st.clients["wl-pay"] = core.Client{ID: "wl-pay", Realm: "r", ClientID: "wl-pay", Enabled: true, Public: true}
	if code, _ = ie.exchangeJWT("wl-pay", tok, nil); code != 200 {
		t.Fatalf("restored client should work, got %d", code)
	}
	// Disabled identity.
	if _, err := ie.ms.SetWorkloadEnabled(context.Background(), "r", w.ID, false); err != nil {
		t.Fatal(err)
	}
	code, out = ie.exchangeJWT("wl-pay", tok, nil)
	wantErr(t, code, out, 400, "invalid_grant")
	// Disabled client.
	ie.st.clients["wl-pay"] = core.Client{ID: "wl-pay", Realm: "r", ClientID: "wl-pay", Enabled: false, Public: true}
	_, _ = ie.ms.SetWorkloadEnabled(context.Background(), "r", w.ID, true)
	code, out = ie.exchangeJWT("wl-pay", tok, nil)
	wantErr(t, code, out, 401, "invalid_client")
}

func TestWorkloadScopeAndParamRules(t *testing.T) {
	ie := newIDEnv(t)
	ie.workload("pay", nil)
	tok := ie.k8sToken(nil)
	for _, sc := range []string{"admin", "read admin", "openid", "read  w\x00"} {
		code, out := ie.exchangeJWT("wl-pay", tok, url.Values{"scope": {sc}})
		wantErr(t, code, out, 400, "invalid_scope")
	}
	code, out := ie.exchangeJWT("wl-pay", tok, url.Values{"actor_token": {"x"}, "actor_token_type": {ttJWT}})
	wantErr(t, code, out, 400, "invalid_request")
	code, out = ie.exchangeJWT("wl-pay", tok, url.Values{"requested_token_type": {"urn:ietf:params:oauth:token-type:refresh_token"}})
	wantErr(t, code, out, 400, "invalid_request")
	code, out = ie.exchangeJWT("wl-pay", tok, url.Values{"audience": {"https://x"}})
	wantErr(t, code, out, 400, "invalid_target")
	code, out = ie.exchangeJWT("wl-pay", tok, url.Values{"subject_token_type": {"urn:ietf:params:oauth:token-type:id_token"}})
	wantErr(t, code, out, 400, "invalid_request")
	code, out = ie.exchangeJWT("wl-pay", tok, url.Values{"subject_token": {tok, tok}})
	wantErr(t, code, out, 400, "invalid_request")
}

func TestWorkloadTTLIsCappedByRealm(t *testing.T) {
	ie := newIDEnv(t)
	ie.workload("pay", func(w *core.WorkloadIdentity) { w.TTLSeconds = 3600 })
	_, out := ie.exchangeJWT("wl-pay", ie.k8sToken(nil), nil)
	if out["expires_in"] != float64(300) { // realm AccessTokenTTL is 5m
		t.Fatalf("expires_in %v", out["expires_in"])
	}
}

func TestIdentityFeatureOffWithoutStores(t *testing.T) {
	ie := newIDEnv(t)
	ie.workload("pay", nil)
	ie.rebuild(ie.st, nil) // plain fake store: no workload/agent support
	code, out := ie.exchangeJWT("wl-pay", ie.k8sToken(nil), nil)
	wantErr(t, code, out, 501, "feature_unavailable")
	code, out = ie.exchangeJWT("wl-pay", "hvag_x", url.Values{"subject_token_type": {ttAgentCredential}})
	wantErr(t, code, out, 501, "feature_unavailable")
	doc := ie.discoveryDoc()
	if strings.Contains(fmt.Sprint(doc["grant_types_supported"]), "token-exchange") {
		t.Fatalf("discovery advertises the grant: %v", doc["grant_types_supported"])
	}
}

func (ie *idEnv) discoveryDoc() map[string]any {
	w := ie.do(httptest.NewRequest("GET", "/realms/r/.well-known/openid-configuration", nil))
	var doc map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &doc)
	return doc
}

func TestIdentityDiscoveryAdvertisesGrants(t *testing.T) {
	ie := newIDEnv(t)
	g := fmt.Sprint(ie.discoveryDoc()["grant_types_supported"])
	if !strings.Contains(g, grantTokenExchange) || !strings.Contains(g, grantJWTBearer) {
		t.Fatalf("grants %s", g)
	}
}

// JWKS fetched by URL goes through the SSRF-safe client: a loopback issuer is
// refused by default and the server is never contacted.
func TestWorkloadJWKSURISSRFSafe(t *testing.T) {
	ie := newIDEnv(t)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(ie.sig.jwks()))
	}))
	defer srv.Close()
	ie.workload("pay", func(w *core.WorkloadIdentity) { w.JWKS, w.JWKSURI = "", srv.URL+"/jwks" })
	tok := ie.k8sToken(nil)

	ie.rebuild(&identFake{fakeStore: ie.st, WorkloadStore: ie.ms, AgentStore: ie.ms}, upstream.NewManager(safehttp.Options{}, func() time.Time { return ie.now }))
	code, out := ie.exchangeJWT("wl-pay", tok, nil)
	wantErr(t, code, out, 400, "invalid_grant")
	if hits.Load() != 0 {
		t.Fatalf("the loopback JWKS server was contacted %d times", hits.Load())
	}
	if ev, _ := ie.lastEvent("WORKLOAD_TOKEN_ERROR"); !strings.HasSuffix(ev.Detail, "reason=bad_url") {
		t.Fatalf("event %+v", ev)
	}
	// Dev manager (private allowed): the same setup works, proving the refusal above is the policy.
	ie.rebuild(&identFake{fakeStore: ie.st, WorkloadStore: ie.ms, AgentStore: ie.ms}, upstream.NewManager(safehttp.Options{AllowPrivate: true}, func() time.Time { return ie.now }))
	if code, out = ie.exchangeJWT("wl-pay", tok, nil); code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if hits.Load() == 0 {
		t.Fatal("expected one JWKS fetch")
	}
}

func TestIdentityRateLimitFailsClosed(t *testing.T) {
	ie := newIDEnv(t)
	ie.workload("pay", nil)
	bad := ie.k8sToken(map[string]any{"sub": "x"})
	var last int
	for i := 0; i < identLimitMax+1; i++ {
		last, _ = ie.exchangeJWT("wl-pay", bad, nil)
	}
	if last != 429 {
		t.Fatalf("attempt %d got %d, want 429", identLimitMax+1, last)
	}
	// Even a valid token is refused while limited.
	if code, _ := ie.exchangeJWT("wl-pay", ie.k8sToken(nil), nil); code != 429 {
		t.Fatalf("limited client got %d", code)
	}
	// A limiter that errors denies (server_error), never allows.
	ie2 := newIDEnv(t)
	ie2.workload("pay", nil)
	ie2.rebuild(&failingLimiter{&identFake{fakeStore: ie2.st, WorkloadStore: ie2.ms, AgentStore: ie2.ms}}, nil)
	code, out := ie2.exchangeJWT("wl-pay", ie2.k8sToken(nil), nil)
	wantErr(t, code, out, 500, "server_error")
}

type failingLimiter struct{ *identFake }

func (failingLimiter) HitRateLimit(context.Context, string, time.Time, time.Duration, int) (bool, error) {
	return false, fmt.Errorf("db down")
}

// ---- agent identities ----

const agentSecret = "hvag_0123456789abcdef0123456789abcdef0123456789a"

func (ie *idEnv) agent(name string, mut func(*core.Agent)) core.Agent {
	ie.t.Helper()
	cid := "agent-" + name
	ie.st.clients[cid] = core.Client{ID: cid, Realm: "r", ClientID: cid, Name: name, Enabled: true, Public: true}
	a := core.Agent{Realm: "r", Name: name, Kind: "agent", ClientID: cid, OwnerUserID: "u1",
		AllowedScopes: []string{"mcp:read", "mcp:write"}, TokenTTL: 300, Enabled: true, CreatedAt: ie.now}
	if mut != nil {
		mut(&a)
	}
	out, err := ie.ms.CreateAgent(context.Background(), a)
	if err != nil {
		ie.t.Fatal(err)
	}
	return out
}

func (ie *idEnv) cred(a core.Agent, secret string, ttl time.Duration, scopes ...string) core.AgentCredential {
	ie.t.Helper()
	if len(scopes) == 0 {
		scopes = a.AllowedScopes
	}
	c, err := ie.ms.CreateAgentCredential(context.Background(), core.AgentCredential{Realm: "r", AgentID: a.ID,
		SecretHash: HashSecret(secret), Scopes: scopes, CreatedAt: ie.now, ExpiresAt: ie.now.Add(ttl)}, 5, ie.now)
	if err != nil {
		ie.t.Fatal(err)
	}
	return c
}

func (ie *idEnv) exchangeAgent(client, secret string, extra url.Values) (int, map[string]any) {
	ie.t.Helper()
	f := url.Values{"grant_type": {grantTokenExchange}, "client_id": {client}, "subject_token": {secret}, "subject_token_type": {ttAgentCredential}}
	for k, v := range extra {
		f[k] = v
	}
	code, out, _ := ie.tokenReq(f, "", "")
	return code, out
}

func TestAgentExchangeIssuesDelegatedToken(t *testing.T) {
	ie := newIDEnv(t)
	a := ie.agent("bot", func(a *core.Agent) {
		a.AllowedRoles = []string{"admin", "dba"} // owner u1 holds only admin
		a.Audiences = []string{"https://mcp.example"}
	})
	cred := ie.cred(a, agentSecret, time.Hour)
	code, out := ie.exchangeAgent("agent-bot", agentSecret, url.Values{"scope": {"mcp:read"}, "audience": {"https://mcp.example"}})
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	if out["issued_token_type"] != ttAccess || out["scope"] != "mcp:read" || out["expires_in"] != float64(300) {
		t.Fatalf("response %v", out)
	}
	if _, has := out["refresh_token"]; has {
		t.Fatal("agents get no refresh token")
	}
	c := claimsOf(t, out["access_token"].(string))
	act, _ := c["act"].(map[string]any)
	if c["sub"] != "u1" || c["aud"] != "https://mcp.example" || c["azp"] != "agent-bot" || act["sub"] != "agent:agent-bot" ||
		act["iss"] != "https://idp.example/realms/r" || fmt.Sprint(c["realm_access"]) != "map[roles:[admin]]" {
		t.Fatalf("claims %v", c)
	}
	ev, ok := ie.lastEvent("AGENT_TOKEN")
	if !ok || ev.UserID != "u1" || ev.ClientID != "agent-bot" || !strings.Contains(ev.Detail, "credential="+cred.ID) {
		t.Fatalf("event %+v", ev)
	}
	for _, e := range ie.st.events {
		if strings.Contains(e.Detail, agentSecret) || strings.Contains(e.Detail, HashSecret(agentSecret)) {
			t.Fatalf("secret in audit event: %+v", e)
		}
	}
	got, _ := ie.ms.GetAgentCredentialBySecret(context.Background(), "r", a.ID, HashSecret(agentSecret))
	if !got.LastUsedAt.Equal(ie.now) {
		t.Fatalf("last used %v", got.LastUsedAt)
	}
	// Default audience is the agent's own client, default roles none.
	b := ie.agent("plain", nil)
	ie.cred(b, agentSecret+"2", time.Hour)
	_, out = ie.exchangeAgent("agent-plain", agentSecret+"2", nil)
	c = claimsOf(t, out["access_token"].(string))
	if c["aud"] != "agent-plain" || fmt.Sprint(c["realm_access"]) != "map[roles:[]]" || out["scope"] != "mcp:read mcp:write" {
		t.Fatalf("defaults %v %v", c, out)
	}
}

func TestAgentRejectsBadCredentials(t *testing.T) {
	ie := newIDEnv(t)
	a := ie.agent("bot", nil)
	good := ie.cred(a, agentSecret, time.Hour)
	b := ie.agent("other", nil)
	ie.cred(b, agentSecret+"B", time.Hour)
	ie.cred(a, agentSecret+"X", time.Minute) // will be expired
	rv := ie.cred(a, agentSecret+"R", time.Hour)
	if _, err := ie.ms.RevokeAgentCredential(context.Background(), "r", a.ID, rv.ID, "admin", ie.now); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ name, client, secret, reason string }{
		{"unknown", "agent-bot", agentSecret + "nope", "unknown_credential"},
		{"revoked", "agent-bot", agentSecret + "R", "revoked"},
		{"other agent's credential", "agent-bot", agentSecret + "B", "unknown_credential"},
		{"no prefix", "agent-bot", "plain-secret", "malformed"},
		{"oversize", "agent-bot", "hvag_" + strings.Repeat("a", 200), "malformed"},
	} {
		code, out := ie.exchangeAgent(c.client, c.secret, nil)
		wantErr(t, code, out, 400, "invalid_grant")
		if ev, _ := ie.lastEvent("AGENT_TOKEN_ERROR"); !strings.HasSuffix(ev.Detail, "reason="+c.reason) {
			t.Fatalf("%s: event %+v", c.name, ev)
		}
	}
	ie.now = ie.now.Add(2 * time.Minute) // the short credential expires
	code, out := ie.exchangeAgent("agent-bot", agentSecret+"X", nil)
	wantErr(t, code, out, 400, "invalid_grant")
	if ev, _ := ie.lastEvent("AGENT_TOKEN_ERROR"); !strings.HasSuffix(ev.Detail, "reason=expired") {
		t.Fatalf("event %+v", ev)
	}
	// Revoking the good credential takes effect on the next exchange.
	if code, _ := ie.exchangeAgent("agent-bot", agentSecret, nil); code != 200 {
		t.Fatalf("good credential: %d", code)
	}
	if _, err := ie.ms.RevokeAgentCredential(context.Background(), "r", a.ID, good.ID, "admin", ie.now); err != nil {
		t.Fatal(err)
	}
	code, out = ie.exchangeAgent("agent-bot", agentSecret, nil)
	wantErr(t, code, out, 400, "invalid_grant")
	// Not an agent client at all.
	code, out = ie.exchangeAgent("app", agentSecret, nil)
	wantErr(t, code, out, 400, "unauthorized_client")
}

func TestAgentDisabledOrOrphanedOwner(t *testing.T) {
	ie := newIDEnv(t)
	a := ie.agent("bot", nil)
	ie.cred(a, agentSecret, time.Hour)
	if code, _ := ie.exchangeAgent("agent-bot", agentSecret, nil); code != 200 {
		t.Fatalf("baseline %d", code)
	}
	if _, err := ie.ms.SetAgentEnabled(context.Background(), "r", a.ID, false); err != nil {
		t.Fatal(err)
	}
	code, out := ie.exchangeAgent("agent-bot", agentSecret, nil)
	wantErr(t, code, out, 400, "invalid_grant")
	if _, err := ie.ms.SetAgentEnabled(context.Background(), "r", a.ID, true); err != nil {
		t.Fatal(err)
	}
	u := ie.st.users["u1"]
	u.Enabled = false
	ie.st.users["u1"] = u
	code, out = ie.exchangeAgent("agent-bot", agentSecret, nil)
	wantErr(t, code, out, 400, "invalid_grant")
	if ev, _ := ie.lastEvent("AGENT_TOKEN_ERROR"); !strings.HasSuffix(ev.Detail, "reason=owner_disabled") {
		t.Fatalf("event %+v", ev)
	}
	delete(ie.st.users, "u1")
	code, out = ie.exchangeAgent("agent-bot", agentSecret, nil)
	wantErr(t, code, out, 400, "invalid_grant")
	if ev, _ := ie.lastEvent("AGENT_TOKEN_ERROR"); !strings.HasSuffix(ev.Detail, "reason=owner_missing") {
		t.Fatalf("event %+v", ev)
	}
}

func TestAgentScopeAudienceAndTTLRules(t *testing.T) {
	ie := newIDEnv(t)
	a := ie.agent("bot", func(a *core.Agent) { a.Audiences = []string{"https://mcp.example", "https://other.example"} })
	ie.cred(a, agentSecret, 2*time.Minute, "mcp:read") // narrower than the agent
	for _, sc := range []string{"mcp:write", "mcp:read mcp:write", "openid", "offline_access", "mcp:read\x00"} {
		code, out := ie.exchangeAgent("agent-bot", agentSecret, url.Values{"scope": {sc}})
		wantErr(t, code, out, 400, "invalid_scope")
	}
	for name, v := range map[string]url.Values{
		"not allowed":    {"audience": {"https://evil.example"}},
		"prefix":         {"audience": {"https://mcp.example/x"}},
		"two":            {"audience": {"https://mcp.example", "https://other.example"}},
		"audience+res":   {"audience": {"https://mcp.example"}, "resource": {"https://other.example"}},
		"empty explicit": {"audience": {""}},
	} {
		code, out := ie.exchangeAgent("agent-bot", agentSecret, v)
		if code != 400 || out["error"] != "invalid_target" {
			t.Fatalf("%s: %d %v", name, code, out)
		}
	}
	// resource (RFC 8707) works like audience.
	_, out := ie.exchangeAgent("agent-bot", agentSecret, url.Values{"resource": {"https://other.example"}})
	if claimsOf(t, out["access_token"].(string))["aud"] != "https://other.example" {
		t.Fatalf("resource: %v", out)
	}
	// Never outlives the credential: 2 minutes left < 5 minute agent TTL.
	if out["expires_in"] != float64(120) {
		t.Fatalf("expires_in %v", out["expires_in"])
	}
	// The agent's scope list shrinking after issue narrows the credential.
	a2 := ie.agent("shrunk", func(a *core.Agent) { a.AllowedScopes = []string{"mcp:read"} })
	ie.cred(a2, agentSecret+"S", time.Hour, "mcp:read")
	// (simulate: credential holds a scope the agent no longer allows)
	if _, err := ie.ms.CreateAgentCredential(context.Background(), core.AgentCredential{Realm: "r", AgentID: a2.ID,
		SecretHash: HashSecret(agentSecret + "T"), Scopes: []string{"mcp:read", "mcp:admin"}, ExpiresAt: ie.now.Add(time.Hour)}, 5, ie.now); err != nil {
		t.Fatal(err)
	}
	code, out := ie.exchangeAgent("agent-shrunk", agentSecret+"T", url.Values{"scope": {"mcp:admin"}})
	wantErr(t, code, out, 400, "invalid_scope")
	_, out = ie.exchangeAgent("agent-shrunk", agentSecret+"T", nil)
	if out["scope"] != "mcp:read" {
		t.Fatalf("scope %v", out["scope"])
	}
}

func TestAgentRolesNeverExceedOwner(t *testing.T) {
	ie := newIDEnv(t)
	// The agent is allowed "root", the owner is not: the claim must be empty.
	a := ie.agent("bot", func(a *core.Agent) { a.AllowedRoles = []string{"root"} })
	ie.cred(a, agentSecret, time.Hour)
	_, out := ie.exchangeAgent("agent-bot", agentSecret, nil)
	if got := fmt.Sprint(claimsOf(t, out["access_token"].(string))["realm_access"]); got != "map[roles:[]]" {
		t.Fatalf("roles %s", got)
	}
}

func TestAgentCredentialNotAcceptedAsWorkloadJWT(t *testing.T) {
	ie := newIDEnv(t)
	ie.workload("pay", nil)
	a := ie.agent("bot", nil)
	ie.cred(a, agentSecret, time.Hour)
	// agent credential presented as a JWT, and a JWT presented as a credential
	code, out := ie.exchangeJWT("agent-bot", agentSecret, nil)
	wantErr(t, code, out, 400, "unauthorized_client")
	code, out = ie.exchangeAgent("wl-pay", ie.k8sToken(nil), nil)
	wantErr(t, code, out, 400, "unauthorized_client")
}
