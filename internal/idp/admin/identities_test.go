// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

type idHarness struct {
	*env
	r   string
	key *ecdsa.PrivateKey
	uid string
}

func newIDHarness(t *testing.T) *idHarness {
	t.Helper()
	e := newEnv(t)
	ctx := context.Background()
	rl, err := e.st.GetRealm(ctx, realm)
	if err != nil {
		t.Fatal(err)
	}
	rl.AuthEventsLogged, rl.AdminEventsLogged = true, true
	if err := e.st.UpdateRealm(ctx, rl); err != nil {
		t.Fatal(err)
	}
	e.token = e.clientToken(realm, "haven-admin", adminSecret)
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := &idHarness{env: e, r: "/realms/" + realm, key: k}
	e.createID(h.r+"/roles", map[string]any{"name": "ops"})
	h.uid = e.createID(h.r+"/users", map[string]any{"username": "alice", "enabled": true})
	u, err := e.st.GetUser(ctx, realm, h.uid)
	if err != nil {
		t.Fatal(err)
	}
	u.Roles = []string{"ops"}
	if err := e.st.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	return h
}

func (h *idHarness) jwks() string {
	b := func(n *big.Int) string { return base64.RawURLEncoding.EncodeToString(n.FillBytes(make([]byte, 32))) }
	return fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","kid":"k1","use":"sig","alg":"ES256","x":%q,"y":%q}]}`, b(h.key.X), b(h.key.Y))
}

func (h *idHarness) jwt(iss, aud, sub string) string {
	hdr, _ := json.Marshal(map[string]any{"alg": "ES256", "kid": "k1", "typ": "JWT"})
	now := time.Now()
	pl, _ := json.Marshal(map[string]any{"iss": iss, "aud": aud, "sub": sub, "iat": now.Unix(), "exp": now.Add(time.Hour).Unix()})
	in := base64.RawURLEncoding.EncodeToString(hdr) + "." + base64.RawURLEncoding.EncodeToString(pl)
	d := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, h.key, d[:])
	if err != nil {
		h.t.Fatal(err)
	}
	return in + "." + base64.RawURLEncoding.EncodeToString(append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...))
}

func (h *idHarness) exchange(form url.Values) (int, map[string]any) {
	h.t.Helper()
	req, _ := http.NewRequest("POST", h.srv.URL+"/realms/"+realm+"/protocol/openid-connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func (h *idHarness) wlExchange(client, tok string) (int, map[string]any) {
	return h.exchange(url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_id": {client},
		"subject_token": {tok}, "subject_token_type": {"urn:ietf:params:oauth:token-type:jwt"}})
}

func (h *idHarness) agExchange(client, secret string, extra url.Values) (int, map[string]any) {
	f := url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_id": {client},
		"subject_token": {secret}, "subject_token_type": {"urn:haven:params:oauth:token-type:agent-credential"}}
	for k, v := range extra {
		f[k] = v
	}
	return h.exchange(f)
}

func (h *idHarness) clientExists(clientID string) (core.Client, bool) {
	c, err := h.st.GetClientByClientID(context.Background(), realm, clientID)
	return c, err == nil
}

func (h *idHarness) eventsOf(typ string) []core.Event {
	evs, _ := h.st.ListEvents(context.Background(), realm, 1000)
	var out []core.Event
	for _, e := range evs {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func TestWorkloadIdentityAdminEndToEnd(t *testing.T) {
	h := newIDHarness(t)
	body := map[string]any{"name": "payments", "issuer": "https://oidc.cluster.example", "jwks": h.jwks(),
		"audience": "haven", "subject": "system:serviceaccount:prod:payments", "scopes": []string{"read"}, "ttlSeconds": 120}
	var w struct {
		ID, ClientID string
		Enabled      bool
	}
	if err := json.Unmarshal(h.api(201, "POST", h.r+"/workload-identities", body), &w); err != nil || w.ClientID != "wl-payments" || !w.Enabled {
		t.Fatalf("create: %+v %v", w, err)
	}
	// The backing client is inert: public, no flows, no redirect URIs.
	c, ok := h.clientExists("wl-payments")
	if !ok || !c.Public || c.AuthCodeFlow || c.PasswordFlow || c.ServiceAccount || c.DeviceFlow || len(c.RedirectURIs) != 0 || c.SecretHash != "" {
		t.Fatalf("backing client %+v", c)
	}
	tok := h.jwt("https://oidc.cluster.example", "haven", "system:serviceaccount:prod:payments")
	code, out := h.wlExchange("wl-payments", tok)
	if code != 200 || out["scope"] != "read" || out["expires_in"] != float64(120) {
		t.Fatalf("exchange %d %v", code, out)
	}
	if evs := h.eventsOf("WORKLOAD_TOKEN"); len(evs) != 1 {
		t.Fatalf("token events %d", len(evs))
	}
	if evs := h.eventsOf("WORKLOAD_IDENTITY_CREATE"); len(evs) != 1 {
		t.Fatalf("create events %d", len(evs))
	}
	// Other subject: rejected.
	if code, _ := h.wlExchange("wl-payments", h.jwt("https://oidc.cluster.example", "haven", "system:serviceaccount:prod:other")); code != 400 {
		t.Fatalf("wrong subject got %d", code)
	}
	// list / get never expose the inline JWKS body
	if b := string(h.api(200, "GET", h.r+"/workload-identities", nil)); strings.Contains(b, `"kty"`) || !strings.Contains(b, `"inlineJwks":true`) {
		t.Fatalf("list: %s", b)
	}
	h.api(200, "POST", h.r+"/workload-identities/"+w.ID+"/disable", nil)
	if code, _ := h.wlExchange("wl-payments", tok); code != 400 {
		t.Fatalf("disabled identity got %d", code)
	}
	h.api(200, "POST", h.r+"/workload-identities/"+w.ID+"/enable", nil)
	if code, _ := h.wlExchange("wl-payments", tok); code != 200 {
		t.Fatalf("re-enabled got %d", code)
	}
	h.api(204, "DELETE", h.r+"/workload-identities/"+w.ID, nil)
	if _, ok := h.clientExists("wl-payments"); ok {
		t.Fatal("backing client survived delete")
	}
	if code, _ := h.wlExchange("wl-payments", tok); code != 401 {
		t.Fatalf("deleted identity got %d", code)
	}
	h.api(404, "GET", h.r+"/workload-identities/"+w.ID, nil)
}

func TestWorkloadIdentityValidation(t *testing.T) {
	h := newIDHarness(t)
	ok := func() map[string]any {
		return map[string]any{"name": "svc", "issuer": "https://oidc.cluster.example", "jwks": h.jwks(), "audience": "haven",
			"subject": "system:serviceaccount:prod:svc", "scopes": []string{"read"}}
	}
	with := func(k string, v any) map[string]any { m := ok(); m[k] = v; return m }
	without := func(k string) map[string]any { m := ok(); delete(m, k); return m }
	for name, body := range map[string]map[string]any{
		"wildcard subject":      with("subject", "system:serviceaccount:prod:*"),
		"question subject":      with("subject", "system:serviceaccount:prod:?"),
		"no subject":            without("subject"),
		"padded subject":        with("subject", " x"),
		"no audience":           without("audience"),
		"wildcard audience":     with("audience", "*"),
		"no issuer":             without("issuer"),
		"http issuer":           with("issuer", "http://oidc.cluster.example"),
		"loopback issuer":       with("issuer", "http://127.0.0.1:8080"),
		"no keys":               without("jwks"),
		"both keys":             with("jwksUri", "https://oidc.cluster.example/jwks"),
		"loopback jwksUri":      func() map[string]any { m := without("jwks"); m["jwksUri"] = "http://127.0.0.1/jwks"; return m }(),
		"userinfo jwksUri":      func() map[string]any { m := without("jwks"); m["jwksUri"] = "https://u:p@x.example/jwks"; return m }(),
		"garbage jwks":          with("jwks", "not json"),
		"empty jwks":            with("jwks", `{"keys":[]}`),
		"no scopes":             without("scopes"),
		"openid scope":          with("scopes", []string{"openid"}),
		"offline scope":         with("scopes", []string{"offline_access"}),
		"spaced scope":          with("scopes", []string{"a b"}),
		"ttl too long":          with("ttlSeconds", 7200),
		"ttl too short":         with("ttlSeconds", 5),
		"bad name":              with("name", "Bad Name"),
		"bad client id":         with("clientId", "a b"),
		"unknown field":         with("secret", "x"),
		"existing admin client": with("clientId", "haven-admin"),
	} {
		code, b, _ := h.call("POST", h.r+"/workload-identities", h.token, body)
		if code != 400 && code != 409 {
			t.Errorf("%s: got %d %s", name, code, b)
		}
	}
	// None of the failures created anything, and the admin client is untouched.
	var list []map[string]any
	_ = json.Unmarshal(h.api(200, "GET", h.r+"/workload-identities", nil), &list)
	if len(list) != 0 {
		t.Fatalf("created despite errors: %v", list)
	}
	if c, found := h.clientExists("haven-admin"); !found || c.Public || c.SecretHash == "" {
		t.Fatalf("existing client was modified: %+v", c)
	}
	h.api(201, "POST", h.r+"/workload-identities", ok())
	code, _, _ := h.call("POST", h.r+"/workload-identities", h.token, ok())
	if code != 409 {
		t.Fatalf("duplicate name got %d", code)
	}
	// The failed duplicate must not leave a stray client behind either.
	cs, _ := h.st.ListClients(context.Background(), realm)
	n := 0
	for _, c := range cs {
		if strings.HasPrefix(c.ClientID, "wl-") {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("stray backing clients: %d", n)
	}
}

func TestIdentityAdminRequiresAuth(t *testing.T) {
	h := newIDHarness(t)
	for _, p := range []string{"/workload-identities", "/agents"} {
		for _, tok := range []string{"", "garbage"} {
			if code, _, _ := h.call("GET", h.r+p, tok, nil); code != 401 && code != 403 {
				t.Errorf("GET %s with token %q: %d", p, tok, code)
			}
			if code, _, _ := h.call("POST", h.r+p, tok, map[string]any{}); code != 401 && code != 403 {
				t.Errorf("POST %s with token %q: %d", p, tok, code)
			}
		}
	}
}

func TestAgentAdminEndToEnd(t *testing.T) {
	h := newIDHarness(t)
	mk := func(m map[string]any) map[string]any {
		b := map[string]any{"name": "bot", "ownerUserId": h.uid, "scopes": []string{"mcp:read", "mcp:write"},
			"roles": []string{"ops"}, "audiences": []string{"https://mcp.example"}}
		for k, v := range m {
			b[k] = v
		}
		return b
	}
	// Validation: owner, roles, scopes, ttl.
	for name, body := range map[string]map[string]any{
		"unknown owner":  mk(map[string]any{"ownerUserId": "nope"}),
		"role not owned": mk(map[string]any{"roles": []string{"root"}}),
		"no scopes":      mk(map[string]any{"scopes": []string{}}),
		"openid":         mk(map[string]any{"scopes": []string{"openid"}}),
		"wildcard aud":   mk(map[string]any{"audiences": []string{"*"}}),
		"ttl too long":   mk(map[string]any{"tokenTtlSeconds": 3600}),
		"bad name":       mk(map[string]any{"name": "Bad Name"}),
		"unknown field":  mk(map[string]any{"clientId": "x"}),
	} {
		if code, b, _ := h.call("POST", h.r+"/agents", h.token, body); code != 400 {
			t.Errorf("%s: got %d %s", name, code, b)
		}
	}
	var a struct {
		ID, Name, Kind, ClientID string
		Enabled                  bool
		TokenTTL                 int `json:"tokenTtlSeconds"`
	}
	if err := json.Unmarshal(h.api(201, "POST", h.r+"/agents", mk(nil)), &a); err != nil || a.Kind != "agent" || !a.Enabled ||
		!strings.HasPrefix(a.ClientID, "agent-") || a.TokenTTL != 300 {
		t.Fatalf("create: %+v %v", a, err)
	}
	if code, _, _ := h.call("POST", h.r+"/agents", h.token, mk(nil)); code != 409 {
		t.Fatalf("duplicate name got %d", code)
	}
	c, found := h.clientExists(a.ClientID)
	if !found || !c.Public || c.AuthCodeFlow || c.DeviceFlow || c.PasswordFlow || c.ServiceAccount || len(c.RedirectURIs) != 0 {
		t.Fatalf("backing client %+v", c)
	}
	var mine []struct{ ID string }
	_ = json.Unmarshal(h.api(200, "GET", h.r+"/agents?owner="+h.uid, nil), &mine)
	var none []struct{ ID string }
	_ = json.Unmarshal(h.api(200, "GET", h.r+"/agents?owner=someone-else", nil), &none)
	if len(mine) != 1 || len(none) != 0 {
		t.Fatalf("owner filter: %d / %d", len(mine), len(none))
	}

	// Credentials: validation, one-time secret, list without secret.
	cp := h.r + "/agents/" + a.ID + "/credentials"
	for name, body := range map[string]map[string]any{
		"ttl too long":  {"ttlSeconds": 30 * 24 * 3600},
		"ttl too short": {"ttlSeconds": 5},
		"foreign scope": {"scopes": []string{"mcp:admin"}},
		"unknown field": {"secret": "x"},
	} {
		if code, b, _ := h.call("POST", cp, h.token, body); code != 400 {
			t.Errorf("credential %s: got %d %s", name, code, b)
		}
	}
	var issued struct {
		Credential struct {
			ID, State string
			ExpiresAt time.Time
			Scopes    []string
		}
		Secret string
	}
	if err := json.Unmarshal(h.api(201, "POST", cp, map[string]any{"ttlSeconds": 600, "scopes": []string{"mcp:read"}, "note": "ci"}), &issued); err != nil ||
		!strings.HasPrefix(issued.Secret, "hvag_") || issued.Credential.State != "active" || len(issued.Credential.Scopes) != 1 {
		t.Fatalf("issue: %+v %v", issued, err)
	}
	if b := string(h.api(200, "GET", cp, nil)); strings.Contains(b, issued.Secret) || strings.Contains(b, "secret") || !strings.Contains(b, issued.Credential.ID) {
		t.Fatalf("list leaks or misses: %s", b)
	}
	if d := time.Until(issued.Credential.ExpiresAt); d < 9*time.Minute || d > 11*time.Minute {
		t.Fatalf("expiry %v", d)
	}

	// Real token endpoint.
	code, out := h.agExchange(a.ClientID, issued.Secret, url.Values{"audience": {"https://mcp.example"}})
	if code != 200 || out["scope"] != "mcp:read" {
		t.Fatalf("exchange %d %v", code, out)
	}
	parts := strings.Split(out["access_token"].(string), ".")
	pb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims map[string]any
	_ = json.Unmarshal(pb, &claims)
	act, _ := claims["act"].(map[string]any)
	if claims["sub"] != h.uid || act["sub"] != "agent:"+a.ClientID || claims["aud"] != "https://mcp.example" ||
		fmt.Sprint(claims["realm_access"]) != "map[roles:[ops]]" {
		t.Fatalf("claims %v", claims)
	}
	if code, _ := h.agExchange(a.ClientID, issued.Secret, url.Values{"scope": {"mcp:write"}}); code != 400 {
		t.Fatalf("scope beyond credential got %d", code)
	}

	// Audit: issue and token events exist and never contain the secret.
	if len(h.eventsOf("AGENT_CREDENTIAL_ISSUED")) != 1 || len(h.eventsOf("AGENT_TOKEN")) != 1 || len(h.eventsOf("AGENT_CREATE")) != 1 {
		t.Fatalf("events: issued %d token %d create %d", len(h.eventsOf("AGENT_CREDENTIAL_ISSUED")), len(h.eventsOf("AGENT_TOKEN")), len(h.eventsOf("AGENT_CREATE")))
	}
	all, _ := h.st.ListEvents(context.Background(), realm, 1000)
	for _, e := range all {
		if strings.Contains(e.Detail, issued.Secret) || strings.Contains(e.Detail, strings.TrimPrefix(issued.Secret, "hvag_")) {
			t.Fatalf("secret in event %+v", e)
		}
	}

	// Revoke one credential: the next exchange fails, a second revoke is 409.
	h.api(204, "DELETE", cp+"/"+issued.Credential.ID, nil)
	if code, _ := h.agExchange(a.ClientID, issued.Secret, nil); code != 400 {
		t.Fatalf("revoked credential got %d", code)
	}
	if code, _, _ := h.call("DELETE", cp+"/"+issued.Credential.ID, h.token, nil); code != 409 {
		t.Fatalf("double revoke got %d", code)
	}
	h.api(404, "DELETE", cp+"/nope", nil)
	if len(h.eventsOf("AGENT_CREDENTIAL_REVOKED")) != 1 {
		t.Fatal("no revoke event")
	}

	// Active credential limit, revoke-all.
	secrets := []string{}
	for i := 0; i < core.MaxActiveCredentialsPerAgent; i++ {
		var r struct{ Secret string }
		_ = json.Unmarshal(h.api(201, "POST", cp, map[string]any{}), &r)
		secrets = append(secrets, r.Secret)
	}
	if code, _, _ := h.call("POST", cp, h.token, map[string]any{}); code != 409 {
		t.Fatalf("limit got %d", code)
	}
	var ra map[string]int
	_ = json.Unmarshal(h.api(200, "POST", h.r+"/agents/"+a.ID+"/revoke-credentials", nil), &ra)
	if ra["revoked"] != core.MaxActiveCredentialsPerAgent {
		t.Fatalf("revoke-all %v", ra)
	}
	for _, s := range secrets {
		if code, _ := h.agExchange(a.ClientID, s, nil); code != 400 {
			t.Fatalf("credential survived revoke-all: %d", code)
		}
	}

	// Disabling the agent stops issuing and exchanging; deleting removes the client.
	var fresh struct{ Secret string }
	_ = json.Unmarshal(h.api(201, "POST", cp, map[string]any{}), &fresh)
	h.api(200, "POST", h.r+"/agents/"+a.ID+"/disable", nil)
	if code, _ := h.agExchange(a.ClientID, fresh.Secret, nil); code != 400 {
		t.Fatalf("disabled agent got %d", code)
	}
	if code, _, _ := h.call("POST", cp, h.token, map[string]any{}); code != 409 {
		t.Fatalf("issuing for a disabled agent got %d", code)
	}
	h.api(200, "POST", h.r+"/agents/"+a.ID+"/enable", nil)
	if code, _ := h.agExchange(a.ClientID, fresh.Secret, nil); code != 200 {
		t.Fatalf("re-enabled agent got %d", code)
	}
	h.api(204, "DELETE", h.r+"/agents/"+a.ID, nil)
	if _, found := h.clientExists(a.ClientID); found {
		t.Fatal("backing client survived delete")
	}
	if code, _ := h.agExchange(a.ClientID, fresh.Secret, nil); code != 401 {
		t.Fatalf("deleted agent got %d", code)
	}
	h.api(404, "GET", h.r+"/agents/"+a.ID, nil)
}
