// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package kubeauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/oidc"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

type live struct {
	issuer string
	ca     []byte
	signer core.Signer
}

// liveIDP is the real provider (discovery, JWKS, ES256 keys) behind TLS.
func liveIDP(t *testing.T, optedIn string, mutate func(h http.Handler) http.Handler) *live {
	t.Helper()
	st := memstore.New()
	if err := st.CreateRealm(context.Background(), core.Realm{Name: "r", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	sg := keys.New(st, keys.Options{})
	if err := sg.EnsureKey(context.Background(), "r"); err != nil {
		t.Fatal(err)
	}
	pol, err := oidc.ParseGroupsClaimClients(optedIn)
	if err != nil {
		t.Fatal(err)
	}
	var h http.Handler
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // failed handshakes are the point of some cases
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h = oidc.New(oidc.Config{Store: st, Signer: sg, Hasher: password.New(password.TestParams), BaseURL: srv.URL, GroupsClaim: pol})
	if mutate != nil {
		h = mutate(h)
	}
	return &live{issuer: srv.URL + "/realms/r", signer: sg,
		ca: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})}
}

func (l *live) token(t *testing.T, mut func(core.Claims)) string {
	t.Helper()
	now := time.Now()
	c := core.Claims{"iss": l.issuer, "sub": "u1", "aud": "kubernetes", "azp": "kubernetes", "typ": "ID",
		"exp": now.Add(time.Hour).Unix(), "iat": now.Unix(), "preferred_username": "alice", "groups": []string{"devs", "eng/ops"}}
	if mut != nil {
		mut(c)
	}
	tok, err := l.signer.Sign(context.Background(), "r", c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func check(t *testing.T, l *live, in CheckInput) Report {
	t.Helper()
	if in.Issuer == "" {
		in.Issuer = l.issuer
	}
	if in.CAPEM == nil && l != nil {
		in.CAPEM = l.ca
	}
	rep, err := Check(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if in.Token != "" {
		b, _ := json.Marshal(rep)
		for _, part := range strings.Split(in.Token, ".") {
			if len(part) > 16 && strings.Contains(string(b), part) {
				t.Fatalf("the report contains part of the token: %s", b)
			}
		}
	}
	return rep
}

func failed(rep Report) map[string]string {
	m := map[string]string{}
	for _, r := range rep.Results {
		if r.State == StateFail {
			m[r.Check] += r.Message + " | " + r.Fix
		}
	}
	return m
}

func TestCheckGoodToken(t *testing.T) {
	l := liveIDP(t, "r/kubernetes", nil)
	rep := check(t, l, CheckInput{Token: l.token(t, nil), RequireGroups: []string{"devs", "haven:eng/ops", "/devs"}})
	if !rep.OK {
		t.Fatalf("%+v", rep.Results)
	}
	if rep.Identity == nil || rep.Identity.Username != "haven:alice" || strings.Join(rep.Identity.Groups, ",") != "haven:devs,haven:eng/ops" {
		t.Fatalf("identity %+v", rep.Identity)
	}
	for _, r := range rep.Results {
		if r.Check == "groups-scope" && r.State != StateOK {
			t.Errorf("groups scope: %+v", r)
		}
	}
	// Without a token: endpoints only, and an explicit skip.
	rep = check(t, l, CheckInput{})
	if !rep.OK || rep.Results[len(rep.Results)-1].State != StateSkip || rep.Identity != nil {
		t.Fatalf("%+v", rep)
	}
	// An issuer without any opted-in client is pointed out, not failed.
	l2 := liveIDP(t, "", nil)
	rep = check(t, l2, CheckInput{})
	found := false
	for _, r := range rep.Results {
		found = found || r.Check == "groups-scope" && r.State == StateWarn && strings.Contains(r.Fix, "HAVEN_IDP_GROUPS_CLAIM_CLIENTS=r/kubernetes")
	}
	if !found || !rep.OK {
		t.Fatalf("%+v", rep)
	}
}

func TestCheckTokenFailures(t *testing.T) {
	l := liveIDP(t, "r/kubernetes", nil)
	other := liveIDP(t, "r/kubernetes", nil) // different signing keys
	good := l.token(t, nil)
	for name, c := range map[string]struct {
		token   string
		require []string
		check   string // the check that must fail
		text    string
	}{
		"wrong audience":      {token: l.token(t, func(c core.Claims) { c["aud"] = "webapp" }), check: "token-audience", text: "another client"},
		"audience prefix":     {token: l.token(t, func(c core.Claims) { c["aud"] = []string{"kubernetes-x"} }), check: "token-audience"},
		"access token":        {token: l.token(t, func(c core.Claims) { c["typ"] = "Bearer" }), check: "token-type", text: "not an ID token"},
		"no typ":              {token: l.token(t, func(c core.Claims) { delete(c, "typ") }), check: "token-type"},
		"expired":             {token: l.token(t, func(c core.Claims) { c["exp"] = time.Now().Add(-time.Second).Unix() }), check: "token-time", text: "expired"},
		"no exp":              {token: l.token(t, func(c core.Claims) { delete(c, "exp") }), check: "token-time"},
		"not yet valid":       {token: l.token(t, func(c core.Claims) { c["nbf"] = time.Now().Add(time.Hour).Unix() }), check: "token-time"},
		"other issuer":        {token: l.token(t, func(c core.Claims) { c["iss"] = "https://evil.example/realms/r" }), check: "token-issuer"},
		"other keys":          {token: other.token(t, func(c core.Claims) { c["iss"] = l.issuer }), check: "token-signature"},
		"altered payload":     {token: tamper(good), check: "token-signature"},
		"alg none":            {token: "eyJhbGciOiJub25lIn0." + strings.Split(good, ".")[1] + ".", check: "token-signature", text: "unsupported"},
		"no username":         {token: l.token(t, func(c core.Claims) { delete(c, "preferred_username") }), check: "username"},
		"no groups":           {token: l.token(t, func(c core.Claims) { delete(c, "groups") }), check: "groups", text: "HAVEN_IDP_GROUPS_CLAIM_CLIENTS containing r/kubernetes"},
		"groups wrong type":   {token: l.token(t, func(c core.Claims) { c["groups"] = 7 }), check: "groups"},
		"groups mixed types":  {token: l.token(t, func(c core.Claims) { c["groups"] = []any{"devs", 1} }), check: "groups"},
		"system group":        {token: l.token(t, func(c core.Claims) { c["groups"] = []string{"devs", "System:Masters"} }), check: "groups", text: "reserved"},
		"required missing":    {token: good, require: []string{"admins"}, check: "require-group", text: "admins"},
		"required, no claim":  {token: l.token(t, func(c core.Claims) { delete(c, "groups") }), require: []string{"devs"}, check: "require-group"},
		"required, empty set": {token: l.token(t, func(c core.Claims) { c["groups"] = []string{} }), require: []string{"devs"}, check: "require-group"},
		"not a jwt":           {token: "opaque-token", check: "token", text: "not a JWT"},
		"oversized":           {token: strings.Repeat("a", 70<<10), check: "token"},
	} {
		t.Run(name, func(t *testing.T) {
			rep := check(t, l, CheckInput{Token: c.token, RequireGroups: c.require})
			f := failed(rep)
			if rep.OK || f[c.check] == "" || !strings.Contains(f[c.check], c.text) {
				t.Fatalf("want %q to fail mentioning %q, got %v", c.check, c.text, f)
			}
		})
	}
}

// tamper rewrites the user name inside the payload, keeping the signature.
func tamper(tok string) string {
	p := strings.Split(tok, ".")
	b, _ := base64.RawURLEncoding.DecodeString(p[1])
	b = bytes.Replace(b, []byte("alice"), []byte("admin"), 1)
	return p[0] + "." + base64.RawURLEncoding.EncodeToString(b) + "." + p[2]
}

func TestCheckEndpointFailures(t *testing.T) {
	l := liveIDP(t, "r/kubernetes", nil)
	wrongCA, _ := testCA(t)
	port := l.issuer[strings.LastIndex(l.issuer, ":")+1 : strings.Index(l.issuer, "/realms")]
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := "https://" + ln.Addr().String() + "/realms/r"
	_ = ln.Close()
	serve := func(h http.HandlerFunc) *live {
		return liveIDP(t, "", func(http.Handler) http.Handler { return h })
	}
	redirect := serve(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://elsewhere.example/", http.StatusFound)
	})
	html := serve(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "<html>proxy</html>") })
	huge := serve(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(make([]byte, maxDoc+10)) })
	insecureJWKS := &live{}
	*insecureJWKS = *serve(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "https://" + r.Host + "/realms/r", "jwks_uri": "http://" + r.Host + "/k",
			"id_token_signing_alg_values_supported": []string{"ES256"}})
	})
	noKeys := serve(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/k") {
			_, _ = io.WriteString(w, `{"keys":[]}`)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": "https://" + r.Host + "/realms/r", "jwks_uri": "https://" + r.Host + "/k",
			"id_token_signing_alg_values_supported": []string{"RS256"}})
	})
	for name, c := range map[string]struct {
		idp         *live
		issuer      string
		ca          []byte
		check, text string
	}{
		"wrong CA":        {idp: l, ca: wrongCA, check: "connect", text: "not signed by the CA"},
		"system roots":    {idp: l, ca: []byte{}, check: "connect", text: "pass the issuing CA with --ca-file"},
		"host name":       {idp: l, issuer: "https://localhost:" + port + "/realms/r", check: "connect", text: "not valid for this host name"},
		"refused":         {idp: l, issuer: closed, check: "connect", text: "refused"},
		"unknown realm":   {idp: l, issuer: strings.Replace(l.issuer, "/realms/r", "/realms/nope", 1), check: "discovery", text: "404"},
		"issuer mismatch": {idp: l, issuer: strings.Replace(l.issuer, "/realms/r", "/x/../realms/r", 1), check: "discovery", text: ""},
		"redirect":        {idp: redirect, check: "discovery", text: "redirects"},
		"not json":        {idp: html, check: "discovery", text: "not valid JSON"},
		"huge":            {idp: huge, check: "connect", text: "1 MiB"},
		"http jwks":       {idp: insecureJWKS, check: "jwks", text: "not https"},
		"no keys":         {idp: noKeys, check: "jwks", text: "no usable key"},
		"no ES256":        {idp: noKeys, check: "algorithms", text: "ES256"},
		"http issuer":     {idp: l, issuer: "http://127.0.0.1:" + port + "/realms/r", check: "issuer-url", text: "https"},
	} {
		t.Run(name, func(t *testing.T) {
			rep := check(t, c.idp, CheckInput{Options: Options{Issuer: c.issuer, CAPEM: c.ca}, Timeout: 5 * time.Second})
			f := failed(rep)
			if rep.OK || f[c.check] == "" || !strings.Contains(f[c.check], c.text) {
				t.Fatalf("want %q to fail mentioning %q, got %v (%+v)", c.check, c.text, f, rep.Results)
			}
		})
	}
	// A signature cannot be vouched for when the keys were not fetched.
	rep := check(t, l, CheckInput{Options: Options{CAPEM: wrongCA}, Token: l.token(t, nil)})
	if f := failed(rep); f["token-signature"] == "" {
		t.Fatalf("unverified signature reported as fine: %+v", rep.Results)
	}
	// Bad settings that are not about the issuer are errors, not findings.
	if _, err := Check(context.Background(), CheckInput{Options: Options{Issuer: l.issuer, GroupsPrefix: "system:"}}); err == nil {
		t.Error("system: prefix accepted by check")
	}
}
