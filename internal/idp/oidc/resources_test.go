// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	resA = "https://mcp.example.com/mcp"
	resB = "https://files.example.com/api"
)

func policy(t *testing.T, js string) *ResourcePolicy {
	t.Helper()
	p, err := ParseResourcePolicy([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// renv is the fakeStore harness with an allow-list: app may use resA and resB,
// svc only resB.
func renv(t *testing.T) *env {
	e := newEnv(t, nil)
	e.h.cfg.Resources = policy(t, `{"realms":{"r":{"resources":["`+resA+`","`+resB+`"],
		"clients":{"svc":["`+resB+`"]}}}}`)
	return e
}

func audOf(t *testing.T, tok string) []string {
	t.Helper()
	switch v := claimsOf(t, tok)["aud"].(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, a := range v {
			out = append(out, a.(string))
		}
		return out
	}
	t.Fatal("no aud")
	return nil
}

func TestCanonicalResource(t *testing.T) {
	ok := map[string]string{
		"https://mcp.example.com/mcp":      "https://mcp.example.com/mcp",
		"HTTPS://MCP.Example.COM/mcp":      "https://mcp.example.com/mcp",
		"https://mcp.example.com":          "https://mcp.example.com",
		"https://mcp.example.com:443/x":    "https://mcp.example.com/x",
		"https://mcp.example.com:8443":     "https://mcp.example.com:8443",
		"https://mcp.example.com/server/a": "https://mcp.example.com/server/a",
		"https://mcp.example.com/":         "https://mcp.example.com/", // trailing slash is significant
		"https://[::1]:8443/mcp":           "https://[::1]:8443/mcp",
	}
	for in, want := range ok {
		if got, err := CanonicalResource(in); err != nil || got != want {
			t.Errorf("%q: got %q, %v want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "mcp.example.com", "http://mcp.example.com", "https://mcp.example.com#frag",
		"https://mcp.example.com/a#", "https://mcp.example.com/?q=1", "https://u:p@mcp.example.com", "https:///x",
		"urn:example:res", "ftp://x.example/", "https://mcp.example.com/a/../b", "https://mcp.example.com/./b",
		"https://mcp.example.com/a b", "https://mcp.example.com/é", "https://mcp.example.com/\n",
		"https://mcp.example.com/" + strings.Repeat("a", 300), "javascript:alert(1)", "//mcp.example.com/x"} {
		if got, err := CanonicalResource(in); err == nil {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}

func TestResourcePolicyFile(t *testing.T) {
	p := policy(t, `{"realms":{"r":{"resources":["HTTPS://A.example/x","https://a.example/x"],"clients":{"c":[],"d":["https://d.example"]}}}}`)
	if got := p.AllowedResources("r", "other"); !slices.Equal(got, []string{"https://a.example/x"}) {
		t.Fatalf("realm default (canonical, deduped): %v", got)
	}
	if got := p.AllowedResources("r", "c"); len(got) != 0 {
		t.Fatalf("an empty client entry replaces the realm list: %v", got)
	}
	if got := p.AllowedResources("r", "d"); !slices.Equal(got, []string{"https://d.example"}) {
		t.Fatalf("client entry replaces: %v", got)
	}
	if p.AllowedResources("nope", "d") != nil || (*ResourcePolicy)(nil).AllowedResources("r", "c") != nil {
		t.Fatal("unknown realm / nil policy must allow nothing")
	}
	for name, js := range map[string]string{
		"unknown field": `{"realms":{},"extra":1}`,
		"http resource": `{"realms":{"r":{"resources":["http://a.example"]}}}`,
		"fragment":      `{"realms":{"r":{"clients":{"c":["https://a.example#x"]}}}}`,
		"trailing":      `{"realms":{}} {}`,
		"not json":      `nope`,
	} {
		if _, err := ParseResourcePolicy([]byte(js)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	path := filepath.Join(t.TempDir(), "res.json")
	if err := os.WriteFile(path, []byte(`{"realms":{"r":{"resources":["https://a.example"]}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if lp, err := LoadResourcePolicy(path); err != nil || lp == nil {
		t.Fatal(lp, err)
	}
	if lp, err := LoadResourcePolicy(""); err != nil || lp != nil {
		t.Fatal("empty path must switch the feature off")
	}
	if _, err := LoadResourcePolicy(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file must be an error")
	}
}

func TestResourceCodeRefreshFlow(t *testing.T) {
	e := renv(t)
	code := e.getCode(authQuery(nil)) // no resource: legacy behaviour
	st, out, _ := e.tokenReq(codeForm(code), "", "")
	if st != 200 || fmt.Sprint(claimsOf(t, out["access_token"].(string))["aud"]) != "app" {
		t.Fatalf("plain token must keep aud=client id: %d %v", st, out)
	}

	q := authQuery(nil)
	q.Add("resource", "HTTPS://MCP.example.com/mcp") // non-canonical host case
	q.Add("resource", resB)
	code = e.getCode(q)
	if !strings.Contains(code, resSep) {
		t.Fatal("code does not carry the granted set")
	}
	// Narrow at the token endpoint: access token for resA only.
	f := codeForm(code)
	f.Set("resource", resA)
	st, out, _ = e.tokenReq(f, "", "")
	if st != 200 {
		t.Fatalf("%d %v", st, out)
	}
	if got := audOf(t, out["access_token"].(string)); !slices.Equal(got, []string{"app", resA}) {
		t.Fatalf("aud = %v", got)
	}
	if got := claimsOf(t, out["id_token"].(string))["aud"]; got != "app" {
		t.Fatalf("id_token aud must stay the client id: %v", got)
	}
	// The resource-bound token still works at userinfo (client id is in aud).
	req := httptest.NewRequest("GET", base+"userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+out["access_token"].(string))
	if w := e.do(req); w.Code != 200 {
		t.Fatalf("userinfo with resource-bound token: %d", w.Code)
	}
	rt := out["refresh_token"].(string)

	refresh := func(rt string, res ...string) (int, map[string]any) {
		f := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"app"}}
		for _, r := range res {
			f.Add("resource", r)
		}
		st, o, _ := e.tokenReq(f, "", "")
		return st, o
	}
	// Widening beyond the grant is refused, and the failed request must not
	// burn the refresh token.
	if st, o := refresh(rt, "https://evil.example/x"); st != 400 || o["error"] != "invalid_target" {
		t.Fatalf("widen: %d %v", st, o)
	}
	// No resource: the whole granted set, and the rotated token keeps the full set.
	st2, o := refresh(rt)
	if st2 != 200 {
		t.Fatalf("%d %v", st2, o)
	}
	if got := audOf(t, o["access_token"].(string)); !slices.Equal(got, []string{"app", resA, resB}) {
		t.Fatalf("aud = %v", got)
	}
	rt = o["refresh_token"].(string)
	// Narrow on refresh; the new refresh token still carries both.
	st2, o = refresh(rt, resB)
	if st2 != 200 || !slices.Equal(audOf(t, o["access_token"].(string)), []string{"app", resB}) {
		t.Fatalf("%d %v", st2, o)
	}
	rt = o["refresh_token"].(string)
	if g, _ := decodeResources(rt); !slices.Equal(g, []string{resA, resB}) {
		t.Fatalf("refresh token lost the original grant: %v", g)
	}
	// After narrowing, going back to the other granted resource is fine.
	if st2, o = refresh(rt, resA); st2 != 200 {
		t.Fatalf("%d %v", st2, o)
	}
	// Allow-list shrinks: the grant loses resB, a request for it fails, the rest works.
	e.h.cfg.Resources = policy(t, `{"realms":{"r":{"resources":["`+resA+`"]}}}`)
	rt = o["refresh_token"].(string)
	if st2, o = refresh(rt, resB); st2 != 400 || o["error"] != "invalid_target" {
		t.Fatalf("revoked resource: %d %v", st2, o)
	}
	if st2, o = refresh(rt); st2 != 200 || !slices.Equal(audOf(t, o["access_token"].(string)), []string{"app", resA}) {
		t.Fatalf("shrunk grant: %d %v", st2, o)
	}
	// If nothing of the grant is allowed any more, the refresh fails closed.
	e.h.cfg.Resources = nil
	if st2, o = refresh(o["refresh_token"].(string)); st2 != 400 || o["error"] != "invalid_target" {
		t.Fatalf("grant with no allowed resource left: %d %v", st2, o)
	}
}

func TestResourceCodeBinding(t *testing.T) {
	e := renv(t)
	q := authQuery(nil)
	q.Add("resource", resA)

	// A token request may not widen: resB was not part of the code.
	code := e.getCode(q)
	f := codeForm(code)
	f.Set("resource", resB)
	if st, o, _ := e.tokenReq(f, "", ""); st != 400 || o["error"] != "invalid_target" {
		t.Fatalf("widen at token endpoint: %d %v", st, o)
	}
	// A code without resources cannot be upgraded by a token request either.
	code = e.getCode(authQuery(nil))
	f = codeForm(code)
	f.Set("resource", resA)
	if st, o, _ := e.tokenReq(f, "", ""); st != 400 || o["error"] != "invalid_target" {
		t.Fatalf("upgrade plain code: %d %v", st, o)
	}
	// Tampering with the suffix (adding resB) is just an unknown code.
	code = e.getCode(q)
	forged := strings.SplitN(code, resSep, 2)[0] + encodeResources([]string{resA, resB})
	if st, o, _ := e.tokenReq(codeForm(forged), "", ""); st != 400 || o["error"] != "invalid_grant" {
		t.Fatalf("forged suffix: %d %v", st, o)
	}
	// Dropping the suffix is no better.
	if st, o, _ := e.tokenReq(codeForm(strings.SplitN(code, resSep, 2)[0]), "", ""); st != 400 || o["error"] != "invalid_grant" {
		t.Fatalf("stripped suffix: %d %v", st, o)
	}
	// The real code still works (the forgeries did not consume it).
	if st, o, _ := e.tokenReq(codeForm(code), "", ""); st != 200 {
		t.Fatalf("%d %v", st, o)
	}
	// Allow-list shrinks between authorization and redemption.
	code = e.getCode(q)
	e.h.cfg.Resources = nil
	if st, o, _ := e.tokenReq(codeForm(code), "", ""); st != 400 || o["error"] != "invalid_target" {
		t.Fatalf("revoked before redemption: %d %v", st, o)
	}
}

func TestResourceAuthorizeErrors(t *testing.T) {
	e := renv(t)
	for name, res := range map[string][]string{
		"unknown":  {"https://evil.example/mcp"},
		"one bad":  {resA, "https://evil.example/mcp"},
		"http":     {"http://mcp.example.com/mcp"},
		"fragment": {resA + "#x"},
		"query":    {resA + "?x=1"},
		"relative": {"/mcp"},
		"empty":    {""},
		"too many": {resA, resB, "https://c.example", "https://d.example", "https://e.example", "https://f.example"},
	} {
		q := authQuery(nil)
		for _, r := range res {
			q.Add("resource", r)
		}
		w := e.do(httptest.NewRequest("GET", base+"auth?"+q.Encode(), nil))
		loc, _ := url.Parse(w.Header().Get("Location"))
		if w.Code != 302 || loc.Query().Get("error") != "invalid_target" || loc.Query().Get("state") != "st8" {
			t.Errorf("%s: %d %s", name, w.Code, w.Header().Get("Location"))
		}
	}
	// Without a policy every resource is refused (fail closed), not ignored.
	e.h.cfg.Resources = nil
	q := authQuery(nil)
	q.Set("resource", resA)
	w := e.do(httptest.NewRequest("GET", base+"auth?"+q.Encode(), nil))
	if loc, _ := url.Parse(w.Header().Get("Location")); w.Code != 302 || loc.Query().Get("error") != "invalid_target" {
		t.Fatalf("no policy: %d %s", w.Code, w.Header().Get("Location"))
	}
	// A realm the policy does not mention gets nothing.
	e.h.cfg.Resources = policy(t, `{"realms":{"elsewhere":{"resources":["`+resA+`"]}}}`)
	w = e.do(httptest.NewRequest("GET", base+"auth?"+q.Encode(), nil))
	if loc, _ := url.Parse(w.Header().Get("Location")); w.Code != 302 || loc.Query().Get("error") != "invalid_target" {
		t.Fatalf("other realm: %d %s", w.Code, w.Header().Get("Location"))
	}
	// The error is only sent to the (already validated) redirect URI.
	q.Set("redirect_uri", "https://evil.example/cb")
	if w = e.do(httptest.NewRequest("GET", base+"auth?"+q.Encode(), nil)); w.Code != 400 {
		t.Fatalf("bad redirect_uri must not redirect: %d", w.Code)
	}
}

func TestResourceClientCredentials(t *testing.T) {
	e := renv(t)
	cc := func(res ...string) (int, map[string]any) {
		f := url.Values{"grant_type": {"client_credentials"}}
		for _, r := range res {
			f.Add("resource", r)
		}
		st, o, _ := e.tokenReq(f, "svc", "s3cret")
		return st, o
	}
	st, o := cc()
	if st != 200 || fmt.Sprint(claimsOf(t, o["access_token"].(string))["aud"]) != "svc" {
		t.Fatalf("plain: %d %v", st, o)
	}
	st, o = cc(resB)
	if st != 200 || !slices.Equal(audOf(t, o["access_token"].(string)), []string{"svc", resB}) {
		t.Fatalf("allowed: %d %v", st, o)
	}
	// svc has its own list (resB only): the realm default does not apply to it.
	if st, o = cc(resA); st != 400 || o["error"] != "invalid_target" {
		t.Fatalf("client entry must replace the realm list: %d %v", st, o)
	}
	if st, o = cc(resB, "https://evil.example"); st != 400 || o["error"] != "invalid_target" {
		t.Fatalf("%d %v", st, o)
	}
}

func TestResourceDeviceFlow(t *testing.T) {
	e := newDEnv(t, devOpts{})
	e.h.cfg.Resources = policy(t, `{"realms":{"r":{"clients":{"cli":["`+resA+`"]}}}}`)
	st, out, _ := e.post(devPath, url.Values{"client_id": {"cli"}, "resource": {"https://evil.example"}}, "", "", "")
	if st != 400 || out["error"] != "invalid_target" {
		t.Fatalf("%d %v", st, out)
	}
	st, out, _ = e.post(devPath, url.Values{"client_id": {"cli"}, "scope": {"openid"}, "resource": {resA}}, "", "", "")
	if st != 200 {
		t.Fatalf("%d %v", st, out)
	}
	g := devGrant{DeviceCode: out["device_code"].(string), UserCode: out["user_code"].(string),
		VerificationURIComplete: out["verification_uri_complete"].(string)}
	b := e.browser()
	b.openAndLogin(g, "alice", "pw")
	if w := b.decide(g.UserCode, "approve"); w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	e.advance(10 * time.Second)
	// A token request that widens is refused.
	pc, po, _ := e.post(base+"token", url.Values{"grant_type": {deviceGrant}, "device_code": {g.DeviceCode},
		"client_id": {"cli"}, "resource": {resB}}, "", "", "")
	if pc != 400 || po["error"] != "invalid_target" {
		t.Fatalf("%d %v", pc, po)
	}
	e.advance(30 * time.Second) // the refused request counted as a poll
	code, o := e.poll("cli", g.DeviceCode)
	if code != 200 {
		t.Fatalf("%d %v", code, o)
	}
	if got := audOf(t, o["access_token"].(string)); !slices.Equal(got, []string{"cli", resA}) {
		t.Fatalf("aud = %v", got)
	}
}

func TestResourceDPoPComposition(t *testing.T) {
	e := newDEnv(t, devOpts{})
	e.addSvc()
	e.h.cfg.Resources = policy(t, `{"realms":{"r":{"resources":["`+resA+`"]}}}`)
	k := newES(t)
	f := url.Values{"grant_type": {"client_credentials"}, "resource": {resA}}
	st, out, _ := e.tok(f, "svc", "s3cret", e.proof(t, k, pOpt{}))
	if st != 200 || out["token_type"] != "DPoP" {
		t.Fatalf("%d %v", st, out)
	}
	at := out["access_token"].(string)
	if cnfJKT(t, at) != k.jkt || !slices.Equal(audOf(t, at), []string{"svc", resA}) {
		t.Fatalf("token must carry both cnf and the resource audience: %v", claimsOf(t, at))
	}
}

func TestRFC8414DiscoveryAliasesAndMCPRequirements(t *testing.T) {
	e := renv(t)
	get := func(path string) (int, map[string]any) {
		w := e.do(httptest.NewRequest("GET", path, nil))
		var d map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &d)
		return w.Code, d
	}
	// The three URLs an MCP client probes for the issuer https://idp.example/realms/r
	// (MCP authorization spec 2025-11-25, "Authorization Server Metadata Discovery").
	var docs []map[string]any
	for _, path := range []string{
		"/.well-known/oauth-authorization-server/realms/r",
		"/.well-known/openid-configuration/realms/r",
		"/realms/r/.well-known/openid-configuration",
	} {
		st, d := get(path)
		if st != 200 {
			t.Fatalf("%s: %d", path, st)
		}
		docs = append(docs, d)
	}
	if fmt.Sprint(docs[0]) != fmt.Sprint(docs[2]) || fmt.Sprint(docs[1]) != fmt.Sprint(docs[2]) {
		t.Fatal("aliases must serve the same document")
	}
	d := docs[0]
	strs := func(k string) []string {
		var out []string
		for _, v := range d[k].([]any) {
			out = append(out, v.(string))
		}
		return out
	}
	// RFC 8414 section 3.3: the issuer in the document equals the issuer the
	// URL was built from.
	if d["issuer"] != "https://idp.example/realms/r" {
		t.Fatalf("issuer %v", d["issuer"])
	}
	// PKCE discoverability (MCP: clients MUST refuse to proceed without it).
	if !slices.Equal(strs("code_challenge_methods_supported"), []string{"S256"}) {
		t.Fatalf("pkce: %v", d["code_challenge_methods_supported"])
	}
	for _, k := range []string{"authorization_endpoint", "token_endpoint", "jwks_uri"} {
		if s, _ := d[k].(string); !strings.HasPrefix(s, "https://idp.example/realms/r/") {
			t.Errorf("%s = %v", k, d[k])
		}
	}
	if !slices.Contains(strs("response_types_supported"), "code") ||
		!slices.Contains(strs("grant_types_supported"), "authorization_code") ||
		!slices.Contains(strs("grant_types_supported"), "refresh_token") ||
		!slices.Contains(strs("token_endpoint_auth_methods_supported"), "none") { // public MCP clients
		t.Fatalf("grants/auth methods: %v", d)
	}
	if d["authorization_response_iss_parameter_supported"] != true {
		t.Fatal("RFC 9207 iss parameter not advertised")
	}
	if st, _ := get("/.well-known/oauth-authorization-server/realms/nope"); st != 404 {
		t.Fatalf("unknown realm: %d", st)
	}
	if w := e.do(httptest.NewRequest("POST", "/.well-known/oauth-authorization-server/realms/r", nil)); w.Code != 405 {
		t.Fatalf("POST: %d", w.Code)
	}
}
