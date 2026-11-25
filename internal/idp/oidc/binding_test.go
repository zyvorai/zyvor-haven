// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/secretbox"
	"github.com/zyvorai/haven/internal/idp/totp"
)

// Resource binding, per-scope consent, and the authentication level through
// consent, PAR/JAR and CIBA.

const (
	mcpRes   = "https://mcp.example/mcp"
	otherRes = "https://other.example/mcp"
)

// consentFlow shows the consent page for q and allows exactly the ticked
// scopes (openid is not a form field).
func consentFlow(t *testing.T, b *browser, q url.Values, ticked ...string) *httptest.ResponseRecorder {
	t.Helper()
	page := b.authorize(q)
	if !isConsentPage(page) {
		t.Fatalf("not a consent page: %d %s %s", page.Code, page.Header().Get("Location"), page.Body)
	}
	body := page.Body.String()
	return b.do("POST", base+"auth?"+q.Encode(), url.Values{"csrf": {csrfRe.FindStringSubmatch(body)[1]},
		"consent_proof": {digestRe.FindStringSubmatch(body)[1]}, "consent_decision": {"allow"}, "consent_scope": ticked})
}

func appToken(t *testing.T, h http.Handler, code string) map[string]any {
	t.Helper()
	st, out := exchange(t, h, code)
	if st != 200 {
		t.Fatalf("exchange: %d %v", st, out)
	}
	return out
}

func rolesOf(c map[string]any) string {
	ra, _ := c["realm_access"].(map[string]any)
	return fmt.Sprint(ra["roles"])
}

func TestConsentPerScopeSubsetIsWhatTokensCarry(t *testing.T) {
	e := newConsentEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{RequireAll: true})
	b := e.browser()
	q := authQuery(map[string]string{"scope": "openid profile email roles offline_access"})

	page := b.authorize(q)
	if got := tickedScopes(page.Body.String()); !slices.Equal(got, []string{"email", "offline_access", "profile", "roles"}) {
		t.Fatalf("every optional scope starts ticked, openid is not optional: %v", got)
	}
	if !strings.Contains(page.Body.String(), `value="openid" checked disabled>`) {
		t.Fatal("openid must be shown as required")
	}
	// A scope that was not requested cannot be added through the form.
	narrow := authQuery(map[string]string{"scope": "openid email"})
	if w := consentFlow(t, b, narrow, "email", "roles"); w.Code != 400 || w.Header().Get("Location") != "" {
		t.Fatalf("added scope: %d %s", w.Code, w.Header().Get("Location"))
	}
	if n := len(e.receipts()); n != 0 {
		t.Fatalf("a rejected decision left %d receipts", n)
	}

	// Untick everything but email.
	out := appToken(t, e.h, consentCodeOf(t, consentFlow(t, b, q, "email")))
	if out["scope"] != "openid email" {
		t.Fatalf("granted scope: %v", out["scope"])
	}
	at, idc := claimsOf(t, out["access_token"].(string)), claimsOf(t, out["id_token"].(string))
	if at["scope"] != "openid email" || rolesOf(at) != "[]" || at["preferred_username"] != nil ||
		idc["preferred_username"] != nil || idc["name"] != nil || idc["email"] != "a@x" {
		t.Fatalf("claims exceed the grant: at=%v id=%v", at, idc)
	}
	req := httptest.NewRequest("GET", base+"userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+out["access_token"].(string))
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	var ui map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &ui)
	if w.Code != 200 || ui["preferred_username"] != nil || ui["name"] != nil || ui["email"] != "a@x" {
		t.Fatalf("userinfo: %d %s", w.Code, w.Body)
	}
	if in := acrIntrospect(t, e.h, e.st, out["access_token"].(string)); in["username"] != nil || in["scope"] != "openid email" {
		t.Fatalf("introspection: %v", in)
	}
	gs, _ := e.st.ListConsentGrants(context.Background(), "r", "u1", "app", false, e.now, 10)
	rs := e.receipts()
	if len(gs) != 1 || strings.Join(gs[0].Scopes, " ") != "email openid" || len(rs) != 1 ||
		strings.Join(rs[0].Scopes, " ") != "email openid" || rs[0].Detail != "declined: profile roles offline_access" {
		t.Fatalf("grant %+v receipt %+v", gs, rs)
	}
	// Refresh keeps the subset and cannot widen.
	rt := out["refresh_token"].(string)
	st, bad := tokenCall(t, e.h, base+"token", url.Values{"grant_type": {"refresh_token"}, "client_id": {"app"},
		"refresh_token": {rt}, "scope": {"openid email profile"}}, "", "")
	if st != 400 || bad["error"] != "invalid_scope" {
		t.Fatalf("widen: %d %v", st, bad)
	}
	st, o := refresh(t, e.h, rt)
	if st != 200 || o["scope"] != "openid email" {
		t.Fatalf("refresh: %d %v", st, o)
	}
	if c := claimsOf(t, o["access_token"].(string)); rolesOf(c) != "[]" || c["preferred_username"] != nil {
		t.Fatalf("refreshed claims: %v", c)
	}
	// The remembered grant covers only the subset: asking again for more asks
	// the user again, and prompt=none does not slip it through.
	wantACRErr(t, b.authorize(authQuery(map[string]string{"scope": "openid profile", "prompt": "none"})), "consent_required")
	// ...and a covered request keeps the limits without asking.
	out = appToken(t, e.h, consentCodeOf(t, b.authorize(narrow)))
	if c := claimsOf(t, out["access_token"].(string)); rolesOf(c) != "[]" || c["preferred_username"] != nil {
		t.Fatalf("remembered grant: %v", c)
	}
	// Granting the rest puts the claims back.
	all := appToken(t, e.h, consentCodeOf(t, consentFlow(t, b, q, "email", "profile", "roles", "offline_access")))
	if c := claimsOf(t, all["access_token"].(string)); rolesOf(c) != "[admin]" || c["preferred_username"] != "alice" {
		t.Fatalf("full grant: %v", c)
	}
	// Withdrawing a scope that was allowed ends the refresh tokens carrying it.
	again := authQuery(map[string]string{"scope": "openid profile email roles offline_access", "prompt": "consent"})
	consentCodeOf(t, consentFlow(t, b, again, "email", "profile"))
	if st, o := refresh(t, e.h, all["refresh_token"].(string)); st != 400 || o["error"] != "invalid_grant" {
		t.Fatalf("a token with a withdrawn scope still refreshes: %d %v", st, o)
	}
}

func TestConsentNothingTickedWithoutOpenID(t *testing.T) {
	e := newConsentEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{RequireAll: true})
	b := e.browser()
	q := authQuery(map[string]string{"scope": "email profile"})
	w := consentFlow(t, b, q)
	if !isConsentPage(w) || !strings.Contains(w.Body.String(), "Tick at least one") || len(e.receipts()) != 0 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// A client that is not asked for consent keeps the previous claim behaviour.
func TestUnconsentedClientsKeepTheirClaims(t *testing.T) {
	e := newConsentEnv(t, true, devOpts{})
	out := appToken(t, e.h, consentCodeOf(t, e.browser().authorize(authQuery(map[string]string{"scope": "openid"}))))
	if c := claimsOf(t, out["access_token"].(string)); rolesOf(c) != "[admin]" || c["preferred_username"] != "alice" {
		t.Fatalf("%v", c)
	}
}

func TestConsentResourcesAreTheAudience(t *testing.T) {
	e := newConsentEnv(t, true, devOpts{})
	e.policy(core.ConsentPolicy{RequireAll: true})
	b := e.browser()
	// Non-canonical spelling: shown, recorded and bound in canonical form.
	q := authQuery(map[string]string{"resource": "HTTPS://MCP.example:443/mcp"})
	q.Add("resource", otherRes)
	page := b.authorize(q)
	if !strings.Contains(page.Body.String(), mcpRes) || strings.Contains(page.Body.String(), "<code>HTTPS://MCP") {
		t.Fatalf("page: %s", page.Body)
	}
	out := appToken(t, e.h, consentCodeOf(t, consentFlow(t, b, q, "email")))
	if got := audOf(t, out["access_token"].(string)); !slices.Equal(got, []string{"app", mcpRes, otherRes}) {
		t.Fatalf("aud = %v", got)
	}
	gs, _ := e.st.ListConsentGrants(context.Background(), "r", "u1", "app", false, e.now, 10)
	if len(gs) != 1 || !slices.Equal(gs[0].Resources, []string{mcpRes, otherRes}) {
		t.Fatalf("grant: %+v", gs)
	}
	// Not on the allow-list: refused before any page.
	w := b.authorize(authQuery(map[string]string{"resource": "https://evil.example/mcp"}))
	wantACRErr(t, w, "invalid_target")
}

// ---- PAR and JAR ----

func TestPARAndJARCarryACRAndResources(t *testing.T) {
	f := newFEnv(t, nil, devOpts{})
	f.h.cfg.Resources = &ResourcePolicy{Realms: map[string]RealmResources{"r": {Resources: []string{mcpRes, otherRes}}}}
	essential := `{"id_token":{"acr":{"essential":true,"values":["` + acrMFA + `"]}}}`
	for name, mut := range map[string]func(url.Values){
		"acr_values": func(q url.Values) { q.Set("acr_values", acrMFA) },
		"claims":     func(q url.Values) { q.Set("claims", essential) },
	} {
		q := pkce()
		mut(q)
		ru := f.pushOK(q)
		w := f.authorize(f.browser(), url.Values{"client_id": {"fapi"}, "request_uri": {ru}})
		if errOfRedirect(w) != errUnmetACR {
			t.Fatalf("PAR %s was dropped: %d %s", name, w.Code, w.Header().Get("Location"))
		}
	}
	var claimsObj map[string]any
	must(t, json.Unmarshal([]byte(essential), &claimsObj))
	for name, over := range map[string]map[string]any{
		"acr_values": {"acr_values": acrMFA},
		"claims":     {"claims": claimsObj},
	} {
		obj := f.jar(t, "ES256", f.objClaims(over), nil)
		w := f.authorize(f.browser(), url.Values{"client_id": {"fapi"}, "request": {obj}})
		if errOfRedirect(w) != errUnmetACR {
			t.Fatalf("JAR %s was dropped: %d %s %s", name, w.Code, w.Header().Get("Location"), w.Body)
		}
	}
	q := pkce()
	q["resource"] = []string{mcpRes, otherRes}
	q.Set("acr_values", acr1)
	code := f.pushedCode(q)
	st, out, _ := f.redeem(code)
	if st != 200 {
		t.Fatalf("%d %v", st, out)
	}
	if got := audOf(t, out["access_token"].(string)); !slices.Equal(got, []string{"fapi", mcpRes, otherRes}) {
		t.Fatalf("PAR resources: aud = %v", got)
	}
	wantContext(t, "PAR", out["access_token"].(string), acr1, "pwd")
	obj := f.jar(t, "ES256", f.objClaims(map[string]any{"resource": []any{mcpRes, otherRes}}), nil)
	st, out, _ = f.redeem(codeOf(t, f.authorize(f.browser(), url.Values{"client_id": {"fapi"}, "request": {obj}})))
	if st != 200 {
		t.Fatalf("%d %v", st, out)
	}
	if got := audOf(t, out["access_token"].(string)); !slices.Equal(got, []string{"fapi", mcpRes, otherRes}) {
		t.Fatalf("JAR resources: aud = %v", got)
	}
	// A pushed resource off the allow-list is refused, not ignored.
	q = pkce()
	q.Set("resource", "https://evil.example/mcp")
	w := f.authorize(f.browser(), url.Values{"client_id": {"fapi"}, "request_uri": {f.pushOK(q)}})
	if errOfRedirect(w) != "invalid_target" {
		t.Fatalf("%d %s", w.Code, w.Header().Get("Location"))
	}
}

// ---- CIBA ----

func TestCIBAResourcesAreBound(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	for name, res := range map[string]string{"not allowed": "https://evil.example/api", "http": "http://shop.example/api"} {
		if c, out := e.start("alice", url.Values{"resource": {res}}); c != 400 || cerr(out) != "invalid_target" {
			t.Fatalf("%s: %d %v", name, c, out)
		}
	}
	id := e.mustStart("alice", url.Values{"resource": {"https://shop.example/api", "https://pay.example/v1"}})
	link := e.link("alice@x.example")
	b := e.browser()
	b.open(link, "alice", "pw")
	if w := b.decide(tokenOf(link), "approve"); w.Code != 200 {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	e.advance(10 * time.Second)
	tok := func(res ...string) (int, map[string]any) {
		w, out := e.do("POST", base+"token", url.Values{"grant_type": {cibaGrant}, "auth_req_id": {id}, "resource": res}, "agent", "s3cret", "")
		return w.Code, out
	}
	// Widening is refused and does not burn the approval.
	if c, out := tok("https://other.example/api"); c != 400 || cerr(out) != "invalid_target" {
		t.Fatalf("widen: %d %v", c, out)
	}
	e.advance(30 * time.Second)
	c, out := tok("https://pay.example/v1")
	if c != 200 {
		t.Fatalf("narrow: %d %v", c, out)
	}
	if got := audOf(t, out["access_token"].(string)); !slices.Equal(got, []string{"agent", "https://pay.example/v1"}) {
		t.Fatalf("aud = %v", got)
	}
}

func TestCIBAResourceRemovedFromAllowList(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	id := e.mustStart("alice", url.Values{"resource": {"https://shop.example/api"}})
	link := e.link("alice@x.example")
	b := e.browser()
	b.open(link, "alice", "pw")
	b.decide(tokenOf(link), "approve")
	e.h.cfg.Resources = &ResourcePolicy{}
	e.advance(10 * time.Second)
	if c, out := e.poll("agent", id); c != 400 || cerr(out) != "invalid_target" {
		t.Fatalf("a token without the approved audience must not be issued: %d %v", c, out)
	}
}

// cibaTOTP switches two-step verification on and enrolls dave.
func cibaTOTP(t *testing.T, e *cenv) (code func() string) {
	t.Helper()
	k, _ := secretbox.ParseKey(secretbox.GenerateKey())
	box, _ := secretbox.New(k)
	e.h.cfg.SecretBox = box
	seed := totp.NewSeed()
	must(t, e.st.PutTOTP(context.Background(), core.TOTPCredential{Realm: "r", UserID: "u4", CreatedAt: e.now,
		SealedSeed: box.Seal(seed, "totp|r|u4")}))
	if ok, err := e.st.ConfirmTOTP(context.Background(), "r", "u4", totp.StepAt(e.now)-5); err != nil || !ok {
		t.Fatal(ok, err)
	}
	return func() string { return totp.CodeAt(seed, totp.StepAt(e.now)) }
}

// cibaMFALogin signs dave in with password and code at an approval login URL.
func cibaMFALogin(t *testing.T, b *cbrowser, loc, code string) *httptest.ResponseRecorder {
	t.Helper()
	pg := b.loginAt(loc, "dave", "pw")
	tk := tokenRe.FindStringSubmatch(pg.Body.String())
	if tk == nil {
		t.Fatalf("no code page: %d %s", pg.Code, pg.Body)
	}
	w := b.do("POST", loc, url.Values{"csrf": {csrfRe.FindStringSubmatch(pg.Body.String())[1]}, "mfa_token": {tk[1]}, "code": {code}})
	if w.Code != 302 {
		t.Fatalf("code step: %d %s", w.Code, w.Body)
	}
	return b.do("GET", w.Header().Get("Location"), nil)
}

func TestCIBAACRValues(t *testing.T) {
	e := newCEnv(t, cibaOpts{})
	for name, c := range map[string]struct {
		form url.Values
		err  string
	}{
		"unknown":  {url.Values{"acr_values": {"gold"}}, errUnmetACR},
		"claims":   {url.Values{"claims": {"{}"}}, "invalid_request"},
		"repeated": {url.Values{"acr_values": {acr1, acrMFA}}, "invalid_request"},
		"long":     {url.Values{"acr_values": {strings.Repeat("a", 100) + " " + strings.Repeat("b", 100) + " " + strings.Repeat("c", 100) + " " + strings.Repeat("d", 100) + " " + strings.Repeat("e", 120)}}, "invalid_request"},
	} {
		if st, out := e.start("alice", c.form); st != 400 || cerr(out) != c.err {
			t.Fatalf("%s: %d %v", name, st, out)
		}
	}
	code := cibaTOTP(t, e)

	// A user who cannot reach the level cannot approve.
	e.mustStart("alice", url.Values{"acr_values": {acrMFA}})
	link := e.link("alice@x.example")
	b := e.browser()
	w := b.do("GET", link, nil)
	if !strings.Contains(w.Header().Get("Location"), "acr_values="+url.QueryEscape(acrMFA)) {
		t.Fatalf("the approval login does not demand the level: %s", w.Header().Get("Location"))
	}
	loc := w.Header().Get("Location")
	pg := b.do("GET", loc, nil)
	w = b.do("POST", loc, url.Values{"username": {"alice"}, "password": {"pw"}, "csrf": {csrfRe.FindStringSubmatch(pg.Body.String())[1]}})
	if w.Code != 302 || !strings.Contains(w.Header().Get("Location"), "error="+errUnmetACR) {
		t.Fatalf("login: %d %s", w.Code, w.Header().Get("Location"))
	}
	if w = b.do("GET", w.Header().Get("Location"), nil); w.Code != 403 || !strings.Contains(w.Body.String(), "stronger sign-in") {
		t.Fatalf("landing: %d %s", w.Code, w.Body)
	}
	// Removing acr_values from the login URL gets a session, not an approval.
	u, _ := url.Parse(loc)
	q := u.Query()
	q.Del("acr_values")
	stripped := idpBase + base + "auth?" + q.Encode()
	w = b.loginAt(stripped, "alice", "pw")
	if w.Code != 401 || strings.Contains(w.Body.String(), `value="approve"`) {
		t.Fatalf("weak session reached the approval page: %d %s", w.Code, w.Body)
	}
	if w = b.decide(tokenOf(link), "approve"); w.Code == 200 {
		t.Fatalf("approval with a weak session: %d %s", w.Code, w.Body)
	}

	// dave has the factor.
	id := e.mustStart("dave", url.Values{"acr_values": {acrMFA}})
	link = e.link("dave@x.example")
	b = e.browser()
	w = b.do("GET", link, nil)
	page := cibaMFALogin(t, b, w.Header().Get("Location"), code())
	if page.Code != 200 || !strings.Contains(page.Body.String(), `value="approve"`) {
		t.Fatalf("approval page: %d %s", page.Code, page.Body)
	}
	// The form carries the CSRF token of the approval page.
	if w = b.decide(tokenOf(link), "approve"); w.Code != 200 || !strings.Contains(w.Body.String(), "You approved") {
		t.Fatalf("approve: %d %s", w.Code, w.Body)
	}
	// The ladder changes before the token is fetched: nothing is issued.
	strict := core.DefaultACRPolicy()
	strict.Levels[1].AnyOf = [][]string{{core.AMRWebAuthn, core.AMRMFA}}
	must(t, e.st.PutACRPolicy(context.Background(), "r", strict))
	e.advance(10 * time.Second)
	if st, out := e.poll("agent", id); st != 400 || cerr(out) != "invalid_grant" {
		t.Fatalf("after policy change: %d %v", st, out)
	}
	must(t, e.st.DeleteACRPolicy(context.Background(), "r"))
	e.advance(30 * time.Second)
	st, out := e.poll("agent", id)
	if st != 200 {
		t.Fatalf("%d %v", st, out)
	}
	wantContext(t, "CIBA access token", out["access_token"].(string), acrMFA, "pwd otp mfa")
	wantContext(t, "CIBA id token", out["id_token"].(string), acrMFA, "pwd otp mfa")
}
