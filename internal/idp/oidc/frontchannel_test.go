// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp/core"
)

var iframeRe = regexp.MustCompile(`<iframe src="([^"]*)" sandbox="([^"]*)" referrerpolicy="no-referrer" title="[^"]*" hidden></iframe>`)

// fcEnv: a logout env with applications that registered front-channel logout.
type fcEnv struct{ *lenv }

func newFCEnv(t *testing.T) fcEnv {
	t.Helper()
	e := fcEnv{newLEnv(t, nil)}
	e.fcClient("one", "https://one.example/cb", "https://one.example/fc?tenant=a")
	e.fcClient("two", "https://two.example:8443/cb", "https://two.example:8443/fc")
	e.fcClient("three", "https://one.example/other-cb", "https://one.example/fc3") // same origin as "one"
	e.fcClient("quiet", "https://quiet.example/cb", "")
	return e
}

func (e fcEnv) fcClient(id, redirect, fc string) core.Client {
	e.t.Helper()
	ctx := context.Background()
	must(e.t, e.st.CreateClient(ctx, core.Client{ID: "uuid-" + id, Realm: "r", ClientID: id, Enabled: true, Public: true,
		AuthCodeFlow: true, RedirectURIs: []string{redirect}}))
	if fc != "" {
		must(e.t, e.st.SetFrontchannelLogoutURI(ctx, "r", "uuid-"+id, fc))
	}
	cl, err := e.st.GetClient(ctx, "r", "uuid-"+id)
	must(e.t, err)
	return cl
}

func cspDirectives(t *testing.T, w *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, d := range strings.Split(w.Header().Get("Content-Security-Policy"), ";") {
		name, val, _ := strings.Cut(strings.TrimSpace(d), " ")
		if _, dup := out[name]; dup {
			t.Fatalf("directive %q twice", name)
		}
		out[name] = val
	}
	return out
}

func frames(w *httptest.ResponseRecorder) map[string]string {
	out := map[string]string{}
	for _, m := range iframeRe.FindAllStringSubmatch(w.Body.String(), -1) {
		out[html.UnescapeString(m[1])] = m[2]
	}
	return out
}

func TestFrontchannelLogoutPage(t *testing.T) {
	e := newFCEnv(t)
	_, ck := e.session("s1", "u1", "one", "two", "three", "quiet", "app", "gone")
	csrf, cc := e.confirm(nil, ck)
	w := e.do("POST", nil, url.Values{"csrf": {csrf}, "client_id": {"app"}, "post_logout_redirect_uri": {cb}, "state": {"x y"}}, ck, cc)
	if w.Code != 200 || e.alive("s1") {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	got := frames(w)
	if len(got) != 3 || strings.Count(w.Body.String(), "<iframe") != 3 {
		t.Fatalf("frames: %v", got)
	}
	for src, sandbox := range got {
		u, err := url.Parse(src)
		must(t, err)
		if u.Query().Get("iss") != "https://idp.example/realms/r" || u.Query().Get("sid") != "s1" {
			t.Errorf("iss/sid missing: %s", src)
		}
		if u.Host == "one.example" && u.Path == "/fc" && u.Query().Get("tenant") != "a" {
			t.Errorf("registered query lost: %s", src)
		}
		if sandbox != "allow-scripts allow-same-origin" {
			t.Errorf("sandbox %q", sandbox)
		}
	}
	// CSP: frame-src lists exactly the origins needed, once each, and the rest
	// is the policy of every other page.
	d := cspDirectives(t, w)
	if d["frame-src"] != "https://one.example https://two.example:8443" {
		t.Errorf("frame-src %q", d["frame-src"])
	}
	if len(d) != 5 || d["default-src"] != "'none'" || d["base-uri"] != "'none'" || d["frame-ancestors"] != "'none'" ||
		!strings.HasPrefix(d["style-src"], "'nonce-") || strings.Contains(w.Header().Get("Content-Security-Policy"), "*") {
		t.Errorf("policy: %v", d)
	}
	if w.Header().Get("X-Frame-Options") != "DENY" || w.Header().Get("Referrer-Policy") != "no-referrer" ||
		!strings.Contains(w.Header().Get("Cache-Control"), "no-store") {
		t.Errorf("headers: %v", w.Header())
	}
	if strings.Contains(w.Body.String(), "<script") {
		t.Error("the page needs no script")
	}
	want := cb + "?state=x+y"
	if w.Header().Get("Refresh") != "5; url="+want || !strings.Contains(html.UnescapeString(w.Body.String()), `href="`+want+`"`) || w.Header().Get("Location") != "" {
		t.Errorf("continue: %q", w.Header().Get("Refresh"))
	}
	if c := cookieNamed(w, ssoCookie); c == nil || c.MaxAge >= 0 {
		t.Error("SSO cookie not cleared")
	}
	// Back-channel logout still fires.
	if e.rec.count("s1", "one") != 1 {
		t.Error("no back-channel notification")
	}
}

func TestFrontchannelOnlyForThisBrowsersSession(t *testing.T) {
	redirect := "https://app.example/cb"
	t.Run("hint with own cookie", func(t *testing.T) {
		e := newFCEnv(t)
		_, ck := e.session("s1", "u1", "one")
		h := e.hint("r", core.Claims{"sub": "u1", "sid": "s1"})
		w := e.do("GET", url.Values{"id_token_hint": {h}, "post_logout_redirect_uri": {redirect}}, nil, ck)
		if w.Code != 200 || len(frames(w)) != 1 || w.Header().Get("Refresh") != "5; url="+redirect {
			t.Fatalf("%d %v", w.Code, frames(w))
		}
		// Replaying the logout shows no frames (nothing was ended).
		w = e.do("GET", url.Values{"id_token_hint": {h}, "post_logout_redirect_uri": {redirect}}, nil, ck)
		if w.Code != http.StatusFound || strings.Contains(w.Body.String(), "iframe") {
			t.Fatalf("replay: %d", w.Code)
		}
	})
	t.Run("hint without cookie reveals nothing", func(t *testing.T) {
		e := newFCEnv(t)
		e.session("s1", "u1", "one", "two")
		h := e.hint("r", core.Claims{"sub": "u1", "sid": "s1"})
		w := e.do("GET", url.Values{"id_token_hint": {h}, "post_logout_redirect_uri": {redirect}}, nil)
		if w.Code != http.StatusFound || strings.Contains(w.Body.String(), "two.example") || e.alive("s1") {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
		if d := cspDirectives(t, w); d["frame-src"] != "" {
			t.Fatal("frame-src on a redirect")
		}
	})
	t.Run("hint naming a session of another browser", func(t *testing.T) {
		e := newFCEnv(t)
		e.session("s1", "u1", "two")
		_, other := e.session("s2", "u2", "one")
		h := e.hint("r", core.Claims{"sub": "u1", "sid": "s1"})
		w := e.do("GET", url.Values{"id_token_hint": {h}}, nil, other)
		if strings.Contains(w.Body.String(), "<iframe") || strings.Contains(w.Body.String(), "two.example") || !e.alive("s2") {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	})
	t.Run("same user, other session: only the browser's own is framed", func(t *testing.T) {
		e := newFCEnv(t)
		e.session("s1", "u1", "two")
		_, mine := e.session("s2", "u1", "one")
		h := e.hint("r", core.Claims{"sub": "u1", "sid": "s1"})
		w := e.do("GET", url.Values{"id_token_hint": {h}}, nil, mine)
		got := frames(w)
		if len(got) != 1 {
			t.Fatalf("frames: %v", got)
		}
		for src := range got {
			if !strings.HasPrefix(src, "https://one.example/") || !strings.Contains(src, "sid=s2") {
				t.Fatalf("frame %s", src)
			}
		}
	})
}

func TestNoFrontchannelUnchangedLogout(t *testing.T) {
	e := newFCEnv(t)
	_, ck := e.session("s1", "u1", "quiet")
	csrf, cc := e.confirm(nil, ck)
	w := e.do("POST", nil, url.Values{"csrf": {csrf}, "client_id": {"app"}, "post_logout_redirect_uri": {cb}}, ck, cc)
	if w.Code != http.StatusFound || w.Header().Get("Location") != cb || w.Header().Get("Refresh") != "" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
}

// Only the sign-out page with frames may frame anything.
func TestFrameSrcNowhereElse(t *testing.T) {
	e := newFCEnv(t)
	_, ck := e.session("s1", "u1", "one")
	pages := map[string]*httptest.ResponseRecorder{
		"confirm":    e.do("GET", nil, nil, ck),
		"signed out": e.do("GET", nil, nil),
		"error":      e.do("GET", url.Values{"id_token_hint": {"junk"}}, nil),
	}
	get := func(path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		return w
	}
	pages["login"] = get(authPath + authQuery(nil).Encode())
	pages["unknown realm"] = get("/realms/nope/account/passkeys")
	for name, w := range pages {
		csp := w.Header().Get("Content-Security-Policy")
		if csp == "" || strings.Contains(csp, "frame-src") || strings.Contains(csp, "child-src") || !strings.Contains(csp, "default-src 'none'") {
			t.Errorf("%s: %q", name, csp)
		}
	}
}

// A stored URI is checked again when it is used.
func TestFrontchannelRevalidatedAtLogout(t *testing.T) {
	e := newFCEnv(t)
	ctx := context.Background()
	// The redirect URI moved to another origin after registration.
	cl, err := e.st.GetClient(ctx, "r", "uuid-one")
	must(t, err)
	cl.RedirectURIs = []string{"https://moved.example/cb"}
	must(t, e.st.UpdateClient(ctx, cl))
	// A disabled client.
	two, err := e.st.GetClient(ctx, "r", "uuid-two")
	must(t, err)
	two.Enabled = false
	must(t, e.st.UpdateClient(ctx, two))
	// Hostile or malformed values written straight into the store.
	for id, uri := range map[string]string{
		"semi":   "https://semi.example;script-src/fc",
		"star":   "https://*.example/fc",
		"plain":  "http://plain.example/fc",
		"scheme": "javascript:alert(1)",
		"v6":     "https://[2001:db8::1]/fc",
	} {
		c := e.fcClient(id, "https://"+id+".example/cb", "")
		c.RedirectURIs = append(c.RedirectURIs, uri)
		must(t, e.st.UpdateClient(ctx, c))
		must(t, e.st.SetFrontchannelLogoutURI(ctx, "r", c.ID, uri))
	}
	_, ck := e.session("s1", "u1", "one", "two", "three", "semi", "star", "plain", "scheme", "v6")
	csrf, cc := e.confirm(nil, ck)
	w := e.do("POST", nil, url.Values{"csrf": {csrf}}, ck, cc)
	got := frames(w)
	if len(got) != 1 {
		t.Fatalf("frames: %v", got)
	}
	if d := cspDirectives(t, w); d["frame-src"] != "https://one.example" || len(d) != 5 {
		t.Errorf("policy: %v", d)
	}
}

func TestFrontchannelSameOriginIsIsolated(t *testing.T) {
	e := newFCEnv(t)
	e.fcClient("self", "https://idp.example/app/cb", "https://idp.example/app/fc")
	_, ck := e.session("s1", "u1", "self")
	csrf, cc := e.confirm(nil, ck)
	w := e.do("POST", nil, url.Values{"csrf": {csrf}}, ck, cc)
	got := frames(w)
	if len(got) != 1 {
		t.Fatalf("frames: %v", got)
	}
	for _, sandbox := range got {
		if sandbox != "allow-scripts" {
			t.Fatalf("a same-origin frame got %q", sandbox)
		}
	}
	if w.Header().Get("Refresh") != "" {
		t.Error("refresh without a redirect")
	}
}

func TestFrontchannelNativeRedirectKept(t *testing.T) {
	e := newFCEnv(t)
	cl := e.fcClient("native", "https://native.example/cb", "https://native.example/fc")
	cl.RedirectURIs = append(cl.RedirectURIs, "com.example.app:/signed-out")
	must(t, e.st.UpdateClient(context.Background(), cl))
	_, ck := e.session("s1", "u1", "native")
	csrf, cc := e.confirm(nil, ck)
	w := e.do("POST", nil, url.Values{"csrf": {csrf}, "client_id": {"native"}, "post_logout_redirect_uri": {"com.example.app:/signed-out"}}, ck, cc)
	if !strings.Contains(w.Body.String(), `href="com.example.app:/signed-out"`) || strings.Contains(w.Body.String(), "ZgotmplZ") {
		t.Fatalf("%s", w.Body.String()[strings.Index(w.Body.String(), "<main"):])
	}
}

func TestFrontchannelDiscovery(t *testing.T) {
	e := newFCEnv(t)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, httptest.NewRequest("GET", "/realms/r/.well-known/openid-configuration", nil))
	var doc map[string]any
	must(t, json.Unmarshal(w.Body.Bytes(), &doc))
	if doc["frontchannel_logout_supported"] != true || doc["frontchannel_logout_session_supported"] != true {
		t.Fatalf("%v", doc)
	}
}
