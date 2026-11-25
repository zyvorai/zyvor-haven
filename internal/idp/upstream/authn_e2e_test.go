// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package upstream_test

import (
	"context"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/oidc"
)

const fedRes = "https://mcp.example/mcp"

// brokered runs a federated login for the /auth query plus extra parameters.
func (f *fed) brokered(extra url.Values) (*browser, *http.Response, string) {
	f.t.Helper()
	q := authQuery()
	if len(extra) > 0 {
		q += "&" + extra.Encode()
	}
	b := f.newBrowser()
	resp, body := b.get(f.srv.URL + "/realms/" + realm + "/broker/fake/login?" + q)
	if resp.StatusCode != http.StatusFound {
		return b, resp, body
	}
	resp, body = b.get(f.callbackURL(resp.Header.Get("Location"), goodClaims()))
	return b, resp, body
}

func TestBrokeredLoginAuthenticationContext(t *testing.T) {
	f := newFed(t, fedOpts{})
	_, resp, body := f.brokered(url.Values{"acr_values": {core.ACRSingleFactor}})
	out := f.tokenExchange(succeeded(t, resp, body))
	for _, k := range []string{"access_token", "id_token"} {
		c := jwtClaims(t, out[k].(string))
		if c["acr"] != core.ACRSingleFactor || fmt.Sprint(c["amr"]) != "[fed]" || c["auth_time"] == nil {
			t.Fatalf("%s: %v", k, c)
		}
	}
	// The upstream cannot satisfy a stronger level: no code, no downgrade.
	for name, extra := range map[string]url.Values{
		"acr_values": {"acr_values": {core.ACRMultiFactor}},
		"claims":     {"claims": {`{"id_token":{"acr":{"essential":true,"values":["` + core.ACRMultiFactor + `"]}}}`}},
	} {
		_, resp, body = f.brokered(extra)
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusFound || loc.Query().Get("error") != "unmet_authentication_requirements" || loc.Query().Get("code") != "" {
			t.Fatalf("brokered step-up (%s): %d %s %s", name, resp.StatusCode, resp.Header.Get("Location"), body)
		}
	}
}

func TestBrokeredLoginBindsResourcesAndAsksConsent(t *testing.T) {
	f := newFed(t, fedOpts{resources: &oidc.ResourcePolicy{Realms: map[string]oidc.RealmResources{realm: {Resources: []string{fedRes}}}}})
	res := url.Values{"resource": {fedRes}}
	_, resp, body := f.brokered(res)
	out := f.tokenExchange(succeeded(t, resp, body))
	if got := fmt.Sprint(jwtClaims(t, out["access_token"].(string))["aud"]); got != "[app "+fedRes+"]" {
		t.Fatalf("a brokered login lost the resource: aud = %s", got)
	}
	// Off the allow-list: refused before going upstream.
	_, resp, _ = f.brokered(url.Values{"resource": {"https://evil.example/mcp"}})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("evil resource: %d", resp.StatusCode)
	}

	// With consent required, the screen shown after the upstream login posts
	// back to /auth with the original request.
	cs, _ := core.StoreAs[core.ConsentStore](f.st)
	if err := cs.PutConsentPolicy(context.Background(), core.ConsentPolicy{Realm: realm, RequireAll: true}); err != nil {
		t.Fatal(err)
	}
	b, resp, page := f.brokered(res)
	if resp.StatusCode != 200 || !strings.Contains(page, "consent_decision") || !strings.Contains(page, fedRes) {
		t.Fatalf("consent after broker: %d %s", resp.StatusCode, page)
	}
	field := func(name string) string {
		m := regexp.MustCompile(`name="` + name + `" value="([^"]+)"`).FindStringSubmatch(page)
		if m == nil {
			t.Fatalf("no %s in %s", name, page)
		}
		return m[1]
	}
	am := regexp.MustCompile(`<form method="post" action="([^"]+)"`).FindStringSubmatch(page)
	if am == nil || !strings.HasPrefix(html.UnescapeString(am[1]), "/realms/"+realm+"/protocol/openid-connect/auth?") {
		t.Fatalf("consent form target: %v", am)
	}
	r, err := b.c.PostForm(f.srv.URL+html.UnescapeString(am[1]), url.Values{"csrf": {field("csrf")},
		"consent_proof": {field("consent_proof")}, "consent_decision": {"allow"}, "consent_scope": {"email"}})
	if err != nil {
		t.Fatal(err)
	}
	rb, _ := io.ReadAll(r.Body)
	_ = r.Body.Close()
	out = f.tokenExchange(succeeded(t, r, string(rb)))
	c := jwtClaims(t, out["access_token"].(string))
	if out["scope"] != "openid email" || fmt.Sprint(c["aud"]) != "[app "+fedRes+"]" || fmt.Sprint(c["amr"]) != "[fed]" || c["preferred_username"] != nil {
		t.Fatalf("%v %v", out["scope"], c)
	}
}
