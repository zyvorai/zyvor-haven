// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package upstream_test

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/safehttp"
	"github.com/zyvorai/haven/internal/idp/upstream"
	"github.com/zyvorai/haven/internal/idp/upstream/upstreamtest"
)

func TestParseConfigPresets(t *testing.T) {
	tid := "11111111-2222-3333-4444-555555555555"
	cases := []struct {
		name    string
		typ     string
		cfg     map[string]string
		issuer  string
		multi   bool
		wantErr string
	}{
		{"google", "google", map[string]string{"clientId": "c"}, "https://accounts.google.com", false, ""},
		{"google custom issuer", "google", map[string]string{"clientId": "c", "issuer": "https://evil.example"}, "", false, "fixed"},
		{"google hosted domain", "google", map[string]string{"clientId": "c", "hostedDomain": "Corp.Example"}, "https://accounts.google.com", false, ""},
		{"google bad domain", "google", map[string]string{"clientId": "c", "hostedDomain": "not a domain"}, "", false, "hostedDomain"},
		{"microsoft default is multi-tenant", "microsoft", map[string]string{"clientId": "c"}, "https://login.microsoftonline.com/{tenantid}/v2.0", true, ""},
		{"microsoft organizations", "microsoft", map[string]string{"clientId": "c", "tenant": "organizations"}, "https://login.microsoftonline.com/{tenantid}/v2.0", true, ""},
		{"microsoft tenant guid", "microsoft", map[string]string{"clientId": "c", "tenant": tid}, "https://login.microsoftonline.com/" + tid + "/v2.0", false, ""},
		{"microsoft tenant domain", "microsoft", map[string]string{"clientId": "c", "tenant": "contoso.com"}, "", false, "tenant"},
		{"microsoft multi-tenant link by email", "microsoft", map[string]string{"clientId": "c", "linkExistingByEmail": "true"}, "", false, "multi-tenant"},
		{"microsoft concrete link by email", "microsoft", map[string]string{"clientId": "c", "tenant": tid, "linkExistingByEmail": "true"}, "https://login.microsoftonline.com/" + tid + "/v2.0", false, ""},
		{"oidc", "oidc", map[string]string{"clientId": "c", "issuer": "https://idp.example/realms/x"}, "https://idp.example/realms/x", false, ""},
		{"oidc discovery only", "oidc", map[string]string{"clientId": "c", "discoveryUrl": "https://idp.example/r/.well-known/openid-configuration"}, "https://idp.example/r", false, ""},
		{"oidc http", "oidc", map[string]string{"clientId": "c", "issuer": "http://idp.example"}, "", false, "https"},
		{"oidc nothing", "oidc", map[string]string{"clientId": "c"}, "", false, "issuer"},
		{"github", "github", map[string]string{"clientId": "c"}, "", false, "providerId"},
		{"saml", "saml", map[string]string{"clientId": "c"}, "", false, "providerId"},
		{"unknown key", "oidc", map[string]string{"clientId": "c", "issuer": "https://i.example", "clientsecret": "x"}, "", false, "unknown config key"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, canon, err := upstream.ParseConfig(c.typ, c.cfg, false)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("want error containing %q, got %v", c.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s.Issuer != c.issuer || s.MultiTenant() != c.multi {
				t.Fatalf("issuer %q multi=%v", s.Issuer, s.MultiTenant())
			}
			if _, ok := canon["clientSecret"]; ok {
				t.Fatal("clientSecret in the canonical config")
			}
			if canon["autoCreateUsers"] != "false" || canon["linkExistingByEmail"] == "" || canon["scopes"] != "openid email profile" {
				t.Fatalf("defaults not explicit: %v", canon)
			}
		})
	}
	// Loopback http only with allowPrivate.
	if _, _, err := upstream.ParseConfig("oidc", map[string]string{"clientId": "c", "issuer": "http://127.0.0.1:9000/realms/x"}, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := upstream.ParseConfig("oidc", map[string]string{"clientId": "c", "issuer": "http://idp.example"}, true); err == nil {
		t.Fatal("allowPrivate must not allow http to a public host")
	}
}

func TestRoleRules(t *testing.T) {
	for _, bad := range []string{`{}`, `[{"claim":"","value":"v","roles":["r"]}]`, `[{"claim":"c","value":"","roles":["r"]}]`,
		`[{"claim":"c","value":"v","roles":[]}]`, `[{"claim":"c","value":"v","roles":["bad name"]}]`, `[{"claim":"c","value":"v","roles":["r"],"extra":1}]`, `not json`} {
		if _, err := upstream.ParseRules(bad); err == nil {
			t.Errorf("accepted %s", bad)
		}
	}
	rules, err := upstream.ParseRules(`[{"claim":"groups","value":"a","roles":["x","y"]},{"claim":"groups","value":"b","roles":["y","z"]},{"claim":"o.p","value":"1","roles":["n"]},{"claim":"s","value":"v","roles":["s1"]}]`)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"groups": []any{"b", "a"}, "o": map[string]any{"p": json.Number("1")}, "s": "other"}
	if got := upstream.MapRoles(rules, claims); !reflect.DeepEqual(got, []string{"n", "x", "y", "z"}) {
		t.Fatalf("roles %v", got)
	}
	if got := upstream.MapRoles(rules, map[string]any{"groups": "a"}); !reflect.DeepEqual(got, []string{"x", "y"}) {
		t.Fatalf("scalar claim: %v", got)
	}
	if got := upstream.MapRoles(rules, map[string]any{"groups": "ab"}); len(got) != 0 {
		t.Fatalf("substring must not match: %v", got)
	}
}

// Multi-tenant Microsoft: the issuer contains the tenant id, so it is matched
// against the token's tid claim.
func TestMicrosoftMultiTenantIssuer(t *testing.T) {
	up := upstreamtest.New(t)
	m := upstream.NewManager(safehttp.Options{AllowPrivate: true, RootCAs: up.Pool}, nil)
	spec := upstream.Spec{Type: upstream.TypeMicrosoft, Issuer: "https://login.microsoftonline.com/{tenantid}/v2.0", ClientID: up.ClientID, Tenant: "common"}
	if !spec.MultiTenant() {
		t.Fatal("not multi-tenant")
	}
	disc := &upstream.Discovery{JWKSURI: up.URL() + "/jwks"}
	tid := "11111111-2222-3333-4444-555555555555"
	now := time.Now()
	mk := func(mut func(c map[string]any)) string {
		c := map[string]any{"iss": "https://login.microsoftonline.com/" + tid + "/v2.0", "tid": tid, "aud": up.ClientID, "sub": "s", "nonce": "n",
			"iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
		if mut != nil {
			mut(c)
		}
		return up.Mint(c)
	}
	ctx := context.Background()
	cl, err := m.VerifyIDToken(ctx, spec, disc, mk(nil), "n")
	if err != nil {
		t.Fatal(err)
	}
	if got := upstream.Subject(spec, cl); got != tid+"/s" {
		t.Fatalf("multi-tenant subject %q must be tenant-qualified", got)
	}
	for name, mut := range map[string]func(map[string]any){
		"iss of another tenant": func(c map[string]any) {
			c["iss"] = "https://login.microsoftonline.com/99999999-2222-3333-4444-555555555555/v2.0"
		},
		"no tid":                   func(c map[string]any) { delete(c, "tid") },
		"tid not a guid":           func(c map[string]any) { c["tid"] = "../evil" },
		"iss with the placeholder": func(c map[string]any) { c["iss"] = "https://login.microsoftonline.com/{tenantid}/v2.0" },
		"issuer of another host":   func(c map[string]any) { c["iss"] = "https://evil.example/" + tid + "/v2.0" },
	} {
		if _, err := m.VerifyIDToken(ctx, spec, disc, mk(mut), "n"); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// Entra has no email_verified: only xms_edov counts.
	if upstream.EmailVerified(spec, upstream.Claims{"email_verified": true}) {
		t.Error("email_verified must not count for microsoft")
	}
	if !upstream.EmailVerified(spec, upstream.Claims{"xms_edov": true}) {
		t.Error("xms_edov=true must count for microsoft")
	}
	if upstream.EmailVerified(upstream.Spec{Type: upstream.TypeOIDC}, upstream.Claims{"xms_edov": true}) {
		t.Error("xms_edov must not count for oidc")
	}
}

func TestGoogleIssuerAndHostedDomain(t *testing.T) {
	up := upstreamtest.New(t)
	m := upstream.NewManager(safehttp.Options{AllowPrivate: true, RootCAs: up.Pool}, nil)
	spec := upstream.Spec{Type: upstream.TypeGoogle, Issuer: upstream.GoogleIssuer, ClientID: up.ClientID, HostedDomain: "corp.example"}
	disc := &upstream.Discovery{JWKSURI: up.URL() + "/jwks"}
	now := time.Now()
	mk := func(iss, hd string) string {
		c := map[string]any{"iss": iss, "aud": up.ClientID, "sub": "s", "nonce": "n", "iat": now.Unix(), "exp": now.Add(time.Minute).Unix()}
		if hd != "" {
			c["hd"] = hd
		}
		return up.Mint(c)
	}
	ctx := context.Background()
	if _, err := m.VerifyIDToken(ctx, spec, disc, mk("accounts.google.com", "Corp.Example"), "n"); err != nil {
		t.Fatalf("google's scheme-less issuer must be accepted: %v", err)
	}
	if _, err := m.VerifyIDToken(ctx, spec, disc, mk("https://accounts.google.com", "other.example"), "n"); err == nil {
		t.Fatal("wrong hosted domain accepted")
	}
	if _, err := m.VerifyIDToken(ctx, spec, disc, mk("https://accounts.google.com", ""), "n"); err == nil {
		t.Fatal("missing hd accepted although a hosted domain is required")
	}
	// The scheme-less issuer is Google-only.
	oidcSpec := upstream.Spec{Type: upstream.TypeOIDC, Issuer: "https://accounts.google.com", ClientID: up.ClientID}
	if _, err := m.VerifyIDToken(ctx, oidcSpec, disc, mk("accounts.google.com", ""), "n"); err == nil {
		t.Fatal("scheme-less issuer accepted for a generic provider")
	}
}

func TestVerifyIDTokenStructure(t *testing.T) {
	up := upstreamtest.New(t)
	m := upstream.NewManager(safehttp.Options{AllowPrivate: true, RootCAs: up.Pool}, nil)
	spec := upstream.Spec{Type: upstream.TypeOIDC, Issuer: up.URL(), ClientID: up.ClientID}
	disc := &upstream.Discovery{JWKSURI: up.URL() + "/jwks"}
	ctx := context.Background()
	for _, tok := range []string{"", "a.b", "a.b.c.d", "....", strings.Repeat("a", 20000), "e30.e30.e30"} {
		if _, err := m.VerifyIDToken(ctx, spec, disc, tok, "n"); err == nil {
			t.Errorf("accepted %.20q", tok)
		}
	}
}

func TestSafeHTTP(t *testing.T) {
	up := upstreamtest.New(t)
	// Policy on: the loopback test server is refused at dial time.
	strict := safehttp.New(safehttp.Options{RootCAs: up.Pool, Timeout: time.Second})
	req, _ := newReq(up.URL() + "/jwks")
	if _, _, err := strict.Fetch(req); !safehttp.IsBlocked(err) {
		t.Fatalf("loopback must be blocked, got %v", err)
	}
	// Policy off: works, and the body limit is enforced.
	open := safehttp.New(safehttp.Options{AllowPrivate: true, RootCAs: up.Pool, MaxBody: 10})
	req, _ = newReq(up.URL() + "/jwks")
	if _, _, err := open.Fetch(req); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("body limit not enforced: %v", err)
	}
	open = safehttp.New(safehttp.Options{AllowPrivate: true, RootCAs: up.Pool})
	req, _ = newReq(up.URL() + "/jwks")
	if st, body, err := open.Fetch(req); err != nil || st != 200 || len(body) == 0 {
		t.Fatalf("fetch: %d %v", st, err)
	}
	// Without the test CA the TLS handshake fails (no insecure skip).
	noCA := safehttp.New(safehttp.Options{AllowPrivate: true})
	req, _ = newReq(up.URL() + "/jwks")
	if _, _, err := noCA.Fetch(req); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	for _, bad := range []string{"http://idp.example", "https://u:p@idp.example", "https://idp.example/#f", "ftp://x", "https://", "https://a b", "javascript:alert(1)"} {
		if _, err := safehttp.ValidateURL(bad, false, "url", 512); err == nil {
			t.Errorf("ValidateURL accepted %q", bad)
		}
	}
	if _, err := safehttp.ValidateURL("http://localhost:8080/x", true, "url", 512); err != nil {
		t.Errorf("loopback http with allowPrivate: %v", err)
	}
	if _, err := safehttp.ValidateURL("http://localhost:8080/x", false, "url", 512); err == nil {
		t.Error("loopback http without allowPrivate accepted")
	}
}

func newReq(u string) (*http.Request, error) { return http.NewRequest(http.MethodGet, u, nil) }
