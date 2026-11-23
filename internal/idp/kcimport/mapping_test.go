// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package kcimport

import (
	"strings"
	"testing"
)

func realmWith(body string) string { return `{"realm":"r",` + body + `}` }

func TestSettingsMapping(t *testing.T) {
	res := conv(t, realmWith(`"registrationAllowed":true,"verifyEmail":false,"bruteForceProtected":true,"sslRequired":"all",
		"accessTokenLifespan":120,"ssoSessionIdleTimeout":900,"eventsEnabled":true,"adminEventsEnabled":true,"revokeRefreshToken":false,"enabled":false`))
	s := res.Spec.Settings
	if s.SelfRegistration == nil || !*s.SelfRegistration || s.EmailVerificationRequired == nil || *s.EmailVerificationRequired ||
		s.BruteForceProtection == nil || !*s.BruteForceProtection || *s.TransportSecurity != "all" ||
		*s.AccessTokenSeconds != 120 || *s.SessionIdleSeconds != 900 || !*s.AuthEvents || !*s.AdminEvents || *s.RefreshTokenRotation {
		t.Errorf("settings = %+v", s)
	}
	if res.Spec.Enabled == nil || *res.Spec.Enabled {
		t.Error("enabled not mapped")
	}
	// unset => unmanaged
	empty := conv(t, `{"realm":"r","clients":[]}`)
	if empty.Spec.Settings.SelfRegistration != nil || empty.Spec.Settings.AccessTokenSeconds != nil || empty.Spec.Settings.PasswordPolicy != nil {
		t.Errorf("unset settings must be nil: %+v", empty.Spec.Settings)
	}
	bad := conv(t, realmWith(`"sslRequired":"sometimes","accessTokenLifespan":0`))
	if bad.Spec.Settings.TransportSecurity != nil || bad.Spec.Settings.AccessTokenSeconds != nil || bad.Report.WarningCounts["realm.ssl_required_unknown"] != 1 {
		t.Errorf("bad values: %+v %v", bad.Spec.Settings, bad.Report.WarningCounts)
	}
}

func TestPasswordPolicy(t *testing.T) {
	cases := []struct {
		in, want string
		dropped  int
	}{
		{"length(12) and digits(1)", "length(12) and digits(1)", 0},
		{"length(8) and notUsername and hashIterations(1000)", "length(8)", 2},
		{"specialChars(1) and lowerCase(2) and upperCase(3)", "specialChars(1) and lowerCase(2) and upperCase(3)", 0},
		{"length(abc) and digits()", "", 2},
		{"notUsername", "", 1},
		{"", "", 0},
	}
	for _, c := range cases {
		res := conv(t, realmWith(`"passwordPolicy":"`+c.in+`"`))
		got := ""
		if p := res.Spec.Settings.PasswordPolicy; p != nil {
			got = *p
		}
		if got != c.want || res.Report.WarningCounts["realm.policy_term_dropped"] != c.dropped {
			t.Errorf("%q => %q (%d dropped), want %q (%d)", c.in, got, res.Report.WarningCounts["realm.policy_term_dropped"], c.want, c.dropped)
		}
	}
}

func TestRolesAndGroups(t *testing.T) {
	res := conv(t, realmWith(`"roles":{"realm":[{"name":"b"},{"name":"a","composite":true},{"name":"offline_access"},{"name":"uma_authorization"},{"name":"default-roles-r"},{"name":"a"},{"name":""}]},
		"groups":[{"name":"z"},{"name":"y","subGroups":[{"name":"c","subGroups":[{"name":"d"}]}]},{"name":"z"}]`))
	if len(res.Spec.Roles) != 2 || res.Spec.Roles[0].Name != "a" || res.Spec.Roles[1].Name != "b" {
		t.Errorf("roles = %+v", res.Spec.Roles)
	}
	if len(res.Spec.Groups) != 2 || res.Spec.Groups[0].Name != "y" {
		t.Errorf("groups = %+v", res.Spec.Groups)
	}
	wc := res.Report.WarningCounts
	want := map[string]int{"role.builtin_skipped": 3, "role.composite_dropped": 1, "role.duplicate": 1, "role.invalid": 1, "group.subgroups_dropped": 1, "group.duplicate": 1}
	for k, v := range want {
		if wc[k] != v {
			t.Errorf("%s = %d, want %d", k, wc[k], v)
		}
	}
}

func TestClientMapping(t *testing.T) {
	cases := []struct {
		name, client string
		emitted      bool
		code         string
	}{
		{"builtin", `{"clientId":"admin-cli"}`, false, "client.builtin_skipped"},
		{"saml", `{"clientId":"s","protocol":"saml"}`, false, "client.saml_skipped"},
		{"other protocol", `{"clientId":"s","protocol":"wsfed"}`, false, "client.protocol_skipped"},
		{"bearer", `{"clientId":"b","bearerOnly":true}`, false, "client.bearer_only_skipped"},
		{"authz", `{"clientId":"a","authorizationServicesEnabled":true}`, false, "client.authorization_skipped"},
		{"implicit", `{"clientId":"i","publicClient":true,"implicitFlowEnabled":true,"redirectUris":["https://a.example/cb"]}`, true, "client.implicit_disabled"},
		{"direct grant", `{"clientId":"d","publicClient":true,"directAccessGrantsEnabled":true,"redirectUris":["https://a.example/cb"]}`, true, "client.direct_grant_disabled"},
		{"wildcard", `{"clientId":"w","publicClient":true,"redirectUris":["https://a.example/*"]}`, true, "client.wildcard_redirect"},
		{"wildcard origin plus", `{"clientId":"w","publicClient":true,"redirectUris":["https://a.example/cb"],"webOrigins":["+"]}`, true, "client.wildcard_origin"},
		{"no redirect", `{"clientId":"n","publicClient":true,"redirectUris":["myapp://cb"]}`, true, "client.no_redirect_uri"},
		{"invalid redirect", `{"clientId":"n","publicClient":true,"redirectUris":["http://example.com/cb"]}`, true, "client.invalid_redirect"},
		{"invalid origin", `{"clientId":"n","publicClient":true,"redirectUris":["https://a.example/cb"],"webOrigins":["https://a.example/path"]}`, true, "client.invalid_origin"},
		{"secret", `{"clientId":"c","secret":"S3CR3T","redirectUris":["https://a.example/cb"]}`, true, "client.new_secret_on_apply"},
		{"public+sa", `{"clientId":"p","publicClient":true,"serviceAccountsEnabled":true,"redirectUris":["https://a.example/cb"]}`, true, "client.public_service_account"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := conv(t, realmWith(`"clients":[`+c.client+`]`))
			if got := len(res.Spec.Clients) == 1; got != c.emitted {
				t.Errorf("emitted = %v", got)
			}
			if res.Report.WarningCounts[c.code] != 1 {
				t.Errorf("warnings = %v, want %s", res.Report.WarningCounts, c.code)
			}
			if err := res.Spec.Validate(); err != nil {
				t.Errorf("invalid spec: %v", err)
			}
		})
	}
	res := conv(t, realmWith(`"clients":[{"clientId":"c","enabled":false,"standardFlowEnabled":false,"redirectUris":["https://a.example/cb","https://a.example/cb"],"attributes":{"pkce.code.challenge.method":"S256"}}]`))
	cl := res.Spec.Clients[0]
	if cl.Enabled == nil || *cl.Enabled || cl.AuthCodeFlow == nil || *cl.AuthCodeFlow || cl.RequirePKCE == nil || !*cl.RequirePKCE || len(cl.RedirectURIs) != 1 {
		t.Errorf("client = %+v", cl)
	}
	if len(res.Report.NewSecretClients) != 1 || res.Report.NewSecretClients[0] != "c" {
		t.Errorf("new secrets = %v", res.Report.NewSecretClients)
	}
}

func TestUserRules(t *testing.T) {
	res := conv(t, realmWith(`"users":[
	 {"username":"b","enabled":true,"groups":["/g","/g/sub","nogroup"],"clientRoles":{"x":["y"]},"federationLink":"abc","requiredActions":["VERIFY_EMAIL","TERMS_AND_CONDITIONS"],
	  "credentials":[{"type":"webauthn"},{"type":"recovery-authn-codes"},{"type":"password","secretData":"{\"value\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"salt\":\"AAAAAAAAAAAAAAAAAAAAAA==\"}","credentialData":"{\"hashIterations\":10000,\"algorithm\":\"pbkdf2-sha256\"}"}]},
	 {"username":"a","enabled":true},
	 {"username":"a"},
	 {"username":""}
	]`))
	if len(res.Users) != 2 || res.Users[0].Username != "a" {
		t.Fatalf("users = %+v", res.Users)
	}
	b := res.Users[1]
	if len(b.Groups) != 1 || b.Groups[0] != "/g" || len(b.RequiredActions) != 1 || b.RequiredActions[0] != "VERIFY_EMAIL" || b.PasswordHash == "" {
		t.Errorf("b = %+v", b)
	}
	wc := res.Report.WarningCounts
	for _, k := range []string{"user.nested_group_dropped:2", "user.client_roles_dropped:1", "user.federation_link_dropped:1", "user.required_action_dropped:1",
		"user.webauthn_not_migrated:1", "user.credential_not_migrated:1", "user.duplicate:1", "user.invalid:1", "user.no_password:1"} {
		name, n, _ := strings.Cut(k, ":")
		if wc[name] != int(n[0]-'0') {
			t.Errorf("%s = %d", name, wc[name])
		}
	}
}

func TestWarningListIsBounded(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"realm":"r","users":[`)
	for i := 0; i < 500; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(`{"username":"u` + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + string(rune('a'+i/26)) + `"}`)
	}
	sb.WriteString(`]}`)
	res := conv(t, sb.String())
	if res.Report.WarningCounts["user.no_password"] != 500 {
		t.Errorf("count = %d", res.Report.WarningCounts["user.no_password"])
	}
	if len(res.Report.Warnings) > maxListedPerCode+5 || !res.Report.WarningsTruncated {
		t.Errorf("listed %d warnings, truncated=%v", len(res.Report.Warnings), res.Report.WarningsTruncated)
	}
}

// A realm that requires verified email locks out unverified users for good
// (no email flow in haven-idp yet): the importer must say so per user, whatever
// order Keycloak wrote the keys in, and must not guess the user is verified.
func TestUnverifiedEmailLockoutWarning(t *testing.T) {
	usersFirst := `{"users":[
	  {"username":"locked","email":"l@x.test","enabled":true,"emailVerified":false,"credentials":[{"type":"password","hashedSaltedValue":"AAAAAAAAAAAAAAAAAAAAAAAAAAA=","salt":"AAAAAAAAAAAAAAAAAAAAAA==","hashIterations":27500,"algorithm":"pbkdf2-sha256"}]},
	  {"username":"fine","email":"f@x.test","enabled":true,"emailVerified":true,"credentials":[{"type":"password","hashedSaltedValue":"AAAAAAAAAAAAAAAAAAAAAAAAAAA=","salt":"AAAAAAAAAAAAAAAAAAAAAA==","hashIterations":27500,"algorithm":"pbkdf2-sha256"}]},
	  {"username":"disabled","enabled":false,"emailVerified":false,"credentials":[{"type":"password","hashedSaltedValue":"AAAAAAAAAAAAAAAAAAAAAAAAAAA=","salt":"AAAAAAAAAAAAAAAAAAAAAA==","hashIterations":27500,"algorithm":"pbkdf2-sha256"}]},
	  {"username":"nopw","enabled":true,"emailVerified":false}
	],"realm":"r","verifyEmail":true}`
	warned := func(res *Result) []string {
		var who []string
		for _, w := range res.Report.Warnings {
			if w.Code == "user.email_unverified_blocked" {
				who = append(who, w.Where)
			}
		}
		return who
	}
	// "verifyEmail" comes AFTER the users here: order must not matter.
	got := warned(conv(t, usersFirst))
	if len(got) != 1 || got[0] != "locked" {
		t.Fatalf("only enabled users with a password and an unverified email are locked out, got %v", got)
	}
	// Not required (or unset): nothing to warn about.
	off := strings.Replace(usersFirst, `"verifyEmail":true`, `"verifyEmail":false`, 1)
	if w := warned(conv(t, off)); len(w) != 0 {
		t.Fatalf("no warning when verification is not required, got %v", w)
	}
	unset := strings.Replace(usersFirst, `,"verifyEmail":true`, "", 1)
	if w := warned(conv(t, unset)); len(w) != 0 {
		t.Fatalf("no warning when the export does not say, got %v", w)
	}
	// Default never marks anyone verified.
	for _, u := range conv(t, usersFirst).Users {
		if u.Username == "locked" && u.EmailVerified {
			t.Fatal("the importer must not mark an email verified on its own")
		}
	}
	// Explicit opt-in marks addresses verified, only where an address exists.
	res, err := Convert(strings.NewReader(usersFirst), Options{TrustEmails: true})
	if err != nil {
		t.Fatal(err)
	}
	if w := warned(res); len(w) != 0 {
		t.Fatalf("with --trust-emails nobody is locked out, got %v", w)
	}
	byName := map[string]bool{}
	for _, u := range res.Users {
		byName[u.Username] = u.EmailVerified
	}
	if !byName["locked"] {
		t.Fatalf("locked must be verified with --trust-emails: %v", byName)
	}
	if byName["nopw"] || byName["disabled"] {
		t.Fatalf("users without an email address must stay unverified: %v", byName)
	}
	if res.Report.WarningCounts["user.emails_marked_verified"] != 1 {
		t.Fatalf("the opt-in must be reported: %v", res.Report.WarningCounts)
	}
}
