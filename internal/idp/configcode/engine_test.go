// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package configcode

import (
	"context"
	"errors"
	"math/rand"
	"reflect"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp"
)

func bp(b bool) *bool     { return &b }
func sp(s string) *string { return &s }
func ip(i int) *int       { return &i }
func okSpec() *Spec {
	return &Spec{
		APIVersion: APIVersion, Kind: KindRealm, Realm: "acme", DisplayName: "Acme", Enabled: bp(true),
		Settings: Settings{
			SelfRegistration: bp(false), EmailVerificationRequired: bp(true), BruteForceProtection: bp(true),
			TransportSecurity: sp("all"), PasswordPolicy: sp("length(14)"), AccessTokenSeconds: ip(600),
			SessionIdleSeconds: ip(900), AuthEvents: bp(true), AdminEvents: bp(true), RefreshTokenRotation: bp(true),
		},
		Roles:  []Role{{Name: "viewer", Description: "read only"}, {Name: "admin"}},
		Groups: []Group{{Name: "staff"}, {Name: "ops"}},
		Clients: []Client{
			{ClientID: "web", Name: "Web", Public: true, RedirectURIs: []string{"https://b.example/cb", "https://a.example/cb"}, Origins: []string{"https://a.example"}},
			{ClientID: "api", Name: "API", ServiceAccount: true},
			{ClientID: "portal", Name: "Portal", RedirectURIs: []string{"http://localhost:3000/cb"}},
		},
	}
}

func TestParse(t *testing.T) {
	good := "apiVersion: haven.zyvor.dev/v1\nkind: Realm\nrealm: acme\nclients:\n- clientId: web\n  public: true\n"
	if s, err := Parse(strings.NewReader(good)); err != nil || s.Clients[0].ClientID != "web" {
		t.Fatalf("good: %v %+v", err, s)
	}
	if _, err := Parse(strings.NewReader("---\n" + good)); err != nil {
		t.Fatalf("leading marker: %v", err)
	}
	cases := map[string]string{
		"unknown field":  good + "bogus: 1\n",
		"unknown nested": good + "  nope: 1\n",
		"duplicate doc":  good + "---\n" + good,
		"empty":          "# only a comment\n",
		"bad yaml":       "apiVersion: [unclosed\n",
		"oversize":       good + "# " + strings.Repeat("x", MaxSpecBytes) + "\n",
		"invalid":        "apiVersion: nope\nkind: Realm\nrealm: acme\n",
	}
	for name, in := range cases {
		if _, err := Parse(strings.NewReader(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestMarshalRoundTripStable(t *testing.T) {
	a, err := Marshal(okSpec())
	if err != nil {
		t.Fatal(err)
	}
	shuffled := okSpec()
	shuffled.Clients[0], shuffled.Clients[2] = shuffled.Clients[2], shuffled.Clients[0]
	b, _ := Marshal(shuffled)
	if string(a) != string(b) {
		t.Fatalf("not canonical:\n%s\n%s", a, b)
	}
	back, err := Parse(strings.NewReader(string(a)))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(normalized(back), normalized(okSpec())) {
		t.Fatal("round trip differs")
	}
}

func TestValidate(t *testing.T) {
	mut := func(f func(s *Spec)) *Spec { s := okSpec(); f(s); return s }
	cases := []struct {
		name string
		s    *Spec
		want string
	}{
		{"ok", okSpec(), ""},
		{"apiVersion", mut(func(s *Spec) { s.APIVersion = "x" }), "apiVersion"},
		{"kind", mut(func(s *Spec) { s.Kind = "x" }), "kind"},
		{"realm", mut(func(s *Spec) { s.Realm = "Bad Realm" }), "realm"},
		{"dup role", mut(func(s *Spec) { s.Roles = append(s.Roles, Role{Name: "admin"}) }), "roles[2].name"},
		{"dup group", mut(func(s *Spec) { s.Groups = append(s.Groups, Group{Name: "ops"}) }), "groups[2].name"},
		{"dup client", mut(func(s *Spec) { s.Clients[1].ClientID = "web" }), "clients[1].clientId"},
		{"empty client", mut(func(s *Spec) { s.Clients[1].ClientID = "" }), "clients[1].clientId"},
		{"wildcard", mut(func(s *Spec) { s.Clients[0].RedirectURIs[0] = "https://*.example/cb" }), "clients[0].redirectUris[0]"},
		{"http remote", mut(func(s *Spec) { s.Clients[2].RedirectURIs[0] = "http://evil.example/cb" }), "clients[2].redirectUris[0]"},
		{"scheme", mut(func(s *Spec) { s.Clients[2].RedirectURIs[0] = "ftp://x.example/cb" }), "clients[2].redirectUris[0]"},
		{"origin path", mut(func(s *Spec) { s.Clients[0].Origins[0] = "https://a.example/x" }), "clients[0].origins[0]"},
		{"origin star", mut(func(s *Spec) { s.Clients[0].Origins[0] = "*" }), "clients[0].origins[0]"},
		{"transport", mut(func(s *Spec) { s.Settings.TransportSecurity = sp("sometimes") }), "settings.transportSecurity"},
		{"ttl", mut(func(s *Spec) { s.Settings.AccessTokenSeconds = ip(0) }), "settings.accessTokenSeconds"},
		{"idle", mut(func(s *Spec) { s.Settings.SessionIdleSeconds = ip(-1) }), "settings.sessionIdleSeconds"},
		{"pkce off", mut(func(s *Spec) { s.Clients[0].RequirePKCE = bp(false) }), "clients[0].requirePKCE"},
		{"public sa", mut(func(s *Spec) { s.Clients[1].Public = true }), "clients[1].serviceAccount"},
	}
	for _, c := range cases {
		err := c.s.Validate()
		if c.want == "" {
			if err != nil {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: want %q in %v", c.name, c.want, err)
		}
	}
	s := okSpec()
	s.APIVersion, s.Realm = "x", "!"
	s.Clients[0].RedirectURIs[0] = "*"
	s.Settings.AccessTokenSeconds = ip(0)
	err := s.Validate()
	for _, w := range []string{"apiVersion", "realm", "clients[0].redirectUris[0]", "accessTokenSeconds"} {
		if err == nil || !strings.Contains(err.Error(), w) {
			t.Errorf("joined errors missing %q: %v", w, err)
		}
	}
}

func applyAll(t *testing.T, p idp.Provider, s *Spec, o Options) *ApplyResult {
	t.Helper()
	live, err := Read(context.Background(), p, s.Realm)
	if err != nil {
		if !errors.Is(err, idp.ErrNotFound) {
			t.Fatal(err)
		}
		live = nil
	}
	res, err := Apply(context.Background(), p, Diff(s, live, o), s)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	return res
}

func TestRoundTripIdempotent(t *testing.T) {
	for name, mk := range map[string]func(*fakeProvider) idp.Provider{
		"plain":         func(f *fakeProvider) idp.Provider { return f },
		"secretcreator": func(f *fakeProvider) idp.Provider { return fakeSC{f} },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake()
			p := mk(f)
			spec := okSpec()
			// A built-in and the admin client must be invisible.
			res := applyAll(t, p, spec, Options{})
			f.clients["acme"] = append(f.clients["acme"], idp.Client{ID: "b", ClientID: "account", Enabled: true}, idp.Client{ID: "h", ClientID: "haven-admin", Enabled: true})
			got, err := Read(context.Background(), p, "acme")
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, normalized(spec)) {
				t.Fatalf("read != spec\n got %+v\nwant %+v", got, normalized(spec))
			}
			if plan := Diff(spec, got, Options{Prune: true}); len(plan.Changes) != 0 {
				t.Fatalf("second diff not empty: %+v", plan.Changes)
			}
			if name == "secretcreator" && len(res.NewSecrets) != 2 { // api and portal
				t.Fatalf("secrets: %v", res.NewSecrets)
			}
			if name == "plain" && len(res.NewSecrets) != 2 {
				t.Fatalf("unexpected secrets: %v", res.NewSecrets)
			}
		})
	}
}

func TestReadNotFound(t *testing.T) {
	if _, err := Read(context.Background(), newFake(), "nope"); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestDiffCreateOnly(t *testing.T) {
	plan := Diff(okSpec(), nil, Options{})
	if !plan.RealmMissing || plan.Realm != "acme" {
		t.Fatalf("%+v", plan)
	}
	var got []string
	for _, c := range plan.Changes {
		if c.Action != ActionCreate {
			t.Errorf("non-create %+v", c)
		}
		got = append(got, c.Kind+":"+c.Name)
	}
	want := []string{"realm:acme", "role:admin", "role:viewer", "group:ops", "group:staff", "client:api", "client:portal", "client:web"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("order\n got %v\nwant %v", got, want)
	}
}

func liveOf(t *testing.T, s *Spec) *Spec {
	t.Helper()
	f := newFake()
	applyAll(t, f, s, Options{})
	live, err := Read(context.Background(), f, s.Realm)
	if err != nil {
		t.Fatal(err)
	}
	return live
}

func TestDiffUpdatesAndDefaults(t *testing.T) {
	live := liveOf(t, okSpec())
	// A file that omits defaults shows no drift against the live state.
	d := okSpec()
	if plan := Diff(d, live, Options{}); len(plan.Changes) != 0 {
		t.Fatalf("drift: %+v", plan.Changes)
	}
	d.Settings.AccessTokenSeconds = ip(300)
	d.Clients[0].RedirectURIs = []string{"https://c.example/cb", "https://a.example/cb"}
	d.Clients[1].Enabled = bp(false)
	plan := Diff(d, live, Options{})
	if len(plan.Changes) != 3 {
		t.Fatalf("%+v", plan.Changes)
	}
	c0 := plan.Changes[0]
	if c0.Kind != KindOfRealm || c0.Action != ActionUpdate || !reflect.DeepEqual(c0.Fields, []FieldChange{{Field: "settings.accessTokenSeconds", Old: "600", New: "300"}}) {
		t.Fatalf("realm change %+v", c0)
	}
	if plan.Changes[1].Name != "api" || plan.Changes[1].Fields[0] != (FieldChange{Field: "enabled", Old: "true", New: "false"}) {
		t.Fatalf("api %+v", plan.Changes[1])
	}
	if plan.Changes[2].Name != "web" || plan.Changes[2].Fields[0].New != "https://a.example/cb, https://c.example/cb" {
		t.Fatalf("web %+v", plan.Changes[2])
	}
	// URI order does not matter.
	d2 := okSpec()
	d2.Clients[0].RedirectURIs = []string{"https://a.example/cb", "https://b.example/cb"}
	if plan := Diff(d2, live, Options{}); len(plan.Changes) != 0 {
		t.Fatalf("order drift: %+v", plan.Changes)
	}
}

func TestDiffUnmanagedIgnored(t *testing.T) {
	live := liveOf(t, okSpec())
	d := &Spec{APIVersion: APIVersion, Kind: KindRealm, Realm: "acme"}
	if plan := Diff(d, live, Options{}); len(plan.Changes) != 0 {
		t.Fatalf("unmanaged produced changes: %+v", plan.Changes)
	}
}

func TestDiffPrune(t *testing.T) {
	live := liveOf(t, okSpec())
	live.Clients = append(live.Clients,
		Client{ClientID: "old"}, Client{ClientID: "account"}, Client{ClientID: "haven-admin"})
	live.Roles = append(live.Roles, Role{Name: "stale"})
	live.Groups = append(live.Groups, Group{Name: "stale"})
	d := okSpec()
	if plan := Diff(d, live, Options{}); len(plan.Changes) != 0 {
		t.Fatalf("prune off: %+v", plan.Changes)
	}
	plan := Diff(d, live, Options{Prune: true})
	if len(plan.Changes) != 1 || !reflect.DeepEqual(plan.Changes[0], Change{Action: ActionDelete, Kind: KindOfClient, Name: "old"}) {
		t.Fatalf("prune on: %+v", plan.Changes)
	}
}

func TestDiffDeterministic(t *testing.T) {
	live := liveOf(t, okSpec())
	d := okSpec()
	d.Roles = append(d.Roles, Role{Name: "z"}, Role{Name: "a"})
	d.Clients = append(d.Clients, Client{ClientID: "new2"}, Client{ClientID: "new1"})
	d.Clients[0].Name = "changed"
	want := Diff(d, live, Options{Prune: true})
	r := rand.New(rand.NewSource(1))
	for i := 0; i < 30; i++ {
		s := okSpec()
		s.Roles, s.Clients = d.Roles, append([]Client(nil), d.Clients...)
		r.Shuffle(len(s.Clients), func(a, b int) { s.Clients[a], s.Clients[b] = s.Clients[b], s.Clients[a] })
		r.Shuffle(len(s.Roles), func(a, b int) { s.Roles[a], s.Roles[b] = s.Roles[b], s.Roles[a] })
		l := *live
		l.Clients = append([]Client(nil), live.Clients...)
		r.Shuffle(len(l.Clients), func(a, b int) { l.Clients[a], l.Clients[b] = l.Clients[b], l.Clients[a] })
		if got := Diff(s, &l, Options{Prune: true}); !reflect.DeepEqual(got, want) {
			t.Fatalf("nondeterministic\n got %+v\nwant %+v", got, want)
		}
	}
}

func TestApplyOrderAndSecrets(t *testing.T) {
	f := newFake()
	res := applyAll(t, fakeSC{f}, okSpec(), Options{})
	want := []string{"CreateRealm", "CreateRole:admin", "CreateRole:viewer", "CreateGroup:ops", "CreateGroup:staff",
		"CreateClientWithSecret:api", "CreateClientWithSecret:portal", "CreateClient:web"}
	if got := f.callLog(); !reflect.DeepEqual(got, want) {
		t.Fatalf("calls\n got %v\nwant %v", got, want)
	}
	if res.NewSecrets["api"] != "s3cr3t-api" || res.NewSecrets["portal"] != "s3cr3t-portal" || len(res.NewSecrets) != 2 {
		t.Fatalf("%v", res.NewSecrets)
	}
	if len(res.Applied) != len(want) {
		t.Fatalf("applied %d", len(res.Applied))
	}
	// Second run is a no-op that yields no secrets.
	f.calls = nil
	res = applyAll(t, fakeSC{f}, okSpec(), Options{})
	if len(f.callLog()) != 0 || len(res.NewSecrets) != 0 {
		t.Fatalf("not idempotent: %v %v", f.callLog(), res.NewSecrets)
	}
}

func TestApplyUpdateAndPrune(t *testing.T) {
	f := newFake()
	applyAll(t, f, okSpec(), Options{})
	d := okSpec()
	d.Clients = d.Clients[:2] // drop portal
	d.Clients[0].Origins = []string{"https://z.example"}
	for i := range f.clients["acme"] {
		if f.clients["acme"][i].ClientID == "web" {
			f.clients["acme"][i].Attributes = map[string]string{"custom": "keep", pkceAttr: "S256"}
		}
	}
	applyAll(t, f, d, Options{Prune: true})
	var haveWeb, havePortal bool
	for _, c := range f.clients["acme"] {
		if c.ClientID == "portal" {
			havePortal = true
		}
		if c.ClientID == "web" {
			haveWeb = true
			if !reflect.DeepEqual(c.WebOrigins, []string{"https://z.example"}) || c.Attributes["custom"] != "keep" || c.Attributes[pkceAttr] != "S256" {
				t.Fatalf("web %+v", c)
			}
		}
	}
	if !haveWeb || havePortal {
		t.Fatalf("clients %+v", f.clients["acme"])
	}
}

func TestApplyRaceConflictIsSuccess(t *testing.T) {
	f := newFake()
	f.fail = func(call string) error {
		if call == "CreateRole:admin" || call == "CreateClient:web" {
			return statusErr(409, "exists")
		}
		return nil
	}
	if _, err := Apply(context.Background(), f, Diff(okSpec(), nil, Options{}), okSpec()); err != nil {
		t.Fatal(err)
	}
}

func TestApplyStopsAtFirstError(t *testing.T) {
	f := newFake()
	f.fail = func(call string) error {
		if call == "CreateGroup:ops" {
			return statusErr(500, "boom")
		}
		return nil
	}
	spec := okSpec()
	res, err := Apply(context.Background(), fakeSC{f}, Diff(spec, nil, Options{}), spec)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err %v", err)
	}
	if res == nil || len(res.Applied) != 3 { // realm, 2 roles
		t.Fatalf("applied %+v", res)
	}
	for _, c := range f.callLog() {
		if strings.Contains(c, "Client") {
			t.Fatalf("continued after error: %v", f.callLog())
		}
	}
}

func TestApplySecretNotInError(t *testing.T) {
	f := newFake()
	f.fail = func(call string) error {
		if call == "CreateClient:web" {
			return statusErr(500, "failure leaked s3cr3t-api token")
		}
		return nil
	}
	spec := okSpec()
	res, err := Apply(context.Background(), fakeSC{f}, Diff(spec, nil, Options{}), spec)
	if err == nil {
		t.Fatal("want error")
	}
	if res.NewSecrets["api"] != "s3cr3t-api" {
		t.Fatalf("partial secrets lost: %v", res.NewSecrets)
	}
	for _, s := range res.NewSecrets {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("secret in error: %v", err)
		}
	}
	if idp.AsStatus(err) == nil {
		t.Fatal("error should still unwrap to StatusError")
	}
}

func TestApplyPartialRealmUpdateKeepsUnmanaged(t *testing.T) {
	f := newFake()
	applyAll(t, f, okSpec(), Options{})
	r := f.realms["acme"]
	r.RegistrationAllowed = true
	r.DisplayName = "Live Name"
	pol := "length(20)"
	r.PasswordPolicy = &pol
	live, _ := Read(context.Background(), f, "acme")
	d := &Spec{APIVersion: APIVersion, Kind: KindRealm, Realm: "acme", Settings: Settings{AccessTokenSeconds: ip(120)}}
	plan := Diff(d, live, Options{})
	if len(plan.Changes) != 1 {
		t.Fatalf("%+v", plan.Changes)
	}
	if _, err := Apply(context.Background(), f, plan, d); err != nil {
		t.Fatal(err)
	}
	got := f.realms["acme"]
	if *got.AccessTokenLifespan != 120 || !got.RegistrationAllowed || got.DisplayName != "Live Name" ||
		*got.PasswordPolicy != "length(20)" || *got.SSLRequired != "all" || !got.BruteForceProtected || !got.VerifyEmail {
		t.Fatalf("unmanaged settings were reset: %+v %+v", got, got.RealmHardening)
	}
}

func TestApplyRefusesProtectedDelete(t *testing.T) {
	f := newFake()
	spec := okSpec()
	applyAll(t, f, spec, Options{})
	plan := &Plan{Realm: "acme", Changes: []Change{{Action: ActionDelete, Kind: KindOfClient, Name: "haven-admin"}}}
	if _, err := Apply(context.Background(), f, plan, spec); err == nil {
		t.Fatal("expected refusal")
	}
}

func TestFakeRejectsWildcard(t *testing.T) {
	f := newFake()
	_ = f.CreateRealm(context.Background(), idp.Realm{Realm: "r"})
	err := f.CreateClient(context.Background(), "r", idp.Client{ClientID: "x", RedirectURIs: []string{"https://*"}})
	if se := idp.AsStatus(err); se == nil || se.Code != 400 {
		t.Fatalf("%v", err)
	}
}
