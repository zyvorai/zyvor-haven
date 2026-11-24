// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

// flakyStore makes ListClients (used only by Guard on these routes) fail or
// panic on demand.
type flakyStore struct {
	core.Store
	mode atomic.Int32 // 0 ok, 1 error, 2 panic
}

func (f *flakyStore) ListClients(ctx context.Context, realm string) ([]core.Client, error) {
	switch f.mode.Load() {
	case 1:
		return nil, errors.New("boom: database password=hunter2")
	case 2:
		panic("boom")
	}
	return f.Store.ListClients(ctx, realm)
}

func guardEnv(t *testing.T, g admin.GuardConfig) *env {
	t.Helper()
	e := newEnvWith(t, func(cfg *admin.Config, _ *memstore.Store, _ string) { cfg.Guard = g })
	e.api(201, "POST", "/realms", map[string]any{"realm": "gt", "enabled": true})
	return e
}

func flakyGuardEnv(t *testing.T, g admin.GuardConfig) (*env, *flakyStore) {
	t.Helper()
	fs := &flakyStore{}
	e := newEnvWith(t, func(cfg *admin.Config, st *memstore.Store, _ string) {
		fs.Store = st
		cfg.Store = fs
		cfg.Guard = g
	})
	e.api(201, "POST", "/realms", map[string]any{"realm": "gt", "enabled": true})
	return e, fs
}

// gcall is e.call with extra request headers.
func (e *env) gcall(method, path, token string, body any, hdr map[string]string) (int, []byte, http.Header) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, e.srv.URL+"/admin/v1"+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b, resp.Header
}

func (e *env) put(want int, method, path string, body any, hdr map[string]string) (http.Header, []byte) {
	e.t.Helper()
	code, b, h := e.gcall(method, path, e.token, body, hdr)
	if code != want {
		e.t.Fatalf("%s %s: got %d want %d: %s", method, path, code, want, b)
	}
	return h, b
}

func (e *env) realmJSON(name string) string {
	e.t.Helper()
	r, err := e.st.GetRealm(context.Background(), name)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	return string(b)
}

func (e *env) clientsJSON(name string) string {
	e.t.Helper()
	cs, err := e.st.ListClients(context.Background(), name)
	if err != nil {
		e.t.Fatal(err)
	}
	b, _ := json.Marshal(cs)
	return string(b)
}

func (e *env) events(rlm, typ string) []core.Event {
	e.t.Helper()
	all, err := e.st.ListEvents(context.Background(), rlm, 1000)
	if err != nil {
		e.t.Fatal(err)
	}
	var out []core.Event
	for _, ev := range all {
		if ev.Type == typ {
			out = append(out, ev)
		}
	}
	return out
}

// realmBody is a full realm PUT body (the route replaces the basic fields).
func realmBody(h map[string]any) map[string]any {
	b := map[string]any{"realm": "gt", "enabled": true, "bruteForceProtected": true}
	for k, v := range h { // RealmHardening is embedded: its fields are top-level
		b[k] = v
	}
	return b
}

func weakTLS() map[string]any { return realmBody(map[string]any{"sslRequired": "none"}) }

// setWeak writes a realm with ssl=none straight to the store, so the finding
// exists before the gate is asked anything.
func (e *env) setWeak(t *testing.T) {
	t.Helper()
	rl, err := e.st.GetRealm(context.Background(), "gt")
	if err != nil {
		t.Fatal(err)
	}
	rl.TransportSecurity = "none"
	if err := e.st.UpdateRealm(context.Background(), rl); err != nil {
		t.Fatal(err)
	}
}

type blockedBody struct {
	Error    string             `json:"error"`
	Findings []idp.GuardFinding `json:"findings"`
	Override string             `json:"override"`
}

func decodeBlocked(t *testing.T, b []byte) blockedBody {
	t.Helper()
	var out blockedBody
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%v: %s", err, b)
	}
	return out
}

func ruleSet(fs []idp.GuardFinding) string {
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.RuleID)
	}
	return strings.Join(ids, ",")
}

var headerShape = regexp.MustCompile(`^findings=\d+ max=(critical|high|medium|low)( override=1)?$`)

const httpRedirect = "http://app.example.com/cb" // HAVEN002 (high)

func clientBody(id string, redirects ...string) map[string]any {
	return map[string]any{"clientId": id, "enabled": true, "publicClient": true, "standardFlowEnabled": true, "redirectUris": redirects}
}

func TestGuardRealmUpdateModes(t *testing.T) {
	// enforce: refused with an actionable body; the stored realm is untouched.
	e := guardEnv(t, admin.GuardConfig{Mode: "enforce"})
	before := e.realmJSON("gt")
	hdr, body := e.put(422, "PUT", "/realms/gt", weakTLS(), nil)
	bb := decodeBlocked(t, body)
	if bb.Error != "guard_blocked" || len(bb.Findings) != 1 {
		t.Fatalf("body: %s", body)
	}
	f := bb.Findings[0]
	if f.RuleID != "HAVEN014" || f.Severity != "high" || f.Resource != "realm/gt" || f.Fix == "" || f.Title == "" || f.Detail == "" {
		t.Errorf("finding: %+v", f)
	}
	if bb.Override == "" {
		t.Error("an override hint is expected when overrides are allowed")
	}
	if got := hdr.Get("X-Haven-Guard"); got != "findings=1 max=high" {
		t.Errorf("header: %q", got)
	}
	if e.realmJSON("gt") != before {
		t.Error("blocked write changed the stored realm")
	}
	if n := len(e.events("gt", "GUARD_BLOCK")); n != 1 {
		t.Errorf("GUARD_BLOCK events: %d", n)
	}

	// warn (the default): applied, header + GUARD_WARN listing rule ids only.
	e = guardEnv(t, admin.GuardConfig{})
	hdr, _ = e.put(204, "PUT", "/realms/gt", weakTLS(), nil)
	if got := hdr.Get("X-Haven-Guard"); got != "findings=1 max=high" {
		t.Errorf("warn header: %q", got)
	}
	if rl, _ := e.st.GetRealm(context.Background(), "gt"); rl.TransportSecurity != "none" {
		t.Error("warn mode must apply the write")
	}
	evs := e.events("gt", "GUARD_WARN")
	if len(evs) != 1 || evs[0].Detail != "kind=realm rules=HAVEN014" || evs[0].UserID != "client:haven-admin" {
		t.Errorf("GUARD_WARN: %+v", evs)
	}

	// off: nothing evaluated, nothing recorded.
	e = guardEnv(t, admin.GuardConfig{Mode: "off"})
	hdr, _ = e.put(204, "PUT", "/realms/gt", weakTLS(), nil)
	if hdr.Get("X-Haven-Guard") != "" || len(e.events("gt", "GUARD_WARN"))+len(e.events("gt", "GUARD_BLOCK")) != 0 {
		t.Error("off mode must be a no-op")
	}
}

func TestGuardPreexistingAndFixes(t *testing.T) {
	e := guardEnv(t, admin.GuardConfig{Mode: "enforce", Threshold: "medium"})
	e.setWeak(t)

	// An unrelated edit on an already-risky realm is not held hostage.
	b := weakTLS()
	b["displayName"] = "Renamed"
	e.put(204, "PUT", "/realms/gt", b, nil)

	// But a NEW finding is still refused, and only that one is reported.
	b = realmBody(map[string]any{"sslRequired": "none", "passwordPolicy": "length(8)"})
	_, body := e.put(422, "PUT", "/realms/gt", b, nil)
	if got := ruleSet(decodeBlocked(t, body).Findings); got != "HAVEN016" {
		t.Errorf("blocked rules = %q, want only HAVEN016", got)
	}

	// Fixing the finding is allowed, and the dry run says it is Fixed.
	_, body = e.put(200, "POST", "/realms/gt/guard/evaluate",
		map[string]any{"kind": "realm", "body": realmBody(map[string]any{"sslRequired": "external"})}, nil)
	var v idp.GuardVerdict
	_ = json.Unmarshal(body, &v)
	if len(v.Fixed) != 1 || v.Fixed[0].RuleID != "HAVEN014" || !v.Allowed {
		t.Errorf("verdict: %+v", v)
	}
	e.put(204, "PUT", "/realms/gt", realmBody(map[string]any{"sslRequired": "external"}), nil)
}

func TestGuardClientCreateAndUpdate(t *testing.T) {
	e := guardEnv(t, admin.GuardConfig{Mode: "enforce"})
	before := e.clientsJSON("gt")

	// create: new high finding blocked; nothing stored.
	_, body := e.put(422, "POST", "/realms/gt/clients", clientBody("app", httpRedirect), nil)
	bb := decodeBlocked(t, body)
	if len(bb.Findings) != 1 || bb.Findings[0].RuleID != "HAVEN002" || bb.Findings[0].Resource != "client/gt/app" {
		t.Fatalf("body: %s", body)
	}
	if e.clientsJSON("gt") != before {
		t.Error("blocked create changed the store")
	}
	// the secret of a refused confidential client never appears
	c := clientBody("svc", httpRedirect)
	c["publicClient"] = false
	_, body = e.put(422, "POST", "/realms/gt/clients", c, nil)
	if strings.Contains(string(body), "secret") && !strings.Contains(string(body), "guard_blocked") {
		t.Errorf("body: %s", body)
	}

	// a safe client is fine; then an update that introduces a finding is blocked.
	id := e.createID("/realms/gt/clients", clientBody("app", "https://app.example.com/cb"))
	snapshot := e.clientsJSON("gt")
	e.put(422, "PUT", "/realms/gt/clients/"+id, clientBody("app", httpRedirect), nil)
	if e.clientsJSON("gt") != snapshot {
		t.Error("blocked update changed the store")
	}

	// warn mode: applied with the header
	w := guardEnv(t, admin.GuardConfig{})
	hdr, body := w.put(201, "POST", "/realms/gt/clients", func() map[string]any {
		c := clientBody("svc", httpRedirect)
		c["publicClient"] = false
		return c
	}(), nil)
	if !headerShape.MatchString(hdr.Get("X-Haven-Guard")) {
		t.Errorf("header: %q", hdr.Get("X-Haven-Guard"))
	}
	var created struct{ ID, Secret string }
	_ = json.Unmarshal(body, &created)
	if created.Secret == "" || strings.Contains(hdr.Get("X-Haven-Guard"), created.Secret) {
		t.Error("secret handling")
	}
	for k, vs := range hdr {
		for _, v := range vs {
			if strings.Contains(v, created.Secret) {
				t.Errorf("secret leaked in header %s", k)
			}
		}
	}
	if evs := w.events("gt", "GUARD_WARN"); len(evs) != 1 || evs[0].ClientID != "svc" || strings.Contains(evs[0].Detail, created.Secret) {
		t.Errorf("events: %+v", evs)
	}
}

func TestGuardClientPreexistingAndFix(t *testing.T) {
	e := guardEnv(t, admin.GuardConfig{Mode: "enforce"})
	// seed a risky client directly in the store
	if err := e.st.CreateClient(context.Background(), core.Client{
		Realm: "gt", ClientID: "old", Enabled: true, Public: true, AuthCodeFlow: true, RequirePKCE: true,
		RedirectURIs: []string{httpRedirect},
	}); err != nil {
		t.Fatal(err)
	}
	cs, _ := e.st.ListClients(context.Background(), "gt")
	id := cs[0].ID
	// rename only: pre-existing HAVEN002 does not block
	b := clientBody("old", httpRedirect)
	b["name"] = "Old app"
	e.put(204, "PUT", "/realms/gt/clients/"+id, b, nil)
	// fixing it is allowed
	e.put(204, "PUT", "/realms/gt/clients/"+id, clientBody("old", "https://app.example.com/cb"), nil)
	// a different client getting the same finding is still blocked
	e.put(422, "POST", "/realms/gt/clients", clientBody("other", httpRedirect), nil)
}

func TestGuardThresholdBoundaries(t *testing.T) {
	cases := []struct {
		name, threshold string
		hardening       map[string]any
		blocked         bool
	}{
		{"high finding, threshold high", "high", map[string]any{"sslRequired": "none"}, true},
		{"high finding, threshold critical", "critical", map[string]any{"sslRequired": "none"}, false},
		{"medium finding, threshold high", "high", map[string]any{"passwordPolicy": "length(8)"}, false},
		{"medium finding, threshold medium", "medium", map[string]any{"passwordPolicy": "length(8)"}, true},
		{"low finding, threshold medium", "medium", map[string]any{"ssoSessionIdleTimeout": 90000}, false},
		{"low finding, threshold low", "low", map[string]any{"ssoSessionIdleTimeout": 90000}, true},
		{"empty threshold defaults to high", "", map[string]any{"passwordPolicy": "length(8)"}, false},
		{"unknown threshold falls back to high, not off", "bogus", map[string]any{"sslRequired": "none"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := guardEnv(t, admin.GuardConfig{Mode: "enforce", Threshold: c.threshold})
			want := 204
			if c.blocked {
				want = 422
			}
			e.put(want, "PUT", "/realms/gt", realmBody(c.hardening), nil)
		})
	}
}

func writeWaivers(t *testing.T, realm, rule, expires string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "waivers.json")
	j, _ := json.Marshal(map[string]any{"version": 1, "waivers": []map[string]string{{
		"ruleId": rule, "realm": realm, "reason": "legacy", "approver": "sec", "expires": expires}}})
	if err := os.WriteFile(p, j, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGuardWaivers(t *testing.T) {
	future := time.Now().UTC().Add(30 * 24 * time.Hour).Format("2006-01-02")
	cases := []struct {
		name, realm, expires string
		want                 int
	}{
		{"valid waiver", "gt", future, 204},
		{"expired waiver", "gt", "2020-01-01", 422},
		{"waiver for another realm", "other", future, 422},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := guardEnv(t, admin.GuardConfig{Mode: "enforce", WaiverFile: writeWaivers(t, c.realm, "HAVEN014", future)})
			if c.expires != future {
				// expired files are accepted by the parser (reported as reopened)
				e = guardEnv(t, admin.GuardConfig{Mode: "enforce", WaiverFile: writeWaivers(t, c.realm, "HAVEN014", c.expires)})
			}
			e.put(c.want, "PUT", "/realms/gt", weakTLS(), nil)
		})
	}
	// A waiver for a different rule does not cover HAVEN014.
	e := guardEnv(t, admin.GuardConfig{Mode: "enforce", WaiverFile: writeWaivers(t, "gt", "HAVEN016", future)})
	e.put(422, "PUT", "/realms/gt", weakTLS(), nil)
}

func TestGuardWaiverFileFailures(t *testing.T) {
	p := filepath.Join(t.TempDir(), "w.json")
	if err := os.WriteFile(p, []byte(`{"version":1,"waivers":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// enforce fails closed when the file turns bad after startup
	e := guardEnv(t, admin.GuardConfig{Mode: "enforce", WaiverFile: p})
	if err := os.WriteFile(p, []byte(`not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	before := e.realmJSON("gt")
	_, body := e.put(500, "PUT", "/realms/gt", realmBody(map[string]any{"passwordPolicy": "length(20)"}), nil)
	if !strings.Contains(string(body), "guard_unavailable") || strings.Contains(string(body), p) {
		t.Errorf("body: %s", body)
	}
	if e.realmJSON("gt") != before {
		t.Error("fail-closed write changed the store")
	}
	// warn fails open
	e = guardEnv(t, admin.GuardConfig{WaiverFile: p})
	e.put(204, "PUT", "/realms/gt", weakTLS(), nil)
}

func TestGuardOverride(t *testing.T) {
	e := guardEnv(t, admin.GuardConfig{Mode: "enforce"})
	before := e.realmJSON("gt")

	for name, reason := range map[string]string{"short": "too short", "long": strings.Repeat("x", 301)} {
		_, body := e.put(400, "PUT", "/realms/gt", weakTLS(), map[string]string{"X-Haven-Guard-Override": reason})
		if !strings.Contains(string(body), "guard_override_invalid") {
			t.Errorf("%s: %s", name, body)
		}
	}
	if e.realmJSON("gt") != before {
		t.Fatal("invalid override changed the store")
	}
	e.put(422, "PUT", "/realms/gt", weakTLS(), nil)

	hdr, _ := e.put(204, "PUT", "/realms/gt", weakTLS(), map[string]string{"X-Haven-Guard-Override": "  temporary lab realm, ticket SEC-42  "})
	if got := hdr.Get("X-Haven-Guard"); got != "findings=1 max=high override=1" {
		t.Errorf("header: %q", got)
	}
	evs := e.events("gt", "GUARD_OVERRIDE")
	if len(evs) != 1 {
		t.Fatalf("events: %+v", evs)
	}
	if ev := evs[0]; ev.UserID != "client:haven-admin" || !strings.Contains(ev.Detail, "HAVEN014") ||
		!strings.Contains(ev.Detail, "temporary lab realm, ticket SEC-42") || strings.HasPrefix(ev.Detail, " ") {
		t.Errorf("override event: %+v", ev)
	}
	if rl, _ := e.st.GetRealm(context.Background(), "gt"); rl.TransportSecurity != "none" {
		t.Error("override must apply the write")
	}
	// An override with nothing to override records nothing.
	e.put(204, "PUT", "/realms/gt", weakTLS(), map[string]string{"X-Haven-Guard-Override": "no new findings here at all"})
	if n := len(e.events("gt", "GUARD_OVERRIDE")); n != 1 {
		t.Errorf("override events = %d, want 1", n)
	}
}

func TestGuardOverrideIgnoredOutsideEnforce(t *testing.T) {
	e := guardEnv(t, admin.GuardConfig{})
	e.put(204, "PUT", "/realms/gt", weakTLS(), map[string]string{"X-Haven-Guard-Override": "no need in warn mode"})
	if len(e.events("gt", "GUARD_OVERRIDE")) != 0 || len(e.events("gt", "GUARD_WARN")) != 1 {
		t.Error("warn mode must record a warning, not an override")
	}
}

func TestGuardNoOverrideForServiceAccounts(t *testing.T) {
	e := guardEnv(t, admin.GuardConfig{Mode: "enforce", NoOverride: true})
	// human admin user
	e.api(201, "POST", "/realms/"+realm+"/roles", map[string]any{"name": "haven-admin"})
	e.createID("/realms/"+realm+"/clients", map[string]any{
		"clientId": "app", "enabled": true, "publicClient": true, "standardFlowEnabled": true,
		"redirectUris": []string{"http://localhost/cb"}})
	uid := e.createID("/realms/"+realm+"/users", map[string]any{"username": "boss", "enabled": true})
	e.api(204, "PUT", "/realms/"+realm+"/users/"+uid+"/password", map[string]any{"type": "password", "value": goodPW})
	e.api(204, "POST", "/realms/"+realm+"/users/"+uid+"/roles", []map[string]string{{"name": "haven-admin"}})
	userTok := e.login("app", "boss", goodPW)

	ov := map[string]string{"X-Haven-Guard-Override": "approved by on-call, ticket 1234"}
	before := e.realmJSON("gt")
	code, body, _ := e.gcall("PUT", "/realms/gt", e.token, weakTLS(), ov)
	if code != 403 || !strings.Contains(string(body), "guard_override_denied") {
		t.Fatalf("service account: %d %s", code, body)
	}
	if e.realmJSON("gt") != before {
		t.Error("denied override changed the store")
	}
	code, body, _ = e.gcall("PUT", "/realms/gt", e.token, weakTLS(), nil)
	if code != 422 || decodeBlocked(t, body).Override != "" {
		t.Errorf("service account 422 must not advertise an override: %d %s", code, body)
	}
	code, body, _ = e.gcall("PUT", "/realms/gt", userTok, weakTLS(), ov)
	if code != 204 {
		t.Fatalf("user override: %d %s", code, body)
	}
	evs := e.events("gt", "GUARD_OVERRIDE")
	if len(evs) != 1 || evs[0].UserID != "user:"+uid {
		t.Errorf("events: %+v", evs)
	}
}

func TestGuardDryRunMatchesRealVerdict(t *testing.T) {
	e := guardEnv(t, admin.GuardConfig{Mode: "enforce"})
	realm0, clients0 := e.realmJSON("gt"), e.clientsJSON("gt")

	check := func(kind, method, path string, body map[string]any) {
		t.Helper()
		_, real := e.put(422, method, path, body, nil)
		_, dry := e.put(200, "POST", "/realms/gt/guard/evaluate", map[string]any{"kind": kind, "body": body}, nil)
		var v idp.GuardVerdict
		if err := json.Unmarshal(dry, &v); err != nil {
			t.Fatal(err)
		}
		a, _ := json.Marshal(v.Blocked)
		b, _ := json.Marshal(decodeBlocked(t, real).Findings)
		if v.Allowed || v.Kind != kind || string(a) != string(b) || len(v.Blocked) == 0 {
			t.Errorf("%s: dry run %s vs real %s", kind, dry, real)
		}
		if e.realmJSON("gt") != realm0 || e.clientsJSON("gt") != clients0 {
			t.Errorf("%s: dry run or blocked write changed the store", kind)
		}
	}
	check("realm", "PUT", "/realms/gt", weakTLS())
	check("client", "POST", "/realms/gt/clients", clientBody("app", httpRedirect))

	// a clean proposal is allowed
	_, dry := e.put(200, "POST", "/realms/gt/guard/evaluate",
		map[string]any{"kind": "client", "body": clientBody("app", "https://app.example.com/cb")}, nil)
	var v idp.GuardVerdict
	_ = json.Unmarshal(dry, &v)
	if !v.Allowed || len(v.Blocked) != 0 || e.clientsJSON("gt") != clients0 {
		t.Errorf("clean verdict: %s", dry)
	}

	// realm that does not exist yet (create semantics)
	_, dry = e.put(200, "POST", "/realms/brandnew/guard/evaluate", map[string]any{"kind": "realm", "body": map[string]any{
		"realm": "brandnew", "enabled": true, "sslRequired": "none"}}, nil)
	_ = json.Unmarshal(dry, &v)
	if v.Allowed || ruleSet(v.Blocked) != "HAVEN014" {
		t.Errorf("create dry run: %s", dry)
	}
	if _, err := e.st.GetRealm(context.Background(), "brandnew"); err == nil {
		t.Error("dry run created a realm")
	}

	// bad input
	for name, body := range map[string]any{
		"unknown kind":  map[string]any{"kind": "user", "body": map[string]any{}},
		"missing body":  map[string]any{"kind": "realm"},
		"unknown field": map[string]any{"kind": "realm", "body": map[string]any{"nope": 1}},
		"bad client":    map[string]any{"kind": "client", "body": map[string]any{"clientId": "x", "redirectUris": []string{"javascript:alert(1)"}}},
		"outer unknown": map[string]any{"kind": "realm", "body": map[string]any{}, "extra": 1},
	} {
		if code, b, _ := e.gcall("POST", "/realms/gt/guard/evaluate", e.token, body, nil); code != 400 {
			t.Errorf("%s: %d %s", name, code, b)
		}
	}
	if code, _, _ := e.gcall("POST", "/realms/nope/guard/evaluate", e.token, map[string]any{"kind": "client", "body": clientBody("a")}, nil); code != 404 {
		t.Errorf("client dry run in unknown realm: %d", code)
	}
}

func TestGuardCreateRealmGated(t *testing.T) {
	e := guardEnv(t, admin.GuardConfig{Mode: "enforce"})
	e.put(422, "POST", "/realms", map[string]any{"realm": "weak", "enabled": true, "sslRequired": "none"}, nil)
	if _, err := e.st.GetRealm(context.Background(), "weak"); err == nil {
		t.Error("blocked realm create was stored")
	}
	e.put(201, "POST", "/realms", map[string]any{"realm": "fine", "enabled": true}, nil)
}

func TestGuardFailurePaths(t *testing.T) {
	for _, mode := range []int32{1, 2} { // 1 error, 2 panic
		e, fs := flakyGuardEnv(t, admin.GuardConfig{Mode: "enforce"})
		before := e.realmJSON("gt")
		fs.mode.Store(mode)
		_, body := e.put(500, "PUT", "/realms/gt", realmBody(map[string]any{"passwordPolicy": "length(20)"}), nil)
		if !strings.Contains(string(body), "guard_unavailable") || strings.Contains(string(body), "hunter2") || strings.Contains(string(body), "boom") {
			t.Errorf("mode %d body: %s", mode, body)
		}
		fs.mode.Store(0)
		if e.realmJSON("gt") != before {
			t.Errorf("mode %d: fail-closed write changed the store", mode)
		}
		fs.mode.Store(mode)
		// An override still lets the write through, and says so.
		hdr, _ := e.put(204, "PUT", "/realms/gt", realmBody(map[string]any{"passwordPolicy": "length(20)"}),
			map[string]string{"X-Haven-Guard-Override": "guard outage, emergency change"})
		if hdr.Get("X-Haven-Guard") != "unavailable override=1" {
			t.Errorf("header: %q", hdr.Get("X-Haven-Guard"))
		}
		fs.mode.Store(0)
		if evs := e.events("gt", "GUARD_OVERRIDE"); len(evs) != 1 || !strings.Contains(evs[0].Detail, "rules=unavailable") {
			t.Errorf("events: %+v", evs)
		}

		// warn fails open
		e, fs = flakyGuardEnv(t, admin.GuardConfig{Mode: "warn"})
		fs.mode.Store(mode)
		e.put(204, "PUT", "/realms/gt", realmBody(map[string]any{"passwordPolicy": "length(20)"}), nil)
	}
	// off never touches the evaluator
	e, fs := flakyGuardEnv(t, admin.GuardConfig{Mode: "off"})
	fs.mode.Store(2)
	e.put(204, "PUT", "/realms/gt", weakTLS(), nil)
}

func TestGuardUnknownModeEnforces(t *testing.T) {
	e := guardEnv(t, admin.GuardConfig{Mode: "enfroce"})
	e.put(422, "PUT", "/realms/gt", weakTLS(), nil)
}

func TestGuardRoutesNeedAuth(t *testing.T) {
	e := guardEnv(t, admin.GuardConfig{Mode: "enforce"})
	for _, rt := range [][2]string{{"GET", "/realms/gt/guard"}, {"POST", "/realms/gt/guard/evaluate"}} {
		for _, tok := range []string{"", "garbage"} {
			if code, _, _ := e.gcall(rt[0], rt[1], tok, map[string]any{"kind": "realm", "body": map[string]any{}}, nil); code != 401 {
				t.Errorf("%s %s token %q: %d", rt[0], rt[1], tok, code)
			}
		}
	}
	// a blocked write without a token never reaches Guard or the store
	before := e.realmJSON("gt")
	if code, _, _ := e.gcall("PUT", "/realms/gt", "", weakTLS(), map[string]string{"X-Haven-Guard-Override": "no token but a long reason"}); code != 401 {
		t.Errorf("unauthenticated override: %d", code)
	}
	if e.realmJSON("gt") != before || len(e.events("gt", "GUARD_OVERRIDE")) != 0 {
		t.Error("unauthenticated request had an effect")
	}
}

func TestGuardStatusRoute(t *testing.T) {
	future := time.Now().UTC().Add(24 * time.Hour).Format("2006-01-02")
	e := guardEnv(t, admin.GuardConfig{Mode: "enforce", WaiverFile: writeWaivers(t, "gt", "HAVEN014", future)})
	e.setWeak(t)
	rl, _ := e.st.GetRealm(context.Background(), "gt")
	rl.PasswordPolicy = "length(8)"
	_ = e.st.UpdateRealm(context.Background(), rl)

	_, body := e.put(200, "GET", "/realms/gt/guard", nil, nil)
	var out struct {
		Realm, Mode, Threshold string
		Findings               []idp.GuardFinding
		Waived                 []struct{ RuleID, Reason, Approver string }
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if out.Realm != "gt" || out.Mode != "enforce" || ruleSet(out.Findings) != "HAVEN016" ||
		len(out.Waived) != 1 || out.Waived[0].RuleID != "HAVEN014" || out.Waived[0].Approver != "sec" {
		t.Errorf("status: %s", body)
	}
	if code, _, _ := e.gcall("GET", "/realms/nope/guard", e.token, nil, nil); code != 404 {
		t.Errorf("unknown realm: %d", code)
	}
}

func TestGuardConfigValidate(t *testing.T) {
	good := writeWaivers(t, "gt", "HAVEN014", time.Now().UTC().Add(48*time.Hour).Format("2006-01-02"))
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte("{"), 0o600)
	for name, c := range map[string]struct {
		g  admin.GuardConfig
		ok bool
	}{
		"zero":          {admin.GuardConfig{}, true},
		"enforce":       {admin.GuardConfig{Mode: "Enforce", Threshold: "LOW", WaiverFile: good}, true},
		"bad mode":      {admin.GuardConfig{Mode: "strict"}, false},
		"bad threshold": {admin.GuardConfig{Threshold: "info"}, false},
		"missing file":  {admin.GuardConfig{WaiverFile: filepath.Join(t.TempDir(), "none")}, false},
		"bad file":      {admin.GuardConfig{WaiverFile: bad}, false},
	} {
		if err := c.g.Validate(time.Now()); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}
