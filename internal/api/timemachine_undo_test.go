// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/auth"
	"github.com/zyvorai/haven/internal/identityops"
	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/bootstrap"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/native"
	"github.com/zyvorai/haven/internal/idp/oidc"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

const undoAdminSecret = "undo-admin-secret-0123456789abcdef"

type undoEnv struct {
	t      *testing.T
	h      http.Handler
	tok    string
	p      *native.Client
	snapID string
}

// newUndoEnv wires the console API to a REAL haven-idp (memstore + admin API)
// through the native client, the same path production uses.
func newUndoEnv(t *testing.T) *undoEnv {
	t.Helper()
	st := memstore.New()
	hasher := password.New(password.TestParams)
	sg := keys.New(st, keys.Options{})
	var handler http.Handler
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	if _, err := bootstrap.Run(context.Background(), st, hasher, sg, bootstrap.Options{Realm: "platform", AdminClientSecret: undoAdminSecret}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/realms/", oidc.New(oidc.Config{Store: st, Signer: sg, Hasher: hasher, BaseURL: srv.URL}))
	mux.Handle("/admin/v1/", admin.New(admin.Config{Store: st, Signer: sg, Hasher: hasher, BaseURL: srv.URL, AdminRealm: "platform"}))
	handler = mux

	p := native.New(native.Config{BaseURL: srv.URL, Realm: "platform", ClientID: "haven-admin", ClientSecret: undoAdminSecret})
	sessions := auth.NewStoreFromEnv()
	e := &undoEnv{t: t, p: p, tok: sessions.Issue("op.erator", "admin", "local").Token,
		h: NewRouter(idp.NewStaticBackend(p, srv.URL, "haven-admin"), nil, sessions)}
	return e
}

func (e *undoEnv) must(err error) {
	e.t.Helper()
	if err != nil {
		e.t.Fatal(err)
	}
}

func (e *undoEnv) call(method, path, body string) (int, map[string]any, string) {
	e.t.Helper()
	rec := do(e.t, e.h, method, path, e.tok, body)
	var m map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return rec.Code, m, rec.Body.String()
}

func (e *undoEnv) users() map[string]bool {
	us, err := e.p.ListAllUsers(context.Background(), "platform")
	e.must(err)
	m := map[string]bool{}
	for _, u := range us {
		m[u.Username] = true
	}
	return m
}

func (e *undoEnv) clients() map[string]string {
	cs, err := e.p.ListClients(context.Background(), "platform")
	e.must(err)
	m := map[string]string{}
	for _, c := range cs {
		m[c.ClientID] = c.ID
	}
	return m
}

// seedAndSnapshot creates the "good" state, snapshots it, then drifts the realm.
func (e *undoEnv) seedAndSnapshot() {
	ctx := context.Background()
	for _, u := range []string{"alice", "bob"} {
		e.must(e.p.CreateUser(ctx, "platform", idp.User{Username: u, Enabled: true, Email: u + "@example.org"}))
	}
	e.must(e.p.CreateClient(ctx, "platform", idp.Client{ClientID: "grafana", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
		RedirectURIs: []string{"https://grafana.example/cb"}}))
	e.must(e.p.CreateRole(ctx, "platform", idp.Role{Name: "admin"}))
	e.must(e.p.CreateGroup(ctx, "platform", idp.Group{Name: "eng"}))
	code, m, body := e.call("POST", "/api/v1/time-machine/snapshots", `{"realm":"platform","reason":"before"}`)
	if code != 201 {
		e.t.Fatalf("snapshot: %d %s", code, body)
	}
	e.snapID = m["id"].(string)

	// Drift: bob and grafana deleted; carol, a new client, a new role appear.
	us, _ := e.p.ListAllUsers(ctx, "platform")
	for _, u := range us {
		if u.Username == "bob" {
			e.must(e.p.DeleteUser(ctx, "platform", u.ID))
		}
	}
	e.must(e.p.DeleteClient(ctx, "platform", e.clients()["grafana"]))
	e.must(e.p.CreateUser(ctx, "platform", idp.User{Username: "carol", Enabled: true}))
	e.must(e.p.CreateClient(ctx, "platform", idp.Client{ClientID: "rogue", Enabled: true, PublicClient: true, StandardFlowEnabled: true,
		RedirectURIs: []string{"https://rogue.example/cb"}}))
	e.must(e.p.CreateRole(ctx, "platform", idp.Role{Name: "temp"}))
}

func TestUndoPreviewApplyAndAudit(t *testing.T) {
	e := newUndoEnv(t)
	e.seedAndSnapshot()
	path := "/api/v1/time-machine/snapshots/" + e.snapID + "/undo"

	// Default is a dry run and changes nothing.
	code, m, body := e.call("POST", path, `{"all":true}`)
	if code != 200 || m["dryRun"] != true {
		t.Fatalf("dry run: %d %s", code, body)
	}
	fp := m["plan"].(map[string]any)["liveFingerprint"].(string)
	if fp == "" || m["executable"].(float64) != 4 { // bob, grafana, carol, rogue; role temp is unsupported
		t.Fatalf("plan: %s", body)
	}
	if !e.users()["carol"] || e.users()["bob"] || e.clients()["rogue"] == "" {
		t.Fatal("a dry run changed the realm")
	}
	if !strings.Contains(body, `"unsupported"`) {
		t.Errorf("the role that cannot be deleted must be reported unsupported: %s", body)
	}

	// Applying needs the fingerprint from the preview.
	if code, _, _ := e.call("POST", path, `{"all":true,"dryRun":false}`); code != 400 {
		t.Errorf("apply without fingerprint: %d", code)
	}
	if code, _, _ := e.call("POST", path, `{"all":true,"dryRun":false,"liveFingerprint":"deadbeef"}`); code != 409 {
		t.Errorf("apply with stale fingerprint: %d", code)
	}
	if !e.users()["carol"] || e.users()["bob"] {
		t.Fatal("a rejected apply changed the realm")
	}

	code, m, body = e.call("POST", path, `{"all":true,"dryRun":false,"liveFingerprint":"`+fp+`"}`)
	if code != 200 || m["outcome"] != "completed" {
		t.Fatalf("apply: %d %s", code, body)
	}
	us := e.users()
	if !us["bob"] || us["carol"] || !us["alice"] {
		t.Errorf("users after undo: %v", us)
	}
	cl := e.clients()
	if cl["grafana"] == "" || cl["rogue"] != "" || cl["haven-admin"] == "" {
		t.Errorf("clients after undo: %v", cl)
	}
	if m["remainingChanges"].(float64) != 1 { // the extra role, which the Admin API cannot delete
		t.Errorf("remaining: %v", m["remainingChanges"])
	}

	// The same plan cannot be replayed: the realm moved on.
	if code, _, _ := e.call("POST", path, `{"all":true,"dryRun":false,"liveFingerprint":"`+fp+`"}`); code != 409 {
		t.Errorf("replay: %d", code)
	}

	// Audited: our journal and the IdP's own admin events.
	code, _, body = e.call("GET", "/api/v1/time-machine/undos?realm=platform", "")
	if code != 200 {
		t.Fatalf("journal: %d %s", code, body)
	}
	var recs []identityops.UndoRecord
	if err := json.Unmarshal([]byte(body), &recs); err != nil || len(recs) != 1 {
		t.Fatalf("journal: %v %s", err, body)
	}
	if recs[0].Actor != "op.erator" || recs[0].Outcome != "completed" || recs[0].SnapshotID != e.snapID {
		t.Errorf("record: %+v", recs[0])
	}
	files, _ := filepath.Glob(filepath.Join(os.Getenv("HAVEN_DATA_DIR"), "time-machine-undo", "*.json"))
	if len(files) == 0 {
		t.Fatal("no journal file")
	}
	for _, f := range files {
		if fi, _ := os.Stat(f); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode %v", f, fi.Mode().Perm())
		}
	}
	evs, err := e.p.ListAdminEvents(context.Background(), "platform")
	e.must(err)
	if len(evs) == 0 {
		t.Error("the IdP recorded no admin events for the undo")
	}
}

func TestUndoSelectionIsValidatedAgainstTheDiff(t *testing.T) {
	e := newUndoEnv(t)
	e.seedAndSnapshot()
	path := "/api/v1/time-machine/snapshots/" + e.snapID + "/undo"
	for name, body := range map[string]string{
		"empty":           `{"changes":[]}`,
		"unknown user":    `{"changes":[{"kind":"user","name":"ghost","change":"added"}]}`,
		"alice untouched": `{"changes":[{"kind":"user","name":"alice","change":"added"}]}`,
		"wrong direction": `{"changes":[{"kind":"user","name":"carol","change":"removed"}]}`,
		"bad kind":        `{"changes":[{"kind":"realm","name":"platform","change":"added"}]}`,
		"admin client":    `{"changes":[{"kind":"client","name":"haven-admin","change":"added"}]}`,
		"bad change":      `{"changes":[{"kind":"user","name":"carol","change":"x"}]}`,
		"bad json":        `{`,
	} {
		if code, _, b := e.call("POST", path, body); code != 400 {
			t.Errorf("%s: %d %s", name, code, b)
		}
	}
	// One selected change touches only that object.
	code, m, b := e.call("POST", path, `{"changes":[{"kind":"user","name":"carol","change":"added"}]}`)
	if code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	fp := m["plan"].(map[string]any)["liveFingerprint"].(string)
	if code, _, b := e.call("POST", path, `{"changes":[{"kind":"user","name":"carol","change":"added"}],"dryRun":false,"liveFingerprint":"`+fp+`"}`); code != 200 {
		t.Fatalf("%d %s", code, b)
	}
	if e.users()["carol"] || e.users()["bob"] || e.clients()["rogue"] == "" {
		t.Errorf("a partial selection changed other objects: users=%v clients=%v", e.users(), e.clients())
	}
}

func TestUndoNeedsSessionAndNativeBackend(t *testing.T) {
	e := newUndoEnv(t)
	e.seedAndSnapshot()
	path := "/api/v1/time-machine/snapshots/" + e.snapID + "/undo"
	if rec := do(t, e.h, "POST", path, "", `{"all":true}`); rec.Code != 401 {
		t.Errorf("no session: %d", rec.Code)
	}
	if rec := do(t, e.h, "GET", "/api/v1/time-machine/undos", "", ""); rec.Code != 401 {
		t.Errorf("journal without session: %d", rec.Code)
	}
	if code, _, _ := e.call("POST", "/api/v1/time-machine/snapshots/nope/undo", `{"all":true}`); code != 404 {
		t.Errorf("unknown snapshot: %d", code)
	}
	// A non-native provider (a provider without the native marker) is refused before anything is read.
	sessions := auth.NewStoreFromEnv()
	tok := sessions.Issue("op", "admin", "local").Token
	h := NewRouter(idp.NewStaticBackend(&secretProvider{}, "http://kc.test", "admin"), nil, sessions)
	if rec := do(t, h, "POST", path, tok, `{"all":true}`); rec.Code != http.StatusNotImplemented {
		t.Errorf("non-native backend: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, NewRouter(nil, nil, sessions), "POST", path, tok, `{"all":true}`); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("no backend: %d", rec.Code)
	}
}
