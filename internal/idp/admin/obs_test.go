// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/bootstrap"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/obs"
	"github.com/zyvorai/haven/internal/idp/oidc"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

// recorder is an obs.Recorder that remembers every call as a string.
type recorder struct {
	mu    sync.Mutex
	calls []string
}

func (r *recorder) add(s string) {
	r.mu.Lock()
	r.calls = append(r.calls, s)
	r.mu.Unlock()
}
func (r *recorder) Login(realm, res string)        { r.add("login:" + realm + ":" + res) }
func (r *recorder) Lockout(realm string)           { r.add("lockout:" + realm) }
func (r *recorder) RefreshReuse(realm string)      { r.add("reuse:" + realm) }
func (r *recorder) CodeReplay(realm string)        { r.add("replay:" + realm) }
func (r *recorder) TokenIssued(realm, g, k string) { r.add("issued:" + realm + ":" + g + ":" + k) }
func (r *recorder) TokenError(realm, g, c string)  { r.add("tokerr:" + realm + ":" + g + ":" + c) }
func (r *recorder) AdminAuthFailure(kind string)   { r.add("adminauth:" + kind) }
func (r *recorder) AdminOp(realm, res, act string, ok bool) {
	r.add("adminop:" + realm + ":" + res + ":" + act + ":" + map[bool]string{true: "ok", false: "err"}[ok])
}

var _ obs.Recorder = (*recorder)(nil)

func (r *recorder) take() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.calls
	r.calls = nil
	return out
}

// expect asserts the calls since the last take, in order.
func (r *recorder) expect(t *testing.T, want ...string) {
	t.Helper()
	got := r.take()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("recorder calls\n got: %v\nwant: %v", got, want)
	}
}

// newObsEnv is newEnv with a Recorder on the admin API.
func newObsEnv(t *testing.T) (*env, *recorder) {
	t.Helper()
	rec := &recorder{}
	st := memstore.New()
	h := password.New(password.TestParams)
	sg := keys.New(st, keys.Options{})
	e := &env{t: t, st: st, signer: sg, hasher: h}
	var handler http.Handler
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(e.srv.Close)
	if _, err := bootstrap.Run(context.Background(), st, h, sg, bootstrap.Options{
		Realm: realm, AdminClientSecret: adminSecret,
	}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/realms/", oidc.New(oidc.Config{Store: st, Signer: sg, Hasher: h, BaseURL: e.srv.URL}))
	mux.Handle("/admin/v1/", admin.New(admin.Config{Store: st, Signer: sg, Hasher: h, BaseURL: e.srv.URL,
		AdminRealm: realm, Obs: rec}))
	handler = mux
	e.token = e.clientToken(realm, "haven-admin", adminSecret)
	rec.take()
	return e, rec
}

// A nil Obs must behave as obs.Nop: newEnv leaves it unset, and both auth
// failures and mutating routes (which call the recorder) must work.
func TestObsAdminNilDefaultsToNop(t *testing.T) {
	e := newEnv(t)
	if c, _, _ := e.call("GET", "/status", "", nil); c != 401 {
		t.Fatalf("auth failure path: %d", c)
	}
	e.createID("/realms", map[string]any{"realm": "nopcheck", "enabled": true})
	e.api(404, "DELETE", "/realms/ghost", nil)
}

func TestObsAdminOps(t *testing.T) {
	e, rec := newObsEnv(t)
	const p = "platform"
	r := "/realms/" + p

	// realm
	e.api(201, "POST", "/realms", map[string]any{"realm": "acme", "enabled": true})
	rec.expect(t, "adminop:acme:realm:create:ok")
	e.api(409, "POST", "/realms", map[string]any{"realm": "acme", "enabled": true})
	rec.expect(t, "adminop:unknown:realm:create:err")
	e.api(400, "POST", "/realms", map[string]any{"realm": "Bad Name"})
	rec.expect(t, "adminop:unknown:realm:create:err")
	e.api(204, "PUT", "/realms/acme", map[string]any{"realm": "acme", "enabled": true, "displayName": "Acme"})
	rec.expect(t, "adminop:acme:realm:update:ok")
	e.api(400, "PUT", "/realms/acme", map[string]any{"realm": "other"})
	rec.expect(t, "adminop:acme:realm:update:err")
	e.api(404, "PUT", "/realms/ghost", map[string]any{"realm": "ghost"})
	rec.expect(t, "adminop:unknown:realm:update:err")
	e.api(409, "DELETE", r, nil)
	rec.expect(t, "adminop:platform:realm:delete:err")
	e.api(204, "DELETE", "/realms/acme", nil)
	rec.expect(t, "adminop:acme:realm:delete:ok")

	// client + secret
	cid := e.createID(r+"/clients", map[string]any{"clientId": "web", "enabled": true, "serviceAccountsEnabled": true})
	rec.expect(t, "adminop:platform:client:create:ok")
	e.api(409, "POST", r+"/clients", map[string]any{"clientId": "web", "enabled": true, "serviceAccountsEnabled": true})
	rec.expect(t, "adminop:platform:client:create:err")
	e.api(400, "POST", r+"/clients", map[string]any{"clientId": "", "enabled": true})
	rec.expect(t, "adminop:platform:client:create:err")
	e.api(204, "PUT", r+"/clients/"+cid, map[string]any{"clientId": "web", "enabled": true, "serviceAccountsEnabled": true})
	rec.expect(t, "adminop:platform:client:update:ok")
	e.api(400, "PUT", r+"/clients/"+cid, map[string]any{"clientId": "renamed", "enabled": true})
	rec.expect(t, "adminop:platform:client:update:err")
	e.api(200, "POST", r+"/clients/"+cid+"/secret", nil)
	rec.expect(t, "adminop:platform:secret:action:ok")
	e.api(404, "POST", r+"/clients/nope/secret", nil)
	rec.expect(t, "adminop:platform:secret:action:err")
	e.api(204, "DELETE", r+"/clients/"+cid, nil)
	rec.expect(t, "adminop:platform:client:delete:ok")
	e.api(404, "DELETE", r+"/clients/"+cid, nil)
	rec.expect(t, "adminop:platform:client:delete:err")

	// user + password
	uid := e.createID(r+"/users", map[string]any{"username": "alice", "enabled": true})
	rec.expect(t, "adminop:platform:user:create:ok")
	e.api(409, "POST", r+"/users", map[string]any{"username": "alice", "enabled": true})
	rec.expect(t, "adminop:platform:user:create:err")
	e.api(204, "PUT", r+"/users/"+uid, map[string]any{"username": "alice", "email": "a@example.com", "enabled": true})
	rec.expect(t, "adminop:platform:user:update:ok")
	e.api(204, "PUT", r+"/users/"+uid+"/password", map[string]any{"type": "password", "value": goodPW})
	rec.expect(t, "adminop:platform:user:action:ok")
	e.api(400, "PUT", r+"/users/"+uid+"/password", map[string]any{"type": "password", "value": "short"})
	rec.expect(t, "adminop:platform:user:action:err")

	// role, group, membership
	e.createID(r+"/roles", map[string]any{"name": "viewer"})
	rec.expect(t, "adminop:platform:role:create:ok")
	e.api(409, "POST", r+"/roles", map[string]any{"name": "viewer"})
	rec.expect(t, "adminop:platform:role:create:err")
	gid := e.createID(r+"/groups", map[string]any{"name": "ops"})
	rec.expect(t, "adminop:platform:group:create:ok")
	e.api(409, "POST", r+"/groups", map[string]any{"name": "ops"})
	rec.expect(t, "adminop:platform:group:create:err")
	e.api(204, "POST", r+"/users/"+uid+"/roles", []map[string]string{{"name": "viewer"}})
	rec.expect(t, "adminop:platform:role:action:ok")
	e.api(204, "PUT", r+"/users/"+uid+"/groups/"+gid, nil)
	rec.expect(t, "adminop:platform:group:action:ok")

	// user delete
	e.api(204, "DELETE", r+"/users/"+uid, nil)
	rec.expect(t, "adminop:platform:user:delete:ok")
	e.api(404, "DELETE", r+"/users/"+uid, nil)
	rec.expect(t, "adminop:platform:user:delete:err")

	// import
	e.api(200, "POST", r+"/import", `{"version":1,"realm":"x"}`)
	rec.expect(t, "adminop:platform:import:action:ok")
	e.api(400, "POST", r+"/import", `{"version":2,"realm":"x"}`)
	rec.expect(t, "adminop:platform:import:action:err")
	e.api(404, "POST", "/realms/nope/import", `{"version":1,"realm":"x"}`)
	rec.expect(t, "adminop:unknown:import:action:err")

	// reads record nothing
	e.api(200, "GET", r+"/users", nil)
	e.api(200, "GET", "/status", nil)
	e.api(404, "GET", r+"/users/ghost", nil)
	rec.expect(t)
}

func TestObsAdminAuthFailures(t *testing.T) {
	e, rec := newObsEnv(t)
	r := "/realms/" + realm

	// missing
	if c, _, _ := e.call("GET", "/status", "", nil); c != 401 {
		t.Fatalf("missing: %d", c)
	}
	rec.expect(t, "adminauth:missing")
	// invalid
	if c, _, _ := e.call("GET", "/status", "not.a.jwt", nil); c != 401 {
		t.Fatalf("invalid: %d", c)
	}
	rec.expect(t, "adminauth:invalid")
	// invalid on a mutating route: only the auth failure, no AdminOp
	if c, _, _ := e.call("POST", "/realms", "not.a.jwt", map[string]any{"realm": "z"}); c != 401 {
		t.Fatalf("invalid post: %d", c)
	}
	rec.expect(t, "adminauth:invalid")
	// a non-bearer scheme counts as missing
	req, _ := http.NewRequest("GET", e.srv.URL+"/admin/v1/status", nil)
	req.Header.Set("Authorization", "Basic abc")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	rec.expect(t, "adminauth:missing")

	// forbidden: a service account that is not an admin client
	rid := e.createID(r+"/clients", map[string]any{"clientId": "rogue", "enabled": true, "serviceAccountsEnabled": true})
	var out struct{ Value string }
	_ = json.Unmarshal(e.api(200, "POST", r+"/clients/"+rid+"/secret", nil), &out)
	rec.take()
	tok := e.clientToken(realm, "rogue", out.Value)
	if c, _, _ := e.call("GET", "/status", tok, nil); c != 403 {
		t.Fatalf("forbidden: %d", c)
	}
	rec.expect(t, "adminauth:forbidden")
	if c, _, _ := e.call("DELETE", r+"/clients/"+rid, tok, nil); c != 403 {
		t.Fatalf("forbidden delete: %d", c)
	}
	rec.expect(t, "adminauth:forbidden")

	// a good request records no auth failure
	e.api(200, "GET", "/status", nil)
	rec.expect(t)
}
