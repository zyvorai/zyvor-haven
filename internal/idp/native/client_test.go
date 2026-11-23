// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package native

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
)

type reqRec struct {
	Method, Path, Query, Body string
}

// fake is a small in-memory haven-idp Admin API.
type fake struct {
	mu         sync.Mutex
	tokenHits  int
	token      string
	seq        int
	expiresIn  int
	fail401    int // number of upcoming API calls to answer 401
	reqs       []reqRec
	realms     map[string]*idp.Realm
	clients    map[string][]idp.Client
	users      map[string][]idp.User
	passwords  map[string]idp.PasswordReset
	roles      map[string][]idp.Role
	groups     map[string][]idp.Group
	userGroups map[string][]string
	imported   json.RawMessage
}

func newFake() *fake {
	return &fake{
		expiresIn: 3600,
		realms:    map[string]*idp.Realm{}, clients: map[string][]idp.Client{},
		users: map[string][]idp.User{}, passwords: map[string]idp.PasswordReset{},
		roles: map[string][]idp.Role{}, groups: map[string][]idp.Group{},
		userGroups: map[string][]string{},
	}
}

func (f *fake) nextID(p string) string { f.seq++; return p + strconv.Itoa(f.seq) }

func wj(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

func werr(w http.ResponseWriter, code int, msg string) { wj(w, code, map[string]string{"error": msg}) }

func (f *fake) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /realms/{r}/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.tokenHits++
		id, sec, ok := r.BasicAuth()
		_ = r.ParseForm()
		if !ok || id != "haven-admin" || sec != "s3cret" || r.PostForm.Get("grant_type") != "client_credentials" {
			werr(w, 401, "invalid_client")
			return
		}
		f.token = "tok-" + strconv.Itoa(f.tokenHits)
		wj(w, 200, map[string]any{"access_token": f.token, "token_type": "Bearer", "expires_in": f.expiresIn})
	})
	api := http.NewServeMux()
	f.routes(api)
	mux.HandleFunc("/admin/v1/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		b, _ := io.ReadAll(r.Body)
		f.reqs = append(f.reqs, reqRec{r.Method, r.URL.EscapedPath(), r.URL.RawQuery, string(b)})
		if r.Header.Get("Authorization") != "Bearer "+f.token || f.token == "" {
			w.Header().Set("WWW-Authenticate", "Bearer")
			werr(w, 401, "unauthorized")
			return
		}
		if f.fail401 > 0 {
			f.fail401--
			werr(w, 401, "unauthorized")
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(b)))
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/admin/v1")
		r.URL.RawPath = ""
		api.ServeHTTP(w, r)
	})
	return mux
}

func dec(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }

func (f *fake) routes(m *http.ServeMux) {
	m.HandleFunc("GET /status", func(w http.ResponseWriter, r *http.Request) {
		wj(w, 200, idp.Status{Connected: true, Version: "1.0", RealmCount: len(f.realms)})
	})
	m.HandleFunc("GET /realms", func(w http.ResponseWriter, r *http.Request) {
		out := []idp.Realm{}
		for _, v := range f.realms {
			out = append(out, *v)
		}
		wj(w, 200, out)
	})
	m.HandleFunc("POST /realms", func(w http.ResponseWriter, r *http.Request) {
		var in idp.Realm
		if dec(r, &in) != nil {
			werr(w, 400, "bad")
			return
		}
		if _, ok := f.realms[in.Realm]; ok {
			werr(w, 409, "exists")
			return
		}
		f.realms[in.Realm] = &in
		wj(w, 201, map[string]string{"id": in.Realm})
	})
	m.HandleFunc("GET /realms/{r}", func(w http.ResponseWriter, r *http.Request) {
		if v, ok := f.realms[r.PathValue("r")]; ok {
			wj(w, 200, v)
			return
		}
		werr(w, 404, "not found")
	})
	m.HandleFunc("PUT /realms/{r}", func(w http.ResponseWriter, r *http.Request) {
		var in idp.Realm
		_ = dec(r, &in)
		f.realms[r.PathValue("r")] = &in
		w.WriteHeader(204)
	})
	m.HandleFunc("DELETE /realms/{r}", func(w http.ResponseWriter, r *http.Request) {
		delete(f.realms, r.PathValue("r"))
		w.WriteHeader(204)
	})
	// clients
	m.HandleFunc("GET /realms/{r}/clients", func(w http.ResponseWriter, r *http.Request) {
		wj(w, 200, append([]idp.Client{}, f.clients[r.PathValue("r")]...))
	})
	m.HandleFunc("POST /realms/{r}/clients", func(w http.ResponseWriter, r *http.Request) {
		rn := r.PathValue("r")
		var in idp.Client
		_ = dec(r, &in)
		for _, c := range f.clients[rn] {
			if c.ClientID == in.ClientID {
				werr(w, 409, "exists")
				return
			}
		}
		in.ID = f.nextID("c")
		f.clients[rn] = append(f.clients[rn], in)
		wj(w, 201, map[string]string{"id": in.ID, "secret": "once"})
	})
	findC := func(r *http.Request) int {
		for i, c := range f.clients[r.PathValue("r")] {
			if c.ID == r.PathValue("id") {
				return i
			}
		}
		return -1
	}
	m.HandleFunc("GET /realms/{r}/clients/{id}", func(w http.ResponseWriter, r *http.Request) {
		if i := findC(r); i >= 0 {
			wj(w, 200, f.clients[r.PathValue("r")][i])
			return
		}
		werr(w, 404, "not found")
	})
	m.HandleFunc("PUT /realms/{r}/clients/{id}", func(w http.ResponseWriter, r *http.Request) {
		i := findC(r)
		if i < 0 {
			werr(w, 404, "not found")
			return
		}
		var in idp.Client
		_ = dec(r, &in)
		in.ID = r.PathValue("id")
		f.clients[r.PathValue("r")][i] = in
		w.WriteHeader(204)
	})
	m.HandleFunc("DELETE /realms/{r}/clients/{id}", func(w http.ResponseWriter, r *http.Request) {
		i := findC(r)
		if i < 0 {
			werr(w, 404, "not found")
			return
		}
		rn := r.PathValue("r")
		f.clients[rn] = append(f.clients[rn][:i], f.clients[rn][i+1:]...)
		w.WriteHeader(204)
	})
	m.HandleFunc("POST /realms/{r}/clients/{id}/secret", func(w http.ResponseWriter, r *http.Request) {
		wj(w, 200, idp.ClientSecret{Type: "secret", Value: "regen"})
	})
	m.HandleFunc("GET /realms/{r}/clients/{id}/secret", func(w http.ResponseWriter, r *http.Request) {
		werr(w, 501, "unsupported")
	})
	m.HandleFunc("GET /realms/{r}/clients/{id}/secret/rotated", func(w http.ResponseWriter, r *http.Request) {
		werr(w, 404, "no rotated secret")
	})
	m.HandleFunc("DELETE /realms/{r}/clients/{id}/secret/rotated", func(w http.ResponseWriter, r *http.Request) {
		werr(w, 404, "no rotated secret")
	})
	m.HandleFunc("GET /realms/{r}/client-scopes", func(w http.ResponseWriter, r *http.Request) {
		wj(w, 200, []idp.ClientScope{{Name: "openid"}, {Name: "profile"}})
	})
	// users
	m.HandleFunc("GET /realms/{r}/users", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		first, _ := strconv.Atoi(q.Get("first"))
		max, _ := strconv.Atoi(q.Get("max"))
		if max == 0 {
			max = 100
		}
		var all []idp.User
		for _, u := range f.users[r.PathValue("r")] {
			if s := q.Get("search"); s == "" || strings.Contains(u.Username, s) {
				all = append(all, u)
			}
		}
		if first > len(all) {
			first = len(all)
		}
		end := min(first+max, len(all))
		wj(w, 200, append([]idp.User{}, all[first:end]...))
	})
	m.HandleFunc("POST /realms/{r}/users", func(w http.ResponseWriter, r *http.Request) {
		rn := r.PathValue("r")
		var in idp.User
		_ = dec(r, &in)
		for _, u := range f.users[rn] {
			if u.Username == in.Username {
				werr(w, 409, "exists")
				return
			}
		}
		in.ID = f.nextID("u")
		f.users[rn] = append(f.users[rn], in)
		wj(w, 201, map[string]string{"id": in.ID})
	})
	findU := func(r *http.Request) int {
		for i, u := range f.users[r.PathValue("r")] {
			if u.ID == r.PathValue("id") {
				return i
			}
		}
		return -1
	}
	m.HandleFunc("GET /realms/{r}/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		if i := findU(r); i >= 0 {
			wj(w, 200, f.users[r.PathValue("r")][i])
			return
		}
		werr(w, 404, "not found")
	})
	m.HandleFunc("PUT /realms/{r}/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		i := findU(r)
		if i < 0 {
			werr(w, 404, "not found")
			return
		}
		var in idp.User
		_ = dec(r, &in)
		in.ID = r.PathValue("id")
		f.users[r.PathValue("r")][i] = in
		w.WriteHeader(204)
	})
	m.HandleFunc("DELETE /realms/{r}/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		i := findU(r)
		if i < 0 {
			werr(w, 404, "not found")
			return
		}
		rn := r.PathValue("r")
		f.users[rn] = append(f.users[rn][:i], f.users[rn][i+1:]...)
		w.WriteHeader(204)
	})
	m.HandleFunc("PUT /realms/{r}/users/{id}/password", func(w http.ResponseWriter, r *http.Request) {
		if findU(r) < 0 {
			werr(w, 404, "not found")
			return
		}
		var in idp.PasswordReset
		_ = dec(r, &in)
		f.passwords[r.PathValue("id")] = in
		w.WriteHeader(204)
	})
	m.HandleFunc("GET /realms/{r}/users/{id}/roles", func(w http.ResponseWriter, r *http.Request) {
		wj(w, 200, idp.RoleMappings{RealmMappings: f.roles[r.PathValue("r")]})
	})
	m.HandleFunc("POST /realms/{r}/users/{id}/roles", func(w http.ResponseWriter, r *http.Request) {
		var in []idp.Role
		_ = dec(r, &in)
		w.WriteHeader(204)
	})
	m.HandleFunc("GET /realms/{r}/users/{id}/groups", func(w http.ResponseWriter, r *http.Request) {
		out := []idp.Group{}
		for _, gid := range f.userGroups[r.PathValue("id")] {
			for _, g := range f.groups[r.PathValue("r")] {
				if g.ID == gid {
					out = append(out, g)
				}
			}
		}
		wj(w, 200, out)
	})
	m.HandleFunc("PUT /realms/{r}/users/{id}/groups/{gid}", func(w http.ResponseWriter, r *http.Request) {
		f.userGroups[r.PathValue("id")] = append(f.userGroups[r.PathValue("id")], r.PathValue("gid"))
		w.WriteHeader(204)
	})
	m.HandleFunc("GET /realms/{r}/roles", func(w http.ResponseWriter, r *http.Request) {
		wj(w, 200, append([]idp.Role{}, f.roles[r.PathValue("r")]...))
	})
	m.HandleFunc("POST /realms/{r}/roles", func(w http.ResponseWriter, r *http.Request) {
		var in idp.Role
		_ = dec(r, &in)
		in.ID = f.nextID("r")
		f.roles[r.PathValue("r")] = append(f.roles[r.PathValue("r")], in)
		wj(w, 201, map[string]string{"id": in.ID})
	})
	m.HandleFunc("GET /realms/{r}/groups", func(w http.ResponseWriter, r *http.Request) {
		wj(w, 200, append([]idp.Group{}, f.groups[r.PathValue("r")]...))
	})
	m.HandleFunc("POST /realms/{r}/groups", func(w http.ResponseWriter, r *http.Request) {
		var in idp.Group
		_ = dec(r, &in)
		in.ID = f.nextID("g")
		in.Path = "/" + in.Name
		f.groups[r.PathValue("r")] = append(f.groups[r.PathValue("r")], in)
		wj(w, 201, map[string]string{"id": in.ID})
	})
	m.HandleFunc("GET /realms/{r}/identity-providers", func(w http.ResponseWriter, r *http.Request) { wj(w, 200, []any{}) })
	m.HandleFunc("POST /realms/{r}/identity-providers", func(w http.ResponseWriter, r *http.Request) {
		werr(w, 501, "federation is not implemented")
	})
	m.HandleFunc("DELETE /realms/{r}/identity-providers/{alias}", func(w http.ResponseWriter, r *http.Request) {
		werr(w, 404, "not found")
	})
	m.HandleFunc("GET /realms/{r}/events", func(w http.ResponseWriter, r *http.Request) {
		wj(w, 200, []idp.AdminEvent{{Time: 5, OperationType: "ADMIN_CREATE", ResourcePath: "clients x"}})
	})
	m.HandleFunc("GET /realms/{r}/keys", func(w http.ResponseWriter, r *http.Request) {
		wj(w, 200, []idp.Key{{ProviderID: "ecdsa-generated", Type: "EC", Status: "ACTIVE", Kid: "k1"}})
	})
	m.HandleFunc("GET /realms/{r}/export", func(w http.ResponseWriter, r *http.Request) {
		wj(w, 200, map[string]any{"version": 1, "realm": r.PathValue("r"), "roles": []any{}, "groups": []any{}, "clients": []any{}})
	})
	m.HandleFunc("POST /realms/{r}/import", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		f.imported = b
		wj(w, 200, map[string]any{"imported": map[string]int{"roles": 0, "groups": 0, "clients": 0}})
	})
}

func setup(t *testing.T) (*Client, *fake) {
	t.Helper()
	f := newFake()
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	c := New(Config{BaseURL: srv.URL + "/", Realm: "platform", ClientID: "haven-admin", ClientSecret: "s3cret", HTTP: srv.Client()})
	return c, f
}

func (f *fake) lastReq() reqRec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reqs[len(f.reqs)-1]
}

func ctx() context.Context { return context.Background() }

func TestAccessorsAndDefaults(t *testing.T) {
	c := New(Config{BaseURL: "http://x:1//", ClientID: "me"})
	if c.BaseURL() != "http://x:1" || c.User() != "me" {
		t.Fatalf("got %q %q", c.BaseURL(), c.User())
	}
	if c.http == nil || c.http.Timeout != 30*time.Second {
		t.Fatalf("default http timeout = %+v", c.http)
	}
}

func TestStatusAndPing(t *testing.T) {
	c, f := setup(t)
	if err := c.Ping(ctx()); err != nil {
		t.Fatal(err)
	}
	st, err := c.Status(ctx())
	if err != nil || !st.Connected || st.Version != "1.0" || st.KeycloakURL != c.BaseURL() {
		t.Fatalf("%+v %v", st, err)
	}
	if r := f.lastReq(); r.Method != "GET" || r.Path != "/admin/v1/status" {
		t.Fatalf("%+v", r)
	}
	// bad credentials: Status degrades, Ping errors with StatusError 401
	bad := New(Config{BaseURL: c.BaseURL(), Realm: "platform", ClientID: "haven-admin", ClientSecret: "nope", HTTP: c.http})
	st, err = bad.Status(ctx())
	if err != nil || st.Connected {
		t.Fatalf("%+v %v", st, err)
	}
	if se := idp.AsStatus(bad.Ping(ctx())); se == nil || se.Code != 401 {
		t.Fatalf("want 401 StatusError, got %v", se)
	}
}

func TestRealmsCRUDAndErrors(t *testing.T) {
	c, f := setup(t)
	if err := c.CreateRealm(ctx(), idp.Realm{Realm: "r1", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	err := c.CreateRealm(ctx(), idp.Realm{Realm: "r1"})
	if !errors.Is(err, idp.ErrConflict) || idp.AsStatus(err).Code != 409 {
		t.Fatalf("want conflict, got %v", err)
	}
	rs, err := c.ListRealms(ctx())
	if err != nil || len(rs) != 1 || rs[0].Realm != "r1" {
		t.Fatalf("%v %v", rs, err)
	}
	g, err := c.GetRealm(ctx(), "r1")
	if err != nil || !g.Enabled {
		t.Fatal(g, err)
	}
	if _, err := c.GetRealm(ctx(), "nope"); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	if ok, err := c.RealmExists(ctx(), "r1"); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if ok, err := c.RealmExists(ctx(), "nope"); ok || err != nil {
		t.Fatal(ok, err)
	}
	if err := c.UpdateRealm(ctx(), "r1", idp.Realm{Realm: "r1", DisplayName: "X"}); err != nil {
		t.Fatal(err)
	}
	if r := f.lastReq(); r.Method != "PUT" || !strings.Contains(r.Body, `"displayName":"X"`) {
		t.Fatalf("%+v", r)
	}
	if err := c.DeleteRealm(ctx(), "r1"); err != nil {
		t.Fatal(err)
	}
	// path segments are escaped
	_, _ = c.GetRealm(ctx(), "a/b c")
	if r := f.lastReq(); r.Path != "/admin/v1/realms/a%2Fb%20c" {
		t.Fatalf("path not escaped: %s", r.Path)
	}
}

func TestClientsAndSecrets(t *testing.T) {
	c, f := setup(t)
	_ = c.CreateRealm(ctx(), idp.Realm{Realm: "r"})
	if err := c.CreateClient(ctx(), "r", idp.Client{ClientID: "app", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateClient(ctx(), "r", idp.Client{ClientID: "app"}); !errors.Is(err, idp.ErrConflict) {
		t.Fatal(err)
	}
	cls, err := c.ListClients(ctx(), "r")
	if err != nil || len(cls) != 1 {
		t.Fatal(cls, err)
	}
	id := cls[0].ID
	got, err := c.GetClient(ctx(), "r", id)
	if err != nil || got.ClientID != "app" {
		t.Fatal(got, err)
	}
	got.Name = "Renamed"
	if err := c.UpdateClient(ctx(), "r", id, *got); err != nil {
		t.Fatal(err)
	}
	if g, _ := c.GetClient(ctx(), "r", id); g.Name != "Renamed" {
		t.Fatal(g)
	}
	s, err := c.RegenerateClientSecret(ctx(), "r", id)
	if err != nil || s.Type != "secret" || s.Value != "regen" {
		t.Fatal(s, err)
	}
	if r := f.lastReq(); r.Method != "POST" || !strings.HasSuffix(r.Path, "/secret") {
		t.Fatalf("%+v", r)
	}
	if _, err := c.GetClientSecret(ctx(), "r", id); idp.AsStatus(err) == nil || idp.AsStatus(err).Code != 501 {
		t.Fatalf("want 501, got %v", err)
	}
	if _, err := c.GetRotatedClientSecret(ctx(), "r", id); !errors.Is(err, idp.ErrNotFound) {
		t.Fatalf("want not found, got %v", err)
	}
	if err := c.InvalidateRotatedClientSecret(ctx(), "r", id); !errors.Is(err, idp.ErrNotFound) {
		t.Fatal(err)
	}
	sc, err := c.ListClientScopes(ctx(), "r")
	if err != nil || len(sc) != 2 {
		t.Fatal(sc, err)
	}
	if err := c.DeleteClient(ctx(), "r", id); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteClient(ctx(), "r", id); !errors.Is(err, idp.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestUsersAndPaging(t *testing.T) {
	c, f := setup(t)
	for i := 0; i < 250; i++ {
		f.users["r"] = append(f.users["r"], idp.User{ID: fmt.Sprintf("x%d", i), Username: fmt.Sprintf("user%03d", i)})
	}
	all, err := c.ListAllUsers(ctx(), "r")
	if err != nil || len(all) != 250 {
		t.Fatalf("len=%d err=%v", len(all), err)
	}
	if all[0].Username != "user000" || all[249].Username != "user249" {
		t.Fatal("order lost")
	}
	// exactly one full page needs a second (empty) request
	f.users["e"] = nil
	for i := 0; i < 100; i++ {
		f.users["e"] = append(f.users["e"], idp.User{ID: fmt.Sprint(i), Username: fmt.Sprint("u", i)})
	}
	f.mu.Lock()
	f.reqs = nil
	f.mu.Unlock()
	all, err = c.ListAllUsers(ctx(), "e")
	if err != nil || len(all) != 100 {
		t.Fatal(len(all), err)
	}
	f.mu.Lock()
	n := len(f.reqs)
	f.mu.Unlock()
	if n != 2 {
		t.Fatalf("want 2 page requests, got %d", n)
	}

	got, err := c.ListUsers(ctx(), "r", "user24")
	if err != nil || len(got) != 10 {
		t.Fatal(len(got), err)
	}
	if r := f.lastReq(); r.Query != "max=100&search=user24" {
		t.Fatalf("query %q", r.Query)
	}

	if err := c.CreateUser(ctx(), "r", idp.User{Username: "new", Enabled: true, RequiredActions: []string{"UPDATE_PASSWORD"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.CreateUser(ctx(), "r", idp.User{Username: "new"}); !errors.Is(err, idp.ErrConflict) {
		t.Fatal(err)
	}
	var id string
	for _, u := range f.users["r"] {
		if u.Username == "new" {
			id = u.ID
		}
	}
	if err := c.UpdateUser(ctx(), "r", id, idp.User{Username: "new", Email: "a@b.c"}); err != nil {
		t.Fatal(err)
	}
	if err := c.ResetPassword(ctx(), "r", id, idp.PasswordReset{Type: "password", Value: "pw", Temporary: true}); err != nil {
		t.Fatal(err)
	}
	if p := f.passwords[id]; p.Value != "pw" || !p.Temporary {
		t.Fatalf("%+v", p)
	}
	if r := f.lastReq(); r.Method != "PUT" || !strings.HasSuffix(r.Path, "/password") {
		t.Fatalf("%+v", r)
	}
	if err := c.DeleteUser(ctx(), "r", id); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteUser(ctx(), "r", id); !errors.Is(err, idp.ErrNotFound) {
		t.Fatal(err)
	}
}

func TestEnsureUserPassword(t *testing.T) {
	c, f := setup(t)
	if err := c.EnsureUserPassword(ctx(), "r", " alice ", "pw1"); err != nil {
		t.Fatal(err)
	}
	if len(f.users["r"]) != 1 || f.users["r"][0].Username != "alice" || !f.users["r"][0].Enabled || !f.users["r"][0].EmailVerified {
		t.Fatalf("%+v", f.users["r"])
	}
	id := f.users["r"][0].ID
	if p := f.passwords[id]; p.Value != "pw1" || p.Temporary || p.Type != "password" {
		t.Fatalf("%+v", p)
	}
	if err := c.EnsureUserPassword(ctx(), "r", "alice", "pw2"); err != nil {
		t.Fatal(err)
	}
	if len(f.users["r"]) != 1 || f.passwords[id].Value != "pw2" {
		t.Fatal("not idempotent")
	}
	if err := c.EnsureUserPassword(ctx(), "r", "", "x"); err == nil {
		t.Fatal("want error")
	}
}

func TestRolesGroups(t *testing.T) {
	c, f := setup(t)
	if err := c.CreateRole(ctx(), "r", idp.Role{Name: "admin"}); err != nil {
		t.Fatal(err)
	}
	roles, err := c.ListRoles(ctx(), "r")
	if err != nil || len(roles) != 1 || roles[0].Name != "admin" {
		t.Fatal(roles, err)
	}
	f.users["r"] = []idp.User{{ID: "u1", Username: "a"}}
	if err := c.AddRealmRoleMappings(ctx(), "r", "u1", roles); err != nil {
		t.Fatal(err)
	}
	if rq := f.lastReq(); rq.Method != "POST" || !strings.Contains(rq.Body, `"admin"`) {
		t.Fatalf("%+v", rq)
	}
	rm, err := c.GetUserRoleMappings(ctx(), "r", "u1")
	if err != nil || len(rm.RealmMappings) != 1 {
		t.Fatal(rm, err)
	}
	if err := c.CreateGroup(ctx(), "r", idp.Group{Name: "ops"}); err != nil {
		t.Fatal(err)
	}
	gs, _ := c.ListGroups(ctx(), "r")
	if len(gs) != 1 || gs[0].Path != "/ops" {
		t.Fatal(gs)
	}
	if err := c.JoinGroup(ctx(), "r", "u1", gs[0].ID); err != nil {
		t.Fatal(err)
	}
	ug, err := c.ListUserGroups(ctx(), "r", "u1")
	if err != nil || len(ug) != 1 || ug[0].Name != "ops" {
		t.Fatal(ug, err)
	}
}

func TestFederationEventsKeysExport(t *testing.T) {
	c, f := setup(t)
	ips, err := c.ListIdentityProviders(ctx(), "r")
	if err != nil || len(ips) != 0 {
		t.Fatal(ips, err)
	}
	if err := c.CreateIdentityProvider(ctx(), "r", idp.IdentityProvider{Alias: "x"}); idp.AsStatus(err) == nil || idp.AsStatus(err).Code != 501 {
		t.Fatalf("want 501, got %v", err)
	}
	if err := c.DeleteIdentityProvider(ctx(), "r", "a/b"); !errors.Is(err, idp.ErrNotFound) {
		t.Fatal(err)
	}
	if r := f.lastReq(); r.Path != "/admin/v1/realms/r/identity-providers/a%2Fb" {
		t.Fatal(r.Path)
	}
	ev, err := c.ListAdminEvents(ctx(), "r")
	if err != nil || len(ev) != 1 || ev[0].OperationType != "ADMIN_CREATE" {
		t.Fatal(ev, err)
	}
	if r := f.lastReq(); r.Query != "max=50" {
		t.Fatal(r.Query)
	}
	ks, err := c.ListKeys(ctx(), "r")
	if err != nil || len(ks) != 1 || ks[0].Kid != "k1" {
		t.Fatal(ks, err)
	}
	raw, err := c.PartialExport(ctx(), "r")
	if err != nil {
		t.Fatal(err)
	}
	var exp map[string]any
	if err := json.Unmarshal(raw, &exp); err != nil || exp["realm"] != "r" {
		t.Fatal(exp, err)
	}
	if err := c.PartialImport(ctx(), "r", raw); err != nil {
		t.Fatal(err)
	}
	var a, b any
	_ = json.Unmarshal(raw, &a)
	_ = json.Unmarshal(f.imported, &b)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("import body %s != %s", f.imported, raw)
	}
}

func TestEnsureHavenConsoleClientMerge(t *testing.T) {
	t.Setenv("HAVEN_OIDC_CLIENT_ID", "haven-console")
	c, f := setup(t)
	if err := c.EnsureHavenConsoleClient(ctx(), "r", "https://console.example/"); err != nil {
		t.Fatal(err)
	}
	cl := f.clients["r"][0]
	if !cl.PublicClient || !cl.StandardFlowEnabled || cl.DirectAccessGrantsEnabled || !cl.Enabled ||
		cl.Attributes["pkce.code.challenge.method"] != "S256" || !reflect.DeepEqual(cl.WebOrigins, []string{"+"}) {
		t.Fatalf("%+v", cl)
	}
	has := func(uris []string, s string) bool {
		for _, u := range uris {
			if u == s {
				return true
			}
		}
		return false
	}
	if !has(cl.RedirectURIs, "https://console.example/*") || !has(cl.RedirectURIs, "https://console.example/api/v1/auth/oidc/callback") ||
		!has(cl.RedirectURIs, "http://localhost:8080/*") {
		t.Fatalf("%v", cl.RedirectURIs)
	}
	// Tamper: custom URI kept, host wildcard dropped, flags reset, extra attr kept.
	cl.RedirectURIs = []string{"https://custom.example/cb", "http://*/*", "https://console.example/*"}
	cl.PublicClient = false
	cl.DirectAccessGrantsEnabled = true
	cl.Enabled = false
	cl.Attributes = map[string]string{"keep": "me", "pkce.code.challenge.method": "plain"}
	f.clients["r"][0] = cl
	if err := c.EnsureHavenConsoleClient(ctx(), "r", "https://other.example"); err != nil {
		t.Fatal(err)
	}
	if len(f.clients["r"]) != 1 {
		t.Fatal("duplicated client")
	}
	got := f.clients["r"][0]
	if got.ID != cl.ID || !got.PublicClient || got.DirectAccessGrantsEnabled || !got.Enabled ||
		got.Attributes["keep"] != "me" || got.Attributes["pkce.code.challenge.method"] != "S256" {
		t.Fatalf("%+v", got)
	}
	if !has(got.RedirectURIs, "https://custom.example/cb") || !has(got.RedirectURIs, "https://other.example/*") ||
		!has(got.RedirectURIs, "https://console.example/*") || has(got.RedirectURIs, "http://*/*") {
		t.Fatalf("%v", got.RedirectURIs)
	}
	seen := map[string]bool{}
	for _, u := range got.RedirectURIs {
		if seen[u] {
			t.Fatalf("duplicate %s", u)
		}
		seen[u] = true
	}
	// Sent update must not carry a secret.
	if r := f.lastReq(); r.Method != "PUT" || strings.Contains(r.Body, `"secret"`) {
		t.Fatalf("%+v", r)
	}
}

func TestBootstrapRealmIdempotent(t *testing.T) {
	c, f := setup(t)
	if err := c.BootstrapRealm(ctx(), "platform"); err != nil {
		t.Fatal(err)
	}
	if r := f.realms["platform"]; r == nil || !r.Enabled || r.DisplayName != "Private Cloud" {
		t.Fatalf("%+v", r)
	}
	if len(f.clients["platform"]) != 2 {
		t.Fatalf("%+v", f.clients["platform"])
	}
	before := fmt.Sprint(f.clients["platform"])
	if err := c.BootstrapRealm(ctx(), "platform"); err != nil {
		t.Fatal(err)
	}
	if len(f.clients["platform"]) != 2 || fmt.Sprint(f.clients["platform"]) != before {
		t.Fatalf("not idempotent: %+v", f.clients["platform"])
	}
}

func TestBootstrapRealmCreateConflictIgnored(t *testing.T) {
	c, f := setup(t)
	// Realm appears between exists-check and create: simulate by pre-seeding
	// after the GET via a wrapper is hard; instead make create return 409 only.
	f.realms["race"] = &idp.Realm{Realm: "race"}
	err := c.CreateRealm(ctx(), idp.Realm{Realm: "race"})
	if !errors.Is(err, idp.ErrConflict) {
		t.Fatal(err)
	}
	if err := c.BootstrapRealm(ctx(), "race"); err != nil {
		t.Fatal(err)
	}
}

func TestTokenCachingAndExpiry(t *testing.T) {
	c, f := setup(t)
	for i := 0; i < 20; i++ {
		if _, err := c.ListRealms(ctx()); err != nil {
			t.Fatal(err)
		}
	}
	if f.tokenHits != 1 {
		t.Fatalf("token hits = %d", f.tokenHits)
	}
	c.mu.Lock()
	c.expires = time.Now().Add(20 * time.Second) // inside the 30s skew
	c.mu.Unlock()
	if _, err := c.ListRealms(ctx()); err != nil {
		t.Fatal(err)
	}
	if f.tokenHits != 2 {
		t.Fatalf("token hits after expiry = %d", f.tokenHits)
	}
	// Short-lived tokens are never cached past the skew.
	f.expiresIn = 10
	c.mu.Lock()
	c.expires = time.Time{}
	c.mu.Unlock()
	_, _ = c.ListRealms(ctx())
	_, _ = c.ListRealms(ctx())
	if f.tokenHits != 4 {
		t.Fatalf("token hits = %d", f.tokenHits)
	}
}

func TestRetryOn401(t *testing.T) {
	c, f := setup(t)
	if _, err := c.ListRealms(ctx()); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.fail401 = 1
	f.mu.Unlock()
	if _, err := c.ListRealms(ctx()); err != nil {
		t.Fatalf("retry should succeed: %v", err)
	}
	if f.tokenHits != 2 {
		t.Fatalf("token hits = %d, want fresh token on retry", f.tokenHits)
	}
	// Persistent 401 is surfaced after exactly one retry.
	f.mu.Lock()
	f.fail401 = 100
	f.reqs = nil
	f.mu.Unlock()
	_, err := c.ListRealms(ctx())
	if se := idp.AsStatus(err); se == nil || se.Code != 401 {
		t.Fatalf("want 401, got %v", err)
	}
	if len(f.reqs) != 2 {
		t.Fatalf("want 2 attempts, got %d", len(f.reqs))
	}
	// Retry replays the body.
	f.mu.Lock()
	f.fail401 = 1
	f.mu.Unlock()
	if err := c.CreateRealm(ctx(), idp.Realm{Realm: "again"}); err != nil {
		t.Fatal(err)
	}
	if f.realms["again"] == nil {
		t.Fatal("body not replayed")
	}
}

func TestBearerEnforcedAndNoSecretLeak(t *testing.T) {
	c, _ := setup(t)
	bad := New(Config{BaseURL: c.BaseURL(), Realm: "platform", ClientID: "haven-admin", ClientSecret: "wrong-secret", HTTP: c.http})
	_, err := bad.ListRealms(ctx())
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "wrong-secret") {
		t.Fatal("secret leaked in error")
	}
}

func TestConcurrentCallers(t *testing.T) {
	c, f := setup(t)
	f.users["r"] = []idp.User{{ID: "1", Username: "a"}}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.ListUsers(ctx(), "r", ""); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.tokenHits != 1 {
		t.Fatalf("single-flight broken: %d token requests", f.tokenHits)
	}
}

func TestBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			wj(w, 200, map[string]any{"access_token": "t", "expires_in": 3600})
			return
		}
		_, _ = w.Write([]byte("["))
		chunk := strings.Repeat(" ", 1<<20)
		for i := 0; i < 9; i++ {
			_, _ = w.Write([]byte(chunk))
		}
		_, _ = w.Write([]byte("]"))
	}))
	defer srv.Close()
	c := New(Config{BaseURL: srv.URL, Realm: "p", ClientID: "a", ClientSecret: "b"})
	if _, err := c.ListRealms(ctx()); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("want too large, got %v", err)
	}
}

func TestContextCancel(t *testing.T) {
	c, _ := setup(t)
	cx, cancel := context.WithCancel(ctx())
	cancel()
	if _, err := c.ListRealms(cx); err == nil {
		t.Fatal("want error")
	}
}
