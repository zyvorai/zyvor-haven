// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package configcode

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/zyvorai/haven/internal/idp"
)

// fakeProvider is an in-memory idp.Provider with the native server's error
// semantics. Methods not overridden panic (nil embedded interface).
type fakeProvider struct {
	idp.Provider
	mu      sync.Mutex
	realms  map[string]*idp.Realm
	roles   map[string][]idp.Role
	groups  map[string][]idp.Group
	clients map[string][]idp.Client
	secrets map[string]string // clientId -> secret
	calls   []string
	fail    func(call string) error // consulted before every mutating call
	seq     int
}

func newFake() *fakeProvider {
	return &fakeProvider{
		realms: map[string]*idp.Realm{}, roles: map[string][]idp.Role{},
		groups: map[string][]idp.Group{}, clients: map[string][]idp.Client{},
		secrets: map[string]string{},
	}
}

// fakeSC adds idp.SecretCreator.
type fakeSC struct{ *fakeProvider }

func (f fakeSC) CreateClientWithSecret(ctx context.Context, realm string, cl idp.Client) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.pre("CreateClientWithSecret:" + cl.ClientID); err != nil {
		return "", "", err
	}
	id, err := f.addClient(realm, cl)
	if err != nil {
		return "", "", err
	}
	secret := "s3cr3t-" + cl.ClientID
	f.secrets[cl.ClientID] = secret
	return id, secret, nil
}

func statusErr(code int, msg string) error { return &idp.StatusError{Code: code, Body: []byte(msg)} }

// pre records the call and applies the failure hook. Caller holds f.mu.
func (f *fakeProvider) pre(call string) error {
	f.calls = append(f.calls, call)
	if f.fail != nil {
		return f.fail(call)
	}
	return nil
}

func (f *fakeProvider) callLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeProvider) GetRealm(_ context.Context, realm string) (*idp.Realm, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.realms[realm]
	if !ok {
		return nil, statusErr(http.StatusNotFound, "realm not found")
	}
	c := *r
	if r.RealmHardening != nil {
		h := *r.RealmHardening
		c.RealmHardening = &h
	}
	return &c, nil
}

func (f *fakeProvider) CreateRealm(_ context.Context, r idp.Realm) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.pre("CreateRealm"); err != nil {
		return err
	}
	if _, ok := f.realms[r.Realm]; ok {
		return statusErr(http.StatusConflict, "realm exists")
	}
	h := idp.RealmHardening{}
	if r.RealmHardening != nil {
		h = *r.RealmHardening
	}
	def := func(p **string, v string) {
		if *p == nil {
			*p = &v
		}
	}
	defInt := func(p **int, v int) {
		if *p == nil {
			*p = &v
		}
	}
	defBool := func(p **bool, v bool) {
		if *p == nil {
			*p = &v
		}
	}
	def(&h.SSLRequired, "external")
	def(&h.PasswordPolicy, "length(12)")
	defInt(&h.AccessTokenLifespan, 300)
	defInt(&h.SSOSessionIdleTimeout, 1800)
	defBool(&h.RevokeRefreshToken, true)
	defBool(&h.EventsEnabled, true)
	defBool(&h.AdminEventsEnabled, false)
	r.RealmHardening = &h
	f.realms[r.Realm] = &r
	return nil
}

func (f *fakeProvider) UpdateRealm(_ context.Context, realm string, body idp.Realm) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.pre("UpdateRealm"); err != nil {
		return err
	}
	if _, ok := f.realms[realm]; !ok {
		return statusErr(http.StatusNotFound, "realm not found")
	}
	// PUT replaces mutable fields; absent hardening fields reset to zero.
	body.Realm = realm
	f.realms[realm] = &body
	return nil
}

func (f *fakeProvider) ListRoles(_ context.Context, realm string) ([]idp.Role, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]idp.Role(nil), f.roles[realm]...), nil
}

func (f *fakeProvider) CreateRole(_ context.Context, realm string, r idp.Role) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.pre("CreateRole:" + r.Name); err != nil {
		return err
	}
	for _, x := range f.roles[realm] {
		if strings.EqualFold(x.Name, r.Name) {
			return statusErr(http.StatusConflict, "role exists")
		}
	}
	f.roles[realm] = append(f.roles[realm], r)
	return nil
}

func (f *fakeProvider) ListGroups(_ context.Context, realm string) ([]idp.Group, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]idp.Group(nil), f.groups[realm]...), nil
}

func (f *fakeProvider) CreateGroup(_ context.Context, realm string, g idp.Group) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.pre("CreateGroup:" + g.Name); err != nil {
		return err
	}
	for _, x := range f.groups[realm] {
		if strings.EqualFold(x.Name, g.Name) {
			return statusErr(http.StatusConflict, "group exists")
		}
	}
	g.Path = "/" + g.Name
	f.groups[realm] = append(f.groups[realm], g)
	return nil
}

func (f *fakeProvider) ListClients(_ context.Context, realm string) ([]idp.Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]idp.Client(nil), f.clients[realm]...), nil
}

func (f *fakeProvider) addClient(realm string, cl idp.Client) (string, error) {
	if _, ok := f.realms[realm]; !ok {
		return "", statusErr(http.StatusNotFound, "realm not found")
	}
	if err := checkClient(cl); err != nil {
		return "", err
	}
	for _, x := range f.clients[realm] {
		if x.ClientID == cl.ClientID {
			return "", statusErr(http.StatusConflict, "client exists")
		}
	}
	f.seq++
	cl.ID = "id-" + cl.ClientID + "-" + string(rune('a'+f.seq%26))
	cl.Secret = ""
	f.clients[realm] = append(f.clients[realm], cl)
	return cl.ID, nil
}

func checkClient(cl idp.Client) error {
	for _, u := range cl.RedirectURIs {
		if strings.Contains(u, "*") {
			return statusErr(http.StatusBadRequest, "wildcard redirect uri")
		}
	}
	if cl.ImplicitFlowEnabled {
		return statusErr(http.StatusBadRequest, "implicit flow not supported")
	}
	if cl.BearerOnly {
		return statusErr(http.StatusBadRequest, "bearerOnly not supported")
	}
	return nil
}

func (f *fakeProvider) CreateClient(_ context.Context, realm string, cl idp.Client) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.pre("CreateClient:" + cl.ClientID); err != nil {
		return err
	}
	_, err := f.addClient(realm, cl)
	return err
}

func (f *fakeProvider) UpdateClient(_ context.Context, realm, id string, cl idp.Client) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.pre("UpdateClient:" + cl.ClientID); err != nil {
		return err
	}
	if err := checkClient(cl); err != nil {
		return err
	}
	for i, x := range f.clients[realm] {
		if x.ID == id {
			cl.ID, cl.Secret = id, ""
			f.clients[realm][i] = cl
			return nil
		}
	}
	return statusErr(http.StatusNotFound, "client not found")
}

// GetClientSecret behaves like Keycloak: the plain fake reads secrets back.
func (f *fakeProvider) GetClientSecret(_ context.Context, _, id string) (*idp.ClientSecret, error) {
	return &idp.ClientSecret{Type: "secret", Value: "kc-" + id}, nil
}

func (f *fakeProvider) DeleteClient(_ context.Context, realm, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.pre("DeleteClient:" + id); err != nil {
		return err
	}
	for i, x := range f.clients[realm] {
		if x.ID == id {
			f.clients[realm] = append(f.clients[realm][:i:i], f.clients[realm][i+1:]...)
			return nil
		}
	}
	return statusErr(http.StatusNotFound, "client not found")
}
