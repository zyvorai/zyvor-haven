// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func (a *api) miscRoutes(m *http.ServeMux) {
	p := pathPrefix + "/realms/{r}"
	m.HandleFunc("GET "+p+"/client-scopes", a.clientScopes)
	// identity-providers: federation.go
	m.HandleFunc("GET "+p+"/events", a.events)
	m.HandleFunc("GET "+p+"/keys", a.keys)
	m.HandleFunc("GET "+p+"/export", a.export)
	m.HandleFunc("POST "+p+"/import", a.op("import", "action", a.importRealm))
}

func (a *api) clientScopes(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.realmOf(w, r); !ok {
		return
	}
	out := []idp.ClientScope{}
	for _, n := range []string{"openid", "profile", "email", "offline_access"} {
		out = append(out, idp.ClientScope{ID: n, Name: n})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) events(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	max, err := intParam(r, "max", 50, 1, 1000)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	// Auth events share the list, so read the whole window and filter.
	evs, err := a.cfg.Store.ListEvents(r.Context(), rl.Name, 1000)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := []idp.AdminEvent{}
	for _, e := range evs {
		if !strings.HasPrefix(e.Type, "ADMIN_") {
			continue
		}
		res, path, _ := strings.Cut(e.Detail, " ")
		out = append(out, idp.AdminEvent{
			Time: e.Time.UnixMilli(), RealmID: rl.Name,
			OperationType: strings.TrimPrefix(e.Type, "ADMIN_"),
			ResourceType:  strings.ToUpper(res), ResourcePath: path,
		})
		if len(out) >= max {
			break
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) keys(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	ks, err := a.cfg.Store.ListSigningKeys(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := []idp.Key{}
	for _, k := range ks {
		st := "PASSIVE"
		if k.Active {
			st = "ACTIVE"
		}
		out = append(out, idp.Key{ProviderID: "ecdsa-generated", Status: st, Type: "EC", Kid: k.KID})
	}
	writeJSON(w, http.StatusOK, out)
}

// ---- native export / import ----

type nativeExport struct {
	Version int          `json:"version"`
	Realm   string       `json:"realm"`
	Roles   []idp.Role   `json:"roles"`
	Groups  []idp.Group  `json:"groups"`
	Clients []idp.Client `json:"clients"`
}

func (a *api) export(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	rs, err := a.cfg.Store.ListRoles(ctx, rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	gs, err := a.cfg.Store.ListGroups(ctx, rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	cs, err := a.cfg.Store.ListClients(ctx, rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := nativeExport{Version: 1, Realm: rl.Name, Roles: []idp.Role{}, Groups: []idp.Group{}, Clients: []idp.Client{}}
	for _, x := range rs {
		out.Roles = append(out.Roles, roleToWire(x))
	}
	for _, x := range gs {
		out.Groups = append(out.Groups, groupToWire(x))
	}
	for _, x := range cs {
		out.Clients = append(out.Clients, clientToWire(x))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) importRealm(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	var in nativeExport
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if in.Version != 1 {
		a.fail(w, r, bad("unsupported export version"))
		return
	}
	// Validate everything before writing anything.
	clients := make([]core.Client, 0, len(in.Clients))
	for _, c := range in.Clients {
		cc, err := clientFromWire(c)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		cc.Realm = rl.Name
		clients = append(clients, cc)
	}
	for _, x := range in.Roles {
		if err := validRole(x); err != nil {
			a.fail(w, r, err)
			return
		}
	}
	for _, g := range in.Groups {
		if err := validGroup(g); err != nil {
			a.fail(w, r, err)
			return
		}
	}

	ctx := r.Context()
	var nr, ng, nc int
	skip := func(err error) (bool, error) {
		if err == nil {
			return true, nil
		}
		if errors.Is(err, idp.ErrConflict) {
			return false, nil
		}
		return false, err
	}
	for _, x := range in.Roles {
		made, err := skip(a.cfg.Store.CreateRole(ctx, core.Role{Realm: rl.Name, Name: x.Name, Description: x.Description}))
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if made {
			nr++
		}
	}
	for _, g := range in.Groups {
		made, err := skip(a.cfg.Store.CreateGroup(ctx, core.Group{Realm: rl.Name, Name: g.Name, Path: "/" + g.Name}))
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if made {
			ng++
		}
	}
	for _, c := range clients {
		made, err := skip(a.cfg.Store.CreateClient(ctx, c))
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if made {
			nc++
		}
	}
	a.audit(r, rl, "ACTION", "import", rl.Name)
	writeJSON(w, http.StatusOK, map[string]any{"imported": map[string]int{"roles": nr, "groups": ng, "clients": nc}})
}
