// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"net/http"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
)

func (a *api) realmRoutes(m *http.ServeMux) {
	p := pathPrefix + "/realms"
	m.HandleFunc("GET "+p, a.listRealms)
	m.HandleFunc("POST "+p, a.op("realm", "create", a.createRealm))
	m.HandleFunc("GET "+p+"/{r}", a.getRealm)
	m.HandleFunc("PUT "+p+"/{r}", a.op("realm", "update", a.updateRealm))
	m.HandleFunc("DELETE "+p+"/{r}", a.op("realm", "delete", a.deleteRealm))
}

func (a *api) status(w http.ResponseWriter, r *http.Request) {
	rs, err := a.cfg.Store.ListRealms(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, idp.Status{
		Connected: true, Version: a.cfg.Version, RealmCount: len(rs), IdentityServerURL: a.base,
	})
}

func (a *api) listRealms(w http.ResponseWriter, r *http.Request) {
	rs, err := a.cfg.Store.ListRealms(r.Context())
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]idp.Realm, 0, len(rs))
	for _, x := range rs {
		out = append(out, realmToWire(x))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) getRealm(w http.ResponseWriter, r *http.Request) {
	if rl, ok := a.realmOf(w, r); ok {
		writeJSON(w, http.StatusOK, realmToWire(rl))
	}
}

func (a *api) createRealm(w http.ResponseWriter, r *http.Request) {
	var in idp.Realm
	present, err := decode(r, &in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !realmNameRE.MatchString(in.Realm) {
		a.fail(w, r, bad("invalid realm name"))
		return
	}
	rl, err := applyRealm(secureRealmDefaults(in.Realm), in, present)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !a.guardRealm(w, r, nil, rl) {
		return
	}
	if err := a.cfg.Store.CreateRealm(r.Context(), rl); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := a.cfg.Signer.EnsureKey(r.Context(), rl.Name); err != nil {
		a.cfg.Logger.Error("admin: ensure signing key", "realm", rl.Name, "err", err.Error())
	}
	noteRealm(r, rl.Name)
	a.audit(r, rl, "CREATE", "realm", rl.Name)
	created(w, pathPrefix+"/realms/"+rl.Name, map[string]string{"id": rl.Name})
}

func (a *api) updateRealm(w http.ResponseWriter, r *http.Request) {
	cur, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	var in idp.Realm
	present, err := decode(r, &in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if in.Realm != "" && !strings.EqualFold(in.Realm, cur.Name) {
		a.fail(w, r, bad("realm name cannot be changed"))
		return
	}
	next, err := applyRealm(cur, in, present)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if strings.EqualFold(cur.Name, a.cfg.AdminRealm) && !next.Enabled {
		writeErr(w, http.StatusConflict, "the admin realm cannot be disabled")
		return
	}
	if !a.guardRealm(w, r, &cur, next) {
		return
	}
	if err := a.cfg.Store.UpdateRealm(r.Context(), next); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, next, "UPDATE", "realm", next.Name)
	noContent(w)
}

func (a *api) deleteRealm(w http.ResponseWriter, r *http.Request) {
	cur, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	if strings.EqualFold(cur.Name, a.cfg.AdminRealm) {
		writeErr(w, http.StatusConflict, "the admin realm cannot be deleted")
		return
	}
	if err := a.cfg.Store.DeleteRealm(r.Context(), cur.Name); err != nil {
		a.fail(w, r, err)
		return
	}
	noContent(w)
}
