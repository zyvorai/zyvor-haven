// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"net/http"
	"regexp"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Login fallback and step-up policy, and known devices (see SPEC.md,
// "Login fallback and step-up").
func init() {
	registerRoutes(func(a *api, m *http.ServeMux) {
		p := pathPrefix + "/realms/{r}"
		m.HandleFunc("GET "+p+"/stepup-policy", a.getStepUpPolicy)
		m.HandleFunc("PUT "+p+"/stepup-policy", a.op("stepup-policy", "update", a.putStepUpPolicy))
		m.HandleFunc("GET "+p+"/users/{id}/devices", a.listDevices)
		m.HandleFunc("DELETE "+p+"/users/{id}/devices", a.op("user-devices", "delete", a.deleteDevices))
		m.HandleFunc("DELETE "+p+"/users/{id}/devices/{hash}", a.op("user-devices", "delete", a.deleteDevice))
	})
}

func (a *api) stepUpStore(w http.ResponseWriter) (core.StepUpStore, bool) {
	st, ok := core.StoreAs[core.StepUpStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "this store does not support step-up policy")
		return nil, false
	}
	return st, true
}

type stepUpBody struct {
	AllowFallback              bool     `json:"allowFallback"`
	Enabled                    bool     `json:"enabled"`
	Enforce                    bool     `json:"enforce"`
	OnNewDevice                bool     `json:"onNewDevice"`
	OnIPChange                 bool     `json:"onIpChange"`
	IdleAfterSeconds           int64    `json:"idleAfterSeconds"`
	OnMaxAge                   bool     `json:"onMaxAge"`
	SensitiveScopes            []string `json:"sensitiveScopes"`
	SensitiveAuthMaxAgeSeconds int64    `json:"sensitiveAuthMaxAgeSeconds"`
}

func toStepUpBody(p core.StepUpPolicy) stepUpBody {
	scopes := p.SensitiveScopes
	if scopes == nil {
		scopes = []string{}
	}
	return stepUpBody{AllowFallback: p.AllowFallback, Enabled: p.Enabled, Enforce: p.Enforce, OnNewDevice: p.OnNewDevice,
		OnIPChange: p.OnIPChange, IdleAfterSeconds: int64(p.IdleAfter / time.Second), OnMaxAge: p.OnMaxAge,
		SensitiveScopes: scopes, SensitiveAuthMaxAgeSeconds: int64(p.SensitiveAuthMaxAge / time.Second)}
}

func (a *api) getStepUpPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.stepUpStore(w)
	if !ok {
		return
	}
	p, err := st.GetStepUpPolicy(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toStepUpBody(p))
}

const (
	maxSensitiveScopes = 20
	maxStepUpSeconds   = 366 * 24 * 3600
)

var scopeTokenRe = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,64}$`)

func (a *api) putStepUpPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.stepUpStore(w)
	if !ok {
		return
	}
	var in stepUpBody
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if in.IdleAfterSeconds < 0 || in.IdleAfterSeconds > maxStepUpSeconds ||
		in.SensitiveAuthMaxAgeSeconds < 0 || in.SensitiveAuthMaxAgeSeconds > maxStepUpSeconds {
		a.fail(w, r, bad("idleAfterSeconds and sensitiveAuthMaxAgeSeconds must be between 0 and one year"))
		return
	}
	if len(in.SensitiveScopes) > maxSensitiveScopes {
		a.fail(w, r, bad("too many sensitiveScopes"))
		return
	}
	seen := map[string]bool{}
	var scopes []string
	for _, s := range in.SensitiveScopes {
		if !scopeTokenRe.MatchString(s) {
			a.fail(w, r, bad("invalid scope in sensitiveScopes"))
			return
		}
		if !seen[s] {
			seen[s] = true
			scopes = append(scopes, s)
		}
	}
	if in.Enforce && !in.Enabled {
		a.fail(w, r, bad("enforce requires enabled"))
		return
	}
	p := core.StepUpPolicy{AllowFallback: in.AllowFallback, Enabled: in.Enabled, Enforce: in.Enforce,
		OnNewDevice: in.OnNewDevice, OnIPChange: in.OnIPChange, IdleAfter: time.Duration(in.IdleAfterSeconds) * time.Second,
		OnMaxAge: in.OnMaxAge, SensitiveScopes: scopes,
		SensitiveAuthMaxAge: time.Duration(in.SensitiveAuthMaxAgeSeconds) * time.Second}
	if err := st.PutStepUpPolicy(r.Context(), rl.Name, p); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "stepup-policy", rl.Name)
	writeJSON(w, http.StatusOK, toStepUpBody(p))
}

type deviceView struct {
	ID        string    `json:"id"`
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

func (a *api) listDevices(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.stepUpStore(w)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	ds, err := st.ListDevices(r.Context(), rl.Name, u.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]deviceView, 0, len(ds))
	for _, d := range ds { // the IP hash is never exposed
		out = append(out, deviceView{ID: d.Hash, FirstSeen: d.FirstSeen.UTC(), LastSeen: d.LastSeen.UTC()})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) deleteDevices(w http.ResponseWriter, r *http.Request) {
	a.forgetDevices(w, r, "")
}

func (a *api) deleteDevice(w http.ResponseWriter, r *http.Request) {
	a.forgetDevices(w, r, r.PathValue("hash"))
}

func (a *api) forgetDevices(w http.ResponseWriter, r *http.Request, hash string) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.stepUpStore(w)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if hash == "" {
		err = st.DeleteUserDevices(r.Context(), rl.Name, u.ID)
	} else {
		err = st.DeleteDevice(r.Context(), rl.Name, u.ID, hash)
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "ACTION", "user-devices", u.Username)
	noContent(w)
}
