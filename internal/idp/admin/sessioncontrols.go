// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"net/http"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// Session controls and front-channel logout (see SPEC.md, "Session controls").
func init() {
	registerRoutes(func(a *api, m *http.ServeMux) {
		p := pathPrefix + "/realms/{r}"
		m.HandleFunc("GET "+p+"/session-policy", a.getSessionPolicy)
		m.HandleFunc("PUT "+p+"/session-policy", a.op("session-policy", "update", a.putSessionPolicy))
		m.HandleFunc("GET "+p+"/clients/{id}/frontchannel-logout", a.getFrontchannel)
		m.HandleFunc("PUT "+p+"/clients/{id}/frontchannel-logout", a.op("client", "update", a.putFrontchannel))
	})
}

type sessionPolicyBody struct {
	MaxSessionsPerUser  int    `json:"maxSessionsPerUser"`
	OnLimit             string `json:"onLimit"`
	RememberMe          bool   `json:"rememberMe"`
	RememberIdleSeconds int64  `json:"rememberIdleSeconds"`
	RememberMaxSeconds  int64  `json:"rememberMaxSeconds"`
}

// toSessionPolicyBody shows the effective values: the default action and, while
// "keep me signed in" is on, the lifetimes actually applied.
func toSessionPolicyBody(p core.SessionPolicy) sessionPolicyBody {
	b := sessionPolicyBody{MaxSessionsPerUser: p.MaxSessions, OnLimit: p.OnLimit, RememberMe: p.RememberMe,
		RememberIdleSeconds: int64(p.RememberIdle / time.Second), RememberMaxSeconds: int64(p.RememberMax / time.Second)}
	if b.OnLimit == "" {
		b.OnLimit = core.SessionLimitRevokeOldest
	}
	if p.RememberMe {
		idle, absolute := p.RememberLifetimes()
		b.RememberIdleSeconds, b.RememberMaxSeconds = int64(idle/time.Second), int64(absolute/time.Second)
	}
	return b
}

func (a *api) sessionPolicyStore(w http.ResponseWriter) (core.SessionPolicyStore, bool) {
	st, ok := core.StoreAs[core.SessionPolicyStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "this store does not support session controls")
	}
	return st, ok
}

func (a *api) getSessionPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.sessionPolicyStore(w)
	if !ok {
		return
	}
	p, err := st.GetSessionPolicy(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, toSessionPolicyBody(p))
}

// putSessionPolicy replaces the policy: absent fields are off / default.
func (a *api) putSessionPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.sessionPolicyStore(w)
	if !ok {
		return
	}
	var in sessionPolicyBody
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	// Bound the seconds before converting: a huge number must not wrap around.
	limit := int64(core.MaxRememberMax / time.Second)
	if in.RememberIdleSeconds < 0 || in.RememberIdleSeconds > limit || in.RememberMaxSeconds < 0 || in.RememberMaxSeconds > limit {
		a.fail(w, r, bad("rememberIdleSeconds and rememberMaxSeconds must be between 0 and 90 days"))
		return
	}
	p := core.SessionPolicy{MaxSessions: in.MaxSessionsPerUser, OnLimit: in.OnLimit, RememberMe: in.RememberMe,
		RememberIdle: time.Duration(in.RememberIdleSeconds) * time.Second,
		RememberMax:  time.Duration(in.RememberMaxSeconds) * time.Second}
	if err := p.Validate(); err != nil {
		a.fail(w, r, bad(err.Error()))
		return
	}
	if err := st.PutSessionPolicy(r.Context(), rl.Name, p); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "session-policy", rl.Name)
	writeJSON(w, http.StatusOK, toSessionPolicyBody(p))
}

type frontchannelBody struct {
	FrontchannelLogoutURL string `json:"frontchannelLogoutUrl"`
}

func (a *api) frontchannelTarget(w http.ResponseWriter, r *http.Request) (core.Realm, core.FrontchannelStore, core.Client, bool) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return rl, nil, core.Client{}, false
	}
	st, ok := core.StoreAs[core.FrontchannelStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "this store does not support front-channel logout")
		return rl, nil, core.Client{}, false
	}
	c, err := a.cfg.Store.GetClient(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return rl, nil, core.Client{}, false
	}
	return rl, st, c, true
}

func (a *api) getFrontchannel(w http.ResponseWriter, r *http.Request) {
	rl, st, c, ok := a.frontchannelTarget(w, r)
	if !ok {
		return
	}
	uri, err := st.FrontchannelLogoutURI(r.Context(), rl.Name, c.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, frontchannelBody{FrontchannelLogoutURL: uri})
}

// putFrontchannel sets the client's frontchannel_logout_uri; "" removes it.
func (a *api) putFrontchannel(w http.ResponseWriter, r *http.Request) {
	rl, st, c, ok := a.frontchannelTarget(w, r)
	if !ok {
		return
	}
	var in frontchannelBody
	present, err := decode(r, &in)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if !present["frontchannelLogoutUrl"] {
		a.fail(w, r, bad(`frontchannelLogoutUrl is required ("" removes it)`))
		return
	}
	if in.FrontchannelLogoutURL != "" {
		if _, err := idp.FrontchannelOrigin(in.FrontchannelLogoutURL, c.RedirectURIs); err != nil {
			a.fail(w, r, bad("invalid frontchannelLogoutUrl: "+err.Error()))
			return
		}
	}
	if err := st.SetFrontchannelLogoutURI(r.Context(), rl.Name, c.ID, in.FrontchannelLogoutURL); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "client", c.ClientID+" frontchannel-logout")
	writeJSON(w, http.StatusOK, in)
}
