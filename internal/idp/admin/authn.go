// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// The per-realm acr ladder (see SPEC.md, "Authentication context and step-up")
// and the Admin API's own use of it: a RFC 9470 resource server for the user
// tokens it accepts.
func init() {
	registerRoutes(func(a *api, m *http.ServeMux) {
		p := pathPrefix + "/realms/{r}/acr-policy"
		m.HandleFunc("GET "+p, a.getACRPolicy)
		m.HandleFunc("PUT "+p, a.op("acr-policy", "update", a.putACRPolicy))
		m.HandleFunc("DELETE "+p, a.op("acr-policy", "delete", a.deleteACRPolicy))
	})
}

func (a *api) authnStore(w http.ResponseWriter) (core.AuthnStore, bool) {
	st, ok := core.StoreAs[core.AuthnStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "this store does not support authentication context policies")
		return nil, false
	}
	return st, true
}

type acrPolicyBody struct {
	core.ACRPolicy
	// Default reports that the realm uses the built-in ladder (read only).
	Default bool `json:"default,omitempty"`
}

func (a *api) getACRPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.authnStore(w)
	if !ok {
		return
	}
	p, err := st.GetACRPolicy(r.Context(), rl.Name)
	def := errors.Is(err, idp.ErrNotFound)
	if def {
		p, err = core.DefaultACRPolicy(), nil
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, acrPolicyBody{ACRPolicy: p, Default: def})
}

func (a *api) putACRPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.authnStore(w)
	if !ok {
		return
	}
	var in acrPolicyBody
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := in.Validate(); err != nil {
		a.fail(w, r, bad(err.Error()))
		return
	}
	if (in.AdminACR != "" || in.AdminMaxAgeSeconds != 0) && rl.Name != a.cfg.AdminRealm {
		a.fail(w, r, bad("adminAcr and adminMaxAgeSeconds apply only to the Admin API realm "+a.cfg.AdminRealm))
		return
	}
	if err := st.PutACRPolicy(r.Context(), rl.Name, in.ACRPolicy); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "acr-policy", rl.Name)
	writeJSON(w, http.StatusOK, acrPolicyBody{ACRPolicy: in.ACRPolicy})
}

func (a *api) deleteACRPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.authnStore(w)
	if !ok {
		return
	}
	if err := st.DeleteACRPolicy(r.Context(), rl.Name); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "DELETE", "acr-policy", rl.Name)
	noContent(w)
}

// stepUpChallenge enforces adminAcr / adminMaxAgeSeconds of the Admin realm on
// an already authenticated USER token. It returns status 0 to let the request
// through; otherwise the status and, for 401, the RFC 9470 WWW-Authenticate
// challenge. Only authenticated callers ever see the requirements. Service
// accounts have no user authentication to judge and pass.
func (a *api) stepUpChallenge(r *http.Request, actor string) (status int, challenge string) {
	if !strings.HasPrefix(actor, "user:") {
		return 0, ""
	}
	st, ok := core.StoreAs[core.AuthnStore](a.cfg.Store)
	if !ok {
		return 0, "" // no store: no requirement can have been configured
	}
	ctx := r.Context()
	pol, err := st.GetACRPolicy(ctx, a.cfg.AdminRealm)
	if errors.Is(err, idp.ErrNotFound) {
		return 0, ""
	}
	if err != nil {
		a.cfg.Logger.Error("admin: acr policy", "err", err.Error())
		return http.StatusInternalServerError, ""
	}
	if pol.AdminACR == "" && pol.AdminMaxAgeSeconds <= 0 {
		return 0, ""
	}
	tok := strings.TrimSpace(r.Header.Get("Authorization")[7:]) // shape checked by authenticate
	cl, err := a.cfg.Signer.Verify(ctx, a.cfg.AdminRealm, tok)
	if err != nil {
		return http.StatusUnauthorized, "Bearer"
	}
	var amr []string
	if l, ok := cl["amr"].([]any); ok {
		for _, v := range l {
			if s, ok := v.(string); ok {
				amr = append(amr, s)
			}
		}
	}
	met := pol.AdminACR == "" || pol.Meets(amr, pol.AdminACR)
	if pol.AdminMaxAgeSeconds > 0 {
		at, ok := numClaim(cl["auth_time"])
		met = met && ok && a.cfg.Clock().Sub(time.Unix(at, 0)) <= time.Duration(pol.AdminMaxAgeSeconds)*time.Second
	}
	if met {
		return 0, ""
	}
	parts := []string{`error="insufficient_user_authentication"`,
		`error_description="a stronger or more recent sign-in is required"`}
	if core.ValidACRValue(pol.AdminACR) { // no quotes or backslashes: safe in the header
		parts = append(parts, `acr_values="`+pol.AdminACR+`"`)
	}
	if pol.AdminMaxAgeSeconds > 0 {
		parts = append(parts, `max_age="`+strconv.FormatInt(pol.AdminMaxAgeSeconds, 10)+`"`)
	}
	return http.StatusUnauthorized, "Bearer " + strings.Join(parts, ", ")
}
