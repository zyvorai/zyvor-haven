// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"net/http"
	"regexp"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/ssf"
)

func init() { registerRoutes(ssfRoutes) }

var ssfNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,62}$`)

func ssfRoutes(a *api, m *http.ServeMux) {
	p := pathPrefix + "/realms/{r}/ssf"
	m.HandleFunc("GET "+p+"/receivers", a.ssfListReceivers)
	m.HandleFunc("POST "+p+"/receivers", a.op("ssf-receiver", "create", a.ssfCreateReceiver))
	m.HandleFunc("DELETE "+p+"/receivers/{id}", a.op("ssf-receiver", "delete", a.ssfDeleteReceiver))
	m.HandleFunc("POST "+p+"/receivers/{id}/rotate-token", a.op("ssf-receiver", "rotate", a.ssfRotate))
	m.HandleFunc("PUT "+p+"/receivers/{id}/disabled", a.op("ssf-receiver", "disable", a.ssfDisable))
	m.HandleFunc("GET "+p+"/streams", a.ssfListStreams)
	m.HandleFunc("DELETE "+p+"/streams/{id}", a.op("ssf-stream", "delete", a.ssfDeleteStream))
	m.HandleFunc("GET "+p+"/outbox", a.ssfOutbox)
	m.HandleFunc("POST "+pathPrefix+"/realms/{r}/users/{id}/ssf/credential-compromise", a.op("ssf-signal", "credential-compromise", a.ssfCompromise))
}

func (a *api) ssfStore(w http.ResponseWriter) (core.SSFStore, bool) {
	st, ok := core.StoreAs[core.SSFStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "shared signals are not supported by this store")
	}
	return st, ok
}

type ssfReceiverJSON struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Audience    string    `json:"audience"`
	AllSubjects bool      `json:"allSubjects"`
	AllowEmail  bool      `json:"allowEmail"`
	Events      []string  `json:"events"`
	Disabled    bool      `json:"disabled"`
	CreatedAt   time.Time `json:"createdAt"`
	Token       string    `json:"token,omitempty"` // only on create / rotate
}

func ssfRecvJSON(r core.SSFReceiver) ssfReceiverJSON {
	ev := r.Events
	if ev == nil {
		ev = []string{}
	}
	return ssfReceiverJSON{ID: r.ID, Name: r.Name, Audience: r.Audience, AllSubjects: r.AllSubjects,
		AllowEmail: r.AllowEmail, Events: ev, Disabled: r.Disabled, CreatedAt: r.CreatedAt}
}

func (a *api) ssfListReceivers(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.ssfStore(w)
	if !ok {
		return
	}
	rs, err := st.ListSSFReceivers(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]ssfReceiverJSON, 0, len(rs))
	for _, x := range rs {
		out = append(out, ssfRecvJSON(x))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) ssfCreateReceiver(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.ssfStore(w)
	if !ok {
		return
	}
	var in struct {
		Name        string   `json:"name"`
		Audience    string   `json:"audience"`
		AllSubjects bool     `json:"allSubjects"`
		AllowEmail  bool     `json:"allowEmail"`
		Events      []string `json:"events"`
	}
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if !ssfNameRE.MatchString(in.Name) {
		a.fail(w, r, bad("name must be 1-63 characters: letters, digits, space, . _ -"))
		return
	}
	if in.Audience == "" {
		in.Audience = in.Name
	}
	if len(in.Audience) > 256 {
		a.fail(w, r, bad("audience is too long"))
		return
	}
	ev, err := ssf.CleanEvents(in.Events)
	if err != nil {
		a.fail(w, r, bad("events: "+err.Error()))
		return
	}
	plain, hash := ssf.NewToken()
	rc, err := st.CreateSSFReceiver(r.Context(), core.SSFReceiver{Realm: rl.Name, Name: in.Name, Audience: in.Audience,
		TokenHash: hash, AllSubjects: in.AllSubjects, AllowEmail: in.AllowEmail, Events: ev, CreatedAt: a.cfg.Clock().UTC()})
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "CREATE", "ssf-receiver", rc.Name)
	out := ssfRecvJSON(rc)
	out.Token = plain // shown once
	writeJSON(w, http.StatusCreated, out)
}

func (a *api) ssfDeleteReceiver(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.ssfStore(w)
	if !ok {
		return
	}
	if err := st.DeleteSSFReceiver(r.Context(), rl.Name, r.PathValue("id")); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "DELETE", "ssf-receiver", r.PathValue("id"))
	noContent(w)
}

func (a *api) ssfRotate(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.ssfStore(w)
	if !ok {
		return
	}
	plain, hash := ssf.NewToken()
	if err := st.SetSSFReceiverToken(r.Context(), rl.Name, r.PathValue("id"), hash); err != nil {
		a.fail(w, r, err)
		return
	}
	rc, err := st.GetSSFReceiver(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "ssf-receiver-token", rc.Name)
	out := ssfRecvJSON(rc)
	out.Token = plain
	writeJSON(w, http.StatusOK, out)
}

func (a *api) ssfDisable(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.ssfStore(w)
	if !ok {
		return
	}
	var in struct {
		Disabled bool `json:"disabled"`
	}
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := st.SetSSFReceiverDisabled(r.Context(), rl.Name, r.PathValue("id"), in.Disabled); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "ssf-receiver-disabled", r.PathValue("id"))
	noContent(w)
}

func (a *api) ssfListStreams(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.ssfStore(w)
	if !ok {
		return
	}
	ss, err := st.ListSSFStreams(r.Context(), rl.Name, r.URL.Query().Get("receiver"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	type streamJSON struct {
		ID              string    `json:"id"`
		ReceiverID      string    `json:"receiverId"`
		Status          string    `json:"status"`
		EndpointURL     string    `json:"endpointUrl"`
		EventsDelivered []string  `json:"eventsDelivered"`
		SubjectFormat   string    `json:"subjectFormat"`
		HasAuthHeader   bool      `json:"hasAuthorizationHeader"` // never the value
		CreatedAt       time.Time `json:"createdAt"`
	}
	out := make([]streamJSON, 0, len(ss))
	for _, s := range ss {
		ev := s.EventsDelivered
		if ev == nil {
			ev = []string{}
		}
		out = append(out, streamJSON{s.ID, s.ReceiverID, s.Status, s.EndpointURL, ev, s.SubjectFormat, s.SealedAuth != "", s.CreatedAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) ssfDeleteStream(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.ssfStore(w)
	if !ok {
		return
	}
	if err := st.DeleteSSFStream(r.Context(), rl.Name, r.PathValue("id")); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "DELETE", "ssf-stream", r.PathValue("id"))
	noContent(w)
}

func (a *api) ssfOutbox(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.ssfStore(w)
	if !ok {
		return
	}
	c, err := st.CountSSFOutbox(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{
		"pending": c[core.SSFOutboxPending], "delivered": c[core.SSFOutboxDelivered], "dead": c[core.SSFOutboxDead]})
}

// ssfCompromise reports a RISC credential-compromise for a user (for example
// after a breach notice). It only signals; it does not touch the credential.
func (a *api) ssfCompromise(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	if _, ok := core.StoreAs[core.SignalEmitter](a.cfg.Store); !ok {
		notImplemented(w, "shared signals are not running")
		return
	}
	var in struct {
		CredentialType string `json:"credentialType"`
		ReasonAdmin    string `json:"reasonAdmin"`
	}
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	switch in.CredentialType {
	case "password", "pin", "x509", "fido2-platform", "fido2-roaming", "fido-u2f", "phone-voice", "phone-sms", "app":
	default:
		a.fail(w, r, bad("credentialType must be one of password, pin, x509, fido2-platform, fido2-roaming, fido-u2f, phone-voice, phone-sms, app"))
		return
	}
	if len(in.ReasonAdmin) > 256 {
		a.fail(w, r, bad("reasonAdmin is too long"))
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	attrs := map[string]any{"credential_type": in.CredentialType}
	if in.ReasonAdmin != "" {
		attrs["reason_admin"] = in.ReasonAdmin
	}
	core.EmitSignal(r.Context(), a.cfg.Store, core.Signal{Realm: rl.Name, UserID: u.ID, Kind: ssf.EvCredentialCompromise, Attrs: attrs})
	a.audit(r, rl, "CREATE", "ssf-credential-compromise", u.Username)
	noContent(w)
}
