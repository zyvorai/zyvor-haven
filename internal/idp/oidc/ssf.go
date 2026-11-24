// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/ssf"
)

// OpenID Shared Signals Framework 1.0 transmitter endpoints (push delivery).
// Receivers authenticate with the bearer token an admin issued them (hashed at
// rest). The feature is OFF (404) unless the store has core.SSFStore and the
// SSF store decorator (ssf.Wrap) is installed, which is what emits events.

func init() { registerFeature(ssfRoutes) }

const (
	ssfBodyMax      = 64 << 10
	ssfAPILimit     = 300 // requests per minute per receiver-IP
	ssfSubjectLimit = 120 // subject lookups per minute per receiver
	ssfWindow       = time.Minute
	ssfMaxEvents    = 64
)

func ssfRoutes(p *Provider, mux *http.ServeMux) {
	mux.HandleFunc("GET /realms/{realm}/.well-known/ssf-configuration", p.ssfMetadata)
	// SSF 1.0 section 7.2.1: well-known path with the issuer path appended.
	mux.HandleFunc("GET /.well-known/ssf-configuration/realms/{realm}", p.ssfMetadata)
	const s = "/realms/{realm}/ssf/"
	mux.HandleFunc("POST "+s+"stream", p.ssfStreamCreate)
	mux.HandleFunc("GET "+s+"stream", p.ssfStreamGet)
	mux.HandleFunc("PATCH "+s+"stream", p.ssfStreamUpdate(false))
	mux.HandleFunc("PUT "+s+"stream", p.ssfStreamUpdate(true))
	mux.HandleFunc("DELETE "+s+"stream", p.ssfStreamDelete)
	mux.HandleFunc("GET "+s+"status", p.ssfStatusGet)
	mux.HandleFunc("POST "+s+"status", p.ssfStatusSet)
	mux.HandleFunc("POST "+s+"subjects/add", p.ssfSubject(true))
	mux.HandleFunc("POST "+s+"subjects/remove", p.ssfSubject(false))
	mux.HandleFunc("POST "+s+"verify", p.ssfVerify)
}

func (p *Provider) ssfBuilder() ssf.Builder {
	return ssf.Builder{Signer: p.cfg.Signer, BaseURL: p.base, Clock: p.now}
}

func ssfErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// ssfStore returns the SSF store and policy, or answers 404 when the
// transmitter is not running.
func (p *Provider) ssfStore(w http.ResponseWriter) (core.SSFStore, core.SSFPolicy, bool) {
	pp, ok := core.StoreAs[core.SSFPolicyProvider](p.cfg.Store)
	ss, ok2 := core.StoreAs[core.SSFStore](p.cfg.Store)
	if !ok || !ok2 {
		http.NotFound(w, nil)
		return nil, core.SSFPolicy{}, false
	}
	return ss, pp.SSFPolicy(), true
}

func (p *Provider) ssfHit(ctx context.Context, key string, window time.Duration, max int) (bool, error) {
	sum := sha256.Sum256([]byte(key))
	return p.cfg.Store.HitRateLimit(ctx, hex.EncodeToString(sum[:]), p.now(), window, max)
}

func (p *Provider) ssfMetadata(w http.ResponseWriter, r *http.Request) {
	rl, ok := p.realm(r.Context(), r.PathValue("realm"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, _, ok := p.ssfStore(w); !ok {
		return
	}
	iss, base := p.issuer(rl.Name), p.issuer(rl.Name)+"/ssf/"
	writeJSON(w, http.StatusOK, map[string]any{
		"spec_version":               "1_0",
		"issuer":                     iss,
		"jwks_uri":                   p.endpoint(rl.Name, "certs"),
		"delivery_methods_supported": []string{ssf.MethodPush},
		"configuration_endpoint":     base + "stream",
		"status_endpoint":            base + "status",
		"add_subject_endpoint":       base + "subjects/add",
		"remove_subject_endpoint":    base + "subjects/remove",
		"verification_endpoint":      base + "verify",
		"default_subjects":           "NONE",
		"authorization_schemes":      []map[string]string{{"spec_urn": ssf.SchemeRFC6750}},
	})
}

// ssfAuth authenticates the receiver from its bearer token.
func (p *Provider) ssfAuth(w http.ResponseWriter, r *http.Request) (core.SSFStore, core.SSFPolicy, core.Realm, core.SSFReceiver, bool) {
	var none core.SSFReceiver
	ss, pol, ok := p.ssfStore(w)
	if !ok {
		return nil, pol, core.Realm{}, none, false
	}
	rl, ok := p.realm(r.Context(), r.PathValue("realm"))
	if !ok {
		http.NotFound(w, r)
		return nil, pol, rl, none, false
	}
	allowed, err := p.ssfHit(r.Context(), "ssfapi|"+rl.Name+"|"+p.clientIP(r), ssfWindow, ssfAPILimit)
	if err != nil {
		ssfErr(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return nil, pol, rl, none, false
	}
	if !allowed {
		w.Header().Set("Retry-After", "60")
		ssfErr(w, http.StatusTooManyRequests, "rate_limited")
		return nil, pol, rl, none, false
	}
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ssf"`)
		ssfErr(w, http.StatusUnauthorized, "invalid_token")
		return nil, pol, rl, none, false
	}
	hash := ssf.HashToken(strings.TrimSpace(h[7:]))
	rc, err := ss.GetSSFReceiverByTokenHash(r.Context(), hash)
	if err != nil && !errors.Is(err, idp.ErrNotFound) {
		ssfErr(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return nil, pol, rl, none, false
	}
	if err != nil || rc.Realm != rl.Name || subtle.ConstantTimeCompare([]byte(rc.TokenHash), []byte(hash)) != 1 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ssf", error="invalid_token"`)
		ssfErr(w, http.StatusUnauthorized, "invalid_token")
		return nil, pol, rl, none, false
	}
	if rc.Disabled {
		ssfErr(w, http.StatusForbidden, "receiver_disabled")
		return nil, pol, rl, none, false
	}
	return ss, pol, rl, rc, true
}

type ssfDelivery struct {
	Method              string  `json:"method"`
	EndpointURL         *string `json:"endpoint_url"`
	AuthorizationHeader *string `json:"authorization_header"`
}

type ssfStreamIn struct {
	StreamID           string       `json:"stream_id"`
	Delivery           *ssfDelivery `json:"delivery"`
	EventsRequested    *[]string    `json:"events_requested"`
	Description        *string      `json:"description"`
	HavenSubjectFormat *string      `json:"haven_subject_format"`
}

func ssfDecode(w http.ResponseWriter, r *http.Request, v any) bool {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, ssfBodyMax))
	if err != nil {
		ssfErr(w, http.StatusRequestEntityTooLarge, "request_too_large")
		return false
	}
	if err := json.Unmarshal(body, v); err != nil {
		ssfErr(w, http.StatusBadRequest, "invalid_request")
		return false
	}
	return true
}

func (p *Provider) ssfStreamJSON(st core.SSFStream, rc core.SSFReceiver, rl core.Realm) map[string]any {
	return map[string]any{
		"stream_id":                 st.ID,
		"iss":                       p.issuer(rl.Name),
		"aud":                       st.Audience,
		"delivery":                  map[string]any{"method": ssf.MethodPush, "endpoint_url": st.EndpointURL},
		"events_supported":          ssf.Allowed(rc),
		"events_requested":          nonNil(st.EventsRequested),
		"events_delivered":          nonNil(st.EventsDelivered),
		"min_verification_interval": ssf.DefaultMinVerificationInterval,
		"description":               st.Description,
		"haven_subject_format":      st.SubjectFormat,
	}
}

// ssfApply validates in on top of base (create: zero stream) and fills st. It
// answers the error itself and returns false on failure.
func (p *Provider) ssfApply(w http.ResponseWriter, in ssfStreamIn, st *core.SSFStream, rc core.SSFReceiver, pol core.SSFPolicy, replace bool) bool {
	if replace {
		st.EndpointURL, st.SealedAuth, st.EventsRequested, st.Description, st.SubjectFormat = "", "", nil, "", ssf.FormatOpaque
	}
	if d := in.Delivery; d != nil {
		if d.Method != "" && d.Method != ssf.MethodPush {
			ssfErr(w, http.StatusBadRequest, "unsupported_delivery_method")
			return false
		}
		if d.EndpointURL != nil {
			if err := ssf.ValidateEndpoint(*d.EndpointURL, pol.AllowPrivate); err != nil {
				ssfErr(w, http.StatusBadRequest, "invalid_endpoint_url")
				return false
			}
			st.EndpointURL = *d.EndpointURL
		}
		if d.AuthorizationHeader != nil {
			if !ssf.ValidAuthHeader(*d.AuthorizationHeader) {
				ssfErr(w, http.StatusBadRequest, "invalid_authorization_header")
				return false
			}
			if p.cfg.SecretBox == nil {
				ssfErr(w, http.StatusConflict, "HAVEN_IDP_SECRET_KEY is not set: authorization_header cannot be stored")
				return false
			}
			st.SealedAuth = p.cfg.SecretBox.Seal([]byte(*d.AuthorizationHeader), ssf.SealContext(st.Realm, st.ID))
		}
	}
	if st.EndpointURL == "" {
		ssfErr(w, http.StatusBadRequest, "delivery.endpoint_url is required")
		return false
	}
	if in.EventsRequested != nil {
		ev := *in.EventsRequested
		if len(ev) > ssfMaxEvents {
			ssfErr(w, http.StatusBadRequest, "too_many_events")
			return false
		}
		st.EventsRequested = nil
		for _, e := range ev {
			if len(e) <= 256 && !slices.Contains(st.EventsRequested, e) {
				st.EventsRequested = append(st.EventsRequested, e)
			}
		}
	}
	if in.Description != nil {
		if len(*in.Description) > core.SSFMaxDescription {
			ssfErr(w, http.StatusBadRequest, "description_too_long")
			return false
		}
		st.Description = *in.Description
	}
	if in.HavenSubjectFormat != nil {
		f := *in.HavenSubjectFormat
		if !ssf.ValidFormat(f) {
			ssfErr(w, http.StatusBadRequest, "invalid_subject_format")
			return false
		}
		st.SubjectFormat = f
	}
	if st.SubjectFormat == "" {
		st.SubjectFormat = ssf.FormatOpaque
	}
	if st.SubjectFormat == ssf.FormatEmail && !rc.AllowEmail {
		ssfErr(w, http.StatusForbidden, "email_subjects_not_permitted")
		return false
	}
	st.EventsDelivered = ssf.Delivered(rc, st.EventsRequested)
	return true
}

func (p *Provider) ssfStreamCreate(w http.ResponseWriter, r *http.Request) {
	ss, pol, rl, rc, ok := p.ssfAuth(w, r)
	if !ok {
		return
	}
	var in ssfStreamIn
	if !ssfDecode(w, r, &in) {
		return
	}
	now := p.now().UTC()
	st := core.SSFStream{ID: randToken(16), Realm: rl.Name, ReceiverID: rc.ID, Status: core.SSFStatusEnabled,
		SubjectFormat: ssf.FormatOpaque, CreatedAt: now, UpdatedAt: now}
	if !p.ssfApply(w, in, &st, rc, pol, true) {
		return
	}
	out, err := ss.CreateSSFStream(r.Context(), st, core.SSFMaxStreamsPerReceiver)
	switch {
	case errors.Is(err, core.ErrSSFStreamLimit):
		ssfErr(w, http.StatusConflict, "stream_limit")
		return
	case err != nil:
		p.cfg.Logger.Error("ssf: create stream", "err", err)
		ssfErr(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	p.event(r.Context(), rl, "SSF_STREAM_CREATE", "", "", p.clientIP(r), "receiver "+rc.Name)
	writeJSON(w, http.StatusCreated, p.ssfStreamJSON(out, rc, rl))
}

// ssfOwned loads the receiver's stream; another receiver's stream is "not found".
func (p *Provider) ssfOwned(w http.ResponseWriter, r *http.Request, ss core.SSFStore, rl core.Realm, rc core.SSFReceiver, id string) (core.SSFStream, bool) {
	if id == "" {
		ssfErr(w, http.StatusBadRequest, "stream_id is required")
		return core.SSFStream{}, false
	}
	st, err := ss.GetSSFStream(r.Context(), rl.Name, id)
	if err != nil || st.ReceiverID != rc.ID {
		if err != nil && !errors.Is(err, idp.ErrNotFound) {
			ssfErr(w, http.StatusServiceUnavailable, "temporarily_unavailable")
			return core.SSFStream{}, false
		}
		ssfErr(w, http.StatusNotFound, "stream_not_found")
		return core.SSFStream{}, false
	}
	return st, true
}

func (p *Provider) ssfStreamGet(w http.ResponseWriter, r *http.Request) {
	ss, _, rl, rc, ok := p.ssfAuth(w, r)
	if !ok {
		return
	}
	if id := r.URL.Query().Get("stream_id"); id != "" {
		st, ok := p.ssfOwned(w, r, ss, rl, rc, id)
		if ok {
			writeJSON(w, http.StatusOK, p.ssfStreamJSON(st, rc, rl))
		}
		return
	}
	all, err := ss.ListSSFStreams(r.Context(), rl.Name, rc.ID)
	if err != nil {
		ssfErr(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	out := make([]map[string]any, 0, len(all))
	for _, st := range all {
		out = append(out, p.ssfStreamJSON(st, rc, rl))
	}
	writeJSON(w, http.StatusOK, out)
}

func (p *Provider) ssfStreamUpdate(replace bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ss, pol, rl, rc, ok := p.ssfAuth(w, r)
		if !ok {
			return
		}
		var in ssfStreamIn
		if !ssfDecode(w, r, &in) {
			return
		}
		id := in.StreamID
		if id == "" {
			id = r.URL.Query().Get("stream_id")
		}
		st, ok := p.ssfOwned(w, r, ss, rl, rc, id)
		if !ok {
			return
		}
		if !p.ssfApply(w, in, &st, rc, pol, replace) {
			return
		}
		st.UpdatedAt = p.now().UTC()
		if err := ss.UpdateSSFStream(r.Context(), st); err != nil {
			ssfErr(w, http.StatusServiceUnavailable, "temporarily_unavailable")
			return
		}
		writeJSON(w, http.StatusOK, p.ssfStreamJSON(st, rc, rl))
	}
}

func (p *Provider) ssfStreamDelete(w http.ResponseWriter, r *http.Request) {
	ss, _, rl, rc, ok := p.ssfAuth(w, r)
	if !ok {
		return
	}
	st, ok := p.ssfOwned(w, r, ss, rl, rc, r.URL.Query().Get("stream_id"))
	if !ok {
		return
	}
	if err := ss.DeleteSSFStream(r.Context(), rl.Name, st.ID); err != nil && !errors.Is(err, idp.ErrNotFound) {
		ssfErr(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	noStore(w)
	w.WriteHeader(http.StatusNoContent)
}

func (p *Provider) ssfStatusGet(w http.ResponseWriter, r *http.Request) {
	ss, _, rl, rc, ok := p.ssfAuth(w, r)
	if !ok {
		return
	}
	st, ok := p.ssfOwned(w, r, ss, rl, rc, r.URL.Query().Get("stream_id"))
	if ok {
		writeJSON(w, http.StatusOK, map[string]string{"stream_id": st.ID, "status": st.Status})
	}
}

func (p *Provider) ssfStatusSet(w http.ResponseWriter, r *http.Request) {
	ss, _, rl, rc, ok := p.ssfAuth(w, r)
	if !ok {
		return
	}
	var in struct {
		StreamID string `json:"stream_id"`
		Status   string `json:"status"`
		Reason   string `json:"reason"`
	}
	if !ssfDecode(w, r, &in) {
		return
	}
	if in.Status != core.SSFStatusEnabled && in.Status != core.SSFStatusPaused && in.Status != core.SSFStatusDisabled {
		ssfErr(w, http.StatusBadRequest, "invalid_status")
		return
	}
	st, ok := p.ssfOwned(w, r, ss, rl, rc, in.StreamID)
	if !ok {
		return
	}
	st.Status, st.UpdatedAt = in.Status, p.now().UTC()
	if err := ss.UpdateSSFStream(r.Context(), st); err != nil {
		ssfErr(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"stream_id": st.ID, "status": st.Status})
}

// ssfResolve maps a subject identifier to a user of the realm. Unknown or
// ambiguous subjects resolve to "" (callers answer as if it worked, so the
// endpoint is no account-existence oracle).
func (p *Provider) ssfResolve(ctx context.Context, rl core.Realm, raw map[string]any) (string, bool) {
	str := func(k string) string { s, _ := raw[k].(string); return s }
	var u core.User
	var err error
	switch str("format") {
	case ssf.FormatOpaque:
		u, err = p.cfg.Store.GetUser(ctx, rl.Name, str("id"))
	case ssf.FormatIssSub:
		if str("iss") != p.issuer(rl.Name) {
			return "", true
		}
		u, err = p.cfg.Store.GetUser(ctx, rl.Name, str("sub"))
	case ssf.FormatEmail:
		email := strings.ToLower(strings.TrimSpace(str("email")))
		if email == "" || len(email) > 320 {
			return "", true
		}
		cands, lerr := p.cfg.Store.ListUsers(ctx, rl.Name, email, 0, 20)
		if lerr != nil {
			return "", false
		}
		n := 0
		for _, c := range cands {
			if strings.EqualFold(c.Email, email) {
				u, n = c, n+1
			}
		}
		if n != 1 {
			return "", true
		}
	default:
		return "", false
	}
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return "", true
		}
		return "", false
	}
	return u.ID, true
}

func (p *Provider) ssfSubject(add bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ss, _, rl, rc, ok := p.ssfAuth(w, r)
		if !ok {
			return
		}
		var in struct {
			StreamID string         `json:"stream_id"`
			Subject  map[string]any `json:"subject"`
		}
		if !ssfDecode(w, r, &in) {
			return
		}
		st, ok := p.ssfOwned(w, r, ss, rl, rc, in.StreamID)
		if !ok {
			return
		}
		if in.Subject == nil {
			ssfErr(w, http.StatusBadRequest, "subject is required")
			return
		}
		allowed, err := p.ssfHit(r.Context(), "ssfsubj|"+rc.ID, ssfWindow, ssfSubjectLimit)
		if err != nil {
			ssfErr(w, http.StatusServiceUnavailable, "temporarily_unavailable")
			return
		}
		if !allowed {
			w.Header().Set("Retry-After", "60")
			ssfErr(w, http.StatusTooManyRequests, "rate_limited")
			return
		}
		uid, valid := p.ssfResolve(r.Context(), rl, in.Subject)
		if !valid {
			ssfErr(w, http.StatusBadRequest, "unsupported_subject")
			return
		}
		if st.AllSubjects {
			if !add {
				ssfErr(w, http.StatusBadRequest, "this stream delivers events for all subjects")
				return
			}
			uid = "" // nothing to record
		}
		if uid != "" {
			if add {
				err = ss.AddSSFSubject(r.Context(), rl.Name, st.ID, uid, p.now())
			} else {
				err = ss.RemoveSSFSubject(r.Context(), rl.Name, st.ID, uid)
			}
			if err != nil {
				ssfErr(w, http.StatusServiceUnavailable, "temporarily_unavailable")
				return
			}
		}
		noStore(w)
		if add {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNoContent)
		}
	}
}

func (p *Provider) ssfVerify(w http.ResponseWriter, r *http.Request) {
	ss, _, rl, rc, ok := p.ssfAuth(w, r)
	if !ok {
		return
	}
	var in struct {
		StreamID string `json:"stream_id"`
		State    string `json:"state"`
	}
	if !ssfDecode(w, r, &in) {
		return
	}
	if len(in.State) > 256 {
		ssfErr(w, http.StatusBadRequest, "state_too_long")
		return
	}
	st, ok := p.ssfOwned(w, r, ss, rl, rc, in.StreamID)
	if !ok {
		return
	}
	allowed, err := p.ssfHit(r.Context(), "ssfverify|"+st.ID, ssf.DefaultMinVerificationInterval*time.Second, 1)
	if err != nil {
		ssfErr(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	if !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(ssf.DefaultMinVerificationInterval))
		ssfErr(w, http.StatusTooManyRequests, "rate_limited")
		return
	}
	row, err := p.ssfBuilder().Verification(r.Context(), st, in.State)
	if err == nil {
		err = ss.EnqueueSSF(r.Context(), []core.SSFOutbox{row})
	}
	if err != nil {
		p.cfg.Logger.Error("ssf: verification", "err", err)
		ssfErr(w, http.StatusServiceUnavailable, "temporarily_unavailable")
		return
	}
	noStore(w)
	w.WriteHeader(http.StatusNoContent)
}

// signalFromEvent turns the credential-related auth events into shared
// signals. Password changes are not here: the SSF store decorator sees the
// user update itself. The user is the subject; no credential data is sent.
func (p *Provider) signalFromEvent(ctx context.Context, rl core.Realm, typ, userID string) {
	if userID == "" {
		return
	}
	cred := func(kind, ctype, change string) {
		attrs := map[string]any{"credential_type": ctype}
		if change != "" {
			attrs["change_type"] = change
		}
		core.EmitSignal(ctx, p.cfg.Store, core.Signal{Realm: rl.Name, UserID: userID, Kind: kind, Attrs: attrs})
	}
	switch typ {
	case "TOTP_ENROLLED":
		cred(ssf.EvCredentialChange, "app", "create")
	case "TOTP_DISABLED", "TOTP_RESET":
		cred(ssf.EvCredentialChange, "app", "delete")
	case "PASSKEY_REGISTERED":
		cred(ssf.EvCredentialChange, "fido2-platform", "create")
	case "PASSKEY_REMOVED":
		cred(ssf.EvCredentialChange, "fido2-platform", "delete")
	case "PASSKEY_CLONE_SUSPECTED":
		cred(ssf.EvCredentialCompromise, "fido2-platform", "")
	}
}
