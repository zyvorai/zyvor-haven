// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package admin serves the haven-idp Admin API v1 under /admin/v1. The
// contract is SPEC.md in this directory.
package admin

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/actions"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/obs"
)

const (
	maxBody    = 1 << 20
	pathPrefix = "/admin/v1"
	adminRole  = "haven-admin"
)

// Config configures the admin API.
type Config struct {
	Store        core.Store
	Signer       core.Signer
	Hasher       core.PasswordHasher
	BaseURL      string   // public base URL; issuer = BaseURL/realms/{AdminRealm}
	AdminRealm   string   // realm whose tokens are accepted
	AdminClients []string // service-account client ids allowed (default ["haven-admin"])
	Version      string   // reported by /status (default "haven-idp")
	Logger       *slog.Logger
	Clock        func() time.Time
	Obs          obs.Recorder // nil records nothing
	// Actions sends verification and reset emails. Nil (or no mailer) makes
	// the send-* routes answer 409 "email is not configured".
	Actions *actions.Service
}

type api struct {
	cfg    Config
	base   string
	mux    *http.ServeMux
	issuer string
}

// New builds the handler. It panics on missing Store, Signer, Hasher, BaseURL
// or AdminRealm, since that is a wiring bug.
func New(cfg Config) http.Handler {
	if cfg.Store == nil || cfg.Signer == nil || cfg.Hasher == nil || cfg.BaseURL == "" || cfg.AdminRealm == "" {
		panic("admin: Store, Signer, Hasher, BaseURL and AdminRealm are required")
	}
	if len(cfg.AdminClients) == 0 {
		cfg.AdminClients = []string{"haven-admin"}
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Obs == nil {
		cfg.Obs = obs.Nop{}
	}
	if cfg.Version == "" {
		cfg.Version = "haven-idp"
	}
	a := &api{cfg: cfg, base: strings.TrimRight(cfg.BaseURL, "/"), mux: http.NewServeMux()}
	a.issuer = a.base + "/realms/" + cfg.AdminRealm
	a.routes()
	return a
}

func (a *api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	actor, status, msg := a.authenticate(r)
	if status != 0 {
		if status == http.StatusUnauthorized {
			h.Set("WWW-Authenticate", "Bearer")
		}
		a.authFailure(r, status)
		writeErr(w, status, msg)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, bodyLimit(r.URL.Path))
	a.mux.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, actor)))
}

type actorKey struct{}

func actorOf(r *http.Request) string {
	s, _ := r.Context().Value(actorKey{}).(string)
	return s
}

func (a *api) routes() {
	m := a.mux
	m.HandleFunc("GET "+pathPrefix+"/status", a.status)
	a.realmRoutes(m)
	a.clientRoutes(m)
	a.userRoutes(m)
	a.importRoutes(m)
	a.roleGroupRoutes(m)
	a.miscRoutes(m)
	m.HandleFunc(pathPrefix+"/", func(w http.ResponseWriter, _ *http.Request) { writeErr(w, http.StatusNotFound, "not found") })
}

// ---- responses and errors ----

type httpErr struct {
	code int
	msg  string
}

func (e *httpErr) Error() string { return e.msg }

func bad(msg string) error { return &httpErr{http.StatusBadRequest, msg} }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// fail maps an error to a response. Store details are never echoed.
func (a *api) fail(w http.ResponseWriter, r *http.Request, err error) {
	var he *httpErr
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &he):
		writeErr(w, he.code, he.msg)
	case errors.As(err, &mbe):
		writeErr(w, http.StatusRequestEntityTooLarge, "request body too large")
	case errors.Is(err, idp.ErrNotFound):
		writeErr(w, http.StatusNotFound, "not found")
	case errors.Is(err, idp.ErrConflict):
		writeErr(w, http.StatusConflict, "already exists")
	case errors.Is(err, idp.ErrUnsupported):
		writeErr(w, http.StatusNotImplemented, "not supported")
	default:
		a.cfg.Logger.Error("admin: internal error", "method", r.Method, "path", r.URL.Path, "err", err.Error())
		writeErr(w, http.StatusInternalServerError, "internal error")
	}
}

// decode reads one JSON object, rejecting unknown fields and trailing data.
// present reports which top-level keys were in the body.
func decode(r *http.Request, v any) (present map[string]bool, err error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, err
		}
		return nil, bad("could not read body")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return nil, bad("invalid JSON body")
	}
	if dec.More() {
		return nil, bad("invalid JSON body")
	}
	var keys map[string]json.RawMessage
	_ = json.Unmarshal(raw, &keys) // not an object (e.g. a list): no key set
	present = make(map[string]bool, len(keys))
	for k := range keys {
		present[k] = true
	}
	return present, nil
}

func created(w http.ResponseWriter, location string, body map[string]string) {
	w.Header().Set("Location", location)
	writeJSON(w, http.StatusCreated, body)
}

func notImplemented(w http.ResponseWriter, msg string) { writeErr(w, http.StatusNotImplemented, msg) }

func noContent(w http.ResponseWriter) { w.WriteHeader(http.StatusNoContent) }

// ---- shared helpers ----

var (
	realmNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)
	pathRealmRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
)

// realmOf loads the realm named by {r}.
func (a *api) realmOf(w http.ResponseWriter, r *http.Request) (core.Realm, bool) {
	name := r.PathValue("r")
	if !pathRealmRE.MatchString(name) {
		writeErr(w, http.StatusNotFound, "not found")
		return core.Realm{}, false
	}
	rl, err := a.cfg.Store.GetRealm(r.Context(), name)
	if err != nil {
		a.fail(w, r, err)
		return core.Realm{}, false
	}
	noteRealm(r, rl.Name)
	return rl, true
}

// audit appends an admin event when the realm logs them. Failures are logged
// but never fail the request. op is CREATE, UPDATE, DELETE or ACTION.
func (a *api) audit(r *http.Request, rl core.Realm, op, resource, name string) {
	if !rl.AdminEventsLogged {
		return
	}
	err := a.cfg.Store.AppendEvent(r.Context(), core.Event{
		Time: a.cfg.Clock().UTC(), Realm: rl.Name, Type: "ADMIN_" + op, UserID: actorOf(r),
		Detail: resource + " " + name,
	})
	if err != nil {
		a.cfg.Logger.Error("admin: append event", "err", err.Error())
	}
}

// newSecret returns 32 random bytes, base64url encoded.
func newSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func validText(s string, max int) bool {
	if len(s) > max {
		return false
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// ---- observability ----

// opState carries the validated realm name from a handler back to the op
// wrapper. Only realm names that exist are ever stored in it.
type opState struct{ realm string }

type opKey struct{}

// noteRealm records the validated realm for the current mutating request.
func noteRealm(r *http.Request, realm string) {
	if st, _ := r.Context().Value(opKey{}).(*opState); st != nil {
		st.realm = realm
	}
}

// statusWriter remembers the response status.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (s *statusWriter) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusWriter) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusWriter) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// op wraps a mutating handler and reports its outcome once it is known. The
// recorder receives only the realm, fixed resource and action enums, and
// whether the response was a success (status below 400).
func (a *api) op(resource, action string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := &opState{realm: "unknown"}
		sw := &statusWriter{ResponseWriter: w}
		h(sw, r.WithContext(context.WithValue(r.Context(), opKey{}, st)))
		status := sw.status
		if status == 0 {
			status = http.StatusOK
		}
		a.cfg.Obs.AdminOp(st.realm, resource, action, status < 400)
	}
}

// authFailure reports a rejected admin call. The kind is derived from the
// request shape only: missing (no bearer token), invalid, or forbidden.
func (a *api) authFailure(r *http.Request, status int) {
	switch status {
	case http.StatusForbidden:
		a.cfg.Obs.AdminAuthFailure("forbidden")
	case http.StatusUnauthorized:
		h := r.Header.Get("Authorization")
		if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") || strings.TrimSpace(h[7:]) == "" {
			a.cfg.Obs.AdminAuthFailure("missing")
		} else {
			a.cfg.Obs.AdminAuthFailure("invalid")
		}
	}
}
