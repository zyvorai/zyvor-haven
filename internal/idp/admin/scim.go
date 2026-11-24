// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// SCIM 2.0 server (RFC 7643, RFC 7644) at /realms/{realm}/scim/v2. It is built
// on the Admin API's own logic (applyUser, validGroup, audit, session
// teardown, email-change handling) but authenticates with a dedicated
// per-realm SCIM bearer token, never an Admin API token. See docs/scim.md.

const (
	scimCT          = "application/scim+json"
	scimMaxBody     = 256 << 10
	scimDefaultPage = 50
	scimMaxPage     = 100
	scimMaxStart    = 1_000_000
	scimScanPage    = 500
	scimMaxOps      = 100
	scimMaxMembers  = 1000
	scimMaxEmails   = 20

	scimSchemaUser = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimSchemaGrp  = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimSchemaList = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimSchemaErr  = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimSchemaPat  = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimSchemaSPC  = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	scimSchemaRT   = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	scimSchemaSch  = "urn:ietf:params:scim:schemas:core:2.0:Schema"

	scimSAPrefix = "service-account-"
)

// Rate limits (fixed windows, shared across replicas through Store.HitRateLimit).
var (
	scimReqMax      = 600 // requests per client address and realm per minute
	scimFailMax     = 20  // failed authentications per client address and realm per minute
	scimRateWindow  = time.Minute
	scimScanCap     = 20000 // users examined by one list request
	errScimNotFound = serr(http.StatusNotFound, "", "Resource not found")
)

type scimErr struct {
	status int
	typ    string
	detail string
}

func (e *scimErr) Error() string { return e.detail }

func serr(status int, typ, detail string) *scimErr { return &scimErr{status, typ, detail} }

type scimCtxKey struct{}

type scimReq struct {
	rl  core.Realm
	tok core.SCIMToken
}

type scimAPI struct {
	*api
	ss    core.SCIMStore
	smux  *http.ServeMux
	locks sync.Map // realm name -> *sync.Mutex
}

// SCIM returns the SCIM 2.0 handler to mount at "/realms/{r}/scim/v2/". When
// the store does not implement core.SCIMStore every request answers 501.
func SCIM(cfg Config) http.Handler {
	s := &scimAPI{api: New(cfg).(*api), smux: http.NewServeMux()}
	s.ss, _ = core.StoreAs[core.SCIMStore](cfg.Store)
	p := scimPrefixPat
	m := s.smux
	rd, wr := false, true
	m.HandleFunc("GET "+p+"/ServiceProviderConfig", s.auth(rd, s.spConfig))
	m.HandleFunc("GET "+p+"/ResourceTypes", s.auth(rd, s.resourceTypes))
	m.HandleFunc("GET "+p+"/ResourceTypes/{id}", s.auth(rd, s.resourceTypes))
	m.HandleFunc("GET "+p+"/Schemas", s.auth(rd, s.schemas))
	m.HandleFunc("GET "+p+"/Schemas/{id}", s.auth(rd, s.schemas))

	m.HandleFunc("GET "+p+"/Users", s.auth(rd, s.listUsers))
	m.HandleFunc("GET "+p+"/Users/{id}", s.auth(rd, s.getUser))
	m.HandleFunc("POST "+p+"/Users", s.auth(wr, s.op("user", "create", s.createUser)))
	m.HandleFunc("PUT "+p+"/Users/{id}", s.auth(wr, s.op("user", "update", s.putUser)))
	m.HandleFunc("PATCH "+p+"/Users/{id}", s.auth(wr, s.op("user", "update", s.patchUser)))
	m.HandleFunc("DELETE "+p+"/Users/{id}", s.auth(wr, s.op("user", "delete", s.deleteUser)))

	m.HandleFunc("GET "+p+"/Groups", s.auth(rd, s.listGroups))
	m.HandleFunc("GET "+p+"/Groups/{id}", s.auth(rd, s.getGroup))
	m.HandleFunc("POST "+p+"/Groups", s.auth(wr, s.op("group", "create", s.createGroup)))
	m.HandleFunc("PUT "+p+"/Groups/{id}", s.auth(wr, s.op("group", "update", s.putGroup)))
	m.HandleFunc("PATCH "+p+"/Groups/{id}", s.auth(wr, s.op("group", "update", s.patchGroup)))
	m.HandleFunc("DELETE "+p+"/Groups/{id}", s.auth(wr, s.op("group", "delete", s.deleteGroup)))

	// Bulk is not supported: say so instead of pretending.
	m.HandleFunc(p+"/Bulk", s.auth(rd, func(w http.ResponseWriter, r *http.Request) {
		s.writeErr(w, serr(http.StatusNotImplemented, "", "bulk operations are not supported (ServiceProviderConfig bulk.supported is false)"))
	}))
	m.HandleFunc(p+"/", func(w http.ResponseWriter, _ *http.Request) { s.writeErr(w, errScimNotFound) })
	return s
}

const scimPrefixPat = "/realms/{r}/scim/v2"

func (s *scimAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Type", scimCT)
	if s.ss == nil {
		s.writeErr(w, serr(http.StatusNotImplemented, "", "SCIM is not available on this store"))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, scimMaxBody)
	s.smux.ServeHTTP(w, r)
}

// ---- responses and errors ----

func (s *scimAPI) writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", scimCT)
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *scimAPI) writeErr(w http.ResponseWriter, e *scimErr) {
	body := map[string]any{"schemas": []string{scimSchemaErr}, "status": strconv.Itoa(e.status), "detail": e.detail}
	if e.typ != "" {
		body["scimType"] = e.typ
	}
	s.writeJSON(w, e.status, body)
}

// ferr maps any error to a SCIM error response. Store details are never echoed.
func (s *scimAPI) ferr(w http.ResponseWriter, r *http.Request, err error) {
	var se *scimErr
	var he *httpErr
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &se):
		s.writeErr(w, se)
	case errors.As(err, &mbe):
		s.writeErr(w, serr(http.StatusRequestEntityTooLarge, "", "request body too large"))
	case errors.As(err, &he):
		s.writeErr(w, serr(he.code, "invalidValue", he.msg))
	case errors.Is(err, idp.ErrNotFound):
		s.writeErr(w, errScimNotFound)
	case errors.Is(err, idp.ErrConflict):
		s.writeErr(w, serr(http.StatusConflict, "uniqueness", "resource already exists"))
	default:
		s.cfg.Logger.Error("scim: internal error", "method", r.Method, "path", r.URL.Path, "err", err.Error())
		s.writeErr(w, serr(http.StatusInternalServerError, "", "internal error"))
	}
}

// ---- authentication, rate limits, locking ----

func sha256Hex(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

// hit records one hit against a rate limit and answers 429 / 503 itself when
// the caller must stop. A limiter error fails closed.
func (s *scimAPI) hit(w http.ResponseWriter, r *http.Request, key string, max int) bool {
	ok, err := s.cfg.Store.HitRateLimit(r.Context(), sha256Hex(key), s.cfg.Clock(), scimRateWindow, max)
	if err != nil {
		s.cfg.Logger.Error("scim: rate limit", "err", err.Error())
		s.writeErr(w, serr(http.StatusServiceUnavailable, "", "temporarily unavailable"))
		return false
	}
	if !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(scimRateWindow.Seconds())))
		s.writeErr(w, serr(http.StatusTooManyRequests, "", "too many requests"))
		return false
	}
	return true
}

func (s *scimAPI) unauth(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	s.writeErr(w, serr(http.StatusUnauthorized, "", "invalid or missing token"))
}

// auth wraps a handler: rate limit, bearer token check against the realm's
// stored hash (constant time), realm enabled and same incarnation, read-only
// tokens refused for writes. Unknown realm, no token configured and wrong
// token are indistinguishable to the caller.
func (s *scimAPI) auth(write bool, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		realm := r.PathValue("r")
		ip := clientIP(r)
		if !pathRealmRE.MatchString(realm) {
			s.unauth(w)
			return
		}
		if !s.hit(w, r, "scimreq|"+realm+"|"+ip, scimReqMax) {
			return
		}
		rl, tok, ok, err := s.checkToken(r, realm)
		if err != nil {
			s.cfg.Logger.Error("scim: auth lookup", "err", err.Error())
			s.writeErr(w, serr(http.StatusInternalServerError, "", "internal error"))
			return
		}
		if !ok {
			if s.hit(w, r, "scimfail|"+realm+"|"+ip, scimFailMax) {
				s.unauth(w)
			}
			return
		}
		if write && tok.ReadOnly {
			s.writeErr(w, serr(http.StatusForbidden, "", "this SCIM token is read-only"))
			return
		}
		ctx := context.WithValue(r.Context(), actorKey{}, "scim:"+rl.Name)
		ctx = context.WithValue(ctx, scimCtxKey{}, &scimReq{rl: rl, tok: tok})
		h(w, r.WithContext(ctx))
	}
}

func (s *scimAPI) checkToken(r *http.Request, realm string) (core.Realm, core.SCIMToken, bool, error) {
	var rl core.Realm
	var tok core.SCIMToken
	h := r.Header.Get("Authorization")
	presented := ""
	if len(h) >= 8 && strings.EqualFold(h[:7], "bearer ") {
		presented = strings.TrimSpace(h[7:])
	}
	if presented == "" || len(presented) > 512 {
		return rl, tok, false, nil
	}
	rl, err := s.cfg.Store.GetRealm(r.Context(), realm)
	realmOK := err == nil
	if err != nil && !errors.Is(err, idp.ErrNotFound) {
		return rl, tok, false, err
	}
	tok, err = s.ss.GetSCIMToken(r.Context(), realm)
	tokOK := err == nil
	if err != nil && !errors.Is(err, idp.ErrNotFound) {
		return rl, tok, false, err
	}
	want := tok.TokenHash
	if !tokOK {
		want = strings.Repeat("0", 64) // dummy: same work for every failure
	}
	match := subtle.ConstantTimeCompare([]byte(sha256Hex(presented)), []byte(want)) == 1
	if !realmOK || !tokOK || !match || !rl.Enabled || tok.RealmID != rl.ID {
		return core.Realm{}, core.SCIMToken{}, false, nil
	}
	return rl, tok, true, nil
}

func scimOf(r *http.Request) *scimReq {
	v, _ := r.Context().Value(scimCtxKey{}).(*scimReq)
	return v
}

// lock serialises SCIM writes within a realm, so an If-Match check and the
// update that follows it are one step (per process; see docs/scim.md).
func (s *scimAPI) lock(realm string) func() {
	v, _ := s.locks.LoadOrStore(realm, &sync.Mutex{})
	mu := v.(*sync.Mutex)
	mu.Lock()
	return mu.Unlock
}

// op wraps a mutating handler with the shared observability counter.
func (s *scimAPI) op(resource, action string, h http.HandlerFunc) http.HandlerFunc {
	return s.api.op(resource, action, func(w http.ResponseWriter, r *http.Request) {
		noteRealm(r, scimOf(r).rl.Name)
		defer s.lock(scimOf(r).rl.Name)()
		h(w, r)
	})
}

// ---- helpers ----

func (s *scimAPI) loc(rl core.Realm, kind, id string) string {
	return s.base + "/realms/" + rl.Name + "/scim/v2/" + kind + "/" + id
}

func scimVersion(parts ...string) string {
	return `W/"` + sha256Hex(strings.Join(parts, "\x00"))[:20] + `"`
}

// ifMatchOK checks the If-Match precondition of a write. No header = allowed.
func ifMatchOK(r *http.Request, version string) bool {
	h := strings.TrimSpace(r.Header.Get("If-Match"))
	if h == "" || h == "*" {
		return true
	}
	cur := strings.TrimPrefix(version, "W/")
	for _, p := range strings.Split(h, ",") {
		if strings.TrimPrefix(strings.TrimSpace(p), "W/") == cur {
			return true
		}
	}
	return false
}

func ifNoneMatch(r *http.Request, version string) bool {
	h := strings.TrimSpace(r.Header.Get("If-None-Match"))
	if h == "" {
		return false
	}
	cur := strings.TrimPrefix(version, "W/")
	for _, p := range strings.Split(h, ",") {
		p = strings.TrimSpace(p)
		if p == "*" || strings.TrimPrefix(p, "W/") == cur {
			return true
		}
	}
	return false
}

func (s *scimAPI) readJSON(r *http.Request) (map[string]any, error) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, err
		}
		return nil, serr(http.StatusBadRequest, "invalidSyntax", "could not read body")
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil || m == nil {
		return nil, serr(http.StatusBadRequest, "invalidSyntax", "body must be a JSON object")
	}
	return m, nil
}

func (s *scimAPI) respond(w http.ResponseWriter, code int, version, location string, body any) {
	if version != "" {
		w.Header().Set("ETag", version)
	}
	if location != "" {
		w.Header().Set("Location", location)
	}
	s.writeJSON(w, code, body)
}

// hidden reports users SCIM must neither show nor touch: administrators of
// this deployment and service-account users.
func hidden(u core.User) bool {
	return slices.Contains(u.Roles, adminRole) || strings.HasPrefix(strings.ToLower(u.Username), scimSAPrefix)
}

func (s *scimAPI) visibleUser(ctx context.Context, realm, id string) (core.User, error) {
	u, err := s.cfg.Store.GetUser(ctx, realm, id)
	if err != nil {
		return core.User{}, err
	}
	if hidden(u) {
		return core.User{}, idp.ErrNotFound
	}
	return u, nil
}

// scanUsers walks the realm's users (at most scimScanCap) in store order.
func (s *scimAPI) scanUsers(ctx context.Context, realm string, visit func(core.User)) error {
	seen := 0
	for off := 0; ; off += scimScanPage {
		page, err := s.cfg.Store.ListUsers(ctx, realm, "", off, scimScanPage)
		if err != nil {
			return err
		}
		for _, u := range page {
			if seen++; seen > scimScanCap {
				return serr(http.StatusBadRequest, "tooMany", "too many users to scan; narrow the request with userName eq, id eq or externalId eq")
			}
			if !hidden(u) {
				visit(u)
			}
		}
		if len(page) < scimScanPage {
			return nil
		}
	}
}

func paging(r *http.Request) (start, count int, err error) {
	q := r.URL.Query()
	start, count = 1, scimDefaultPage
	if v := q.Get("startIndex"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil {
			return 0, 0, serr(http.StatusBadRequest, "invalidValue", "invalid startIndex")
		}
		start = max(1, min(n, scimMaxStart))
	}
	if v := q.Get("count"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil {
			return 0, 0, serr(http.StatusBadRequest, "invalidValue", "invalid count")
		}
		count = max(0, min(n, scimMaxPage))
	}
	return start, count, nil
}

func (s *scimAPI) listBody(total, start int, res []map[string]any) map[string]any {
	if res == nil {
		res = []map[string]any{}
	}
	return map[string]any{"schemas": []string{scimSchemaList}, "totalResults": total, "startIndex": start,
		"itemsPerPage": len(res), "Resources": res}
}

func window[T any](all []T, start, count int) []T {
	i := start - 1
	if i >= len(all) || count == 0 {
		return nil
	}
	return all[i:min(len(all), i+count)]
}

func parseFilterParam(r *http.Request, allowed map[string]bool) (*fnode, error) {
	f := r.URL.Query().Get("filter")
	if f == "" {
		return nil, nil
	}
	n, err := parseSCIMFilter(f, allowed)
	if err != nil {
		return nil, serr(http.StatusBadRequest, "invalidFilter", err.Error())
	}
	return n, nil
}

func filterUses(n *fnode, attr string) bool {
	if n == nil {
		return false
	}
	return n.attr == attr || filterUses(n.l, attr) || filterUses(n.r, attr)
}
