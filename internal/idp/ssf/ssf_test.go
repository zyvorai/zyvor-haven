// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package ssf_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/secretbox"
	"github.com/zyvorai/haven/internal/idp/ssf"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

var ctx = context.Background()

type env struct {
	t      *testing.T
	raw    *memstore.Store
	st     core.Store // decorated
	ss     core.SSFStore
	signer core.Signer
	now    time.Time
}

func newEnv(t *testing.T) *env {
	t.Helper()
	raw := memstore.New()
	e := &env{t: t, raw: raw, now: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	must(t, raw.CreateRealm(ctx, core.Realm{Name: "r", Enabled: true, CreatedAt: e.now}))
	e.signer = keys.New(raw, keys.Options{})
	must(t, e.signer.EnsureKey(ctx, "r"))
	tx := &ssf.Transmitter{Builder: ssf.Builder{Signer: e.signer, BaseURL: "https://idp.example", Clock: func() time.Time { return e.now }}, Store: raw}
	e.st = ssf.Wrap(raw, tx)
	e.ss = raw
	must(t, raw.CreateUser(ctx, core.User{ID: "u1", Realm: "r", Username: "alice", Email: "alice@example.com", Enabled: true,
		PasswordHash: "hash1", Roles: []string{"user"}, CreatedAt: e.now}))
	must(t, raw.CreateUser(ctx, core.User{ID: "u2", Realm: "r", Username: "bob", Email: "bob@example.com", Enabled: true, CreatedAt: e.now}))
	return e
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// stream creates a receiver+stream. events nil = default delivered set (all non-deprecated).
func (e *env) stream(name string, all bool, format string, requested ...string) (core.SSFReceiver, core.SSFStream) {
	e.t.Helper()
	rc, err := e.ss.CreateSSFReceiver(ctx, core.SSFReceiver{Realm: "r", Name: name, Audience: "aud-" + name, TokenHash: ssf.HashToken(name),
		AllSubjects: all, AllowEmail: true, CreatedAt: e.now})
	must(e.t, err)
	st, err := e.ss.CreateSSFStream(ctx, core.SSFStream{Realm: "r", ReceiverID: rc.ID, Status: core.SSFStatusEnabled,
		EndpointURL: "https://rx.example/push", EventsRequested: requested, EventsDelivered: ssf.Delivered(rc, requested),
		SubjectFormat: format, CreatedAt: e.now, UpdatedAt: e.now}, 5)
	must(e.t, err)
	return rc, st
}

type sset struct {
	hdr    map[string]any
	claims map[string]any
	raw    string
}

func (e *env) sets() []sset {
	e.t.Helper()
	rows, err := e.ss.ClaimSSFOutbox(ctx, e.now.Add(time.Hour), time.Minute, 100)
	must(e.t, err)
	var out []sset
	for _, r := range rows {
		out = append(out, decodeSET(e.t, r.SET))
	}
	return out
}

func decodeSET(t *testing.T, tok string) sset {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %q", tok)
	}
	var s sset
	s.raw = tok
	for i, dst := range []*map[string]any{&s.hdr, &s.claims} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		must(t, err)
		must(t, json.Unmarshal(b, dst))
	}
	return s
}

func (s sset) event(uri string) map[string]any {
	ev, _ := s.claims["events"].(map[string]any)
	m, _ := ev[uri].(map[string]any)
	return m
}

func TestUserDisabledEnabledSET(t *testing.T) {
	e := newEnv(t)
	_, st := e.stream("rx", true, ssf.FormatOpaque)
	u, _ := e.raw.GetUser(ctx, "r", "u1")
	u.Enabled = false
	must(t, e.st.UpdateUser(ctx, u))
	sets := e.sets()
	if len(sets) != 1 {
		t.Fatalf("got %d SETs", len(sets))
	}
	s := sets[0]
	if s.hdr["typ"] != ssf.SETType || s.hdr["alg"] != "ES256" || s.hdr["kid"] == "" {
		t.Errorf("header %v", s.hdr)
	}
	if s.claims["iss"] != "https://idp.example/realms/r" || s.claims["aud"] != "aud-rx" {
		t.Errorf("claims %v", s.claims)
	}
	if _, has := s.claims["sub"]; has {
		t.Error("a SSF SET must not carry the JWT sub claim")
	}
	if s.claims["jti"] == "" || s.claims["iat"] == nil {
		t.Errorf("claims %v", s.claims)
	}
	sub, _ := s.claims["sub_id"].(map[string]any)
	if sub["format"] != "opaque" || sub["id"] != "u1" {
		t.Errorf("sub_id %v", sub)
	}
	ev := s.event(ssf.EvAccountDisabled)
	if ev == nil || ev["event_timestamp"] == nil {
		t.Fatalf("events %v", s.claims["events"])
	}
	// the signature verifies with the realm key set
	if _, err := e.signer.Verify(ctx, "r", s.raw); err != nil {
		t.Errorf("signature: %v", err)
	}
	// and nothing about the user leaks in an opaque-subject SET
	if strings.Contains(string(mustJSON(s.claims)), "alice") {
		t.Errorf("PII in opaque SET: %v", s.claims)
	}
	_ = st

	u.Enabled = true
	must(t, e.st.UpdateUser(ctx, u))
	// the first SET was leased by e.sets(); look at counts instead
	c, _ := e.ss.CountSSFOutbox(ctx, "r")
	if c["pending"] != 2 {
		t.Errorf("outbox %v", c)
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestSubjectFormats(t *testing.T) {
	for _, tc := range []struct {
		format string
		check  func(t *testing.T, sub map[string]any)
	}{
		{ssf.FormatEmail, func(t *testing.T, s map[string]any) {
			if s["format"] != "email" || s["email"] != "alice@example.com" {
				t.Errorf("%v", s)
			}
		}},
		{ssf.FormatIssSub, func(t *testing.T, s map[string]any) {
			if s["format"] != "iss_sub" || s["iss"] != "https://idp.example/realms/r" || s["sub"] != "u1" {
				t.Errorf("%v", s)
			}
		}},
		{ssf.FormatOpaque, func(t *testing.T, s map[string]any) {
			if s["format"] != "opaque" || s["id"] != "u1" || s["email"] != nil {
				t.Errorf("%v", s)
			}
		}},
	} {
		t.Run(tc.format, func(t *testing.T) {
			e := newEnv(t)
			e.stream("rx", true, tc.format)
			u, _ := e.raw.GetUser(ctx, "r", "u1")
			u.Enabled = false
			must(t, e.st.UpdateUser(ctx, u))
			s := e.sets()[0]
			sub, _ := s.claims["sub_id"].(map[string]any)
			tc.check(t, sub)
			evSub, _ := s.event(ssf.EvAccountDisabled)["subject"].(map[string]any)
			tc.check(t, evSub)
		})
	}
}

func TestEmailFormatFallsBackToOpaqueWithoutEmail(t *testing.T) {
	e := newEnv(t)
	e.stream("rx", true, ssf.FormatEmail)
	u, _ := e.raw.GetUser(ctx, "r", "u2")
	u.Email = ""
	must(t, e.raw.UpdateUser(ctx, u)) // raw: no event
	u.Enabled = false
	must(t, e.st.UpdateUser(ctx, u))
	sub, _ := e.sets()[0].claims["sub_id"].(map[string]any)
	if sub["format"] != "opaque" || sub["id"] != "u2" {
		t.Errorf("%v", sub)
	}
}

func TestOnlyRegisteredSubjectsAndRequestedEvents(t *testing.T) {
	e := newEnv(t)
	_, st := e.stream("rx", false, ssf.FormatOpaque, ssf.EvAccountDisabled)
	disable := func(id string) {
		u, _ := e.raw.GetUser(ctx, "r", id)
		u.Enabled = false
		must(t, e.st.UpdateUser(ctx, u))
		u.Enabled = true
		must(t, e.raw.UpdateUser(ctx, u))
	}
	disable("u1") // not registered: nothing
	if n := len(e.sets()); n != 0 {
		t.Fatalf("unregistered subject produced %d SETs", n)
	}
	must(t, e.ss.AddSSFSubject(ctx, "r", st.ID, "u1", e.now))
	disable("u1")
	disable("u2") // still not registered
	if n := len(e.sets()); n != 1 {
		t.Fatalf("got %d SETs, want 1", n)
	}
	// an event the stream did not request is not sent
	u, _ := e.raw.GetUser(ctx, "r", "u1")
	u.PasswordHash = "other"
	must(t, e.st.UpdateUser(ctx, u))
	if n := len(e.sets()); n != 0 {
		t.Fatalf("unrequested credential-change produced %d SETs", n)
	}
}

func TestDisabledStreamAndReceiverGetNothing(t *testing.T) {
	e := newEnv(t)
	rc, st := e.stream("rx", true, ssf.FormatOpaque)
	u, _ := e.raw.GetUser(ctx, "r", "u1")
	st.Status = core.SSFStatusDisabled
	must(t, e.ss.UpdateSSFStream(ctx, st))
	u.Enabled = false
	must(t, e.st.UpdateUser(ctx, u))
	st.Status = core.SSFStatusEnabled
	must(t, e.ss.UpdateSSFStream(ctx, st))
	must(t, e.ss.SetSSFReceiverDisabled(ctx, "r", rc.ID, true))
	u.Enabled = true
	must(t, e.st.UpdateUser(ctx, u))
	if c, _ := e.ss.CountSSFOutbox(ctx, "r"); len(c) != 0 {
		t.Fatalf("outbox %v", c)
	}
}

func TestCredentialChangeAndClaims(t *testing.T) {
	e := newEnv(t)
	e.stream("opaque", true, ssf.FormatOpaque)
	e.stream("email", true, ssf.FormatEmail)
	u, _ := e.raw.GetUser(ctx, "r", "u1")
	u.PasswordHash = "hash2"
	must(t, e.st.UpdateUser(ctx, u))
	n := 0
	for _, s := range e.sets() {
		ev := s.event(ssf.EvCredentialChange)
		if ev["credential_type"] != "password" || ev["change_type"] != "update" {
			t.Errorf("%v", ev)
		}
		n++
	}
	if n != 2 {
		t.Fatalf("%d SETs", n)
	}

	// token-claims-change: the opaque stream only learns about roles (no PII)
	u.Roles = []string{"user", "admin"}
	u.Email = "alice2@example.com"
	u.FirstName = "Alice"
	must(t, e.st.UpdateUser(ctx, u))
	got := map[string]map[string]any{}
	for _, s := range e.sets() {
		claims, _ := s.event(ssf.EvTokenClaimsChange)["claims"].(map[string]any)
		got[s.claims["aud"].(string)] = claims
	}
	if c := got["aud-opaque"]; len(c) != 1 || c["realm_access"] == nil {
		t.Errorf("opaque stream claims: %v", c)
	}
	c := got["aud-email"]
	if c["email"] != "alice2@example.com" || c["given_name"] != "Alice" || c["realm_access"] == nil {
		t.Errorf("email stream claims: %v", c)
	}
	// only PII changed: the opaque stream gets no event at all
	u.LastName = "Smith"
	must(t, e.st.UpdateUser(ctx, u))
	sets := e.sets()
	if len(sets) != 1 || sets[0].claims["aud"] != "aud-email" {
		t.Errorf("PII-only change reached %d streams", len(sets))
	}
}

func TestNoSignalForIrrelevantUserUpdates(t *testing.T) {
	e := newEnv(t)
	e.stream("rx", true, ssf.FormatOpaque)
	u, _ := e.raw.GetUser(ctx, "r", "u1")
	u.FailedLogins = 3
	u.LockedUntil = e.now.Add(time.Minute)
	u.PendingActions = []string{"VERIFY_EMAIL"}
	u.Groups = []string{"/g"}
	must(t, e.st.UpdateUser(ctx, u))
	if n := len(e.sets()); n != 0 {
		t.Fatalf("lockout bookkeeping produced %d SETs", n)
	}
}

func TestSessionsRevoked(t *testing.T) {
	e := newEnv(t)
	e.stream("plain", true, ssf.FormatOpaque)
	e.stream("legacy", true, ssf.FormatOpaque, ssf.EvSessionsRevoked, ssf.EvSessionRevoked)
	put := func(id string) {
		must(t, e.raw.PutSession(ctx, core.Session{ID: id, Realm: "r", UserID: "u1", CookieHash: "c" + id, ExpiresAt: e.now.Add(time.Hour), IdleExpires: e.now.Add(time.Hour), CreatedAt: e.now, LastSeen: e.now}))
	}
	put("s1")
	_, err := e.st.TakeSession(ctx, "r", "s1")
	must(t, err)
	sets := e.sets()
	if len(sets) != 2 {
		t.Fatalf("%d SETs", len(sets))
	}
	ev := sets[0].event(ssf.EvSessionRevoked)
	sub, _ := ev["subject"].(map[string]any)
	sess, _ := sub["session"].(map[string]any)
	user, _ := sub["user"].(map[string]any)
	if sub["format"] != "complex" || sess["id"] != "s1" || user["id"] != "u1" {
		t.Errorf("subject %v", sub)
	}
	// no cookie hash or other session secrets
	if strings.Contains(string(mustJSON(sets[0].claims)), "cs1") {
		t.Error("cookie hash leaked")
	}

	put("s2")
	put("s3")
	n := 0
	rows, _ := e.st.TakeUserSessions(ctx, "r", "u1")
	n = len(rows)
	if n != 2 {
		t.Fatalf("took %d", n)
	}
	var revoked, legacy int
	for _, s := range e.sets() {
		if s.event(ssf.EvSessionRevoked) != nil {
			revoked++
		}
		if s.event(ssf.EvSessionsRevoked) != nil {
			legacy++
			if s.claims["aud"] != "aud-legacy" {
				t.Error("deprecated sessions-revoked sent to a stream that did not ask for it")
			}
		}
	}
	if revoked != 4 || legacy != 1 { // 2 sessions x 2 streams; one RISC event for the asking stream
		t.Errorf("revoked=%d legacy=%d", revoked, legacy)
	}
	// taking nothing signals nothing
	_, err = e.st.TakeUserSessions(ctx, "r", "u1")
	must(t, err)
	if len(e.sets()) != 0 {
		t.Error("empty take signalled")
	}
}

func TestEmitSignalCredentialCompromise(t *testing.T) {
	e := newEnv(t)
	e.stream("rx", true, ssf.FormatOpaque)
	core.EmitSignal(ctx, e.st, core.Signal{Realm: "r", UserID: "u1", Kind: ssf.EvCredentialCompromise,
		Attrs: map[string]any{"credential_type": "password", "reason_admin": "breach list"}})
	s := e.sets()
	if len(s) != 1 {
		t.Fatalf("%d", len(s))
	}
	ev := s[0].event(ssf.EvCredentialCompromise)
	if ev["credential_type"] != "password" || ev["reason_admin"] != "breach list" {
		t.Errorf("%v", ev)
	}
	// unknown user / empty realm: no panic, nothing sent
	core.EmitSignal(ctx, e.st, core.Signal{Realm: "r", UserID: "ghost", Kind: ssf.EvCredentialCompromise})
	core.EmitSignal(ctx, e.st, core.Signal{Realm: "", UserID: "u1", Kind: ssf.EvCredentialCompromise})
	core.EmitSignal(ctx, e.raw, core.Signal{Realm: "r", UserID: "u1", Kind: ssf.EvCredentialCompromise}) // undecorated: no-op
}

func TestTokenHashing(t *testing.T) {
	p1, h1 := ssf.NewToken()
	p2, h2 := ssf.NewToken()
	if p1 == p2 || h1 == h2 || !strings.HasPrefix(p1, "hssf_") || len(h1) != 64 || h1 == p1 || ssf.HashToken(p1) != h1 {
		t.Fatalf("%s %s %s", p1, h1, p2)
	}
}

func TestDeliveredRules(t *testing.T) {
	rc := core.SSFReceiver{}
	d := ssf.Delivered(rc, nil)
	if slices.Contains(d, ssf.EvSessionsRevoked) || !slices.Contains(d, ssf.EvSessionRevoked) {
		t.Errorf("default: %v", d)
	}
	if d := ssf.Delivered(rc, []string{ssf.EvSessionsRevoked, "urn:bogus"}); len(d) != 1 || d[0] != ssf.EvSessionsRevoked {
		t.Errorf("explicit: %v", d)
	}
	rc.Events = []string{ssf.EvAccountDisabled}
	if d := ssf.Delivered(rc, []string{ssf.EvAccountEnabled, ssf.EvAccountDisabled}); len(d) != 1 || d[0] != ssf.EvAccountDisabled {
		t.Errorf("restricted receiver: %v", d)
	}
}

func TestValidateEndpoint(t *testing.T) {
	for url, allow := range map[string]bool{
		"https://rx.example/push": false, "http://rx.example/push": false, "http://127.0.0.1:8/x": false,
		"https://u:p@rx.example/": false, "https://rx.example/#f": false, "ftp://rx.example/": false, "": false,
		"https://rx.example/a b": false,
	} {
		err := ssf.ValidateEndpoint(url, false)
		if (err == nil) != (url == "https://rx.example/push") {
			t.Errorf("%q: %v", url, err)
		}
		_ = allow
	}
	if err := ssf.ValidateEndpoint("http://127.0.0.1:8/x", true); err != nil {
		t.Errorf("dev loopback: %v", err)
	}
	if err := ssf.ValidateEndpoint("http://rx.example/x", true); err == nil {
		t.Error("dev mode must not allow plain http to a public host")
	}
}

// ---- worker ----

type rx struct {
	srv   *httptest.Server
	mu    sync.Mutex
	calls int
	auth  []string
	ctyp  []string
	body  []string
	codes []int // status per call; last repeats
}

func newRX(codes ...int) *rx {
	r := &rx{codes: codes}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		i := r.calls
		r.calls++
		r.auth = append(r.auth, req.Header.Get("Authorization"))
		r.ctyp = append(r.ctyp, req.Header.Get("Content-Type"))
		r.body = append(r.body, string(b))
		code := r.codes[min(i, len(r.codes)-1)]
		r.mu.Unlock()
		if code == 307 {
			w.Header().Set("Location", "https://127.0.0.1:1/never")
		}
		w.WriteHeader(code)
	}))
	return r
}

func (r *rx) count() int { r.mu.Lock(); defer r.mu.Unlock(); return r.calls }

func (e *env) worker(r *rx, box *secretbox.Box, private bool) *ssf.Worker {
	pool := x509.NewCertPool()
	if r != nil {
		pool.AddCert(r.srv.Certificate())
	}
	clock := func() time.Time { return e.now }
	return &ssf.Worker{Store: e.raw, Box: box, Clock: clock, AllowPrivate: private, RootCAs: pool,
		Backoff: time.Second, MaxBackoff: 4 * time.Second, MaxAttempts: 3, Timeout: 2 * time.Second}
}

func (e *env) pointStream(st core.SSFStream, url, sealed string) {
	st.EndpointURL, st.SealedAuth = url, sealed
	must(e.t, e.ss.UpdateSSFStream(ctx, st))
}

func (e *env) trigger() {
	u, _ := e.raw.GetUser(ctx, "r", "u1")
	u.Enabled = !u.Enabled
	must(e.t, e.st.UpdateUser(ctx, u))
}

func TestWorkerDeliversWithAuthAndContentType(t *testing.T) {
	e := newEnv(t)
	box, _ := secretbox.New(make([]byte, 32))
	r := newRX(http.StatusAccepted)
	defer r.srv.Close()
	_, st := e.stream("rx", true, ssf.FormatOpaque)
	sealed := box.Seal([]byte("Bearer rx-secret"), ssf.SealContext("r", st.ID))
	e.pointStream(st, r.srv.URL+"/events", sealed)
	e.trigger()

	w := e.worker(r, box, true)
	if n := w.Tick(ctx); n != 1 {
		t.Fatalf("tick %d", n)
	}
	if r.count() != 1 || r.auth[0] != "Bearer rx-secret" || r.ctyp[0] != "application/secevent+jwt" {
		t.Fatalf("calls=%d auth=%v ctyp=%v", r.count(), r.auth, r.ctyp)
	}
	if s := decodeSET(t, r.body[0]); s.event(ssf.EvAccountDisabled) == nil {
		t.Errorf("body is not the SET: %q", r.body[0])
	}
	if strings.Contains(r.body[0], "rx-secret") {
		t.Error("the receiver's own secret must not be in the SET")
	}
	c, _ := e.ss.CountSSFOutbox(ctx, "r")
	if c["delivered"] != 1 || c["pending"] != 0 {
		t.Errorf("%v", c)
	}
	// the stored header is sealed, never plaintext
	got, _ := e.ss.GetSSFStream(ctx, "r", st.ID)
	if strings.Contains(got.SealedAuth, "rx-secret") || got.SealedAuth == "" {
		t.Errorf("sealed auth %q", got.SealedAuth)
	}
	// a ciphertext moved to another stream does not open
	if _, err := box.Open(got.SealedAuth, ssf.SealContext("r", "other-stream")); err == nil {
		t.Error("sealed header opened under another stream's context")
	}
}

func TestWorkerRetriesThenSucceeds(t *testing.T) {
	e := newEnv(t)
	r := newRX(500, 503, 202)
	defer r.srv.Close()
	_, st := e.stream("rx", true, ssf.FormatOpaque)
	e.pointStream(st, r.srv.URL, "")
	e.trigger()
	w := e.worker(r, nil, true)
	w.Tick(ctx)
	if c, _ := e.ss.CountSSFOutbox(ctx, "r"); c["pending"] != 1 {
		t.Fatalf("after 500: %v", c)
	}
	// not due yet: backoff is 1s
	if n := w.Tick(ctx); n != 0 {
		t.Fatalf("retried before the backoff: %d", n)
	}
	e.now = e.now.Add(1500 * time.Millisecond)
	w.Tick(ctx)
	e.now = e.now.Add(2500 * time.Millisecond) // second backoff doubles to 2s
	if n := w.Tick(ctx); n != 1 {
		t.Fatalf("third attempt not made: %d", n)
	}
	c, _ := e.ss.CountSSFOutbox(ctx, "r")
	if c["delivered"] != 1 || r.count() != 3 {
		t.Errorf("%v calls=%d", c, r.count())
	}
}

func TestWorkerGivesUp(t *testing.T) {
	e := newEnv(t)
	r := newRX(500)
	defer r.srv.Close()
	_, st := e.stream("rx", true, ssf.FormatOpaque)
	e.pointStream(st, r.srv.URL, "")
	e.trigger()
	w := e.worker(r, nil, true)
	for i := 0; i < 6; i++ {
		w.Tick(ctx)
		e.now = e.now.Add(10 * time.Second)
	}
	c, _ := e.ss.CountSSFOutbox(ctx, "r")
	if c["dead"] != 1 || r.count() != 3 {
		t.Errorf("%v calls=%d (MaxAttempts is 3)", c, r.count())
	}
}

func TestWorkerDoesNotRetryRejection(t *testing.T) {
	e := newEnv(t)
	r := newRX(400)
	defer r.srv.Close()
	_, st := e.stream("rx", true, ssf.FormatOpaque)
	e.pointStream(st, r.srv.URL, "")
	e.trigger()
	w := e.worker(r, nil, true)
	w.Tick(ctx)
	e.now = e.now.Add(time.Hour)
	w.Tick(ctx)
	c, _ := e.ss.CountSSFOutbox(ctx, "r")
	if c["dead"] != 1 || r.count() != 1 {
		t.Errorf("%v calls=%d", c, r.count())
	}
}

func TestWorkerNeverFollowsRedirects(t *testing.T) {
	e := newEnv(t)
	r := newRX(307)
	defer r.srv.Close()
	_, st := e.stream("rx", true, ssf.FormatOpaque)
	e.pointStream(st, r.srv.URL, "")
	e.trigger()
	e.worker(r, nil, true).Tick(ctx)
	if r.count() != 1 {
		t.Errorf("calls %d", r.count())
	}
	if c, _ := e.ss.CountSSFOutbox(ctx, "r"); c["dead"] != 1 {
		t.Errorf("%v", c)
	}
}

func TestWorkerBlocksPrivateAddresses(t *testing.T) {
	e := newEnv(t)
	r := newRX(202)
	defer r.srv.Close()
	_, st := e.stream("rx", true, ssf.FormatOpaque)
	e.pointStream(st, r.srv.URL, "") // 127.0.0.1 over https
	e.trigger()
	e.worker(r, nil, false).Tick(ctx) // production policy
	if r.count() != 0 {
		t.Fatal("the worker connected to a loopback address")
	}
	rows, _ := e.ss.ClaimSSFOutbox(ctx, e.now.Add(time.Hour), time.Minute, 5)
	c, _ := e.ss.CountSSFOutbox(ctx, "r")
	if c["dead"] != 1 || len(rows) != 0 {
		t.Errorf("%v", c)
	}
}

func TestWorkerSkipsPausedAndHoldsEvents(t *testing.T) {
	e := newEnv(t)
	r := newRX(202)
	defer r.srv.Close()
	_, st := e.stream("rx", true, ssf.FormatOpaque)
	st.Status = core.SSFStatusPaused
	e.pointStream(st, r.srv.URL, "")
	e.trigger()
	w := e.worker(r, nil, true)
	w.Tick(ctx)
	if r.count() != 0 {
		t.Fatal("paused stream received events")
	}
	st.Status, st.EndpointURL = core.SSFStatusEnabled, r.srv.URL
	must(t, e.ss.UpdateSSFStream(ctx, st))
	w.Tick(ctx)
	if r.count() != 1 {
		t.Errorf("held event not released: %d", r.count())
	}
}

func TestWorkerSealedHeaderNeedsKey(t *testing.T) {
	e := newEnv(t)
	box, _ := secretbox.New(make([]byte, 32))
	r := newRX(202)
	defer r.srv.Close()
	_, st := e.stream("rx", true, ssf.FormatOpaque)
	e.pointStream(st, r.srv.URL, box.Seal([]byte("Bearer x"), ssf.SealContext("r", st.ID)))
	e.trigger()
	e.worker(r, nil, true).Tick(ctx) // no key configured: must not send unauthenticated
	if r.count() != 0 {
		t.Fatal("sent without the configured authorization header")
	}
}

func TestWorkerConcurrentWorkersDoNotDoubleSend(t *testing.T) {
	e := newEnv(t)
	r := newRX(202)
	defer r.srv.Close()
	_, st := e.stream("rx", true, ssf.FormatOpaque)
	e.pointStream(st, r.srv.URL, "")
	for i := 0; i < 8; i++ {
		e.trigger()
	}
	var wg sync.WaitGroup
	var total atomic.Int32
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); total.Add(int32(e.worker(r, nil, true).Tick(ctx))) }()
	}
	wg.Wait()
	if r.count() != 8 || total.Load() != 8 {
		t.Errorf("calls=%d claimed=%d, want 8 each", r.count(), total.Load())
	}
}

func TestVerificationSET(t *testing.T) {
	e := newEnv(t)
	_, st := e.stream("rx", false, ssf.FormatOpaque)
	b := ssf.Builder{Signer: e.signer, BaseURL: "https://idp.example", Clock: func() time.Time { return e.now }}
	row, err := b.Verification(ctx, st, "abc")
	must(t, err)
	s := decodeSET(t, row.SET)
	sub, _ := s.claims["sub_id"].(map[string]any)
	ev := s.event(ssf.EvVerification)
	if sub["format"] != "opaque" || sub["id"] != st.ID || ev["state"] != "abc" || s.hdr["typ"] != "secevent+jwt" {
		t.Errorf("%v %v", s.claims, s.hdr)
	}
}
