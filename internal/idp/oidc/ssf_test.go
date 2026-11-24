// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/secretbox"
	"github.com/zyvorai/haven/internal/idp/sessions"
	"github.com/zyvorai/haven/internal/idp/ssf"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

type ssfEnv struct {
	t     *testing.T
	raw   *memstore.Store
	st    core.Store
	h     http.Handler
	now   time.Time
	token string // receiver "rx" (allowEmail, not all subjects)
	other string // receiver "other"
	rx    core.SSFReceiver
}

func newSSFEnv(t *testing.T, decorated bool, box *secretbox.Box) *ssfEnv {
	t.Helper()
	ctx := context.Background()
	e := &ssfEnv{t: t, raw: memstore.New(), now: time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)}
	for _, err := range []error{
		e.raw.CreateRealm(ctx, core.Realm{Name: "r", Enabled: true, CreatedAt: e.now}),
		e.raw.CreateRealm(ctx, core.Realm{Name: "r2", Enabled: true, CreatedAt: e.now}),
		e.raw.CreateUser(ctx, core.User{ID: "u1", Realm: "r", Username: "alice", Email: "alice@example.com", Enabled: true, CreatedAt: e.now}),
		e.raw.CreateUser(ctx, core.User{ID: "u2", Realm: "r", Username: "bob", Email: "bob@example.com", Enabled: true, CreatedAt: e.now}),
	} {
		if err != nil {
			t.Fatal(err)
		}
	}
	signer := keys.New(e.raw, keys.Options{})
	if err := signer.EnsureKey(ctx, "r"); err != nil {
		t.Fatal(err)
	}
	e.st = e.raw
	if decorated {
		e.st = ssf.Wrap(e.raw, &ssf.Transmitter{Builder: ssf.Builder{Signer: signer, BaseURL: "https://idp.example", Clock: func() time.Time { return e.now }}, Store: e.raw, AllowPrivate: true})
	}
	mk := func(name, realm string, allowEmail bool) (string, core.SSFReceiver) {
		tok, hash := ssf.NewToken()
		rc, err := e.raw.CreateSSFReceiver(ctx, core.SSFReceiver{Realm: realm, Name: name, Audience: "aud-" + name, TokenHash: hash, AllowEmail: allowEmail, CreatedAt: e.now})
		if err != nil {
			t.Fatal(err)
		}
		return tok, rc
	}
	e.token, e.rx = mk("rx", "r", true)
	e.other, _ = mk("other", "r", false)
	clock := func() time.Time { return e.now }
	e.h = New(Config{Store: e.st, Signer: signer, Hasher: fakeHasher{}, BaseURL: "https://idp.example", Clock: clock,
		CSRFKey: []byte("0123456789abcdef0123456789abcdef"), SecretBox: box})
	return e
}

func (e *ssfEnv) call(method, path, token, body string) (int, map[string]any, []map[string]any) {
	e.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "192.0.2.1:1"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if cc := w.Header().Get("Cache-Control"); w.Code != 404 && cc != "no-store" {
		e.t.Errorf("%s %s: Cache-Control %q", method, path, cc)
	}
	var obj map[string]any
	var arr []map[string]any
	if json.Unmarshal(w.Body.Bytes(), &obj) != nil {
		_ = json.Unmarshal(w.Body.Bytes(), &arr)
	}
	return w.Code, obj, arr
}

const ssfBase = "/realms/r/ssf/"

func (e *ssfEnv) createStream(token, body string) (int, map[string]any) {
	c, o, _ := e.call("POST", ssfBase+"stream", token, body)
	return c, o
}

const goodStream = `{"delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"https://rx.example/events"},"events_requested":["https://schemas.openid.net/secevent/caep/event-type/session-revoked","urn:bogus"],"description":"d"}`

func TestSSFOffWithoutDecoratorOrStore(t *testing.T) {
	e := newSSFEnv(t, false, nil) // store has SSFStore but nobody emits: feature must stay off
	for _, p := range []struct{ m, path string }{
		{"GET", "/realms/r/.well-known/ssf-configuration"}, {"GET", "/.well-known/ssf-configuration/realms/r"},
		{"POST", ssfBase + "stream"}, {"GET", ssfBase + "stream"}, {"POST", ssfBase + "verify"}, {"POST", ssfBase + "status"},
	} {
		if c, _, _ := e.call(p.m, p.path, e.token, goodStream); c != 404 {
			t.Errorf("%s %s without transmitter: %d", p.m, p.path, c)
		}
	}
	// a store without SSFStore (the unit-test fake) is off too
	fe := newEnv(t, nil)
	if w := fe.do(httptest.NewRequest("GET", "/realms/r/.well-known/ssf-configuration", nil)); w.Code != 404 {
		t.Errorf("fake store: %d", w.Code)
	}
}

func TestSSFMetadata(t *testing.T) {
	e := newSSFEnv(t, true, nil)
	for _, path := range []string{"/realms/r/.well-known/ssf-configuration", "/.well-known/ssf-configuration/realms/r"} {
		c, m, _ := e.call("GET", path, "", "")
		if c != 200 {
			t.Fatalf("%s: %d", path, c)
		}
		want := map[string]string{
			"issuer": "https://idp.example/realms/r", "jwks_uri": "https://idp.example/realms/r/protocol/openid-connect/certs",
			"configuration_endpoint": "https://idp.example/realms/r/ssf/stream", "status_endpoint": "https://idp.example/realms/r/ssf/status",
			"add_subject_endpoint": "https://idp.example/realms/r/ssf/subjects/add", "remove_subject_endpoint": "https://idp.example/realms/r/ssf/subjects/remove",
			"verification_endpoint": "https://idp.example/realms/r/ssf/verify", "spec_version": "1_0", "default_subjects": "NONE",
		}
		for k, v := range want {
			if m[k] != v {
				t.Errorf("%s %s = %v, want %s", path, k, m[k], v)
			}
		}
		dm, _ := m["delivery_methods_supported"].([]any)
		if len(dm) != 1 || dm[0] != ssf.MethodPush {
			t.Errorf("delivery methods %v", dm)
		}
	}
	if c, _, _ := e.call("GET", "/realms/nope/.well-known/ssf-configuration", "", ""); c != 404 {
		t.Errorf("unknown realm %d", c)
	}
}

func TestSSFAuth(t *testing.T) {
	e := newSSFEnv(t, true, nil)
	ctx := context.Background()
	for name, tok := range map[string]string{"none": "", "garbage": "nope", "prefix only": "hssf_", "stored hash": e.rx.TokenHash} {
		c, _, _ := e.call("GET", ssfBase+"stream", tok, "")
		if c != 401 {
			t.Errorf("%s: %d", name, c)
		}
	}
	// Basic scheme and a bare token are not bearer auth.
	req := httptest.NewRequest("GET", ssfBase+"stream", nil)
	req.Header.Set("Authorization", "Basic "+e.token)
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
		t.Errorf("basic: %d %v", w.Code, w.Header())
	}
	if c, _, _ := e.call("GET", ssfBase+"stream", e.token, ""); c != 200 {
		t.Fatalf("valid token: %d", c)
	}
	// a token of another realm does not work here
	tok, hash := ssf.NewToken()
	if _, err := e.raw.CreateSSFReceiver(ctx, core.SSFReceiver{Realm: "r2", Name: "x", Audience: "x", TokenHash: hash, CreatedAt: e.now}); err != nil {
		t.Fatal(err)
	}
	if c, _, _ := e.call("GET", ssfBase+"stream", tok, ""); c != 401 {
		t.Errorf("cross-realm token: %d", c)
	}
	// rotation kills the old token
	_, newHash := ssf.NewToken()
	if err := e.raw.SetSSFReceiverToken(ctx, "r", e.rx.ID, newHash); err != nil {
		t.Fatal(err)
	}
	if c, _, _ := e.call("GET", ssfBase+"stream", e.token, ""); c != 401 {
		t.Errorf("rotated token still works: %d", c)
	}
	// a disabled receiver is refused
	if err := e.raw.SetSSFReceiverDisabled(ctx, "r", e.rx.ID, true); err != nil {
		t.Fatal(err)
	}
	if c, _, _ := e.call("GET", ssfBase+"stream", "", ""); c != 401 {
		t.Errorf("%d", c)
	}
}

func TestSSFDisabledReceiverRefused(t *testing.T) {
	e := newSSFEnv(t, true, nil)
	if err := e.raw.SetSSFReceiverDisabled(context.Background(), "r", e.rx.ID, true); err != nil {
		t.Fatal(err)
	}
	if c, _, _ := e.call("GET", ssfBase+"stream", e.token, ""); c != 403 {
		t.Errorf("disabled receiver: %d", c)
	}
}

func TestSSFRateLimit(t *testing.T) {
	e := newSSFEnv(t, true, nil)
	var last int
	for i := 0; i < ssfAPILimit+5; i++ {
		last, _, _ = e.call("GET", ssfBase+"stream", "bad", "")
	}
	if last != 429 {
		t.Errorf("after %d requests: %d", ssfAPILimit+5, last)
	}
}

func TestSSFStreamLifecycle(t *testing.T) {
	e := newSSFEnv(t, true, nil)
	c, s := e.createStream(e.token, goodStream)
	if c != 201 {
		t.Fatalf("create: %d %v", c, s)
	}
	id, _ := s["stream_id"].(string)
	d, _ := s["delivery"].(map[string]any)
	if id == "" || s["iss"] != "https://idp.example/realms/r" || s["aud"] != "aud-rx" || d["method"] != ssf.MethodPush ||
		d["endpoint_url"] != "https://rx.example/events" || s["haven_subject_format"] != "opaque" || s["min_verification_interval"] == nil {
		t.Fatalf("%v", s)
	}
	if _, has := d["authorization_header"]; has {
		t.Error("authorization_header must never be echoed")
	}
	del, _ := s["events_delivered"].([]any)
	if len(del) != 1 || del[0] != ssf.EvSessionRevoked {
		t.Errorf("delivered %v (unknown requested events must be dropped)", del)
	}
	if sup, _ := s["events_supported"].([]any); len(sup) != len(ssf.Supported) {
		t.Errorf("supported %v", sup)
	}

	// read one / list
	if c, o, _ := e.call("GET", ssfBase+"stream?stream_id="+id, e.token, ""); c != 200 || o["stream_id"] != id {
		t.Errorf("read: %d %v", c, o)
	}
	if c, _, l := e.call("GET", ssfBase+"stream", e.token, ""); c != 200 || len(l) != 1 {
		t.Errorf("list: %d %v", c, l)
	}
	// another receiver sees nothing and cannot touch it
	if c, _, l := e.call("GET", ssfBase+"stream", e.other, ""); c != 200 || len(l) != 0 {
		t.Errorf("other list: %d %v", c, l)
	}
	for _, m := range []string{"GET", "DELETE"} {
		if c, _, _ := e.call(m, ssfBase+"stream?stream_id="+id, e.other, ""); c != 404 {
			t.Errorf("other receiver %s: %d", m, c)
		}
	}
	if c, _, _ := e.call("PATCH", ssfBase+"stream", e.other, `{"stream_id":"`+id+`","description":"hijack"}`); c != 404 {
		t.Errorf("other receiver PATCH: %d", c)
	}
	if c, _, _ := e.call("POST", ssfBase+"status", e.other, `{"stream_id":"`+id+`","status":"disabled"}`); c != 404 {
		t.Errorf("other receiver status: %d", c)
	}

	// PATCH merges; PUT replaces
	c, o, _ := e.call("PATCH", ssfBase+"stream", e.token, `{"stream_id":"`+id+`","description":"new","events_requested":["`+ssf.EvAccountDisabled+`"]}`)
	if c != 200 || o["description"] != "new" || o["delivery"].(map[string]any)["endpoint_url"] != "https://rx.example/events" {
		t.Fatalf("patch: %d %v", c, o)
	}
	if dl, _ := o["events_delivered"].([]any); len(dl) != 1 || dl[0] != ssf.EvAccountDisabled {
		t.Errorf("patch delivered %v", dl)
	}
	c, o, _ = e.call("PUT", ssfBase+"stream", e.token, `{"stream_id":"`+id+`","delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"https://rx.example/v2"}}`)
	if c != 200 || o["description"] != "" || o["delivery"].(map[string]any)["endpoint_url"] != "https://rx.example/v2" {
		t.Fatalf("put: %d %v", c, o)
	}
	if c, _, _ := e.call("PUT", ssfBase+"stream", e.token, `{"stream_id":"`+id+`"}`); c != 400 {
		t.Errorf("PUT without delivery: %d", c)
	}
	// status
	if c, o, _ := e.call("GET", ssfBase+"status?stream_id="+id, e.token, ""); c != 200 || o["status"] != "enabled" {
		t.Errorf("status: %d %v", c, o)
	}
	if c, o, _ := e.call("POST", ssfBase+"status", e.token, `{"stream_id":"`+id+`","status":"paused"}`); c != 200 || o["status"] != "paused" {
		t.Errorf("pause: %d %v", c, o)
	}
	if c, _, _ := e.call("POST", ssfBase+"status", e.token, `{"stream_id":"`+id+`","status":"weird"}`); c != 400 {
		t.Errorf("bad status: %d", c)
	}
	// delete
	if c, _, _ := e.call("DELETE", ssfBase+"stream?stream_id="+id, e.token, ""); c != 204 {
		t.Errorf("delete: %d", c)
	}
	if c, _, _ := e.call("GET", ssfBase+"stream?stream_id="+id, e.token, ""); c != 404 {
		t.Errorf("after delete: %d", c)
	}
	if c, _, _ := e.call("DELETE", ssfBase+"stream", e.token, ""); c != 400 {
		t.Errorf("delete without id: %d", c)
	}
}

func TestSSFStreamValidation(t *testing.T) {
	e := newSSFEnv(t, true, nil)
	for name, body := range map[string]string{
		"http endpoint":     `{"delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"http://rx.example/e"}}`,
		"userinfo":          `{"delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"https://u:p@rx.example/e"}}`,
		"fragment":          `{"delivery":{"method":"urn:ietf:rfc:8935","endpoint_url":"https://rx.example/e#x"}}`,
		"poll":              `{"delivery":{"method":"urn:ietf:rfc:8936","endpoint_url":"https://rx.example/e"}}`,
		"no delivery":       `{}`,
		"not json":          `nope`,
		"bad format":        `{"delivery":{"endpoint_url":"https://rx.example/e"},"haven_subject_format":"phone"}`,
		"long description":  `{"delivery":{"endpoint_url":"https://rx.example/e"},"description":"` + strings.Repeat("x", 300) + `"}`,
		"bad auth header":   `{"delivery":{"endpoint_url":"https://rx.example/e","authorization_header":"a\nb"}}`,
		"empty auth header": `{"delivery":{"endpoint_url":"https://rx.example/e","authorization_header":""}}`,
	} {
		if c, o := e.createStream(e.token, body); c != 400 {
			t.Errorf("%s: %d %v", name, c, o)
		}
	}
	// a secret-bearing header needs the secret key: fail closed
	if c, o := e.createStream(e.token, `{"delivery":{"endpoint_url":"https://rx.example/e","authorization_header":"Bearer s3cret"}}`); c != 409 {
		t.Errorf("auth header without secret key: %d %v", c, o)
	}
	// email subjects only for receivers the admin allowed
	body := `{"delivery":{"endpoint_url":"https://rx.example/e"},"haven_subject_format":"email"}`
	if c, o := e.createStream(e.other, body); c != 403 {
		t.Errorf("email without permission: %d %v", c, o)
	}
	if c, o := e.createStream(e.token, body); c != 201 || o["haven_subject_format"] != "email" {
		t.Errorf("email with permission: %d %v", c, o)
	}
	// limit: 1 created above; 4 more fit, the next is refused
	for i := 0; i < core.SSFMaxStreamsPerReceiver-1; i++ {
		if c, o := e.createStream(e.token, goodStream); c != 201 {
			t.Fatalf("stream %d: %d %v", i, c, o)
		}
	}
	if c, _ := e.createStream(e.token, goodStream); c != 409 {
		t.Errorf("over the limit: %d", c)
	}
	big := `{"delivery":{"endpoint_url":"https://rx.example/e"},"description":"` + strings.Repeat("x", ssfBodyMax) + `"}`
	if c, _ := e.createStream(e.other, big); c != 413 {
		t.Errorf("oversized body: %d", c)
	}
}

func TestSSFAuthorizationHeaderIsSealed(t *testing.T) {
	box, _ := secretbox.New(make([]byte, 32))
	e := newSSFEnv(t, true, box)
	c, s := e.createStream(e.token, `{"delivery":{"endpoint_url":"https://rx.example/e","authorization_header":"Bearer s3cret-value"}}`)
	if c != 201 {
		t.Fatalf("%d %v", c, s)
	}
	if b, _ := json.Marshal(s); strings.Contains(string(b), "s3cret") {
		t.Errorf("secret echoed: %s", b)
	}
	id := s["stream_id"].(string)
	st, err := e.raw.GetSSFStream(context.Background(), "r", id)
	if err != nil {
		t.Fatal(err)
	}
	if st.SealedAuth == "" || strings.Contains(st.SealedAuth, "s3cret") {
		t.Fatalf("stored %q", st.SealedAuth)
	}
	got, err := box.Open(st.SealedAuth, ssf.SealContext("r", id))
	if err != nil || string(got) != "Bearer s3cret-value" {
		t.Errorf("open: %q %v", got, err)
	}
	// a later PATCH without a header keeps it; a GET still never shows it
	if c, o, _ := e.call("PATCH", ssfBase+"stream", e.token, `{"stream_id":"`+id+`","description":"x"}`); c != 200 {
		t.Fatalf("%d %v", c, o)
	}
	st, _ = e.raw.GetSSFStream(context.Background(), "r", id)
	if st.SealedAuth == "" {
		t.Error("PATCH dropped the stored header")
	}
}

func (e *ssfEnv) newStream(token string) string {
	e.t.Helper()
	c, s := e.createStream(token, `{"delivery":{"endpoint_url":"https://rx.example/e"}}`)
	if c != 201 {
		e.t.Fatalf("%d %v", c, s)
	}
	return s["stream_id"].(string)
}

func (e *ssfEnv) subjStreams(user string) int {
	l, err := e.raw.SSFStreamsFor(context.Background(), "r", user)
	if err != nil {
		e.t.Fatal(err)
	}
	return len(l)
}

func TestSSFSubjects(t *testing.T) {
	e := newSSFEnv(t, true, nil)
	id := e.newStream(e.token)
	add := func(subject string) int {
		c, _, _ := e.call("POST", ssfBase+"subjects/add", e.token, `{"stream_id":"`+id+`","subject":`+subject+`}`)
		return c
	}
	rm := func(subject string) int {
		c, _, _ := e.call("POST", ssfBase+"subjects/remove", e.token, `{"stream_id":"`+id+`","subject":`+subject+`}`)
		return c
	}
	if add(`{"format":"opaque","id":"u1"}`) != 200 || e.subjStreams("u1") != 1 {
		t.Fatal("opaque add")
	}
	if rm(`{"format":"opaque","id":"u1"}`) != 204 || e.subjStreams("u1") != 0 {
		t.Fatal("opaque remove")
	}
	if add(`{"format":"email","email":"BOB@example.com"}`) != 200 || e.subjStreams("u2") != 1 {
		t.Fatal("email add (case-insensitive)")
	}
	if add(`{"format":"iss_sub","iss":"https://idp.example/realms/r","sub":"u1"}`) != 200 || e.subjStreams("u1") != 1 {
		t.Fatal("iss_sub add")
	}
	// wrong issuer, unknown user, unknown email: answered like success, nothing recorded (no oracle)
	before := e.subjStreams("u2") + e.subjStreams("ghost")
	for _, s := range []string{`{"format":"iss_sub","iss":"https://evil.example","sub":"u2"}`, `{"format":"opaque","id":"ghost"}`,
		`{"format":"email","email":"nobody@example.com"}`, `{"format":"email","email":""}`} {
		if c := add(s); c != 200 {
			t.Errorf("%s: %d", s, c)
		}
	}
	if e.subjStreams("u2")+e.subjStreams("ghost") != before {
		t.Error("an unresolvable subject was recorded")
	}
	if rm(`{"format":"opaque","id":"ghost"}`) != 204 {
		t.Error("remove unknown")
	}
	// unsupported formats and missing subject are errors
	if add(`{"format":"phone_number","phone_number":"+1"}`) != 400 || add(`null`) != 400 {
		t.Error("bad subjects must be 400")
	}
	// another receiver cannot edit this stream's subjects
	c, _, _ := e.call("POST", ssfBase+"subjects/add", e.other, `{"stream_id":"`+id+`","subject":{"format":"opaque","id":"u2"}}`)
	if c != 404 {
		t.Errorf("foreign stream: %d", c)
	}
	// all-subject receivers: remove is refused, add is a no-op
	if err := e.raw.SetSSFReceiverDisabled(context.Background(), "r", e.rx.ID, false); err != nil {
		t.Fatal(err)
	}
}

func TestSSFAllSubjectsReceiver(t *testing.T) {
	e := newSSFEnv(t, true, nil)
	tok, hash := ssf.NewToken()
	if _, err := e.raw.CreateSSFReceiver(context.Background(), core.SSFReceiver{Realm: "r", Name: "all", Audience: "all", TokenHash: hash, AllSubjects: true, CreatedAt: e.now}); err != nil {
		t.Fatal(err)
	}
	id := e.newStream(tok)
	body := `{"stream_id":"` + id + `","subject":{"format":"opaque","id":"u1"}}`
	if c, _, _ := e.call("POST", ssfBase+"subjects/add", tok, body); c != 200 {
		t.Errorf("add: %d", c)
	}
	if c, _, _ := e.call("POST", ssfBase+"subjects/remove", tok, body); c != 400 {
		t.Errorf("remove: %d", c)
	}
}

func TestSSFSubjectRateLimit(t *testing.T) {
	e := newSSFEnv(t, true, nil)
	id := e.newStream(e.token)
	body := `{"stream_id":"` + id + `","subject":{"format":"email","email":"x@example.com"}}`
	var last int
	for i := 0; i < ssfSubjectLimit+3; i++ {
		last, _, _ = e.call("POST", ssfBase+"subjects/add", e.token, body)
	}
	if last != 429 {
		t.Errorf("subject lookups are not rate limited: %d", last)
	}
}

func TestSSFVerification(t *testing.T) {
	e := newSSFEnv(t, true, nil)
	id := e.newStream(e.token)
	if c, _, _ := e.call("POST", ssfBase+"verify", e.token, `{"stream_id":"`+id+`","state":"abc123"}`); c != 204 {
		t.Fatalf("verify: %d", c)
	}
	rows, _ := e.raw.ClaimSSFOutbox(context.Background(), e.now.Add(time.Hour), time.Minute, 10)
	if len(rows) != 1 || rows[0].EventType != ssf.EvVerification {
		t.Fatalf("outbox %+v", rows)
	}
	parts := strings.Split(rows[0].SET, ".")
	if len(parts) != 3 {
		t.Fatal("not a JWS")
	}
	if _, err := keys.New(e.raw, keys.Options{}).Verify(context.Background(), "r", rows[0].SET); err != nil {
		t.Errorf("verification SET does not verify: %v", err)
	}
	if c, o, _ := e.call("POST", ssfBase+"verify", e.token, `{"stream_id":"`+id+`"}`); c != 429 {
		t.Errorf("min_verification_interval not enforced: %d %v", c, o)
	}
	if c, _, _ := e.call("POST", ssfBase+"verify", e.other, `{"stream_id":"`+id+`"}`); c != 404 {
		t.Errorf("foreign stream: %d", c)
	}
	if c, _, _ := e.call("POST", ssfBase+"verify", e.token, `{"stream_id":"`+id+`","state":"`+strings.Repeat("x", 300)+`"}`); c != 400 {
		t.Errorf("long state: %d", c)
	}
}

// End to end: subscribe a subject over the API, end its session, find the SET.
func TestSSFEndToEndSessionRevoked(t *testing.T) {
	e := newSSFEnv(t, true, nil)
	ctx := context.Background()
	id := e.newStream(e.token)
	if c, _, _ := e.call("POST", ssfBase+"subjects/add", e.token, `{"stream_id":"`+id+`","subject":{"format":"opaque","id":"u1"}}`); c != 200 {
		t.Fatal(c)
	}
	for _, sid := range []string{"s1", "s2"} {
		if err := e.raw.PutSession(ctx, core.Session{ID: sid, Realm: "r", UserID: "u1", CookieHash: "ck-" + sid, ExpiresAt: e.now.Add(time.Hour), IdleExpires: e.now.Add(time.Hour), CreatedAt: e.now}); err != nil {
			t.Fatal(err)
		}
	}
	svc := &sessions.Service{Store: e.st}
	if _, err := svc.End(ctx, "r", "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.st.TakeUserSessions(ctx, "r", "u2"); err != nil { // not subscribed
		t.Fatal(err)
	}
	rows, _ := e.raw.ClaimSSFOutbox(ctx, e.now.Add(time.Hour), time.Minute, 10)
	if len(rows) != 1 || rows[0].EventType != ssf.EvSessionRevoked {
		t.Fatalf("outbox %+v", rows)
	}
	if strings.Contains(rows[0].SET, "ck-s1") {
		t.Error("cookie hash in SET")
	}
	// removing the subject stops the events
	e.call("POST", ssfBase+"subjects/remove", e.token, `{"stream_id":"`+id+`","subject":{"format":"opaque","id":"u1"}}`)
	if _, err := svc.End(ctx, "r", "s2"); err != nil {
		t.Fatal(err)
	}
	if c, _ := e.raw.CountSSFOutbox(ctx, "r"); c["pending"] != 1 {
		t.Errorf("event after unsubscribe: %v", c)
	}
}

func TestSSFSignalFromEvent(t *testing.T) {
	e := newSSFEnv(t, true, nil)
	ctx := context.Background()
	id := e.newStream(e.token)
	e.call("POST", ssfBase+"subjects/add", e.token, `{"stream_id":"`+id+`","subject":{"format":"opaque","id":"u1"}}`)
	p := &Provider{cfg: Config{Store: e.st}}
	rl := core.Realm{Name: "r"} // auth events NOT logged: signals do not depend on the audit flag
	for _, typ := range []string{"TOTP_ENROLLED", "TOTP_DISABLED", "PASSKEY_REGISTERED", "PASSKEY_REMOVED", "PASSKEY_CLONE_SUSPECTED", "LOGIN", "MFA_FAILED"} {
		p.signalFromEvent(ctx, rl, typ, "u1")
	}
	p.signalFromEvent(ctx, rl, "TOTP_ENROLLED", "")
	rows, _ := e.raw.ClaimSSFOutbox(ctx, e.now.Add(time.Hour), time.Minute, 20)
	got := map[string]int{}
	for _, r := range rows {
		got[r.EventType]++
	}
	if got[ssf.EvCredentialChange] != 4 || got[ssf.EvCredentialCompromise] != 1 || len(rows) != 5 {
		t.Errorf("%v", got)
	}
}
