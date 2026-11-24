// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/admin"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/ssf"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

func ssfEnv(t *testing.T, signals bool) *env {
	t.Helper()
	return newEnvWith(t, func(cfg *admin.Config, st *memstore.Store, base string) {
		if signals {
			cfg.Store = ssf.Wrap(st, &ssf.Transmitter{Builder: ssf.Builder{Signer: keys.New(st, keys.Options{}), BaseURL: base}, Store: st})
		}
	})
}

type recvOut struct {
	ID, Name, Audience string
	AllSubjects        bool
	AllowEmail         bool
	Events             []string
	Disabled           bool
	Token              string
}

func (e *env) newReceiver(body any) recvOut {
	e.t.Helper()
	var out recvOut
	if err := json.Unmarshal(e.api(201, "POST", "/realms/"+realm+"/ssf/receivers", body), &out); err != nil || out.ID == "" {
		e.t.Fatalf("receiver response: %v", err)
	}
	return out
}

func TestSSFAdminReceivers(t *testing.T) {
	e := ssfEnv(t, true)
	p := "/realms/" + realm + "/ssf/receivers"
	r := e.newReceiver(map[string]any{"name": "Okta CAEP", "allSubjects": true, "events": []string{ssf.EvSessionRevoked}})
	if !strings.HasPrefix(r.Token, "hssf_") || r.Audience != "Okta CAEP" || !r.AllSubjects || len(r.Events) != 1 {
		t.Fatalf("%+v", r)
	}
	// the token authenticates (hash stored), but is never listed again
	st, _ := e.st.GetSSFReceiverByTokenHash(context.Background(), ssf.HashToken(r.Token))
	if st.ID != r.ID || st.TokenHash == r.Token {
		t.Fatalf("stored %+v", st)
	}
	body := string(e.api(200, "GET", p, nil))
	if strings.Contains(body, r.Token) || strings.Contains(body, st.TokenHash) || strings.Contains(strings.ToLower(body), "token") {
		t.Errorf("list leaks the token: %s", body)
	}
	// validation and uniqueness
	for name, b := range map[string]any{
		"empty name": map[string]any{"name": ""}, "bad chars": map[string]any{"name": "a/b"}, "unknown field": map[string]any{"name": "x", "foo": 1},
		"bad event": map[string]any{"name": "x", "events": []string{"urn:bogus"}}, "long aud": map[string]any{"name": "x", "audience": strings.Repeat("a", 300)},
	} {
		if code, _, _ := e.call("POST", p, e.token, b); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _, _ := e.call("POST", p, e.token, map[string]any{"name": "okta caep"}); code != 409 {
		t.Errorf("duplicate name: %d", code)
	}
	// Unauthenticated callers are refused.
	if code, _, _ := e.call("GET", p, "", nil); code != 401 {
		t.Errorf("no token: %d", code)
	}

	// rotate: new token, old one dead
	var rot recvOut
	if err := json.Unmarshal(e.api(200, "POST", p+"/"+r.ID+"/rotate-token", nil), &rot); err != nil || rot.Token == "" || rot.Token == r.Token {
		t.Fatalf("rotate %+v %v", rot, err)
	}
	if _, err := e.st.GetSSFReceiverByTokenHash(context.Background(), ssf.HashToken(r.Token)); err == nil {
		t.Error("old token still valid after rotation")
	}
	e.api(204, "PUT", p+"/"+r.ID+"/disabled", map[string]any{"disabled": true})
	got, _ := e.st.GetSSFReceiver(context.Background(), realm, r.ID)
	if !got.Disabled {
		t.Error("not disabled")
	}
	// streams and outbox: list, count, delete cascade
	ctx := context.Background()
	rc2, _ := e.st.GetSSFReceiver(ctx, realm, r.ID)
	s, err := e.st.CreateSSFStream(ctx, core.SSFStream{Realm: realm, ReceiverID: rc2.ID, Status: "enabled", EndpointURL: "https://rx.example/e",
		SealedAuth: "SEALED-SECRET", EventsDelivered: []string{ssf.EvSessionRevoked}, SubjectFormat: "opaque", CreatedAt: time.Now(), UpdatedAt: time.Now()}, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.st.EnqueueSSF(ctx, []core.SSFOutbox{{Realm: realm, StreamID: s.ID, JTI: "j", EventType: "e", SET: "x", NextAttempt: time.Now(), CreatedAt: time.Now()}}); err != nil {
		t.Fatal(err)
	}
	sl := string(e.api(200, "GET", "/realms/"+realm+"/ssf/streams", nil))
	if strings.Contains(sl, "SEALED-SECRET") || !strings.Contains(sl, `"hasAuthorizationHeader":true`) || !strings.Contains(sl, s.ID) {
		t.Errorf("stream list: %s", sl)
	}
	var ob map[string]int
	if err := json.Unmarshal(e.api(200, "GET", "/realms/"+realm+"/ssf/outbox", nil), &ob); err != nil || ob["pending"] != 1 {
		t.Errorf("outbox %v", ob)
	}
	e.api(204, "DELETE", p+"/"+r.ID, nil)
	e.api(404, "DELETE", p+"/"+r.ID, nil)
	if l, _ := e.st.ListSSFStreams(ctx, realm, ""); len(l) != 0 {
		t.Error("streams survived receiver delete")
	}
	if c, _ := e.st.CountSSFOutbox(ctx, realm); len(c) != 0 {
		t.Errorf("outbox survived receiver delete: %v", c)
	}
	e.api(404, "GET", "/realms/nope/ssf/receivers", nil)
}

func TestSSFAdminCredentialCompromise(t *testing.T) {
	e := ssfEnv(t, true)
	ctx := context.Background()
	uid := e.createID("/realms/"+realm+"/users", map[string]any{"username": "carol", "enabled": true})
	r := e.newReceiver(map[string]any{"name": "rx", "allSubjects": true})
	if _, err := e.st.CreateSSFStream(ctx, core.SSFStream{Realm: realm, ReceiverID: r.ID, Status: "enabled", EndpointURL: "https://rx.example/e",
		EventsDelivered: ssf.Delivered(core.SSFReceiver{}, nil), SubjectFormat: "opaque", CreatedAt: time.Now(), UpdatedAt: time.Now()}, 5); err != nil {
		t.Fatal(err)
	}
	p := "/realms/" + realm + "/users/" + uid + "/ssf/credential-compromise"
	e.api(204, "POST", p, map[string]any{"credentialType": "password", "reasonAdmin": "found in breach"})
	rows, _ := e.st.ClaimSSFOutbox(ctx, time.Now().Add(time.Hour), time.Minute, 10)
	if len(rows) != 1 || rows[0].EventType != ssf.EvCredentialCompromise {
		t.Fatalf("outbox %+v", rows)
	}
	for name, b := range map[string]any{"missing type": map[string]any{}, "unknown type": map[string]any{"credentialType": "dna"},
		"long reason": map[string]any{"credentialType": "password", "reasonAdmin": strings.Repeat("x", 300)}} {
		if code, _, _ := e.call("POST", p, e.token, b); code != 400 {
			t.Errorf("%s: %d", name, code)
		}
	}
	e.api(404, "POST", "/realms/"+realm+"/users/ghost/ssf/credential-compromise", map[string]any{"credentialType": "password"})
}

// A password reset through the Admin API (which also ends the user's sessions)
// and disabling a user reach receivers, without the Admin API knowing about shared signals.
func TestSSFAdminActionsSignal(t *testing.T) {
	e := ssfEnv(t, true)
	ctx := context.Background()
	uid := e.createID("/realms/"+realm+"/users", map[string]any{"username": "dave", "enabled": true})
	r := e.newReceiver(map[string]any{"name": "rx", "allSubjects": true})
	if _, err := e.st.CreateSSFStream(ctx, core.SSFStream{Realm: realm, ReceiverID: r.ID, Status: "enabled", EndpointURL: "https://rx.example/e",
		EventsDelivered: ssf.Delivered(core.SSFReceiver{}, nil), SubjectFormat: "opaque", CreatedAt: time.Now(), UpdatedAt: time.Now()}, 5); err != nil {
		t.Fatal(err)
	}
	if err := e.st.PutSession(ctx, core.Session{ID: "sx", Realm: realm, UserID: uid, CookieHash: "h", ExpiresAt: time.Now().Add(time.Hour), IdleExpires: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	e.api(204, "PUT", "/realms/"+realm+"/users/"+uid+"/password", map[string]any{"type": "password", "value": goodPW})
	e.api(204, "PUT", "/realms/"+realm+"/users/"+uid, map[string]any{"username": "dave", "enabled": false})
	rows, _ := e.st.ClaimSSFOutbox(ctx, time.Now().Add(time.Hour), time.Minute, 20)
	got := map[string]int{}
	for _, row := range rows {
		got[row.EventType]++
	}
	if got[ssf.EvCredentialChange] < 1 || got[ssf.EvSessionRevoked] != 1 || got[ssf.EvSessionsRevoked] != 0 || got[ssf.EvAccountDisabled] != 1 {
		t.Errorf("events %v", got)
	}
}

func TestSSFAdminOffWithoutTransmitter(t *testing.T) {
	e := ssfEnv(t, false) // memstore supports SSF, but nothing emits
	uid := e.createID("/realms/"+realm+"/users", map[string]any{"username": "erin", "enabled": true})
	e.api(501, "POST", "/realms/"+realm+"/users/"+uid+"/ssf/credential-compromise", map[string]any{"credentialType": "password"})
}
