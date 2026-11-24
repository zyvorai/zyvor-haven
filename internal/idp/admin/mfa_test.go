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
	"github.com/zyvorai/haven/internal/idp/secretbox"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

func mfaEnvWithKey(t *testing.T) *env {
	k, _ := secretbox.ParseKey(secretbox.GenerateKey())
	box, _ := secretbox.New(k)
	return newEnvWith(t, func(cfg *admin.Config, _ *memstore.Store, _ string) { cfg.SecretBox = box })
}

// enroll puts a confirmed credential and n recovery codes straight into the store.
func (e *env) enrollMFA(userID string, n int) {
	e.t.Helper()
	ctx := context.Background()
	if err := e.st.PutTOTP(ctx, core.TOTPCredential{Realm: realm, UserID: userID, SealedSeed: "v1.SEALED-SEED-MARKER", CreatedAt: time.Now()}); err != nil {
		e.t.Fatal(err)
	}
	if ok, err := e.st.ConfirmTOTP(ctx, realm, userID, 7); err != nil || !ok {
		e.t.Fatal(err, ok)
	}
	var hs []string
	for i := 0; i < n; i++ {
		hs = append(hs, strings.Repeat("ab", 31)+string(rune('a'+i))+"c")
	}
	if err := e.st.ReplaceRecoveryCodes(ctx, realm, userID, hs); err != nil {
		e.t.Fatal(err)
	}
}

func TestMFAAdminStatusAndReset(t *testing.T) {
	e := mfaEnvWithKey(t)
	r := "/realms/" + realm
	u := e.mkUser("alice")
	other := e.mkUser("bob")

	type st struct {
		TOTPEnrolled           bool `json:"totpEnrolled"`
		TOTPPending            bool `json:"totpPending"`
		RecoveryCodesRemaining int  `json:"recoveryCodesRemaining"`
	}
	get := func(id string) (st, []byte) {
		raw := e.api(200, "GET", r+"/users/"+id+"/mfa", nil)
		var s st
		if err := json.Unmarshal(raw, &s); err != nil {
			t.Fatal(err)
		}
		return s, raw
	}
	if s, _ := get(u); s.TOTPEnrolled || s.RecoveryCodesRemaining != 0 {
		t.Fatalf("fresh user: %+v", s)
	}
	e.enrollMFA(u, 10)
	e.enrollMFA(other, 4)
	s, raw := get(u)
	if !s.TOTPEnrolled || s.RecoveryCodesRemaining != 10 {
		t.Fatalf("enrolled: %+v", s)
	}
	// Status only: never the seed, the hashes or codes.
	if strings.Contains(string(raw), "SEALED") || strings.Contains(string(raw), "seed") || strings.Contains(string(raw), "abab") {
		t.Errorf("status leaks secret material: %s", raw)
	}
	// Pending enrollment is reported as such.
	p := e.mkUser("carol")
	_ = e.st.PutTOTP(context.Background(), core.TOTPCredential{Realm: realm, UserID: p, SealedSeed: "v1.x", CreatedAt: time.Now()})
	if s, _ := get(p); s.TOTPEnrolled || !s.TOTPPending {
		t.Fatalf("pending: %+v", s)
	}
	e.api(404, "GET", r+"/users/nope/mfa", nil)
	e.api(404, "DELETE", r+"/users/nope/mfa", nil)
	e.api(404, "GET", "/realms/nope/users/"+u+"/mfa", nil)

	// Auth required.
	if code, _, _ := e.call("GET", r+"/users/"+u+"/mfa", "", nil); code != 401 {
		t.Errorf("no token: %d", code)
	}
	if code, _, _ := e.call("DELETE", r+"/users/"+u+"/mfa", "", nil); code != 401 {
		t.Errorf("no token on delete: %d", code)
	}

	// Reset ends the user's sessions and nobody else's.
	sess := e.putSession(u, time.Minute, time.Hour, 2*time.Hour, "app")
	keep := e.putSession(other, time.Minute, time.Hour, 2*time.Hour, "app")
	e.api(204, "DELETE", r+"/users/"+u+"/mfa", nil)
	if s, _ := get(u); s.TOTPEnrolled || s.RecoveryCodesRemaining != 0 {
		t.Fatalf("after reset: %+v", s)
	}
	if _, err := e.st.GetSession(context.Background(), realm, sess.ID); err == nil {
		t.Error("the user's SSO session survived the MFA reset")
	}
	if _, err := e.st.GetSession(context.Background(), realm, keep.ID); err != nil {
		t.Error("another user's session was ended")
	}
	if s, _ := get(other); !s.TOTPEnrolled || s.RecoveryCodesRemaining != 4 {
		t.Errorf("another user's MFA touched: %+v", s)
	}
	e.api(204, "DELETE", r+"/users/"+u+"/mfa", nil) // idempotent

	var resets, audits int
	for _, ev := range e.adminEvents() {
		if ev.Type == "TOTP_RESET" && ev.UserID == u {
			resets++
		}
		if ev.Type == "ADMIN_ACTION" && strings.HasPrefix(ev.Detail, "user-mfa ") {
			audits++
		}
		if strings.Contains(ev.Detail, "SEALED") {
			t.Error("seed in an event")
		}
	}
	if resets != 2 || audits != 2 { // the idempotent second DELETE is audited too
		t.Errorf("TOTP_RESET events %d, ADMIN_ACTION events %d, want 2 and 2", resets, audits)
	}
}

func TestMFAAdminPolicy(t *testing.T) {
	e := mfaEnvWithKey(t)
	r := "/realms/" + realm
	var pol struct {
		RequireMFA bool `json:"requireMfa"`
	}
	read := func() bool {
		pol.RequireMFA = true
		if err := json.Unmarshal(e.api(200, "GET", r+"/mfa-policy", nil), &pol); err != nil {
			t.Fatal(err)
		}
		return pol.RequireMFA
	}
	if read() {
		t.Fatal("default policy requires MFA")
	}
	e.api(200, "PUT", r+"/mfa-policy", map[string]any{"requireMfa": true})
	if !read() {
		t.Fatal("policy not stored")
	}
	p, _ := e.st.GetMFAPolicy(context.Background(), realm)
	if !p.RequireMFA {
		t.Fatal("store policy")
	}
	// Validation.
	e.api(400, "PUT", r+"/mfa-policy", map[string]any{})
	e.api(400, "PUT", r+"/mfa-policy", `{"requireMfa":"yes"}`)
	e.api(400, "PUT", r+"/mfa-policy", map[string]any{"requireMfa": true, "extra": 1})
	e.api(404, "PUT", "/realms/nope/mfa-policy", map[string]any{"requireMfa": true})
	if !read() {
		t.Fatal("a rejected PUT changed the policy")
	}
	e.api(200, "PUT", r+"/mfa-policy", map[string]any{"requireMfa": false})
	if read() {
		t.Fatal("policy not cleared")
	}
	if code, _, _ := e.call("PUT", r+"/mfa-policy", "", map[string]any{"requireMfa": true}); code != 401 {
		t.Errorf("unauthenticated PUT: %d", code)
	}
}

func TestMFAAdminWithoutKeyIs409(t *testing.T) {
	e := newEnv(t) // no SecretBox
	r := "/realms/" + realm
	u := e.mkUser("alice")
	for _, c := range [][2]string{
		{"GET", r + "/users/" + u + "/mfa"}, {"DELETE", r + "/users/" + u + "/mfa"},
		{"GET", r + "/mfa-policy"}, {"PUT", r + "/mfa-policy"},
	} {
		var body any
		if c[0] == "PUT" {
			body = map[string]any{"requireMfa": true}
		}
		raw := e.api(409, c[0], c[1], body)
		if !strings.Contains(string(raw), "HAVEN_IDP_SECRET_KEY") {
			t.Errorf("%s %s: 409 without the key hint: %s", c[0], c[1], raw)
		}
	}
	if p, _ := e.st.GetMFAPolicy(context.Background(), realm); p.RequireMFA {
		t.Error("policy written without a key")
	}
}
