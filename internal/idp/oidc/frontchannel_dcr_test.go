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
)

func TestDCRFrontchannelLogoutURI(t *testing.T) {
	e := newLEnv(t, nil)
	ctx := context.Background()
	const iat = "hiat_test"
	rl, err := e.st.GetRealm(ctx, "r")
	must(t, err)
	// A token must be younger than its realm.
	must(t, e.st.PutInitialAccessToken(ctx, core.InitialAccessToken{ID: "i1", Realm: "r", TokenHash: HashSecret(iat),
		Count: 20, Remaining: 20, CreatedAt: rl.CreatedAt.Add(time.Second), ExpiresAt: e.now.Add(time.Hour)}))
	call := func(method, path, token, body string) (int, map[string]any) {
		req := httptest.NewRequest(method, "/realms/r/clients-registrations/openid-connect"+path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		e.h.ServeHTTP(w, req)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	meta := func(fc string) string {
		b := `{"redirect_uris":["https://rp.example/cb"],"token_endpoint_auth_method":"none"`
		if fc != "" {
			b += `,"frontchannel_logout_uri":"` + fc + `"`
		}
		return b + "}"
	}
	for _, bad := range []string{"https://evil.example/fc", "http://rp.example/fc", "https://rp.example/fc#f",
		"https://rp.example:444/fc", "javascript:alert(1)"} {
		code, out := call("POST", "", iat, meta(bad))
		if code != http.StatusBadRequest || out["error"] != "invalid_client_metadata" {
			t.Errorf("%s: %d %v", bad, code, out)
		}
		if strings.Contains(out["error_description"].(string), bad) {
			t.Errorf("%s echoed in the error", bad)
		}
	}
	if cs, _ := e.st.ListClients(ctx, "r"); len(cs) != 1 {
		t.Fatalf("a refused registration left a client: %d", len(cs))
	}
	code, out := call("POST", "", iat, meta("https://rp.example/fc"))
	if code != http.StatusCreated || out["frontchannel_logout_uri"] != "https://rp.example/fc" || out["frontchannel_logout_session_required"] != true {
		t.Fatalf("register: %d %v", code, out)
	}
	id, rat := out["client_id"].(string), out["registration_access_token"].(string)
	cl, err := e.st.GetClientByClientID(ctx, "r", id)
	must(t, err)
	stored := func() string {
		v, err := e.st.FrontchannelLogoutURI(ctx, "r", cl.ID)
		must(t, err)
		return v
	}
	if stored() != "https://rp.example/fc" {
		t.Fatalf("stored %q", stored())
	}
	if code, out := call("GET", "/"+id, rat, ""); code != 200 || out["frontchannel_logout_uri"] != "https://rp.example/fc" {
		t.Fatalf("read: %d %v", code, out)
	}
	if code, _ := call("PUT", "/"+id, rat, meta("https://evil.example/fc")); code != 400 || stored() != "https://rp.example/fc" {
		t.Fatalf("bad update: %d %q", code, stored())
	}
	if code, out := call("PUT", "/"+id, rat, meta("https://rp.example/fc2")); code != 200 || out["frontchannel_logout_uri"] != "https://rp.example/fc2" || stored() != "https://rp.example/fc2" {
		t.Fatalf("update: %d %v", code, out)
	}
	// RFC 7592 replace semantics: absent removes it.
	if code, out := call("PUT", "/"+id, rat, meta("")); code != 200 || out["frontchannel_logout_uri"] != nil || stored() != "" {
		t.Fatalf("removal: %d %v %q", code, out, stored())
	}
}
