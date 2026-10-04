// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package keycloak

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStatusConnected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/realms/master/protocol/openid-connect/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok", "expires_in": 300})
		case "/admin/realms":
			_ = json.NewEncoder(w).Encode([]Realm{{Realm: "platform", Enabled: true}})
		case "/admin/serverinfo":
			_ = json.NewEncoder(w).Encode(ServerInfo{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := &AdminClient{baseURL: srv.URL, user: "admin", password: "pass", http: srv.Client()}
	st, err := c.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Connected || st.RealmCount != 1 {
		t.Fatalf("unexpected status: %+v", st)
	}
}
