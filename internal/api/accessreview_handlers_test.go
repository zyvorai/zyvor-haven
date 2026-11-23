// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/accessreview"
	"github.com/zyvorai/haven/internal/auth"
	"github.com/zyvorai/haven/internal/identityops"
	"github.com/zyvorai/haven/internal/keycloak"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "haven-api-test")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("HAVEN_DATA_DIR", dir)
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func do(t *testing.T, h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAccessReviewAPI(t *testing.T) {
	sessions := auth.NewStoreFromEnv()
	h := NewRouter(nil, nil, sessions)
	tok := sessions.Issue("alice.reviewer", "admin", "local").Token

	for _, p := range []string{"/api/v1/access-review", "/api/v1/access-review/campaigns", "/api/v1/access-review/campaigns/ar-0000000000000000"} {
		if rec := do(t, h, http.MethodGet, p, "", ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without session: %d", p, rec.Code)
		}
	}
	if rec := do(t, h, http.MethodGet, "/api/v1/access-review", tok, ""); rec.Code != http.StatusBadRequest {
		t.Errorf("missing realm: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/v1/access-review/campaigns/ar-0000000000000000", tok, ""); rec.Code != http.StatusNotFound {
		t.Errorf("unknown campaign: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/api/v1/access-review/campaigns/..%2f..%2fetc", tok, ""); rec.Code != http.StatusNotFound {
		t.Errorf("traversal: %d", rec.Code)
	}

	st := accessReviewStore()
	rep, err := accessreview.Analyze(identityops.RealmSnapshot{Realm: "acme",
		Users:      []keycloak.User{{Username: "u1", Enabled: true}},
		UserAccess: []identityops.UserAccess{{Username: "u1", RealmRoles: []string{"admin"}}}}, accessreview.Options{})
	if err != nil {
		t.Fatal(err)
	}
	c, err := st.Create(rep, "alice.reviewer")
	if err != nil {
		t.Fatal(err)
	}
	base := "/api/v1/access-review/campaigns/" + c.ID

	// reviewer identity comes from the session, a forged field is ignored
	rec := do(t, h, http.MethodPost, base+"/decisions", tok, `{"username":"u1","action":"certify","note":"ok","reviewer":"mallory"}`)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "mallory") || !strings.Contains(rec.Body.String(), "alice.reviewer") {
		t.Fatalf("decision: %d %s", rec.Code, rec.Body)
	}
	for name, body := range map[string]string{
		"bad json": `{`, "bad action": `{"username":"u1","action":"nuke"}`,
		"unknown user": `{"username":"zed","action":"certify"}`,
		"huge note":    `{"username":"u1","action":"certify","note":"` + strings.Repeat("x", 600) + `"}`,
	} {
		if rec := do(t, h, http.MethodPost, base+"/decisions", tok, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
	if rec := do(t, h, http.MethodPost, base+"/decisions", tok, `{"note":"`+strings.Repeat("x", maxRequestBody+10)+`"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("oversized body: %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, base+"/close", tok, ""); rec.Code != http.StatusOK {
		t.Fatalf("close: %d %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, base+"/decisions", tok, `{"username":"u1","action":"revoke","note":"late"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("decision after close: %d", rec.Code)
	}
	rec = do(t, h, http.MethodGet, "/api/v1/access-review/campaigns?realm=acme", tok, "")
	var list []accessreview.Campaign
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 || list[0].Status != accessreview.StatusClosed {
		t.Fatalf("list: %v %s", err, rec.Body)
	}
	if rec := do(t, h, http.MethodPut, base, tok, ""); rec.Code != http.StatusNotFound {
		t.Errorf("method: %d", rec.Code)
	}
}
