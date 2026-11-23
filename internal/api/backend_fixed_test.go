// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp"
)

// A backend fixed by the environment (native IdP) has no admin password to
// change: the handler must say so instead of blaming the caller's password.
func TestChangeAdminPasswordOnFixedBackend(t *testing.T) {
	s := &Server{KC: idp.NewStaticBackend(nil, "http://idp.test", "haven-admin")}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keycloak/admin-password",
		strings.NewReader(`{"currentPassword":"x","newPassword":"long-enough-1"}`))
	rec := httptest.NewRecorder()
	s.ChangeKeycloakAdminPassword(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status %d, want 501; body %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "incorrect") {
		t.Fatalf("must not claim the password is wrong: %s", rec.Body)
	}
}

// secretProvider is a Provider whose CreateClientWithSecret reveals a secret.
type secretProvider struct {
	idp.Provider
	created idp.Client
}

func (p *secretProvider) CreateClientWithSecret(_ context.Context, _ string, c idp.Client) (string, string, error) {
	p.created = c
	return "id-1", "s3cret-once", nil
}

func TestCreateClientRevealsSecretOnceForConfidentialClients(t *testing.T) {
	p := &secretProvider{}
	s := &Server{KC: idp.NewStaticBackend(p, "http://idp.test", "haven-admin")}

	post := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.CreateClient(rec, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)), "acme")
		return rec
	}
	rec := post(`{"clientId":"svc","publicClient":false,"serviceAccountsEnabled":true}`)
	if rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), `"secret":"s3cret-once"`) {
		t.Fatalf("confidential client: %d %s", rec.Code, rec.Body)
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("secret response must be no-store, got %q", rec.Header().Get("Cache-Control"))
	}
}
