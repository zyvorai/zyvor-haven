// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package native

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp"
)

func TestEvaluateGuard(t *testing.T) {
	var gotPath, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/token") {
			wj(w, 200, map[string]any{"access_token": "t", "expires_in": 3600})
			return
		}
		b, _ := io.ReadAll(r.Body)
		gotPath, gotBody = r.Method+" "+r.URL.Path, string(b)
		wj(w, 200, idp.GuardVerdict{Mode: "enforce", Kind: "client", Blocked: []idp.GuardFinding{{RuleID: "HAVEN002"}}})
	}))
	defer srv.Close()
	c := New(Config{BaseURL: srv.URL, Realm: "p", ClientID: "a", ClientSecret: "b"})
	var ev idp.GuardEvaluator = c
	v, err := ev.EvaluateGuard(ctx(), "my realm", "client", idp.Client{ClientID: "x"})
	if err != nil || v.Mode != "enforce" || len(v.Blocked) != 1 {
		t.Fatalf("%+v %v", v, err)
	}
	if gotPath != "POST /admin/v1/realms/my realm/guard/evaluate" {
		t.Errorf("path %q", gotPath)
	}
	var env struct {
		Kind string
		Body map[string]any
	}
	if json.Unmarshal([]byte(gotBody), &env) != nil || env.Kind != "client" || env.Body["clientId"] != "x" {
		t.Errorf("body %s", gotBody)
	}
}
