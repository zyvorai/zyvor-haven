// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func ecJWKS(t *testing.T, withPrivate bool) map[string]any {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pad := func(b []byte) []byte { return append(make([]byte, 32-len(b)), b...) }
	jwk := map[string]any{"kty": "EC", "crv": "P-256", "kid": "k1", "use": "sig",
		"x": base64.RawURLEncoding.EncodeToString(pad(k.X.Bytes())), "y": base64.RawURLEncoding.EncodeToString(pad(k.Y.Bytes()))}
	if withPrivate {
		jwk["d"] = base64.RawURLEncoding.EncodeToString(pad(k.D.Bytes()))
	}
	return map[string]any{"keys": []any{jwk}}
}

func TestClientFAPIAdmin(t *testing.T) {
	e := newEnv(t)
	base := "/realms/" + realm + "/clients"
	conf := e.createID(base, map[string]any{"clientId": "bank", "enabled": true, "publicClient": false, "standardFlowEnabled": true})
	pub := e.createID(base, map[string]any{"clientId": "spa", "enabled": true, "publicClient": true, "standardFlowEnabled": true})

	var got map[string]any
	if err := json.Unmarshal(e.api(200, "GET", base+"/"+conf+"/fapi", nil), &got); err != nil {
		t.Fatal(err)
	}
	if got["requirePar"] != false || got["requireDpop"] != false || got["requireSignedRequest"] != false || got["jwks"] != nil {
		t.Fatalf("defaults must be everything off: %v", got)
	}
	jwks := ecJWKS(t, false)
	body := map[string]any{"requirePar": true, "requireDpop": true, "requireSignedRequest": true, "jwks": jwks,
		"authorizationDetailTypes": []string{"payment_initiation", "payment_initiation", "account_information"}}
	e.api(200, "PUT", base+"/"+conf+"/fapi", body)
	if err := json.Unmarshal(e.api(200, "GET", base+"/"+conf+"/fapi", nil), &got); err != nil {
		t.Fatal(err)
	}
	if got["requirePar"] != true || got["requireDpop"] != true || len(got["authorizationDetailTypes"].([]any)) != 2 || got["jwks"] == nil {
		t.Fatalf("stored: %v", got)
	}
	// Public clients cannot require PAR / signed requests (the PAR endpoint authenticates the client) but may require DPoP.
	e.api(400, "PUT", base+"/"+pub+"/fapi", map[string]any{"requirePar": true})
	e.api(400, "PUT", base+"/"+pub+"/fapi", map[string]any{"requireSignedRequest": true, "jwks": jwks})
	e.api(200, "PUT", base+"/"+pub+"/fapi", map[string]any{"requireDpop": true})

	bads := map[string]map[string]any{
		"unknown field":               {"bogus": 1},
		"signed request without keys": {"requireSignedRequest": true},
		"private key in jwks":         {"jwks": ecJWKS(t, true)},
		"jwks without keys":           {"jwks": map[string]any{"keys": []any{}}},
		"jwks not an object":          {"jwks": "nope"},
		"bad detail type":             {"authorizationDetailTypes": []string{"has space"}},
		"empty detail type":           {"authorizationDetailTypes": []string{""}},
		"too many detail types": {"authorizationDetailTypes": []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
			"n", "o", "p", "q", "r", "s", "t", "u"}},
	}
	for name, b := range bads {
		t.Run(name, func(t *testing.T) { e.api(400, "PUT", base+"/"+conf+"/fapi", b) })
	}
	// Unknown client, and no token.
	e.api(404, "GET", base+"/nope/fapi", nil)
	e.api(404, "PUT", base+"/nope/fapi", map[string]any{})
	if code, _, _ := e.call("PUT", base+"/"+conf+"/fapi", "", body); code != 401 {
		t.Errorf("unauthenticated PUT: %d", code)
	}
	if code, _, _ := e.call("GET", base+"/"+conf+"/fapi", "", nil); code != 401 {
		t.Errorf("unauthenticated GET: %d", code)
	}
	// Replacing clears what is not sent; the failed PUTs changed nothing before that.
	e.api(200, "PUT", base+"/"+conf+"/fapi", map[string]any{"requireDpop": true})
	cl, _ := e.st.GetClientByClientID(context.Background(), realm, "bank")
	st, _ := e.st.GetClientFAPI(context.Background(), realm, cl.ID)
	if st.RequirePAR || !st.RequireDPoP || st.JWKS != "" || len(st.AuthzDetailTypes) != 0 {
		t.Fatalf("stored: %+v", st)
	}
}

func TestClientFAPIAdminAudit(t *testing.T) {
	e := newEnv(t)
	base := "/realms/" + realm + "/clients"
	conf := e.createID(base, map[string]any{"clientId": "bank", "enabled": true, "publicClient": false, "standardFlowEnabled": true})
	e.api(200, "PUT", base+"/"+conf+"/fapi", map[string]any{"jwks": ecJWKS(t, false), "requireDpop": true})
	evs, err := e.st.ListEvents(context.Background(), realm, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range evs {
		if strings.Contains(ev.Detail, "client-fapi") {
			found = true
			if strings.Contains(ev.Detail, "kty") || strings.Contains(ev.Detail, "keys") {
				t.Errorf("audit detail leaks key material: %q", ev.Detail)
			}
		}
	}
	if !found {
		t.Error("no audit event for the update")
	}
}
