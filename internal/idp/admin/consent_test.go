// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

func TestConsentAdminRequiresAuth(t *testing.T) {
	h := newIDHarness(t)
	for _, p := range []string{"/consent-policy", "/consent-grants", "/consent-clients", "/consent-receipts", "/consent-receipts/verify", "/consent-blocks"} {
		for _, tok := range []string{"", "garbage"} {
			if code, _, _ := h.call("GET", h.r+p, tok, nil); code != 401 && code != 403 {
				t.Errorf("GET %s with token %q: %d", p, tok, code)
			}
		}
	}
	for _, p := range []string{"/consent/kill", "/consent/unkill"} {
		if code, _, _ := h.call("POST", h.r+p, "garbage", map[string]any{"clientId": "x"}); code != 401 && code != 403 {
			t.Errorf("POST %s with a bad token: %d", p, code)
		}
	}
	if code, _, _ := h.call("PUT", h.r+"/consent-policy", "", map[string]any{}); code != 401 && code != 403 {
		t.Errorf("PUT policy without a token: %d", code)
	}
	if code, _, _ := h.call("DELETE", h.r+"/consent-grants/x", "", nil); code != 401 && code != 403 {
		t.Errorf("DELETE grant without a token: %d", code)
	}
}

func TestConsentPolicyAPI(t *testing.T) {
	h := newIDHarness(t)
	var p map[string]any
	_ = json.Unmarshal(h.api(200, "GET", h.r+"/consent-policy", nil), &p)
	if p["cimdEnabled"] != false || p["requireAll"] != false || p["grantTtlSeconds"].(float64) != float64(core.ConsentDefaultGrantTTL/time.Second) {
		t.Fatalf("default policy: %v", p)
	}
	h.api(200, "PUT", h.r+"/consent-policy", map[string]any{"cimdEnabled": true, "cimdHosts": []string{"a.example"},
		"requireAll": true, "skipClients": []string{"portal"}, "rememberCimd": true, "grantTtlSeconds": 3600})
	got, err := h.st.GetConsentPolicy(context.Background(), realm)
	if err != nil || !got.CIMDEnabled || !got.RequireAll || !got.RememberCIMD || got.GrantTTLSeconds != 3600 || got.CIMDHosts[0] != "a.example" || got.SkipClients[0] != "portal" {
		t.Fatalf("stored: %+v %v", got, err)
	}
	// PUT replaces: an omitted flag is off again (a typo cannot keep it on).
	h.api(200, "PUT", h.r+"/consent-policy", map[string]any{"requireAll": true})
	got, _ = h.st.GetConsentPolicy(context.Background(), realm)
	if got.CIMDEnabled || got.RememberCIMD || len(got.CIMDHosts) != 0 {
		t.Fatalf("PUT must replace: %+v", got)
	}
	for name, body := range map[string]any{
		"unknown field": map[string]any{"cimdEnabled": true, "x": 1},
		"upper host":    map[string]any{"cimdHosts": []string{"A.example"}},
		"host with url": map[string]any{"cimdHosts": []string{"https://a.example/"}},
		"empty host":    map[string]any{"cimdHosts": []string{""}},
		"negative ttl":  map[string]any{"grantTtlSeconds": -1},
		"huge ttl":      map[string]any{"grantTtlSeconds": 400 * 24 * 3600},
		"empty skip":    map[string]any{"skipClients": []string{""}},
		"too many":      map[string]any{"skipClients": make([]string, 101)},
		"not an object": []int{1},
	} {
		if code, b, _ := h.call("PUT", h.r+"/consent-policy", h.token, body); code != 400 {
			t.Errorf("%s: got %d %s", name, code, b)
		}
	}
	if evs := h.eventsOf("ADMIN_UPDATE"); len(evs) == 0 {
		t.Error("no audit event for the policy change")
	}
}

func TestConsentGrantsReceiptsAndKillAPI(t *testing.T) {
	h := newIDHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	g, err := h.st.PutConsentGrant(ctx, core.ConsentGrant{Realm: realm, UserID: h.uid, ClientID: "https://app.example/c.json", ClientName: "App",
		Scopes: []string{"openid"}, Resources: []string{"https://mcp.example/mcp"}, Fingerprint: "fp", ExpiresAt: now.Add(time.Hour)}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.st.AppendConsentReceipt(ctx, core.ConsentReceipt{Realm: realm, Type: core.ReceiptGrant, UserID: h.uid, ClientID: g.ClientID,
		ClientName: "App", Scopes: g.Scopes, Actor: h.uid}); err != nil {
		t.Fatal(err)
	}
	// A refresh token of that user and client.
	if err := h.st.PutRefreshToken(ctx, core.RefreshToken{TokenHash: "rt1", FamilyID: "f1", Realm: realm, ClientID: g.ClientID, UserID: h.uid,
		Scope: "openid", ExpiresAt: now.Add(time.Hour), CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	var list []map[string]any
	_ = json.Unmarshal(h.api(200, "GET", h.r+"/consent-grants?userId="+h.uid+"&clientId="+url.QueryEscape(g.ClientID), nil), &list)
	if len(list) != 1 || list[0]["id"] != g.ID || list[0]["clientName"] != "App" {
		t.Fatalf("list: %v", list)
	}
	if code, _, _ := h.call("GET", h.r+"/consent-grants?limit=0", h.token, nil); code != 400 {
		t.Errorf("limit=0: %d", code)
	}

	// Admin revokes the grant: tokens die, receipt names the admin.
	h.api(204, "DELETE", h.r+"/consent-grants/"+g.ID, nil)
	if code, _, _ := h.call("DELETE", h.r+"/consent-grants/"+g.ID, h.token, nil); code != 409 {
		t.Errorf("second revoke: %d", code)
	}
	if code, _, _ := h.call("DELETE", h.r+"/consent-grants/nope", h.token, nil); code != 404 {
		t.Errorf("unknown grant: %d", code)
	}
	if rt, _ := h.st.GetRefreshToken(ctx, "rt1"); !rt.Revoked {
		t.Fatal("the admin revoke left the refresh token alive")
	}
	var rcs []map[string]any
	_ = json.Unmarshal(h.api(200, "GET", h.r+"/consent-receipts?userId="+h.uid, nil), &rcs)
	if len(rcs) != 2 || rcs[1]["type"] != "revoke" || !strings.HasPrefix(rcs[1]["actor"].(string), "admin:") {
		t.Fatalf("receipts: %v", rcs)
	}
	var v map[string]any
	_ = json.Unmarshal(h.api(200, "GET", h.r+"/consent-receipts/verify", nil), &v)
	if v["ok"] != true || v["count"].(float64) != 2 || v["headHash"] == "" {
		t.Fatalf("verify: %v", v)
	}
	h.st.TamperConsentReceipt(realm, 1, func(r *core.ConsentReceipt) { r.ClientName = "Other" })
	_ = json.Unmarshal(h.api(200, "GET", h.r+"/consent-receipts/verify", nil), &v)
	if v["ok"] != false {
		t.Fatalf("tampering not detected: %v", v)
	}
	if code, _, _ := h.call("GET", h.r+"/consent-receipts?afterSeq=-1", h.token, nil); code != 400 {
		t.Errorf("afterSeq=-1: %d", code)
	}

	// Kill switch by client id.
	for name, body := range map[string]any{
		"neither":       map[string]any{},
		"both":          map[string]any{"clientId": "x", "agentId": "y"},
		"unknown field": map[string]any{"clientId": "x", "force": true},
		"long reason":   map[string]any{"clientId": "x", "reason": strings.Repeat("r", 300)},
		"unknown agent": map[string]any{"agentId": "nope"},
	} {
		want := 400
		if name == "unknown agent" {
			want = 404
		}
		if code, b, _ := h.call("POST", h.r+"/consent/kill", h.token, body); code != want {
			t.Errorf("kill %s: %d %s", name, code, b)
		}
	}
	var kr core.KillResult
	_ = json.Unmarshal(h.api(200, "POST", h.r+"/consent/kill", map[string]any{"clientId": g.ClientID, "reason": "incident 7"}), &kr)
	if kr.ClientID != g.ClientID || kr.ReceiptSeq == 0 {
		t.Fatalf("kill: %+v", kr)
	}
	var blocks []map[string]any
	_ = json.Unmarshal(h.api(200, "GET", h.r+"/consent-blocks", nil), &blocks)
	if len(blocks) != 1 || blocks[0]["reason"] != "incident 7" || !strings.HasPrefix(blocks[0]["by"].(string), "admin:") {
		t.Fatalf("blocks: %v", blocks)
	}
	h.api(204, "POST", h.r+"/consent/unkill", map[string]any{"clientId": g.ClientID})
	if code, _, _ := h.call("POST", h.r+"/consent/unkill", h.token, map[string]any{"clientId": g.ClientID}); code != 404 {
		t.Errorf("second unkill: %d", code)
	}
}

func TestConsentKillAgentAPI(t *testing.T) {
	h := newIDHarness(t)
	var a struct{ ID, ClientID string }
	if err := json.Unmarshal(h.api(201, "POST", h.r+"/agents", map[string]any{"name": "bot", "ownerUserId": h.uid,
		"scopes": []string{"mcp:read"}, "audiences": []string{"https://mcp.example"}}), &a); err != nil {
		t.Fatal(err)
	}
	var cred struct{ Secret string }
	_ = json.Unmarshal(h.api(201, "POST", h.r+"/agents/"+a.ID+"/credentials", map[string]any{"ttlSeconds": 600}), &cred)
	if code, out := h.agExchange(a.ClientID, cred.Secret, url.Values{"audience": {"https://mcp.example"}}); code != 200 {
		t.Fatalf("agent exchange before kill: %d %v", code, out)
	}
	var kr core.KillResult
	_ = json.Unmarshal(h.api(200, "POST", h.r+"/consent/kill", map[string]any{"agentId": a.ID, "reason": "runaway"}), &kr)
	if !kr.AgentDisabled || kr.CredentialsEnd != 1 || !kr.ClientDisabled {
		t.Fatalf("agent kill: %+v", kr)
	}
	if code, _ := h.agExchange(a.ClientID, cred.Secret, url.Values{"audience": {"https://mcp.example"}}); code == 200 {
		t.Fatal("a killed agent can still exchange its credential")
	}
	var got struct{ Enabled bool }
	_ = json.Unmarshal(h.api(200, "GET", h.r+"/agents/"+a.ID, nil), &got)
	if got.Enabled {
		t.Fatal("agent still enabled")
	}
}
