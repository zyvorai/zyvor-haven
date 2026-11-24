// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClientBackchannelLogoutURL(t *testing.T) {
	e := newEnv(t)
	base := "/realms/" + realm + "/clients"
	get := func(id string) map[string]any {
		var m map[string]any
		if err := json.Unmarshal(e.api(200, "GET", base+"/"+id, nil), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	body := func(u string) map[string]any {
		m := map[string]any{"clientId": "app", "enabled": true, "publicClient": true,
			"standardFlowEnabled": true, "redirectUris": []string{"https://app.example.com/cb"}}
		if u != "" {
			m["backchannelLogoutUrl"] = u
		}
		return m
	}
	id := e.createID(base, body("https://app.example.com/bc"))
	if got := get(id)["backchannelLogoutUrl"]; got != "https://app.example.com/bc" {
		t.Fatalf("get: %v", got)
	}
	var list []map[string]any
	_ = json.Unmarshal(e.api(200, "GET", base+"?clientId=app", nil), &list)
	if len(list) != 1 || list[0]["backchannelLogoutUrl"] != "https://app.example.com/bc" {
		t.Fatalf("list: %v", list)
	}
	e.api(204, "PUT", base+"/"+id, body("https://app.example.com/bc2"))
	if got := get(id)["backchannelLogoutUrl"]; got != "https://app.example.com/bc2" {
		t.Fatalf("update: %v", got)
	}
	// Client PUT is a full replace (like redirectUris): omitting the key clears it.
	e.api(204, "PUT", base+"/"+id, body(""))
	if _, has := get(id)["backchannelLogoutUrl"]; has {
		t.Fatal("omitted key must clear the url")
	}
	// An explicit empty string clears too.
	e.api(204, "PUT", base+"/"+id, body("https://app.example.com/bc"))
	b := body("")
	b["backchannelLogoutUrl"] = ""
	e.api(204, "PUT", base+"/"+id, b)
	if _, has := get(id)["backchannelLogoutUrl"]; has {
		t.Fatal("empty string must clear the url")
	}

	// Loopback http is allowed (dev).
	e.api(204, "PUT", base+"/"+id, body("http://localhost:3000/bc"))
	e.api(204, "PUT", base+"/"+id, body("http://127.0.0.1:3000/bc"))

	// Rejected on update and create with 400 and a clear message.
	for _, u := range []string{
		"http://app.example.com/bc", "ftp://app.example.com/bc", "https://u:p@app.example.com/bc",
		"https://app.example.com/bc#f", "https:///bc", "/relative", "https://app.example.com/\x01",
		"https://app.example.com/" + strings.Repeat("a", 2100),
	} {
		code, out, _ := e.call("PUT", base+"/"+id, e.token, body(u))
		if code != 400 || !strings.Contains(string(out), "backchannelLogoutUrl") {
			t.Errorf("PUT %.40q: %d %s", u, code, out)
		}
		nb := body(u)
		nb["clientId"] = "other"
		if code, _, _ = e.call("POST", base, e.token, nb); code != 400 {
			t.Errorf("POST %.40q: %d", u, code)
		}
	}
	if got := get(id)["backchannelLogoutUrl"]; got != "http://127.0.0.1:3000/bc" {
		t.Fatalf("rejected writes must not change the stored url: %v", got)
	}
}
