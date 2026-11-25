// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp/mail"
)

const (
	brandPath = "/realms/" + realm + "/branding"
	tmplPath  = "/realms/" + realm + "/email-templates"
)

// adminUser creates a user holding the admin role and returns its token.
func adminUser(t *testing.T, e *env, name, email string) string {
	t.Helper()
	r := "/realms/" + realm
	if _, err := e.st.GetClientByClientID(context.Background(), realm, "app"); err != nil {
		e.createID(r+"/roles", map[string]any{"name": "haven-admin"})
		e.createID(r+"/clients", map[string]any{"clientId": "app", "enabled": true, "publicClient": true,
			"standardFlowEnabled": true, "redirectUris": []string{"http://localhost/cb"}})
	}
	body := map[string]any{"username": name, "enabled": true}
	if email != "" {
		body["email"], body["emailVerified"] = email, true
	}
	id := e.createID(r+"/users", body)
	e.api(204, "PUT", r+"/users/"+id+"/password", map[string]any{"type": "password", "value": goodPW})
	e.api(204, "POST", r+"/users/"+id+"/roles", []map[string]string{{"name": "haven-admin"}})
	return e.login("app", name, goodPW)
}

const svgOK = `<svg viewBox="0 0 10 10"><!--c--><circle cx="5" cy="5" r="5" fill="#0a6644"/></svg>`

func TestBrandingRoutes(t *testing.T) {
	e := newEnv(t)
	var got map[string]any
	read := func(b []byte) map[string]any {
		got = map[string]any{}
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("%v: %s", err, b)
		}
		return got
	}
	if g := read(e.api(200, "GET", brandPath, nil)); g["accentColor"] != "" || g["updatedAt"] != nil {
		t.Fatalf("default: %v", g)
	}
	read(e.api(200, "PUT", brandPath, map[string]any{"displayName": "Acme", "accentColor": "#0A6644", "logoLight": svgOK,
		"supportUrl": "https://help.example/", "defaultLocale": "hi"}))
	g := read(e.api(200, "GET", brandPath, nil))
	if g["accentColor"] != "#0a6644" || g["accentColorDark"] != "" || g["defaultLocale"] != "hi" ||
		!strings.HasPrefix(g["effectiveAccentColorDark"].(string), "#") || strings.Contains(g["logoLight"].(string), "<!--") {
		t.Fatalf("stored: %v", g)
	}
	for name, body := range map[string]any{
		"contrast":      map[string]any{"accentColor": "#ffee00"},
		"css injection": map[string]any{"accentColor": "#000000;}"},
		"dark contrast": map[string]any{"accentColor": "#0a6644", "accentColorDark": "#222222"},
		"svg script":    map[string]any{"logoLight": `<svg viewBox="0 0 1 1"><script/></svg>`},
		"http link":     map[string]any{"supportUrl": "http://help.example/"},
		"js link":       map[string]any{"termsUrl": "javascript:alert(1)"},
		"userinfo link": map[string]any{"privacyUrl": "https://a:b@help.example/"},
		"locale":        map[string]any{"defaultLocale": "tlh"},
		"name":          map[string]any{"displayName": "a\u202eb"},
		"unknown field": map[string]any{"css": "body{}"},
		"not json":      "{",
	} {
		if code, b, _ := e.call("PUT", brandPath, e.token, body); code != 400 {
			t.Errorf("%s: %d %s", name, code, b)
		}
	}
	if g := read(e.api(200, "GET", brandPath, nil)); g["displayName"] != "Acme" {
		t.Fatalf("a refused write changed the record: %v", g)
	}
	e.api(404, "PUT", "/realms/nope/branding", map[string]any{})
	e.api(404, "GET", "/realms/nope/branding", nil)
	for _, m := range []string{"GET", "PUT", "DELETE"} {
		if code, _, _ := e.call(m, brandPath, "", map[string]any{}); code != 401 {
			t.Errorf("%s without a token: %d", m, code)
		}
	}
	e.api(204, "DELETE", brandPath, nil)
	if g := read(e.api(200, "GET", brandPath, nil)); g["displayName"] != "" {
		t.Fatalf("not deleted: %v", g)
	}
}

func TestEmailTemplateRoutes(t *testing.T) {
	e, fm := mailEnv(t)
	good := map[string]any{"subject": "Passwort {{realm}}", "text": "Hallo {{username}}\n{{link}}\n",
		"html": `<p><a href="{{link}}">Los</a></p>`}
	p := tmplPath + "/reset_password/de"

	var kinds []struct {
		Kind         string
		Variables    []string
		RequiresLink bool
	}
	if err := json.Unmarshal(e.api(200, "GET", tmplPath+"/kinds", nil), &kinds); err != nil || len(kinds) != 7 {
		t.Fatalf("kinds: %v %v", err, kinds)
	}
	e.api(404, "GET", p, nil)
	e.api(404, "DELETE", p, nil)
	e.api(404, "PUT", tmplPath+"/nope/de", good)
	e.api(404, "PUT", tmplPath+"/reset_password/fr", good)
	for name, body := range map[string]any{
		"foreign link":   map[string]any{"subject": "s", "text": "https://evil.example\n{{link}}"},
		"go template":    map[string]any{"subject": "s", "text": "{{.Link}}\n{{link}}"},
		"secret":         map[string]any{"subject": "s", "text": "{{secret}}\n{{link}}"},
		"script":         map[string]any{"subject": "s", "text": "{{link}}", "html": `<script></script><a href="{{link}}">x</a>`},
		"no link":        map[string]any{"subject": "s", "text": "x"},
		"unknown field":  map[string]any{"subject": "s", "text": "{{link}}", "to": "x@example.com"},
		"missing fields": map[string]any{},
	} {
		if code, b, _ := e.call("PUT", p, e.token, body); code != 400 {
			t.Errorf("%s: %d %s", name, code, b)
		}
	}
	preview := func(path string, body any) map[string]string {
		out := map[string]string{}
		if err := json.Unmarshal(e.api(200, "POST", path+"/preview", body), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if v := preview(p, nil); v["source"] != "builtin" || !strings.Contains(v["subject"], "Passwort") || !strings.Contains(v["text"], "SAMPLE-NOT-A-REAL-LINK") {
		t.Fatalf("builtin preview: %v", v)
	}
	if v := preview(p, good); v["source"] != "draft" || v["subject"] != "Passwort Private Cloud" || !strings.Contains(v["text"], e.srv.URL+"/realms/"+realm+"/login-actions/reset-password?token=SAMPLE") {
		t.Fatalf("draft preview: %v", v)
	}
	e.api(404, "GET", p, nil) // previewing stores nothing
	e.api(400, "POST", p+"/preview", map[string]any{"subject": "s", "text": "https://evil.example {{link}}"})
	e.api(200, "PUT", p, good)
	if v := preview(p, map[string]any{}); v["source"] != "custom" || !strings.HasPrefix(v["text"], "Hallo sample.user\n") {
		t.Fatalf("custom preview: %v", v)
	}
	var list []map[string]any
	if err := json.Unmarshal(e.api(200, "GET", tmplPath, nil), &list); err != nil || len(list) != 1 || list[0]["locale"] != "de" {
		t.Fatalf("list: %v %v", err, list)
	}
	e.api(200, "GET", p, nil)
	for _, path := range []string{p, p + "/preview", p + "/test-send"} {
		if code, _, _ := e.call("POST", path, "", nil); code != 401 {
			t.Errorf("%s without a token: %d", path, code)
		}
	}
	if len(fm.messages()) != 0 {
		t.Fatal("nothing may have been sent yet")
	}
	e.api(204, "DELETE", p, nil)
	e.api(404, "GET", p, nil)
}

func TestEmailTemplateTestSend(t *testing.T) {
	e, fm := mailEnv(t)
	p := tmplPath + "/verify_email/en/test-send"

	// The service account has no address of its own.
	if b := e.api(409, "POST", p, nil); !strings.Contains(string(b), "administrator") {
		t.Errorf("%s", b)
	}
	noMail := adminUser(t, e, "noaddress", "")
	if code, b, _ := e.call("POST", p, noMail, nil); code != 409 {
		t.Errorf("admin without address: %d %s", code, b)
	}
	tok := adminUser(t, e, "boss", "boss@example.org")
	for name, body := range map[string]any{
		"recipient": map[string]any{"subject": "s", "text": "{{link}}", "to": "victim@example.com"},
		"only to":   map[string]any{"to": "victim@example.com"},
		"foreign":   map[string]any{"subject": "s", "text": "https://evil.example {{link}}"},
	} {
		if code, b, _ := e.call("POST", p+"?to=victim@example.com", tok, body); code != 400 {
			t.Errorf("%s: %d %s", name, code, b)
		}
	}
	tests := func() (out []mail.Message) {
		for _, m := range fm.messages() {
			if strings.HasPrefix(m.Subject, "[Test] ") {
				out = append(out, m)
			}
		}
		return out
	}
	if n := tests(); len(n) != 0 {
		t.Fatalf("sent: %+v", n)
	}
	if code, b, _ := e.call("POST", p+"?to=victim@example.com", tok, nil); code != 204 {
		t.Fatalf("send: %d %s", code, b)
	}
	ms := tests()
	if len(ms) != 1 || ms[0].To != "boss@example.org" || !strings.HasPrefix(ms[0].Subject, "[Test] Verify your email address for ") ||
		!strings.Contains(ms[0].Text, "SAMPLE-NOT-A-REAL-LINK") {
		t.Fatalf("sent: %+v", ms)
	}
	// Ten per administrator per hour; the three refused drafts above count too.
	limited := false
	for i := 0; i < 12; i++ {
		code, _, _ := e.call("POST", p, tok, nil)
		if code == 429 {
			limited = true
			break
		}
		if code != 204 {
			t.Fatalf("send %d: %d", i, code)
		}
	}
	if n := len(tests()); !limited || n > 10 {
		t.Fatalf("no rate limit: limited=%v sent=%d", limited, n)
	}
	// Another administrator has a budget of its own, and a delivery failure is
	// not echoed.
	tok2 := adminUser(t, e, "second", "second@example.org")
	fm.mu.Lock()
	fm.fail = errors.New("smtp: password hunter2 rejected")
	fm.mu.Unlock()
	if code, b, _ := e.call("POST", p, tok2, nil); code != 502 || strings.Contains(string(b), "hunter2") {
		t.Errorf("failure: %d %s", code, b)
	}
}

func TestEmailTestSendNeedsMail(t *testing.T) {
	e := newEnv(t)
	tok := adminUser(t, e, "boss", "boss@example.org")
	if code, b, _ := e.call("POST", tmplPath+"/verify_email/en/test-send", tok, nil); code != 409 || !strings.Contains(string(b), "not configured") {
		t.Errorf("%d %s", code, b)
	}
}

func TestBrandingAudit(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	rl, err := e.st.GetRealm(ctx, realm)
	if err != nil {
		t.Fatal(err)
	}
	rl.AdminEventsLogged = true
	if err := e.st.UpdateRealm(ctx, rl); err != nil {
		t.Fatal(err)
	}
	e.api(200, "PUT", brandPath, map[string]any{"displayName": "SecretlyNamed"})
	e.api(200, "PUT", tmplPath+"/password_changed/hi", map[string]any{"subject": "UniqueSubject", "text": "UniqueBody"})
	e.api(204, "DELETE", tmplPath+"/password_changed/hi", nil)
	e.api(204, "DELETE", brandPath, nil)
	evs, err := e.st.ListEvents(ctx, realm, 20)
	if err != nil {
		t.Fatal(err)
	}
	var all []string
	for _, ev := range evs {
		all = append(all, ev.Type+" "+ev.Detail)
	}
	joined := strings.Join(all, "\n")
	for _, want := range []string{"ADMIN_UPDATE branding " + realm, "ADMIN_UPDATE email-template password_changed/hi",
		"ADMIN_DELETE email-template password_changed/hi", "ADMIN_DELETE branding " + realm} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
	for _, leak := range []string{"SecretlyNamed", "UniqueSubject", "UniqueBody"} {
		if strings.Contains(joined, leak) {
			t.Errorf("content in the audit log: %s", leak)
		}
	}
}
