// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"html"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/i18n"
)

// germanPage checks that every text is shown in German and not in English.
func germanPage(t *testing.T, name string, w *httptest.ResponseRecorder, keys ...string) {
	t.Helper()
	body := html.UnescapeString(w.Body.String())
	if !strings.Contains(body, `<html lang="de"`) {
		t.Errorf("%s: page language not German", name)
	}
	for _, k := range keys {
		de, ok := i18n.Lookup("de", k)
		if !ok || !strings.Contains(body, de) || strings.Contains(body, ">"+k+"<") {
			t.Errorf("%s: %q not shown in German", name, k)
		}
	}
}

func TestPasskeyAndSessionPagesAreTranslated(t *testing.T) {
	e := newSC(t, core.SessionPolicy{}, nil, nil)
	a := e.register(-7)
	e.reset()
	e.policy(core.SessionPolicy{RememberMe: true, MaxSessions: 1, OnLimit: core.SessionLimitDenyNew})
	e.passkeyOnly(true)
	de := authPath + authQuery(map[string]string{"ui_locales": "de"}).Encode()

	e.browser()
	germanPage(t, "login", e.do("GET", de, nil), "Keep me signed in", passkeyOnlyNote, "Sign in with a passkey")

	login := func() *httptest.ResponseRecorder {
		e.browser()
		pg := parsePKPage(t, e.do("GET", de, nil))
		return e.do("POST", de, assertionForm(pg, "login", a, pkOrigin))
	}
	if !isCode(login()) {
		t.Fatal("passkey sign-in")
	}
	mine := e.cookies
	germanPage(t, "too many sessions", login(), "Too many sessions")

	// A stale account page, with and without the password option.
	e.cookies = mine
	e.now = e.now.Add(11 * time.Minute)
	account := e.accountPath() + "?ui_locales=de"
	germanPage(t, "re-auth, passkey only", e.do("GET", account, nil), "Confirm with your passkey", "Confirm with a passkey",
		"Your sign-in is older than 10 minutes. Confirm with a passkey to add or remove passkeys.")
	e.passkeyOnly(false)
	w := e.do("GET", account, nil)
	germanPage(t, "re-auth, both", w, "Confirm your password", "Confirm with a passkey",
		"Your sign-in is older than 10 minutes. Confirm your password, or use a passkey, to add or remove passkeys.")
	csrf := csrfRe.FindStringSubmatch(w.Body.String())[1]
	germanPage(t, "re-auth failed", e.do("POST", account, url.Values{"csrf": {csrf}, "pk_action": {"reauth_passkey"}}),
		"That passkey could not confirm it is you. Try again.")

	// The front-channel sign-out page.
	fc := newFCEnv(t)
	_, ck := fc.session("s1", "u1", "one")
	csrf, cc := fc.confirm(nil, ck)
	out := fc.do("POST", url.Values{"ui_locales": {"de"}}, url.Values{"csrf": {csrf}, "client_id": {"app"},
		"post_logout_redirect_uri": {cb}}, ck, cc)
	germanPage(t, "front-channel sign-out", out, "Signed out", "Continue to the application",
		"You have been signed out. Your applications are being told to sign you out too.")
	if len(frames(out)) != 1 || !strings.Contains(out.Body.String(), `title="`+mustDE(t, "Application sign-out")+`"`) {
		t.Errorf("frames on the German page: %v", frames(out))
	}
	// The refusal at the end of a login that used no passkey.
	rl, err := e.st.GetRealm(context.Background(), "r")
	must(t, err)
	cl, err := e.st.GetClientByClientID(context.Background(), "r", "app")
	must(t, err)
	u, err := e.st.GetUser(context.Background(), "r", "u1")
	must(t, err)
	e.passkeyOnly(true)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", de, nil)
	req.SetPathValue("realm", "r")
	e.h.completeLogin(&uiWriter{ResponseWriter: rec, r: req}, req, &authzReq{realm: rl, client: cl, redirect: cb, state: "s"}, u, "totp")
	germanPage(t, "use your passkey", rec, "Use your passkey",
		"This account signs in with a passkey. Start again from the application and choose Sign in with a passkey.")
}

func mustDE(t *testing.T, key string) string {
	t.Helper()
	v, ok := i18n.Lookup("de", key)
	if !ok {
		t.Fatalf("no German %q", key)
	}
	return v
}
