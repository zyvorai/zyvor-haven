// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

func uiAuthPath(extra string) string {
	q := url.Values{"client_id": {"app"}, "redirect_uri": {cb}, "response_type": {"code"}, "state": {"s"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"}}
	return "/realms/r" + oidcPath + "/auth?" + q.Encode() + extra
}

func (e *aenv) page(path, acceptLanguage string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("GET", path, nil)
	if acceptLanguage != "" {
		req.Header.Set("Accept-Language", acceptLanguage)
	}
	return e.do(req)
}

func must200(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	return w.Body.String()
}

func wantAll(t *testing.T, body string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(body, p) {
			t.Errorf("missing %q in:\n%s", p, afterStyle(body))
		}
	}
}

// afterStyle trims the long stylesheet from a failure message.
func afterStyle(body string) string {
	if i := strings.Index(body, "</style>"); i >= 0 {
		return body[i:]
	}
	return body
}

func putBranding(t *testing.T, e *aenv, b core.Branding) {
	t.Helper()
	b.Realm = "r"
	b.UpdatedAt = e.now
	if err := e.st.PutBranding(context.Background(), b); err != nil {
		t.Fatal(err)
	}
}

func TestPageLanguageSelection(t *testing.T) {
	e := newAEnv(t, true)
	body := must200(t, e.page(uiAuthPath(""), ""))
	wantAll(t, body, `<html lang="en">`, "<h1>Sign in to r</h1>", "Forgot your password?")
	if strings.Contains(body, `<footer`) || strings.Contains(body, `<svg class="logo`) {
		t.Error("unbranded page has branding")
	}

	body = must200(t, e.page(uiAuthPath(""), "de-DE,de;q=0.9,en;q=0.5"))
	wantAll(t, body, `<html lang="de">`, "<title>Anmelden</title>", "<h1>Bei r anmelden</h1>", "um mit app fortzufahren",
		"Benutzername oder E-Mail-Adresse", ">Passwort</label>", "Passwort vergessen?")
	if strings.Contains(afterStyle(body), "Sign in") {
		t.Errorf("English left on the German page: %s", afterStyle(body))
	}

	// ui_locales wins, and follows the user to the next page and the post.
	body = must200(t, e.page(uiAuthPath("&ui_locales=fr+hi"), "de"))
	// ("+" is written &#43; inside an attribute.)
	wantAll(t, body, `<html lang="hi">`, "r में साइन इन करें", "forgot-password?ui_locales=fr&#43;hi", "&amp;ui_locales=fr&#43;hi")

	putBranding(t, e, core.Branding{DefaultLocale: "de"})
	wantAll(t, must200(t, e.page(uiAuthPath(""), "")), `<html lang="de">`)
	wantAll(t, must200(t, e.page(uiAuthPath(""), "fr")), `<html lang="de">`)
	wantAll(t, must200(t, e.page(uiAuthPath(""), "hi")), `<html lang="hi">`)

	// Request values never reach the page through the language.
	body = must200(t, e.page(uiAuthPath("&ui_locales=%22%3E%3Cscript%3E"), `hi"><script>`))
	if strings.Contains(body, "<script>") || !strings.Contains(body, `<html lang="de">`) {
		t.Errorf("request value reflected: %s", afterStyle(body))
	}
}

func TestErrorsAreTranslated(t *testing.T) {
	e := newAEnv(t, true)
	w := e.page("/realms/r"+oidcPath+"/auth?client_id=nope", "de")
	if w.Code != 400 || !strings.Contains(w.Body.String(), "Ungültige Anwendung.") || !strings.Contains(w.Body.String(), "<h1>Fehler</h1>") {
		t.Errorf("%d %s", w.Code, afterStyle(w.Body.String()))
	}
	w = e.page(uiAuthPath(""), "de")
	m := csrfRe.FindStringSubmatch(w.Body.String())
	req := httptest.NewRequest("POST", uiAuthPath(""), strings.NewReader(url.Values{"csrf": {m[1]}, "username": {"alice"}, "password": {"wrong"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept-Language", "de")
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}
	wantAll(t, must200(t, e.do(req)), "Benutzername oder Passwort ist falsch")
}

func TestResetFlowInGerman(t *testing.T) {
	e := newAEnv(t, true)
	path := fp + "?ui_locales=de"
	w, csrf, ck := e.form(path)
	wantAll(t, w.Body.String(), "<h1>Passwort zurücksetzen</h1>", `action="https://idp.example/realms/r/login-actions/forgot-password?ui_locales=de"`)
	done := e.post(path, url.Values{"username": {"alice"}, "csrf": {csrf}}, ck)
	e.h.Drain()
	wantAll(t, must200(t, done), "Prüfen Sie Ihr Postfach", "Falls ein passendes Konto existiert")
	ms := e.mail.all()
	if len(ms) != 1 || ms[0].Subject != "Setzen Sie Ihr Passwort für r zurück" || !strings.Contains(ms[0].HTML, `<html lang="de">`) {
		t.Fatalf("mail: %+v", ms)
	}
	// The reset page's form keeps ui_locales; follow its action.
	link := e.lastLink() + "&ui_locales=de"
	reset := func(pw string) *httptest.ResponseRecorder {
		w, csrf, ck := e.form(link)
		wantAll(t, w.Body.String(), `action="https://idp.example/realms/r/login-actions/reset-password?ui_locales=de"`)
		u, err := url.Parse(link)
		if err != nil {
			t.Fatal(err)
		}
		return e.post(u.Path+"?ui_locales=de", url.Values{"token": {u.Query().Get("token")}, "password": {pw},
			"confirm": {pw}, "csrf": {csrf}}, ck)
	}
	wantAll(t, must200(t, reset("short")), "Dieses Passwort ist nicht zulässig: Passwortrichtlinie: length(8) nicht erfüllt")
	wantAll(t, must200(t, reset("long-enough-password")), "Passwort geändert")
	e.h.Drain()
	ms = e.mail.all()
	if last := ms[len(ms)-1]; last.Subject != "Ihr Passwort für r wurde geändert" || !strings.Contains(last.Text, "Link zum Zurücksetzen") {
		t.Fatalf("notice: %+v", last)
	}
}

func TestEmailLanguageFallsBackToRealmDefault(t *testing.T) {
	e := newAEnv(t, true)
	putBranding(t, e, core.Branding{DefaultLocale: "hi", DisplayName: "Acme Cloud"})
	e.forgot("alice") // no Accept-Language
	ms := e.mail.all()
	if len(ms) != 1 || ms[0].Subject != "Acme Cloud के लिए अपना पासवर्ड रीसेट करें" {
		t.Fatalf("mail: %+v", ms)
	}
}

func TestTamperedBrandNameIsNotMailed(t *testing.T) {
	e := newAEnv(t, true)
	putBranding(t, e, core.Branding{DisplayName: "Pay at https://evil.example"})
	e.forgot("alice")
	ms := e.mail.all()
	if len(ms) != 1 || strings.Contains(ms[0].Subject+ms[0].Text+ms[0].HTML, "evil.example") {
		t.Fatalf("mail: %+v", ms)
	}
}

func TestRealmEmailTemplateIsUsedPerLanguage(t *testing.T) {
	e := newAEnv(t, true)
	ctx := context.Background()
	err := e.st.PutEmailTemplate(ctx, core.EmailTemplate{Realm: "r", Kind: "reset_password", Locale: "de",
		Subject: "Eigener Betreff {{realm}}", Text: "Hallo {{username}}\n{{link}}\n", UpdatedAt: e.now})
	if err != nil {
		t.Fatal(err)
	}
	send := func(lang string) {
		_, csrf, ck := e.form(fp)
		req := httptest.NewRequest("POST", fp, strings.NewReader(url.Values{"username": {"alice"}, "csrf": {csrf}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Accept-Language", lang)
		req.AddCookie(ck)
		e.do(req)
		e.h.Drain()
	}
	send("de")
	send("en")
	ms := e.mail.all()
	if len(ms) != 2 || ms[0].Subject != "Eigener Betreff r" || ms[0].HTML != "" || !strings.HasPrefix(ms[0].Text, "Hallo alice\nhttps://idp.example/") {
		t.Fatalf("custom: %+v", ms)
	}
	if ms[1].Subject != "Reset your password for r" {
		t.Fatalf("English must keep the built-in wording: %q", ms[1].Subject)
	}
	// A stored template that breaks the rules (written behind the API's back)
	// is not sent: the built-in wording is.
	err = e.st.PutEmailTemplate(ctx, core.EmailTemplate{Realm: "r", Kind: "reset_password", Locale: "de",
		Subject: "Phish", Text: "https://evil.example/\n{{link}}\n", UpdatedAt: e.now})
	if err != nil {
		t.Fatal(err)
	}
	send("de")
	ms = e.mail.all()
	if last := ms[len(ms)-1]; strings.Contains(last.Text, "evil.example") || last.Subject != "Setzen Sie Ihr Passwort für r zurück" {
		t.Fatalf("hostile stored template used: %+v", last)
	}
}

var cspNonceRE = regexp.MustCompile(`nonce-[A-Za-z0-9_-]+`)

const (
	uiLogo     = `<svg viewBox="0 0 40 10"><rect width="40" height="10" fill="#0a6644"/></svg>`
	uiLogoDark = `<svg viewBox="0 0 40 10"><rect width="40" height="10" fill="#66ddaa"/></svg>`
)

func TestBrandingOnPages(t *testing.T) {
	e := newAEnv(t, true)
	csp := func(w *httptest.ResponseRecorder) string {
		return cspNonceRE.ReplaceAllString(w.Header().Get("Content-Security-Policy"), "nonce-X")
	}
	paths := map[string]string{
		"login": uiAuthPath(""), "forgot": fp, "error": "/realms/r" + oidcPath + "/auth?client_id=nope",
		"logout": "/realms/r" + oidcPath + "/logout", "reset": "/realms/r/login-actions/reset-password?token=x",
		"device": "/realms/r/device",
	}
	plain := map[string]string{}
	for name, path := range paths {
		plain[name] = csp(e.page(path, "de"))
	}
	putBranding(t, e, core.Branding{DisplayName: "Acme & Sons", AccentColor: "#0a6644", AccentColorDark: "#66ddaa",
		LogoLight: uiLogo, LogoDark: uiLogoDark, SupportURL: "https://help.acme.example/?a=1&b=2",
		PrivacyURL: "https://acme.example/privacy", TermsURL: "https://acme.example/terms"})
	for name, path := range paths {
		w := e.page(path, "de")
		body := w.Body.String()
		if n := strings.Count(body, "<style"); n != 1 {
			t.Fatalf("%s: %d style elements", name, n)
		}
		css := body[strings.Index(body, "<style"):strings.Index(body, "</style>")]
		wantAll(t, css, "--accent:#0a6644", "--accent:#66ddaa", "--on-accent:#000000")
		wantAll(t, body, `<svg class="logo logo-light"`, `<svg class="logo logo-dark"`, `aria-label="Acme &amp; Sons"`,
			`<footer class="legal">`, `href="https://help.acme.example/?a=1&amp;b=2" rel="noopener noreferrer">Hilfe</a>`,
			">Datenschutz</a>", ">Nutzungsbedingungen</a>")
		if strings.Contains(body, `<svg class="hero"`) || strings.Contains(body, "style=") {
			t.Errorf("%s: hero still shown or inline style", name)
		}
		// Branding must not need a wider policy.
		if got := csp(w); got == "" || got != plain[name] || strings.Contains(got, "img-src") || strings.Contains(got, "unsafe") {
			t.Errorf("%s: CSP changed by branding:\n%s\n%s", name, plain[name], got)
		}
	}
	wantAll(t, e.page(uiAuthPath(""), "").Body.String(), "<h1>Sign in to Acme &amp; Sons</h1>")
}

// Values that never passed validation (a tampered database) must not reach a
// page: every value is checked again when it is rendered.
func TestHostileStoredBrandingIsNotRendered(t *testing.T) {
	e := newAEnv(t, true)
	putBranding(t, e, core.Branding{
		DisplayName: "x\u202eevil", AccentColor: "#000000}body{display:none}", AccentColorDark: "</style><script>alert(1)</script>",
		LogoLight:  `<svg viewBox="0 0 1 1"><script>alert(2)</script></svg>`,
		SupportURL: "javascript:alert(3)", PrivacyURL: "http://insecure.example/", TermsURL: `https://x.example/"><script>`,
		DefaultLocale: `"><script>`,
	})
	body := must200(t, e.page(uiAuthPath(""), ""))
	for _, bad := range []string{"alert(", "<script>", "}body{", "javascript:", "insecure.example", "x.example", "\u202e", "<footer"} {
		if strings.Contains(body, bad) {
			t.Errorf("%q reached the page", bad)
		}
	}
	wantAll(t, body, `<html lang="en">`, `<svg class="hero"`, "<h1>Sign in to r</h1>")
}

type brokenBranding struct{ core.Store }

func (brokenBranding) GetBranding(context.Context, string) (core.Branding, error) {
	return core.Branding{Realm: "r", AccentColor: "#000000"}, errors.New("database down")
}
func (brokenBranding) PutBranding(context.Context, core.Branding) error { return nil }
func (brokenBranding) DeleteBranding(context.Context, string) error     { return nil }
func (brokenBranding) GetEmailTemplate(context.Context, string, string, string) (core.EmailTemplate, error) {
	return core.EmailTemplate{}, errors.New("database down")
}
func (brokenBranding) ListEmailTemplates(context.Context, string) ([]core.EmailTemplate, error) {
	return nil, nil
}
func (brokenBranding) PutEmailTemplate(context.Context, core.EmailTemplate) error { return nil }
func (brokenBranding) DeleteEmailTemplate(context.Context, string, string, string) error {
	return nil
}

func TestBrandingStoreFailureKeepsPages(t *testing.T) {
	e := newAEnv(t, false)
	h := New(Config{Store: brokenBranding{e.st}, Signer: fakeSigner{now: func() time.Time { return e.now }},
		Hasher: fakeHasher{}, BaseURL: "https://idp.example"})
	req := httptest.NewRequest("GET", uiAuthPath(""), nil)
	req.Header.Set("Accept-Language", "de")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	body := must200(t, w)
	wantAll(t, body, `<html lang="de">`, `<svg class="hero"`)
	if strings.Contains(body, "--accent:#000000") {
		t.Error("partial branding used after an error")
	}
}

func TestDeviceAndAccountPagesTranslated(t *testing.T) {
	e := newAEnv(t, true)
	body := e.page("/realms/r/device", "hi").Body.String()
	wantAll(t, body, `<html lang="hi">`, "डिवाइस जोड़ें", "अपने डिवाइस पर दिखाया गया कोड लिखें।")
	sso := e.ecSession("u1")
	req := httptest.NewRequest("GET", ecPath, nil)
	req.Header.Set("Accept-Language", "de")
	req.AddCookie(sso)
	wantAll(t, must200(t, e.do(req)), `<html lang="de">`, "<h1>E-Mail-Adresse ändern</h1>",
		"Aktuelle Adresse: <strong>alice@example.org</strong>", "Bestätigungslink senden")
}

func TestRightToLeftAndZeroLoc(t *testing.T) {
	var b bytes.Buffer
	if err := pageTmpl.Execute(&b, pageData{Title: "t", Nonce: "n", Login: true, L: Loc{lang: "ar"}}); err != nil {
		t.Fatal(err)
	}
	wantAll(t, b.String(), `<html lang="ar" dir="rtl">`)
	b.Reset()
	if err := pageTmpl.Execute(&b, pageData{Title: "t", Nonce: "n", Login: true}); err != nil {
		t.Fatal(err)
	}
	wantAll(t, b.String(), `<html lang="en">`)
}

// A page that has not opted in is left alone: it needs no Loc and gets no
// branding, so new pages written without it keep working.
func TestPageWithoutOptInIsUnchanged(t *testing.T) {
	src := withTheme("<!doctype html>\n<html lang=\"en\"><head><!--theme--></head><body><main><!--hero:lock--><p>x</p></main></body></html>")
	if strings.Contains(src, ".L") || !strings.Contains(src, "<p>x</p></main>") {
		t.Fatalf("opt-in markup added to a page that did not ask: %s", afterStyle(src))
	}
}

func TestLocHEscapes(t *testing.T) {
	l := Loc{lang: "de"}
	got := string(l.H("%s wants to sign in to %s as %s.", l.B("<img>"), "<script>", l.C(`"q"`)))
	if got != "<strong>&lt;img&gt;</strong> möchte sich bei &lt;script&gt; als <code>&#34;q&#34;</code> anmelden." {
		t.Errorf("%s", got)
	}
	if got := string(l.H("<b>%s</b>", "x")); got != "&lt;b&gt;x&lt;/b&gt;" {
		t.Errorf("format not escaped: %s", got)
	}
}

func TestDiscoveryAdvertisesLocales(t *testing.T) {
	e := newAEnv(t, true)
	w := e.page("/realms/r/.well-known/openid-configuration", "de")
	var doc struct {
		L []string `json:"ui_locales_supported"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil || strings.Join(doc.L, ",") != "en,de,hi" {
		t.Fatalf("%v %v", err, doc.L)
	}
}

func TestKeepUILocalesBounded(t *testing.T) {
	r := httptest.NewRequest("GET", "/x?ui_locales="+strings.Repeat("d", 100), nil)
	w := &uiWriter{ResponseWriter: httptest.NewRecorder(), r: r}
	if got := keepUILocales(w, "/y"); got != "/y" {
		t.Errorf("over-long ui_locales carried: %s", got)
	}
	if got := keepUILocales(http.ResponseWriter(httptest.NewRecorder()), "/y"); got != "/y" {
		t.Errorf("unwrapped writer: %s", got)
	}
}
