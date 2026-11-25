// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package mail

import (
	"fmt"
	"html"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp/i18n"
)

const okText = "Hello {{username}},\n\n{{link}}\n\nBye from {{realm}}.\n"

func good() Custom {
	return Custom{Subject: "Reset for {{realm}}", Text: okText,
		HTML: `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Reset</title></head><body>` +
			`<table role="presentation" width="100%" cellpadding="0"><tr><td align="center" style="color: #333333; font-family: 'Helvetica', serif; padding:8px 0">` +
			`<h1>Hi {{ username }}</h1><p>Valid {{hours}} h.<br/><a href="{{link}}" style="font-weight:600">Choose a password</a></p>` +
			`<p>{{link}}</p></td></tr></table></body></html>`}
}

func TestValidateCustomAccepts(t *testing.T) {
	if err := ValidateCustom(KindResetPassword, good()); err != nil {
		t.Fatal(err)
	}
	hindi := Custom{Subject: "{{realm}}: पासवर्ड", Text: "नमस्ते {{username}}।\n\n{{link}}\n\nक्\u200dष और z. B. 2.5 रुपये।", HTML: ""}
	if err := ValidateCustom(KindResetPassword, hindi); err != nil {
		t.Fatalf("ordinary Hindi text refused: %v", err)
	}
	notice := Custom{Subject: "Changed", Text: "{{username}} {{when}} {{via}} {{realm}}", HTML: "<p>{{when}}</p>"}
	if err := ValidateCustom(KindPasswordChanged, notice); err != nil {
		t.Fatal(err)
	}
}

func TestValidateCustomRefuses(t *testing.T) {
	text := func(s string) func(*Custom) { return func(c *Custom) { c.Text = s + "\n{{link}}\n" } }
	page := func(s string) func(*Custom) {
		return func(c *Custom) { c.HTML = `<p><a href="{{link}}">go</a></p>` + s }
	}
	cases := map[string]func(*Custom){
		// no template execution, no other data
		"go template field":      text("{{.Link}}"),
		"go template call":       text(`{{printf "%s" .}}`),
		"go template range":      text("{{range .}}x{{end}}"),
		"go template define":     text(`{{define "x"}}{{end}}`),
		"unknown variable":       text("{{password}}"),
		"secret-ish variable":    text("{{smtp_password}}"),
		"token variable":         text("{{token}}"),
		"variable of other kind": text("{{client}}"),
		"pipeline":               text("{{username | html}}"),
		"unmatched open":         text("{{username"),
		"unmatched close":        text("username}}"),
		"newline in braces":      text("{{\nusername\n}}"),
		"subject variable":       func(c *Custom) { c.Subject = "{{link}}" },
		"subject newline":        func(c *Custom) { c.Subject = "a\r\nBcc: x" },
		"subject empty":          func(c *Custom) { c.Subject = "  " },
		"subject long":           func(c *Custom) { c.Subject = strings.Repeat("a", 201) },
		"text empty":             func(c *Custom) { c.Text = "" },
		"text without link":      func(c *Custom) { c.Text = "no link here" },
		"html without link":      func(c *Custom) { c.HTML = "<p>no link</p>" },
		"text too big":           text(strings.Repeat("a ", 9000)),
		// links only to our own URLs
		"https url":          text("see https://evil.example/x"),
		"protocol relative":  text("see //evil/x"),
		"bare domain":        text("visit evil.com today"),
		"bare domain path":   text("visit login.evil.co/reset"),
		"www":                text("visit www.evil"),
		"mail address":       text("write to help@evil"),
		"mailto":             text("mailto:x"),
		"tel":                text("tel:+4915112345"),
		"ip address":         text("go to 10.1.2.3 now"),
		"idn":                text("visit пример.рф"),
		"punycode":           text("visit a.xn--p1ai"),
		"ideographic dot":    text("visit evil\u3002com"),
		"fullwidth":          text("visit \uff45\uff56\uff49\uff4c\uff0e\uff43\uff4f\uff4d"),
		"joiner hidden":      text("visit evil\u200d.com"),
		"bidi override":      text("abc \u202e def"),
		"zero width space":   text("evil\u200b com"),
		"completed by value": text("visit evil.{{realm}}"),
		"completes a value":  text("visit {{username}}.com"),
		"link suffix":        func(c *Custom) { c.Text = "{{link}}extra" },
		"link prefix":        func(c *Custom) { c.Text = "x{{link}}" },
		"link glued to var":  func(c *Custom) { c.Text = "{{link}}{{username}}" },
		"subject url":        func(c *Custom) { c.Subject = "go to evil.com" },
		"html href":          page(`<a href="https://evil.example">x</a>`),
		"html href js":       page(`<a href="javascript:alert(1)">x</a>`),
		"html href extended": page(`<a href="{{link}}&next=x">x</a>`),
		"html href prefixed": page(`<a href="https://evil/?u={{link}}">x</a>`),
		"html href other":    page(`<a href="{{username}}">x</a>`),
		"html href unquoted": page(`<a href=evil>x</a>`),
		"html href single":   page(`<a href='evil'>x</a>`),
		"html href upper":    page(`<a HREF="https://evil">x</a>`),
		"html second href":   page(`<a href="{{link}}" href="https://evil">x</a>`),
		"html script":        page(`<script>alert(1)</script>`),
		"html style element": page(`<style>p{}</style>`),
		"html img":           page(`<img src="x">`),
		"html iframe":        page(`<iframe></iframe>`),
		"html form":          page(`<form></form>`),
		"html link element":  page(`<link rel="stylesheet">`),
		"html base":          page(`<base>`),
		"html meta refresh":  page(`<meta http-equiv="refresh" content="0">`),
		"html svg":           page(`<svg></svg>`),
		"html event":         page(`<p onclick="x()">x</p>`),
		"html src":           page(`<p src="x">x</p>`),
		"html background":    page(`<td background="x">x</td>`),
		"html css url":       page(`<p style="background-color: url(x)">x</p>`),
		"html css import":    page(`<p style="color: red; @import x">x</p>`),
		"html css escape":    page(`<p style="color: \75 rl">x</p>`),
		"html css property":  page(`<p style="background-image: none">x</p>`),
		"html css entity":    page(`<p style="color: u&#x72;l">x</p>`),
		"html var in attr":   page(`<p align="{{username}}">x</p>`),
		"html comment":       page(`<!--[if mso]>x<![endif]-->`),
		"html stray lt":      page(`a < b`),
		"html unterminated":  page(`<a href="x"`),
		"html text url":      page(`<p>https://evil.example</p>`),
		"html entity url":    page(`<p>evil&period;com</p>`),
		"html numeric url":   page(`<p>&#x65;vil&#46;com</p>`),
		"html split domain":  page(`<p>evil<span></span>.com</p>`),
		"html split bold":    page(`<p>ev<b>il.c</b>om</p>`),
		"html entity braces": page(`<p>&#123;&#123;x&#125;&#125;</p>`),
		"html entity bidi":   page(`<p>&#x202e;</p>`),
		"html tag in braces": page(`<p>{{<b></b>username}}</p>`),
		"html too big":       page(strings.Repeat("<p>a</p>", 9000)),
	}
	for name, mut := range cases {
		c := good()
		mut(&c)
		if err := ValidateCustom(KindResetPassword, c); err == nil {
			t.Errorf("%s: accepted\n%s\n%s\n%s", name, c.Subject, c.Text, c.HTML)
		}
		if _, err := RenderCustom(KindResetPassword, c, TemplateData{Realm: "R", Link: "https://h/x"}); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
	// A notification can never carry a link.
	for _, k := range []Kind{KindPasswordChanged, KindEmailChanged, KindEmailChangeRequested} {
		if NeedsLink(k) {
			t.Errorf("%s must not take a link", k)
		}
		if err := ValidateCustom(k, Custom{Subject: "s", Text: "{{link}}"}); err == nil {
			t.Errorf("%s: link accepted", k)
		}
	}
	if err := ValidateCustom("nope", good()); err == nil {
		t.Error("unknown kind accepted")
	}
}

func TestRenderCustomEscapesAndSubstitutesOnce(t *testing.T) {
	c := Custom{Subject: "Hi {{username}}", Text: "U={{username}} R={{realm}} H={{hours}}\n{{link}}",
		HTML: `<p>{{username}} {{realm}}</p><a href="{{link}}">go</a>`}
	m, err := RenderCustom(KindResetPassword, c, TemplateData{Username: `{{link}}<script>"'`, Realm: "<img src=x>",
		Link: "https://idp.example/r?token=a&b=c", Hours: 1})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(m.HTML, "<script>") || strings.Contains(m.HTML, "<img") {
		t.Errorf("value not escaped: %s", m.HTML)
	}
	if strings.Count(m.Text, "token=a") != 1 || !strings.Contains(m.Text, "U={{link}}<script>") {
		t.Errorf("a value was expanded again: %s", m.Text)
	}
	if !strings.Contains(m.HTML, `href="https://idp.example/r?token=a&amp;b=c"`) {
		t.Errorf("link: %s", m.HTML)
	}
	if m.To != "" {
		t.Error("To must be left empty")
	}
	for _, d := range []TemplateData{
		{Realm: "R", Link: "javascript:alert(1)"},
		{Realm: "R", Link: ""},
		{Realm: "R\r\nBcc: x", Link: "https://h/x"},
		{Realm: "R", Username: "a\nb", Link: "https://h/x"},
	} {
		if _, err := RenderCustom(KindResetPassword, c, d); err == nil {
			t.Errorf("accepted %+v", d)
		}
	}
}

func TestRenderCustomCIBA(t *testing.T) {
	c := Custom{Subject: "{{client}}", Text: "{{client}} {{binding}} {{scope}} {{resources}} {{minutes}}\n{{link}}"}
	m, err := RenderCustom(KindCIBAApproval, c, TemplateData{Realm: "R", Client: "App", Binding: "line1\nline2",
		Scope: "openid", Resources: []string{"https://a", "https://b"}, Minutes: 5, Link: "https://h/x"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(m.Text, `App "line1\nline2" openid https://a, https://b 5`) {
		t.Errorf("%q", m.Text)
	}
}

func TestRenderEveryKindInEveryLanguage(t *testing.T) {
	d := TemplateData{Realm: "Acme", Username: "alice", Link: "https://idp.example/x?token=t", Hours: 24,
		When: "2026-01-01 12:00:00 UTC", Via: "reset link", NewEmail: "n***@example.com", Client: "App",
		Binding: "b", Scope: "openid", Resources: []string{"https://api"}, Minutes: 3}
	for _, k := range Kinds() {
		en, err := Render(k, d)
		if err != nil {
			t.Fatalf("%s: %v", k, err)
		}
		if strings.Contains(en.HTML, "lang=") {
			t.Errorf("%s: the English message changed shape", k)
		}
		for _, lang := range []string{"de", "hi"} {
			l := d
			l.Lang = lang
			m, err := Render(k, l)
			if err != nil {
				t.Fatalf("%s/%s: %v", k, lang, err)
			}
			if m.Subject == en.Subject || m.Text == en.Text {
				t.Errorf("%s/%s not translated: %q", k, lang, m.Subject)
			}
			if strings.Contains(m.Subject+m.Text+m.HTML, "%!") {
				t.Errorf("%s/%s: format error: %s %s", k, lang, m.Subject, m.Text)
			}
			if m.HTML != "" && !strings.Contains(m.HTML, `<html lang="`+lang+`"><body>`) {
				t.Errorf("%s/%s: no lang attribute: %s", k, lang, m.HTML)
			}
			if NeedsLink(k) != strings.Contains(m.Text, d.Link) {
				t.Errorf("%s/%s: link presence wrong", k, lang)
			}
		}
	}
}

// The three messages that used to be composed elsewhere keep their exact
// English wording.
func TestEnglishWordingUnchanged(t *testing.T) {
	disp, who, link := `A&"co`, "alice", "https://idp.example/c?token=a&x=1"
	m, err := Render(KindChangeEmail, TemplateData{Realm: disp, Username: who, Link: link, Hours: 2})
	if err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprintf("Hello %s, someone asked to use this email address for the %s account.\n\nTo confirm, open this link:\n\n%s\n\nThis link is valid for 2 hours.\n\nIf you did not request this, you can safely ignore this email; nothing changes until the link is opened.\n", who, disp, link)
	body := fmt.Sprintf("<!doctype html>\n<html><body>\n<p>Hello %s, someone asked to use this email address for the %s account.</p>\n<p><a href=\"%s\">Confirm this email address</a></p>\n<p>This link is valid for 2 hours.</p>\n<p>If you did not request this, you can safely ignore this email; nothing changes until the link is opened.</p>\n</body></html>\n",
		html.EscapeString(who), html.EscapeString(disp), html.EscapeString(link))
	if m.Text != text || m.HTML != body || m.Subject != "Confirm your new email address for "+disp {
		t.Errorf("change email:\n%q\n%q\n%q", m.Subject, m.Text, m.HTML)
	}
	for _, done := range []bool{false, true} {
		kind := KindEmailChangeRequested
		subject := "A change of your " + disp + " email address was requested"
		line := "someone asked to change the email address of your " + disp + " account to n***@x.y. Nothing has changed yet; it only takes effect if the link sent to that address is opened."
		if done {
			kind = KindEmailChanged
			subject = "The email address for your " + disp + " account was changed"
			line = "the email address of your " + disp + " account was changed to n***@x.y. This address no longer receives account email."
		}
		when := "2026-01-01 12:00:00 UTC"
		m, err := Render(kind, TemplateData{Realm: disp, Username: who, NewEmail: "n***@x.y", When: when, Link: link})
		if err != nil {
			t.Fatal(err)
		}
		tail := "If this was not you, change your password now and contact your administrator. This email contains no link on purpose."
		text := fmt.Sprintf("Hello %s, %s\n\nWhen: %s\n\n%s\n", who, line, when, tail)
		body := fmt.Sprintf("<!doctype html>\n<html><body>\n<p>Hello %s, %s</p>\n<p>When: %s</p>\n<p>%s</p>\n</body></html>\n",
			html.EscapeString(who), html.EscapeString(line), when, html.EscapeString(tail))
		if m.Text != text || m.HTML != body || m.Subject != subject || strings.Contains(m.Text, "token") {
			t.Errorf("%s:\n%q\n%q\n%q", kind, m.Subject, m.Text, m.HTML)
		}
	}
	m, err = Render(KindCIBAApproval, TemplateData{Realm: "R", Client: "App", Binding: `hi "x"`, Scope: "openid",
		Resources: []string{"https://api"}, Minutes: 2, Link: "https://h/a?req=1"})
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("App is asking for your approval to act on your behalf in R.\n\nMessage from the application (Haven cannot verify it): %q\n\nAccess requested: openid\nResource: https://api\n\nReview and approve or deny it here (you will be asked to sign in):\n\nhttps://h/a?req=1\n\nThis request expires in 2 minute(s). If you were not expecting it, do not approve it; you can open the link and press Deny.\n", `hi "x"`)
	if m.Text != want || m.Subject != "Approval request from App" || m.HTML != "" {
		t.Errorf("ciba:\n%q\n%q", m.Text, want)
	}
}

// The built-in wording would itself pass the rules a realm's template must
// follow once the values are placeholders: the rules do not forbid ordinary
// translated sentences.
func TestTranslationsPassTheAddressCheck(t *testing.T) {
	for _, lang := range []string{"de", "hi"} {
		for _, k := range i18n.Keys(lang) {
			v, _ := i18n.Lookup(lang, k)
			v = strings.NewReplacer("%s", "zz", "%d", "1", "%[1]s", "zz", "%[2]s", "zz", "%[3]s", "zz").Replace(v)
			if err := checkProse(v); err != nil {
				t.Errorf("%s: %q: %v", lang, k, err)
			}
		}
	}
}
