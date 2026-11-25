// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package mail

import (
	"bytes"
	"errors"
	"fmt"
	"html"
	htmltemplate "html/template"
	"net/url"
	"strconv"
	"strings"
	texttemplate "text/template"

	"github.com/zyvorai/haven/internal/idp/i18n"
)

// The built-in wording of every email, in every catalogue language (package
// i18n; the English sentences below are the catalogue keys). A realm may
// replace any of them with its own text (custom.go).

const textTmpl = `{{.Intro}}

{{.Link}}

{{.Validity}}

{{.Ignore}}
`

const htmlTmpl = `<!doctype html>
<html{{if .Lang}} lang="{{.Lang}}"{{end}}{{if .RTL}} dir="rtl"{{end}}><body>
<p>{{.Intro}}</p>
<p><a href="{{.Link}}">{{.Action}}</a></p>
<p>{{.Validity}}</p>
<p>{{.Ignore}}</p>
</body></html>
`

const noticeTextTmpl = `{{.Intro}}
{{if .When}}
{{.When}}{{end}}{{if .Via}}
{{.Via}}{{end}}

{{.Warn}}
{{.NoLink}}
`

const noticeHTMLTmpl = `<!doctype html>
<html{{if .Lang}} lang="{{.Lang}}"{{end}}{{if .RTL}} dir="rtl"{{end}}><body>
<p>{{.Intro}}</p>
{{if .When}}<p>{{.When}}</p>
{{end}}{{if .Via}}<p>{{.Via}}</p>
{{end}}<p>{{.Warn}}</p>
<p>{{.NoLink}}</p>
</body></html>
`

var (
	nText = texttemplate.Must(texttemplate.New("ntext").Parse(noticeTextTmpl))
	nHTML = htmltemplate.Must(htmltemplate.New("nhtml").Parse(noticeHTMLTmpl))
	tText = texttemplate.Must(texttemplate.New("text").Parse(textTmpl))
	tHTML = htmltemplate.Must(htmltemplate.New("html").Parse(htmlTmpl))
)

// page is the language of a message as the templates see it. Lang is empty for
// English, which therefore carries no attribute.
type page struct {
	Lang string
	RTL  bool
}

func pageOf(lang string) page {
	if lang == i18n.Default || !i18n.IsSupported(lang) {
		return page{}
	}
	return page{Lang: lang, RTL: i18n.RTL(lang)}
}

func (p page) openHTML() string {
	s := "<html"
	if p.Lang != "" {
		s += ` lang="` + html.EscapeString(p.Lang) + `"`
	}
	if p.RTL {
		s += ` dir="rtl"`
	}
	return s + "><body>"
}

type view struct {
	page
	Intro, Action, Link, Validity, Ignore string
}

func checkLink(link string) (string, error) {
	u, err := url.Parse(link)
	if err != nil || hasCtl(link) || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", errors.New("mail: link must be an absolute http or https URL")
	}
	return u.String(), nil
}

// Render builds the subject, text and HTML bodies for kind in d.Lang. To is
// left empty. Link, where the kind carries one, must be an absolute http or
// https URL.
func Render(kind Kind, d TemplateData) (Message, error) {
	if hasCtl(d.Realm) || hasCtl(d.Username) {
		return Message{}, errors.New("mail: realm or username contains control characters")
	}
	t := func(key string, args ...any) string { return i18n.T(d.Lang, key, args...) }
	switch kind {
	case KindPasswordChanged:
		return renderNotice(d)
	case KindEmailChangeRequested, KindEmailChanged:
		return renderEmailNotice(kind, d)
	case KindVerifyEmail, KindResetPassword, KindChangeEmail, KindCIBAApproval:
	default:
		return Message{}, fmt.Errorf("mail: unknown template kind %q", kind)
	}
	link, err := checkLink(d.Link)
	if err != nil {
		return Message{}, err
	}
	switch kind {
	case KindChangeEmail:
		return renderChangeEmail(d, link), nil
	case KindCIBAApproval:
		return renderCIBA(d, link), nil
	}
	if d.Hours < 1 {
		d.Hours = 1
	}
	v := view{page: pageOf(d.Lang), Link: link, Ignore: t("If you did not request this, you can safely ignore this email.")}
	if d.Hours == 1 {
		v.Validity = t("This link is valid for 1 hour.")
	} else {
		v.Validity = t("This link is valid for %d hours.", d.Hours)
	}
	who := d.Username
	if who == "" {
		who = t("there")
	}
	var subject string
	if kind == KindVerifyEmail {
		subject = t("Verify your email address for %s", d.Realm)
		v.Intro = t("Hello %s, please verify your email address for %s by opening this link:", who, d.Realm)
		v.Action = t("Verify email address")
	} else {
		subject = t("Reset your password for %s", d.Realm)
		v.Intro = t("Hello %s, a password reset was requested for your %s account. Open this link to choose a new password:", who, d.Realm)
		v.Action = t("Reset password")
	}
	var tb, hb bytes.Buffer
	if err := tText.Execute(&tb, v); err != nil {
		return Message{}, err
	}
	if err := tHTML.Execute(&hb, v); err != nil {
		return Message{}, err
	}
	return Message{Subject: subject, Text: tb.String(), HTML: hb.String()}, nil
}

// renderNotice builds the password-changed notification. It deliberately
// ignores Link: a notification must never carry a live credential.
func renderNotice(d TemplateData) (Message, error) {
	if hasCtl(d.When) || hasCtl(d.Via) {
		return Message{}, errors.New("mail: when or via contains control characters")
	}
	t := func(key string, args ...any) string { return i18n.T(d.Lang, key, args...) }
	who := d.Username
	if who == "" {
		who = t("there")
	}
	nv := struct {
		page
		Intro, When, Via, Warn, NoLink string
	}{page: pageOf(d.Lang), Intro: t("Hello %s, the password for your %s account was changed.", who, d.Realm),
		Warn:   t("If this was not you, contact your administrator or reset your password now."),
		NoLink: t("This email contains no link on purpose.")}
	if d.When != "" {
		nv.When = t("When: %s", d.When)
	}
	if d.Via != "" {
		nv.Via = t("How: %s", t(d.Via))
	}
	var tb, hb bytes.Buffer
	if err := nText.Execute(&tb, nv); err != nil {
		return Message{}, err
	}
	if err := nHTML.Execute(&hb, nv); err != nil {
		return Message{}, err
	}
	return Message{Subject: t("Your password for %s was changed", d.Realm), Text: tb.String(), HTML: hb.String()}, nil
}

// renderChangeEmail builds the confirmation link sent to the NEW address.
func renderChangeEmail(d TemplateData, link string) Message {
	t := func(key string, args ...any) string { return i18n.T(d.Lang, key, args...) }
	intro := t("Hello %s, someone asked to use this email address for the %s account.", d.Username, d.Realm)
	valid := t("This link is valid for 2 hours.")
	ignore := t("If you did not request this, you can safely ignore this email; nothing changes until the link is opened.")
	text := intro + "\n\n" + t("To confirm, open this link:") + "\n\n" + link + "\n\n" + valid + "\n\n" + ignore + "\n"
	body := "<!doctype html>\n" + pageOf(d.Lang).openHTML() + "\n<p>" + html.EscapeString(intro) + "</p>\n<p><a href=\"" +
		html.EscapeString(link) + "\">" + html.EscapeString(t("Confirm this email address")) + "</a></p>\n<p>" +
		html.EscapeString(valid) + "</p>\n<p>" + html.EscapeString(ignore) + "</p>\n</body></html>\n"
	return Message{Subject: t("Confirm your new email address for %s", d.Realm), Text: text, HTML: body}
}

// renderEmailNotice tells the OLD address about a requested or applied change.
// d.NewEmail is already masked. It never carries a link.
func renderEmailNotice(kind Kind, d TemplateData) (Message, error) {
	if hasCtl(d.When) || hasCtl(d.NewEmail) {
		return Message{}, errors.New("mail: when or new address contains control characters")
	}
	t := func(key string, args ...any) string { return i18n.T(d.Lang, key, args...) }
	var subject, line string
	if kind == KindEmailChanged {
		subject = t("The email address for your %s account was changed", d.Realm)
		line = t("the email address of your %s account was changed to %s. This address no longer receives account email.", d.Realm, d.NewEmail)
	} else {
		subject = t("A change of your %s email address was requested", d.Realm)
		line = t("someone asked to change the email address of your %s account to %s. Nothing has changed yet; it only takes effect if the link sent to that address is opened.", d.Realm, d.NewEmail)
	}
	greet := t("Hello %s, %s", d.Username, line)
	when := t("When: %s", d.When)
	tail := t("If this was not you, change your password now and contact your administrator. This email contains no link on purpose.")
	text := greet + "\n\n" + when + "\n\n" + tail + "\n"
	body := "<!doctype html>\n" + pageOf(d.Lang).openHTML() + "\n<p>" + html.EscapeString(greet) + "</p>\n<p>" +
		html.EscapeString(when) + "</p>\n<p>" + html.EscapeString(tail) + "</p>\n</body></html>\n"
	return Message{Subject: subject, Text: text, HTML: body}, nil
}

// quoted is how the CIBA binding message (text chosen by the client) is shown:
// quoted, with control characters escaped.
func quoted(s string) string {
	if s == "" {
		return ""
	}
	return strconv.Quote(s)
}

// renderCIBA builds the approval request of a decoupled (CIBA) sign-in. Plain
// text only.
func renderCIBA(d TemplateData, link string) Message {
	t := func(key string, args ...any) string { return i18n.T(d.Lang, key, args...) }
	var b strings.Builder
	b.WriteString(t("%s is asking for your approval to act on your behalf in %s.", d.Client, d.Realm) + "\n\n")
	if d.Binding != "" {
		b.WriteString(t("Message from the application (Haven cannot verify it): %s", quoted(d.Binding)) + "\n\n")
	}
	b.WriteString(t("Access requested: %s", d.Scope) + "\n")
	for _, res := range d.Resources {
		b.WriteString(t("Resource: %s", res) + "\n")
	}
	b.WriteString("\n" + t("Review and approve or deny it here (you will be asked to sign in):") + "\n\n" + link + "\n\n")
	b.WriteString(t("This request expires in %d minute(s). If you were not expecting it, do not approve it; you can open the link and press Deny.", max(1, d.Minutes)) + "\n")
	return Message{Subject: t("Approval request from %s", d.Client), Text: b.String()}
}
