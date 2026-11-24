// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package mail

import (
	"bytes"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"net/url"
	texttemplate "text/template"
)

const textTmpl = `{{.Intro}}

{{.Link}}

This link is valid for {{.Hours}} {{.HourWord}}.

If you did not request this, you can safely ignore this email.
`

const htmlTmpl = `<!doctype html>
<html><body>
<p>{{.Intro}}</p>
<p><a href="{{.Link}}">{{.Action}}</a></p>
<p>This link is valid for {{.Hours}} {{.HourWord}}.</p>
<p>If you did not request this, you can safely ignore this email.</p>
</body></html>
`

var (
	tText = texttemplate.Must(texttemplate.New("text").Parse(textTmpl))
	tHTML = htmltemplate.Must(htmltemplate.New("html").Parse(htmlTmpl))
)

type view struct {
	Intro, Action, Link, HourWord string
	Hours                         int
}

// Render builds the subject, text and HTML bodies for kind. To is left empty.
// Link must be an absolute http or https URL.
func Render(kind Kind, d TemplateData) (Message, error) {
	if hasCtl(d.Realm) || hasCtl(d.Username) {
		return Message{}, errors.New("mail: realm or username contains control characters")
	}
	u, err := url.Parse(d.Link)
	if err != nil || hasCtl(d.Link) || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return Message{}, errors.New("mail: link must be an absolute http or https URL")
	}
	if d.Hours < 1 {
		d.Hours = 1
	}
	v := view{Link: u.String(), Hours: d.Hours, HourWord: "hours"}
	if d.Hours == 1 {
		v.HourWord = "hour"
	}
	who := d.Username
	if who == "" {
		who = "there"
	}
	var subject string
	switch kind {
	case KindVerifyEmail:
		subject = "Verify your email address for " + d.Realm
		v.Intro = fmt.Sprintf("Hello %s, please verify your email address for %s by opening this link:", who, d.Realm)
		v.Action = "Verify email address"
	case KindResetPassword:
		subject = "Reset your password for " + d.Realm
		v.Intro = fmt.Sprintf("Hello %s, a password reset was requested for your %s account. Open this link to choose a new password:", who, d.Realm)
		v.Action = "Reset password"
	default:
		return Message{}, fmt.Errorf("mail: unknown template kind %q", kind)
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
