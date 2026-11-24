// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"html/template"
	"net/http"
	"regexp"

	"github.com/zyvorai/haven/internal/idp/mail"
)

var devLinkRe = regexp.MustCompile(`https?://[^\s"'<>]+`)

var devMailTmpl = template.Must(template.New("m").Parse(`<!doctype html><meta charset="utf-8">
<title>haven-idp dev mail</title>
<style>body{font-family:system-ui,sans-serif;max-width:46rem;margin:2rem auto;padding:0 1rem}
article{border:1px solid #ccc;border-radius:6px;padding:.75rem 1rem;margin:1rem 0}
h2{font-size:1rem;margin:0}pre{white-space:pre-wrap}</style>
<h1>Dev mailbox</h1>
<p>haven-idp dev sends no real email: messages land here. Memory only, newest first.</p>
{{range .}}<article><h2>{{.Subject}}</h2><p>To: {{.To}}</p>
<pre>{{.Text}}</pre>
{{range .Links}}<p><a href="{{.}}">{{.}}</a></p>{{end}}</article>
{{else}}<p>No messages yet. Try "Forgot your password?" on the sign-in page.</p>{{end}}`))

// devMailHandler renders the dev outbox. It is only mounted by `dev`, which
// listens on loopback.
func devMailHandler(o *mail.Outbox) http.Handler {
	type view struct {
		To, Subject, Text string
		Links             []string
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		var vs []view
		for _, m := range o.Messages() {
			vs = append(vs, view{To: m.To, Subject: m.Subject, Text: m.Text, Links: devLinkRe.FindAllString(m.Text, -1)})
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		_ = devMailTmpl.Execute(w, vs)
	})
}
