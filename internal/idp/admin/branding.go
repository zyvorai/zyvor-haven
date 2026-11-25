// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/branding"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/i18n"
	"github.com/zyvorai/haven/internal/idp/mail"
)

// Per-realm branding and email templates (see SPEC.md "Branding and email
// templates" and docs/branding-and-i18n.md).

const (
	testSendMax    = 10 // test emails per administrator per window
	testSendWindow = time.Hour
)

func init() {
	registerRoutes(func(a *api, m *http.ServeMux) {
		p := pathPrefix + "/realms/{r}"
		m.HandleFunc("GET "+p+"/branding", a.getBranding)
		m.HandleFunc("PUT "+p+"/branding", a.op("branding", "update", a.putBranding))
		m.HandleFunc("DELETE "+p+"/branding", a.op("branding", "delete", a.deleteBranding))
		t := p + "/email-templates"
		m.HandleFunc("GET "+t, a.listEmailTemplates)
		m.HandleFunc("GET "+t+"/kinds", a.listEmailKinds)
		m.HandleFunc("GET "+t+"/{kind}/{locale}", a.getEmailTemplate)
		m.HandleFunc("PUT "+t+"/{kind}/{locale}", a.op("email-template", "update", a.putEmailTemplate))
		m.HandleFunc("DELETE "+t+"/{kind}/{locale}", a.op("email-template", "delete", a.deleteEmailTemplate))
		m.HandleFunc("POST "+t+"/{kind}/{locale}/preview", a.previewEmailTemplate)
		m.HandleFunc("POST "+t+"/{kind}/{locale}/test-send", a.op("email-template", "action", a.testSendEmailTemplate))
	})
}

// brandingStore resolves the realm and the optional store.
func (a *api) brandingStore(w http.ResponseWriter, r *http.Request) (core.Realm, core.BrandingStore, bool) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return rl, nil, false
	}
	st, ok := core.StoreAs[core.BrandingStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "branding is not supported by this store")
		return rl, nil, false
	}
	return rl, st, true
}

type brandingFields struct {
	DisplayName     string `json:"displayName"`
	AccentColor     string `json:"accentColor"`
	AccentColorDark string `json:"accentColorDark"`
	LogoLight       string `json:"logoLight"`
	LogoDark        string `json:"logoDark"`
	SupportURL      string `json:"supportUrl"`
	PrivacyURL      string `json:"privacyUrl"`
	TermsURL        string `json:"termsUrl"`
	DefaultLocale   string `json:"defaultLocale"`
}

type brandingJSON struct {
	brandingFields
	// EffectiveAccentColorDark is the colour dark mode uses (read only).
	EffectiveAccentColorDark string     `json:"effectiveAccentColorDark"`
	SupportedLocales         []string   `json:"supportedLocales"`
	UpdatedAt                *time.Time `json:"updatedAt,omitempty"`
}

func brandingWire(b core.Branding) brandingJSON {
	out := brandingJSON{brandingFields: brandingFields{DisplayName: b.DisplayName, AccentColor: b.AccentColor,
		AccentColorDark: b.AccentColorDark, LogoLight: b.LogoLight, LogoDark: b.LogoDark, SupportURL: b.SupportURL,
		PrivacyURL: b.PrivacyURL, TermsURL: b.TermsURL, DefaultLocale: b.DefaultLocale},
		EffectiveAccentColorDark: branding.DarkAccent(b.AccentColor, b.AccentColorDark), SupportedLocales: i18n.Supported()}
	if !b.UpdatedAt.IsZero() {
		t := b.UpdatedAt
		out.UpdatedAt = &t
	}
	return out
}

func (a *api) getBranding(w http.ResponseWriter, r *http.Request) {
	rl, st, ok := a.brandingStore(w, r)
	if !ok {
		return
	}
	b, err := st.GetBranding(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, brandingWire(b))
}

// putBranding replaces the realm's branding; omitted fields are unset.
func (a *api) putBranding(w http.ResponseWriter, r *http.Request) {
	rl, st, ok := a.brandingStore(w, r)
	if !ok {
		return
	}
	var in brandingFields
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	b, err := branding.Normalize(core.Branding{Realm: rl.Name, DisplayName: in.DisplayName, AccentColor: in.AccentColor,
		AccentColorDark: in.AccentColorDark, LogoLight: in.LogoLight, LogoDark: in.LogoDark, SupportURL: in.SupportURL,
		PrivacyURL: in.PrivacyURL, TermsURL: in.TermsURL, DefaultLocale: in.DefaultLocale})
	if err != nil {
		a.fail(w, r, bad(err.Error()))
		return
	}
	b.UpdatedAt = a.cfg.Clock().UTC().Truncate(time.Microsecond)
	if err := st.PutBranding(r.Context(), b); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "branding", rl.Name)
	writeJSON(w, http.StatusOK, brandingWire(b))
}

func (a *api) deleteBranding(w http.ResponseWriter, r *http.Request) {
	rl, st, ok := a.brandingStore(w, r)
	if !ok {
		return
	}
	if err := st.DeleteBranding(r.Context(), rl.Name); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "DELETE", "branding", rl.Name)
	noContent(w)
}

type emailTemplateFields struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
	HTML    string `json:"html"`
}

type emailTemplateJSON struct {
	Kind   string `json:"kind"`
	Locale string `json:"locale"`
	emailTemplateFields
	UpdatedAt time.Time `json:"updatedAt"`
}

func templateWire(t core.EmailTemplate) emailTemplateJSON {
	return emailTemplateJSON{Kind: t.Kind, Locale: t.Locale, UpdatedAt: t.UpdatedAt,
		emailTemplateFields: emailTemplateFields{Subject: t.Subject, Text: t.Text, HTML: t.HTML}}
}

func (a *api) listEmailTemplates(w http.ResponseWriter, r *http.Request) {
	rl, st, ok := a.brandingStore(w, r)
	if !ok {
		return
	}
	ts, err := st.ListEmailTemplates(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]emailTemplateJSON, 0, len(ts))
	for _, t := range ts {
		out = append(out, templateWire(t))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) listEmailKinds(w http.ResponseWriter, r *http.Request) {
	if _, _, ok := a.brandingStore(w, r); !ok {
		return
	}
	type kind struct {
		Kind         string   `json:"kind"`
		Variables    []string `json:"variables"`
		RequiresLink bool     `json:"requiresLink"`
		Locales      []string `json:"locales"`
	}
	var out []kind
	for _, k := range mail.Kinds() {
		out = append(out, kind{string(k), mail.Variables(k), mail.NeedsLink(k), i18n.Supported()})
	}
	writeJSON(w, http.StatusOK, out)
}

// templateTarget validates the {kind}/{locale} part of the path.
func (a *api) templateTarget(w http.ResponseWriter, r *http.Request) (core.Realm, core.BrandingStore, mail.Kind, string, bool) {
	rl, st, ok := a.brandingStore(w, r)
	if !ok {
		return rl, nil, "", "", false
	}
	kind, locale := mail.Kind(r.PathValue("kind")), r.PathValue("locale")
	if mail.Variables(kind) == nil || !i18n.IsSupported(locale) {
		writeErr(w, http.StatusNotFound, "unknown email kind or locale")
		return rl, nil, "", "", false
	}
	return rl, st, kind, locale, true
}

func (a *api) getEmailTemplate(w http.ResponseWriter, r *http.Request) {
	rl, st, kind, locale, ok := a.templateTarget(w, r)
	if !ok {
		return
	}
	t, err := st.GetEmailTemplate(r.Context(), rl.Name, string(kind), locale)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, templateWire(t))
}

func (a *api) putEmailTemplate(w http.ResponseWriter, r *http.Request) {
	rl, st, kind, locale, ok := a.templateTarget(w, r)
	if !ok {
		return
	}
	var in emailTemplateFields
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if err := mail.ValidateCustom(kind, mail.Custom(in)); err != nil {
		a.fail(w, r, bad(err.Error()))
		return
	}
	t := core.EmailTemplate{Realm: rl.Name, Kind: string(kind), Locale: locale, Subject: in.Subject, Text: in.Text,
		HTML: in.HTML, UpdatedAt: a.cfg.Clock().UTC().Truncate(time.Microsecond)}
	if err := st.PutEmailTemplate(r.Context(), t); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "email-template", string(kind)+"/"+locale)
	writeJSON(w, http.StatusOK, templateWire(t))
}

func (a *api) deleteEmailTemplate(w http.ResponseWriter, r *http.Request) {
	rl, st, kind, locale, ok := a.templateTarget(w, r)
	if !ok {
		return
	}
	if err := st.DeleteEmailTemplate(r.Context(), rl.Name, string(kind), locale); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "DELETE", "email-template", string(kind)+"/"+locale)
	noContent(w)
}

// sample is the made-up data previews and test emails are filled with. The
// link has this server's address and a token that is not one.
func (a *api) sample(r *http.Request, st core.BrandingStore, rl core.Realm, kind mail.Kind, locale string) (mail.TemplateData, error) {
	b, err := st.GetBranding(r.Context(), rl.Name)
	if err != nil {
		return mail.TemplateData{}, err
	}
	name := b.DisplayName
	if name == "" {
		name = rl.DisplayName
	}
	if name == "" {
		name = rl.Name
	}
	path, hours := "login-actions/reset-password?token", 1
	switch kind {
	case mail.KindVerifyEmail:
		path, hours = "login-actions/verify-email?token", 24
	case mail.KindChangeEmail:
		path, hours = "login-actions/confirm-email-change?token", 2
	case mail.KindCIBAApproval:
		path = "ciba/approve?req"
	}
	return mail.TemplateData{Realm: name, Username: "sample.user", Lang: locale, Hours: hours,
		Link: a.base + "/realms/" + url.PathEscape(rl.Name) + "/" + path + "=SAMPLE-NOT-A-REAL-LINK",
		When: a.cfg.Clock().UTC().Format("2006-01-02 15:04:05 UTC"), Via: "reset link", NewEmail: "s***@example.com",
		Client: "Sample application", Binding: "Sample message", Scope: "openid profile",
		Resources: []string{"https://api.example.com"}, Minutes: 10}, nil
}

// renderSample renders a preview: the draft in the request body when there is
// one, else the stored template, else the built-in wording. It writes the
// error response itself.
func (a *api) renderSample(w http.ResponseWriter, r *http.Request, rl core.Realm, st core.BrandingStore, kind mail.Kind, locale string) (mail.Message, string, bool) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		a.fail(w, r, err)
		return mail.Message{}, "", false
	}
	var draft *mail.Custom
	if t := strings.TrimSpace(string(raw)); t != "" && t != "{}" {
		var in emailTemplateFields
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil || dec.More() {
			a.fail(w, r, bad("invalid JSON body"))
			return mail.Message{}, "", false
		}
		c := mail.Custom(in)
		if err := mail.ValidateCustom(kind, c); err != nil {
			a.fail(w, r, bad(err.Error()))
			return mail.Message{}, "", false
		}
		draft = &c
	}
	source := "draft"
	if draft == nil {
		source = "builtin"
		t, err := st.GetEmailTemplate(r.Context(), rl.Name, string(kind), locale)
		switch {
		case err == nil:
			draft, source = &mail.Custom{Subject: t.Subject, Text: t.Text, HTML: t.HTML}, "custom"
		case !errors.Is(err, idp.ErrNotFound):
			a.fail(w, r, err)
			return mail.Message{}, "", false
		}
	}
	d, err := a.sample(r, st, rl, kind, locale)
	if err != nil {
		a.fail(w, r, err)
		return mail.Message{}, "", false
	}
	var msg mail.Message
	if draft != nil {
		msg, err = mail.RenderCustom(kind, *draft, d)
	} else {
		msg, err = mail.Render(kind, d)
	}
	if err != nil {
		a.fail(w, r, &httpErr{http.StatusConflict, "the email could not be rendered: " + err.Error()})
		return mail.Message{}, "", false
	}
	return msg, source, true
}

func (a *api) previewEmailTemplate(w http.ResponseWriter, r *http.Request) {
	rl, st, kind, locale, ok := a.templateTarget(w, r)
	if !ok {
		return
	}
	msg, source, ok := a.renderSample(w, r, rl, st, kind, locale)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"source": source, "subject": msg.Subject, "text": msg.Text, "html": msg.HTML})
}

// testSendEmailTemplate mails the sample to the calling administrator's own
// address. The request cannot name a recipient, so the route cannot be used to
// send mail to anyone else.
func (a *api) testSendEmailTemplate(w http.ResponseWriter, r *http.Request) {
	rl, st, kind, locale, ok := a.templateTarget(w, r)
	if !ok {
		return
	}
	if !a.cfg.Actions.Enabled() {
		a.fail(w, r, &httpErr{http.StatusConflict, "email is not configured"})
		return
	}
	noAddress := &httpErr{http.StatusConflict, "a test email goes to the address of the signed-in administrator: " +
		"call this with an administrator user's token (service accounts have no address) and set that user's email"}
	actor := actorOf(r)
	id, isUser := strings.CutPrefix(actor, "user:")
	if !isUser {
		a.fail(w, r, noAddress)
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), a.cfg.AdminRealm, id)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	to := strings.TrimSpace(u.Email)
	if to == "" || strings.ContainsAny(to, "\r\n,;<>") {
		a.fail(w, r, noAddress)
		return
	}
	key := sha256.Sum256([]byte("brandingtest|" + actor))
	allowed, err := a.cfg.Store.HitRateLimit(r.Context(), hex.EncodeToString(key[:]), a.cfg.Clock(), testSendWindow, testSendMax)
	if err != nil {
		a.fail(w, r, err) // fail closed
		return
	}
	if !allowed {
		a.fail(w, r, &httpErr{http.StatusTooManyRequests, "too many test emails; try again later"})
		return
	}
	msg, _, ok := a.renderSample(w, r, rl, st, kind, locale)
	if !ok {
		return
	}
	msg.To, msg.Subject = to, "[Test] "+msg.Subject
	if err := a.cfg.Actions.Mailer.Send(r.Context(), msg); err != nil {
		a.cfg.Logger.Error("admin: send test email", "realm", rl.Name, "kind", string(kind), "err", err.Error())
		a.fail(w, r, &httpErr{http.StatusBadGateway, "could not send email"})
		return
	}
	a.audit(r, rl, "ACTION", "email-template-test", string(kind)+"/"+locale)
	noContent(w)
}
