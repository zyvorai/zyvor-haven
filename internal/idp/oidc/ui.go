// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/zyvorai/haven/internal/idp/branding"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/i18n"
)

// Language and branding of the server-rendered pages
// (docs/branding-and-i18n.md).
//
// A page opts in like this:
//
//  1. its template starts with <html<!--loc-->> instead of <html lang="en">
//     and goes through withTheme, which then adds lang/dir, the realm's accent
//     colours (inside the one nonce'd style element), its logo (instead of the hero
//     illustration) and its footer links;
//  2. its data has a field L of type Loc, set with p.loc(w);
//  3. every fixed text is written {{$.L.T "English text"}}, or
//     {{$.L.H "Text with %s" ($.L.B .Name)}} when part of it is marked up, and
//     the English text is added to internal/idp/i18n/catalog_*.go.
//
// Pages rendered through simplePage, stepPage and mfaPage are opted in
// already: their title and error message are translated when the catalogue has
// them; a new body only needs step 3. A page that does nothing stays English
// and unbranded.

// Loc is the language and look of one page. The zero value is English with the
// built-in look.
type Loc struct {
	lang string
	look *look
}

type look struct {
	name  string
	css   template.CSS
	logo  template.HTML
	links []uiLink
}

type uiLink struct{ Label, URL string }

// Lang is the page language, for the lang attribute.
func (l Loc) Lang() string {
	if l.lang == "" {
		return i18n.Default
	}
	return l.lang
}

// RTL reports whether the page is written right to left.
func (l Loc) RTL() bool { return i18n.RTL(l.lang) }

// T translates a fixed English text, formatting it when args are given. The
// result is ordinary text: the template escapes it.
func (l Loc) T(key string, args ...any) string { return i18n.T(l.lang, key, args...) }

// H translates a sentence whose %s arguments may carry markup. The translated
// sentence is escaped, so a catalogue can never add markup, and so is every
// argument that is not already template.HTML (made with B or C).
func (l Loc) H(key string, args ...any) template.HTML {
	s := template.HTMLEscapeString(l.T(key))
	if len(args) > 0 {
		esc := make([]any, len(args))
		for i, a := range args {
			if h, ok := a.(template.HTML); ok {
				esc[i] = string(h)
			} else {
				esc[i] = template.HTMLEscapeString(fmt.Sprint(a))
			}
		}
		s = fmt.Sprintf(s, esc...)
	}
	return template.HTML(s) // #nosec G203 -- translation and arguments are escaped above; template.HTML arguments come from B and C, which escape
}

// B is v in <strong>, for use as an argument of H.
func (l Loc) B(v any) template.HTML {
	return template.HTML("<strong>" + template.HTMLEscapeString(fmt.Sprint(v)) + "</strong>") // #nosec G203 -- v is escaped
}

// C is v in <code>, for use as an argument of H.
func (l Loc) C(v any) template.HTML {
	return template.HTML("<code>" + template.HTMLEscapeString(fmt.Sprint(v)) + "</code>") // #nosec G203 -- v is escaped
}

// CSS is the realm's accent colour rules (empty without branding).
func (l Loc) CSS() template.CSS {
	if l.look == nil {
		return ""
	}
	return l.look.css
}

// Logo is the realm's inline logo, or empty (the page keeps its illustration).
func (l Loc) Logo() template.HTML {
	if l.look == nil {
		return ""
	}
	return l.look.logo
}

// Links are the realm's support, privacy and terms links.
func (l Loc) Links() []uiLink {
	if l.look == nil {
		return nil
	}
	return l.look.links
}

// RealmName is the name pages show for a realm: the branded one, else the
// realm's display name, else its name.
func (l Loc) RealmName(rl core.Realm) string {
	if rl.DisplayName != "" {
		return l.brandedName(rl.DisplayName)
	}
	return l.brandedName(rl.Name)
}

// clientName is the name pages show for an application. Only the names of the
// two built-in login clients are ours to translate.
func (l Loc) clientName(cl core.Client) string {
	switch {
	case cl.ClientID == deviceClientID || cl.ClientID == cibaClientID:
		return l.T(cl.Name)
	case cl.Name != "":
		return cl.Name
	}
	return cl.ClientID
}

// brandedName is the branded realm name, or fallback.
func (l Loc) brandedName(fallback string) string {
	if l.look != nil && l.look.name != "" {
		return l.look.name
	}
	return fallback
}

var policyTermRE = regexp.MustCompile(`^password policy: ([A-Za-z]+)\(([0-9]+)\) not satisfied$`)

// PolicyError translates a password policy rejection.
func (l Loc) PolicyError(err error) string {
	s := err.Error()
	if m := policyTermRE.FindStringSubmatch(s); m != nil {
		if n, e := strconv.Atoi(m[2]); e == nil {
			return l.T("password policy: %s(%d) not satisfied", m[1], n)
		}
	}
	return l.T(s)
}

// ---- per request ----

// uiWriter carries the request to the render functions, which receive only the
// ResponseWriter. The language and branding are looked up the first time a
// page is actually rendered, so token and API calls pay nothing.
type uiWriter struct {
	http.ResponseWriter
	r         *http.Request
	uiLocales string // from a pushed or signed request, when not in the URL
	loc       *Loc
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (u *uiWriter) Unwrap() http.ResponseWriter { return u.ResponseWriter }

func uiOf(w http.ResponseWriter) *uiWriter {
	for w != nil {
		if u, ok := w.(*uiWriter); ok {
			return u
		}
		x, ok := w.(interface{ Unwrap() http.ResponseWriter })
		if !ok {
			break
		}
		w = x.Unwrap()
	}
	return nil
}

func (u *uiWriter) requested() string {
	if u.uiLocales != "" {
		return u.uiLocales
	}
	if v := u.r.URL.Query().Get("ui_locales"); v != "" {
		return v
	}
	return u.r.PostForm.Get("ui_locales")
}

// setUILocales records the ui_locales of the effective authorization request
// (PAR and request objects carry it outside the URL).
func setUILocales(w http.ResponseWriter, v string) {
	if u := uiOf(w); u != nil && v != "" {
		u.uiLocales, u.loc = v, nil
	}
}

// loc returns the language and look of the page being written to w. Without a
// request (w did not come through ServeHTTP) it is the zero Loc.
func (p *Provider) loc(w http.ResponseWriter) Loc {
	u := uiOf(w)
	if u == nil {
		return Loc{}
	}
	if u.loc == nil {
		l := p.resolveLoc(u)
		u.loc = &l
	}
	return *u.loc
}

// resolveLoc picks the language (ui_locales, then Accept-Language, then the
// realm's default) and loads the realm's branding. A store failure is logged
// and leaves the built-in look: branding never blocks a page.
func (p *Provider) resolveLoc(u *uiWriter) Loc {
	var b core.Branding
	var rl core.Realm
	if name := u.r.PathValue("realm"); name != "" {
		if bs, ok := core.StoreAs[core.BrandingStore](p.cfg.Store); ok {
			if got, found := p.realm(u.r.Context(), name); found {
				rl = got
				var err error
				if b, err = bs.GetBranding(u.r.Context(), rl.Name); err != nil {
					p.cfg.Logger.Error("oidc: load branding", "realm", rl.Name, "err", err)
					b = core.Branding{}
				}
			}
		}
	}
	l := Loc{lang: i18n.Match(u.requested(), u.r.Header.Get("Accept-Language"), b.DefaultLocale)}
	if b.Realm == "" {
		return l // never branded
	}
	lk := &look{}
	// Stored values are validated again: nothing unchecked reaches the page.
	if branding.CheckName(b.DisplayName) == nil {
		lk.name = b.DisplayName
	}
	label := lk.name
	if label == "" {
		label = rl.DisplayName
	}
	if label == "" {
		label = rl.Name
	}
	lk.css = template.CSS(branding.CSS(b.AccentColor, b.AccentColorDark))        // #nosec G203 -- built from parsed integers only
	lk.logo = template.HTML(branding.LogoMarkup(b.LogoLight, b.LogoDark, label)) // #nosec G203 -- rebuilt from a closed SVG vocabulary
	for _, x := range []uiLink{{"Help", b.SupportURL}, {"Privacy", b.PrivacyURL}, {"Terms", b.TermsURL}} {
		if x.URL != "" && branding.CheckLink(x.URL) == nil {
			lk.links = append(lk.links, uiLink{Label: l.T(x.Label), URL: x.URL})
		}
	}
	l.look = lk
	return l
}

// reqLang is the language of the request being answered on w, for an email sent
// on its behalf; "" (the realm's default) when there is none.
func (p *Provider) reqLang(w http.ResponseWriter) string { return p.loc(w).lang }

// keepUILocales carries the request's ui_locales on a link or form action to
// another page of this server.
func keepUILocales(w http.ResponseWriter, target string) string {
	u := uiOf(w)
	if u == nil || target == "" {
		return target
	}
	v := u.requested()
	if v == "" || len(v) > 64 {
		return target
	}
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	return target + sep + "ui_locales=" + url.QueryEscape(v)
}

func init() {
	registerDiscovery(func(_ *Provider, _ string, doc map[string]any) {
		doc["ui_locales_supported"] = i18n.Supported()
	})
}
