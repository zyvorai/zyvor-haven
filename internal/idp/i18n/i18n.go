// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package i18n is the message catalogue of the haven-idp pages and emails.
//
// It is a gettext-style catalogue: the English source text IS the key, so the
// English wording lives exactly once, where it is used, and a string nobody has
// translated yet is shown in English instead of a placeholder. Translations are
// plain text (never markup) held in catalog_<lang>.go; arguments use %s and %d
// verbs, which a translation may reorder with explicit indexes (%[2]s).
// See docs/branding-and-i18n.md.
package i18n

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// Default is the language of the source strings and the last fallback.
const Default = "en"

// catalogs maps a language to its translations, keyed by the English text.
var catalogs = map[string]map[string]string{
	"de": catalogDE,
	"hi": catalogHI,
}

var supported = []string{Default, "de", "hi"}

// Supported returns the languages with a catalogue, English first.
func Supported() []string { return slices.Clone(supported) }

// IsSupported reports whether lang is exactly one of Supported.
func IsSupported(lang string) bool { return slices.Contains(supported, lang) }

// rtlLanguages are written right to left. None ships today; a catalogue added
// for one of them gets dir="rtl" without further changes.
var rtlLanguages = []string{"ar", "fa", "he", "ur"}

// RTL reports whether pages in lang must be laid out right to left.
func RTL(lang string) bool { return slices.Contains(rtlLanguages, lang) }

// Lookup returns the translation of the English text key in lang.
func Lookup(lang, key string) (string, bool) {
	v, ok := catalogs[lang][key]
	return v, ok
}

// Keys returns the translated English texts of lang, sorted.
func Keys(lang string) []string {
	out := make([]string, 0, len(catalogs[lang]))
	for k := range catalogs[lang] {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// T translates key into lang and, when args are given, formats it. An unknown
// language or an untranslated key yields the English text. Without args the
// text is returned verbatim (a "%" in it is not interpreted), so T is safe to
// apply to a message that was already composed.
func T(lang, key string, args ...any) string {
	s := key
	if v, ok := Lookup(lang, key); ok {
		s = v
	}
	if len(args) == 0 {
		return s
	}
	return fmt.Sprintf(s, args...)
}

const (
	maxHeader = 512 // longest ui_locales / Accept-Language value looked at
	maxTags   = 16  // most language tags looked at in one value
)

// primary maps a BCP 47 tag to a supported language by its primary subtag
// ("de-AT" is "de"), or "".
func primary(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if i := strings.IndexAny(tag, "-_"); i >= 0 {
		tag = tag[:i]
	}
	for _, l := range supported {
		if l == tag {
			return l // the catalogue's own string, never the request's
		}
	}
	return ""
}

// fromUILocales picks the first supported entry of an OIDC ui_locales value
// (space separated, in order of preference).
func fromUILocales(v string) string {
	if len(v) > maxHeader {
		return ""
	}
	for i, tag := range strings.Fields(v) {
		if i >= maxTags {
			break
		}
		if l := primary(tag); l != "" {
			return l
		}
	}
	return ""
}

// fromAccept picks the supported language with the highest quality value of an
// Accept-Language header; ties keep the header's order. q=0 means "not
// acceptable" and "*" is ignored.
func fromAccept(v string) string {
	if len(v) > maxHeader {
		return ""
	}
	best, bestQ := "", 0.0
	for i, part := range strings.Split(v, ",") {
		if i >= maxTags {
			break
		}
		tag, params, _ := strings.Cut(part, ";")
		q := 1.0
		if p := strings.TrimSpace(params); p != "" {
			val, ok := strings.CutPrefix(p, "q=")
			if !ok {
				continue
			}
			f, err := strconv.ParseFloat(val, 64)
			if err != nil || !(f >= 0 && f <= 1) {
				continue
			}
			q = f
		}
		if l := primary(tag); l != "" && q > bestQ {
			best, bestQ = l, q
		}
	}
	return best
}

// Requested returns the language the request itself asks for: the first
// supported entry of ui_locales, then the best supported entry of
// Accept-Language, or "" when it asks for nothing we have.
func Requested(uiLocales, acceptLanguage string) string {
	if l := fromUILocales(uiLocales); l != "" {
		return l
	}
	return fromAccept(acceptLanguage)
}

// Match chooses the language of a page: ui_locales, then Accept-Language, then
// the realm's default, then English. The result is always one of Supported,
// never a copy of request input.
func Match(uiLocales, acceptLanguage, realmDefault string) string {
	if l := Requested(uiLocales, acceptLanguage); l != "" {
		return l
	}
	if l := primary(realmDefault); l != "" {
		return l
	}
	return Default
}

type ctxKey struct{}

// WithLang records the language chosen for a request, so that an email sent on
// its behalf uses it. An unsupported or empty language records nothing.
func WithLang(ctx context.Context, lang string) context.Context {
	if !IsSupported(lang) {
		return ctx
	}
	return context.WithValue(ctx, ctxKey{}, lang)
}

// LangFrom returns the language recorded by WithLang, or "" (use the realm's
// default).
func LangFrom(ctx context.Context) string {
	s, _ := ctx.Value(ctxKey{}).(string)
	return s
}
