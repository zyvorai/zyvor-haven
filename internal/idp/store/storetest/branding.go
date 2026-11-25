// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package storetest

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func init() {
	Register(
		Case{"BrandingRoundtrip", brandingRoundtrip},
		Case{"EmailTemplates", brandingTemplates},
		Case{"BrandingCascade", brandingCascade},
		Case{"EmailTemplateConcurrentPut", brandingConcurrent},
	)
}

func brandingStore(t *testing.T, s core.Store) core.BrandingStore {
	t.Helper()
	m, found := core.StoreAs[core.BrandingStore](s)
	if !found {
		t.Skip("store does not implement core.BrandingStore")
	}
	return m
}

func brandingRoundtrip(t *testing.T, s core.Store) {
	m := brandingStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	got, err := m.GetBranding(ctx, "acme")
	ok(t, err)
	eq(t, got, core.Branding{}) // never set
	got, err = m.GetBranding(ctx, "nope")
	ok(t, err)
	eq(t, got, core.Branding{})

	in := core.Branding{Realm: "acme", DisplayName: "Acme आपका", AccentColor: "#0a6644", AccentColorDark: "#66ddaa",
		LogoLight: `<svg viewBox="0 0 1 1"></svg>`, LogoDark: `<svg viewBox="0 0 2 2"></svg>`,
		SupportURL: "https://help.example/a?b=c&d=e", PrivacyURL: "https://example.com/privacy",
		TermsURL: "https://example.com/terms", DefaultLocale: "de", UpdatedAt: t0}
	ok(t, m.PutBranding(ctx, in))
	got, err = m.GetBranding(ctx, "acme")
	ok(t, err)
	eq(t, got, in)
	other, err := m.GetBranding(ctx, "beta")
	ok(t, err)
	eq(t, other, core.Branding{}) // isolation

	in2 := core.Branding{Realm: "acme", DefaultLocale: "hi", UpdatedAt: t0.Add(time.Hour)}
	ok(t, m.PutBranding(ctx, in2)) // full replace
	got, err = m.GetBranding(ctx, "acme")
	ok(t, err)
	eq(t, got, in2)

	is(t, m.PutBranding(ctx, core.Branding{Realm: "nope", UpdatedAt: t0}), idp.ErrNotFound)

	ok(t, m.DeleteBranding(ctx, "acme"))
	ok(t, m.DeleteBranding(ctx, "acme")) // idempotent
	got, err = m.GetBranding(ctx, "acme")
	ok(t, err)
	eq(t, got, core.Branding{})
}

func emailTmpl(realm, kind, locale, subject string) core.EmailTemplate {
	return core.EmailTemplate{Realm: realm, Kind: kind, Locale: locale, Subject: subject,
		Text: "Hallo {{username}}\n\n{{link}}\n", HTML: `<p><a href="{{link}}">ok</a></p>`, UpdatedAt: t0}
}

func brandingTemplates(t *testing.T, s core.Store) {
	m := brandingStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "beta")
	_, err := m.GetEmailTemplate(ctx, "acme", "reset_password", "de")
	is(t, err, idp.ErrNotFound)
	l, err := m.ListEmailTemplates(ctx, "acme")
	ok(t, err)
	if len(l) != 0 {
		t.Fatalf("unexpected: %+v", l)
	}
	a := emailTmpl("acme", "verify_email", "en", "A")
	b := emailTmpl("acme", "reset_password", "hi", "B")
	c := emailTmpl("acme", "reset_password", "de", "C")
	c.HTML = ""
	other := emailTmpl("beta", "reset_password", "de", "other")
	for _, x := range []core.EmailTemplate{a, b, c, other} {
		ok(t, m.PutEmailTemplate(ctx, x))
	}
	got, err := m.GetEmailTemplate(ctx, "acme", "reset_password", "de")
	ok(t, err)
	eq(t, got, c)
	l, err = m.ListEmailTemplates(ctx, "acme")
	ok(t, err)
	eq(t, l, []core.EmailTemplate{c, b, a}) // by kind, then locale; never another realm's

	c.Subject = "C2"
	ok(t, m.PutEmailTemplate(ctx, c)) // replace
	got, err = m.GetEmailTemplate(ctx, "acme", "reset_password", "de")
	ok(t, err)
	eq(t, got, c)

	is(t, m.PutEmailTemplate(ctx, emailTmpl("nope", "reset_password", "de", "x")), idp.ErrNotFound)
	ok(t, m.DeleteEmailTemplate(ctx, "acme", "reset_password", "de"))
	is(t, m.DeleteEmailTemplate(ctx, "acme", "reset_password", "de"), idp.ErrNotFound)
	_, err = m.GetEmailTemplate(ctx, "acme", "reset_password", "de")
	is(t, err, idp.ErrNotFound)
	got, err = m.GetEmailTemplate(ctx, "beta", "reset_password", "de")
	ok(t, err)
	eq(t, got, other)
}

func brandingCascade(t *testing.T, s core.Store) {
	m := brandingStore(t, s)
	mkRealm(t, s, "acme")
	ok(t, m.PutBranding(ctx, core.Branding{Realm: "acme", DisplayName: "Acme", UpdatedAt: t0}))
	ok(t, m.PutEmailTemplate(ctx, emailTmpl("acme", "verify_email", "en", "A")))
	ok(t, s.DeleteRealm(ctx, "acme"))
	mkRealm(t, s, "acme")
	got, err := m.GetBranding(ctx, "acme")
	ok(t, err)
	eq(t, got, core.Branding{})
	_, err = m.GetEmailTemplate(ctx, "acme", "verify_email", "en")
	is(t, err, idp.ErrNotFound)
}

func brandingConcurrent(t *testing.T, s core.Store) {
	m := brandingStore(t, s)
	mkRealm(t, s, "acme")
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := m.PutEmailTemplate(ctx, emailTmpl("acme", "verify_email", "en", fmt.Sprint(i))); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Wait()
	l, err := m.ListEmailTemplates(ctx, "acme")
	ok(t, err)
	if len(l) != 1 {
		t.Fatalf("want exactly one row, got %d", len(l))
	}
}
