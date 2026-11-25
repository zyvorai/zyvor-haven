// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package actions

import (
	"context"
	"errors"
	"log/slog"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/branding"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/i18n"
	"github.com/zyvorai/haven/internal/idp/mail"
)

// Compose builds one email of a realm: the realm's branded display name, the
// language of the request (i18n.WithLang) or else the realm's default, and the
// realm's own template for that kind and language when it has one, else the
// built-in wording. d.Realm and d.Lang are set here. A branding or template
// lookup that fails never stops the email: the built-in wording is used.
func (s *Service) Compose(ctx context.Context, rl core.Realm, kind mail.Kind, d mail.TemplateData) (mail.Message, error) {
	d.Realm = s.displayRealm(rl)
	d.Lang = i18n.LangFrom(ctx)
	bs, ok := core.StoreAs[core.BrandingStore](s.Store)
	if ok {
		b, err := bs.GetBranding(ctx, rl.Name)
		if err != nil {
			slog.Default().WarnContext(ctx, "actions: load branding", "realm", rl.Name, "err", err)
		} else {
			// Checked again here, as on the pages.
			if b.DisplayName != "" && branding.CheckName(b.DisplayName) == nil {
				d.Realm = b.DisplayName
			}
			if d.Lang == "" {
				d.Lang = b.DefaultLocale
			}
		}
	}
	if !i18n.IsSupported(d.Lang) {
		d.Lang = i18n.Default
	}
	if ok {
		t, err := bs.GetEmailTemplate(ctx, rl.Name, string(kind), d.Lang)
		switch {
		case err == nil:
			m, rerr := mail.RenderCustom(kind, mail.Custom{Subject: t.Subject, Text: t.Text, HTML: t.HTML}, d)
			if rerr == nil {
				return m, nil
			}
			// The error names the rule broken, never a link or token.
			slog.Default().WarnContext(ctx, "actions: stored email template unusable; using the built-in one",
				"realm", rl.Name, "kind", string(kind), "locale", d.Lang)
		case !errors.Is(err, idp.ErrNotFound):
			slog.Default().WarnContext(ctx, "actions: load email template", "realm", rl.Name, "kind", string(kind), "err", err)
		}
	}
	return mail.Render(kind, d)
}
