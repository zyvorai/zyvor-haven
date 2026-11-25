// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package pgstore

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

var _ core.BrandingStore = (*Store)(nil)

// GetBranding implements core.BrandingStore.
func (s *Store) GetBranding(ctx context.Context, realm string) (core.Branding, error) {
	var b core.Branding
	err := s.pool.QueryRow(ctx, `SELECT realm, display_name, accent_color, accent_color_dark, logo_light, logo_dark,
		support_url, privacy_url, terms_url, default_locale, updated_at FROM realm_branding WHERE realm=$1`, realm).
		Scan(&b.Realm, &b.DisplayName, &b.AccentColor, &b.AccentColorDark, &b.LogoLight, &b.LogoDark,
			&b.SupportURL, &b.PrivacyURL, &b.TermsURL, &b.DefaultLocale, &b.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.Branding{}, nil
	}
	if err != nil {
		return core.Branding{}, mapErr(err)
	}
	b.UpdatedAt = b.UpdatedAt.UTC()
	return b, nil
}

// PutBranding implements core.BrandingStore.
func (s *Store) PutBranding(ctx context.Context, b core.Branding) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO realm_branding (realm, display_name, accent_color, accent_color_dark,
		logo_light, logo_dark, support_url, privacy_url, terms_url, default_locale, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		ON CONFLICT (realm) DO UPDATE SET display_name=EXCLUDED.display_name, accent_color=EXCLUDED.accent_color,
		accent_color_dark=EXCLUDED.accent_color_dark, logo_light=EXCLUDED.logo_light, logo_dark=EXCLUDED.logo_dark,
		support_url=EXCLUDED.support_url, privacy_url=EXCLUDED.privacy_url, terms_url=EXCLUDED.terms_url,
		default_locale=EXCLUDED.default_locale, updated_at=EXCLUDED.updated_at`,
		b.Realm, b.DisplayName, b.AccentColor, b.AccentColorDark, b.LogoLight, b.LogoDark,
		b.SupportURL, b.PrivacyURL, b.TermsURL, b.DefaultLocale, b.UpdatedAt)
	return mapErr(err)
}

// DeleteBranding implements core.BrandingStore.
func (s *Store) DeleteBranding(ctx context.Context, realm string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM realm_branding WHERE realm=$1`, realm)
	return mapErr(err)
}

const emailTemplateCols = `realm, kind, locale, subject, body_text, body_html, updated_at`

func scanEmailTemplate(row pgx.Row) (core.EmailTemplate, error) {
	var t core.EmailTemplate
	if err := row.Scan(&t.Realm, &t.Kind, &t.Locale, &t.Subject, &t.Text, &t.HTML, &t.UpdatedAt); err != nil {
		return core.EmailTemplate{}, mapErr(err)
	}
	t.UpdatedAt = t.UpdatedAt.UTC()
	return t, nil
}

// GetEmailTemplate implements core.BrandingStore.
func (s *Store) GetEmailTemplate(ctx context.Context, realm, kind, locale string) (core.EmailTemplate, error) {
	return scanEmailTemplate(s.pool.QueryRow(ctx, `SELECT `+emailTemplateCols+` FROM realm_email_templates
		WHERE realm=$1 AND kind=$2 AND locale=$3`, realm, kind, locale))
}

// ListEmailTemplates implements core.BrandingStore.
func (s *Store) ListEmailTemplates(ctx context.Context, realm string) ([]core.EmailTemplate, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+emailTemplateCols+` FROM realm_email_templates
		WHERE realm=$1 ORDER BY kind COLLATE "C", locale COLLATE "C"`, realm)
	if err != nil {
		return nil, mapErr(err)
	}
	defer rows.Close()
	out := []core.EmailTemplate{}
	for rows.Next() {
		t, err := scanEmailTemplate(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

// PutEmailTemplate implements core.BrandingStore.
func (s *Store) PutEmailTemplate(ctx context.Context, t core.EmailTemplate) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO realm_email_templates (`+emailTemplateCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (realm, kind, locale) DO UPDATE SET subject=EXCLUDED.subject, body_text=EXCLUDED.body_text,
		body_html=EXCLUDED.body_html, updated_at=EXCLUDED.updated_at`,
		t.Realm, t.Kind, t.Locale, t.Subject, t.Text, t.HTML, t.UpdatedAt)
	return mapErr(err)
}

// DeleteEmailTemplate implements core.BrandingStore.
func (s *Store) DeleteEmailTemplate(ctx context.Context, realm, kind, locale string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM realm_email_templates WHERE realm=$1 AND kind=$2 AND locale=$3`, realm, kind, locale)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return idp.ErrNotFound
	}
	return nil
}
