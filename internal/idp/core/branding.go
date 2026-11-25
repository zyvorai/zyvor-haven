// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import (
	"context"
	"time"
)

// Branding is the per-realm look of the IdP pages and emails. Every field is
// optional; the zero value is the built-in look. Values are validated before
// they are stored (package internal/idp/branding) and validated again before
// they are rendered.
type Branding struct {
	Realm           string
	DisplayName     string // replaces the realm's display name on pages and emails
	AccentColor     string // "#rrggbb", readable on the light card
	AccentColorDark string // "#rrggbb", readable on the dark card; empty = derived
	LogoLight       string // sanitised SVG document
	LogoDark        string // sanitised SVG document; only with LogoLight
	SupportURL      string // https
	PrivacyURL      string // https
	TermsURL        string // https
	DefaultLocale   string // language used when the browser asks for none we have
	UpdatedAt       time.Time
}

// EmailTemplate is a realm's own wording of one kind of email in one language.
// It is data in a closed placeholder language, never executable template code.
type EmailTemplate struct {
	Realm     string
	Kind      string
	Locale    string
	Subject   string
	Text      string
	HTML      string // optional
	UpdatedAt time.Time
}

// BrandingStore is the persistence contract of branding and email templates. A
// store that does not implement it offers the built-in look and wording only.
type BrandingStore interface {
	// GetBranding returns the zero value (no error) when nothing was set.
	GetBranding(ctx context.Context, realm string) (Branding, error)
	// PutBranding replaces the whole record; ErrNotFound for an unknown realm.
	PutBranding(ctx context.Context, b Branding) error
	// DeleteBranding is idempotent.
	DeleteBranding(ctx context.Context, realm string) error

	// GetEmailTemplate returns ErrNotFound when the realm has none.
	GetEmailTemplate(ctx context.Context, realm, kind, locale string) (EmailTemplate, error)
	// ListEmailTemplates returns the realm's templates ordered by kind, locale.
	ListEmailTemplates(ctx context.Context, realm string) ([]EmailTemplate, error)
	// PutEmailTemplate inserts or replaces; ErrNotFound for an unknown realm.
	PutEmailTemplate(ctx context.Context, t EmailTemplate) error
	// DeleteEmailTemplate returns ErrNotFound when there was none.
	DeleteEmailTemplate(ctx context.Context, realm, kind, locale string) error
}
