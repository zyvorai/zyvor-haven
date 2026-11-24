// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package actions issues and redeems the single-use emailed links behind
// "verify my email" and "reset my password". The OIDC pages and the Admin API
// share it so both follow the same rules:
//
//   - tokens are 256-bit random, stored only as a sha256 hash, single use;
//   - at most MaxPerHour emails per user and purpose per rolling hour; earlier
//     links stay valid until one is redeemed (callers then call
//     DeleteActionTokens), so a flooded inbox cannot be used to lock someone
//     out of their own latest link;
//   - tokens are bound to the address they were sent to, so changing the
//     address on the account kills any link sent to the old one;
//   - issuing is rate limited per user and purpose.
package actions

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/mail"
)

const (
	ResetTTL  = time.Hour
	VerifyTTL = 24 * time.Hour
	// MaxPerHour caps emails per user and purpose in any rolling hour.
	MaxPerHour = 3
)

var (
	// ErrDisabled: no mailer is configured.
	ErrDisabled = errors.New("actions: email is not configured")
	// ErrRateLimited: too many emails were sent to this user recently.
	ErrRateLimited = errors.New("actions: rate limited")
	// ErrNoEmail: the user has no email address, or it is unusable.
	ErrNoEmail = errors.New("actions: user has no email address")
	// ErrInvalidToken covers unknown, used, expired, wrong-purpose and
	// no-longer-matching tokens alike: callers must not distinguish them.
	ErrInvalidToken = errors.New("actions: invalid or expired link")
)

// Service sends and redeems action links.
type Service struct {
	Store   core.Store
	Mailer  mail.Sender // nil disables every flow
	BaseURL string      // public base URL of haven-idp
	Clock   func() time.Time
}

func (s *Service) now() time.Time {
	if s.Clock != nil {
		return s.Clock()
	}
	return time.Now()
}

// Enabled reports whether emails can be sent.
func (s *Service) Enabled() bool { return s != nil && s.Mailer != nil && s.Store != nil }

// Hash returns the stored form of a raw token.
func Hash(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func ttl(purpose string) time.Duration {
	if purpose == core.ActionVerifyEmail {
		return VerifyTTL
	}
	return ResetTTL
}

func pathFor(purpose string) string {
	if purpose == core.ActionVerifyEmail {
		return "verify-email"
	}
	return "reset-password"
}

func kindFor(purpose string) mail.Kind {
	if purpose == core.ActionVerifyEmail {
		return mail.KindVerifyEmail
	}
	return mail.KindResetPassword
}

// Link builds the URL a token is delivered in.
func (s *Service) Link(realm, purpose, raw string) string {
	return strings.TrimRight(s.BaseURL, "/") + "/realms/" + url.PathEscape(realm) +
		"/login-actions/" + pathFor(purpose) + "?token=" + url.QueryEscape(raw)
}

// SendOpts tunes Send.
type SendOpts struct {
	// IgnoreLimit skips the per-user rate limit (admin-initiated sends).
	IgnoreLimit bool
}

// Send issues a token for u and emails the link to the address on file.
// It never returns the token or link.
func (s *Service) Send(ctx context.Context, rl core.Realm, u core.User, purpose string, o SendOpts) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	if purpose != core.ActionVerifyEmail && purpose != core.ActionResetPassword {
		return fmt.Errorf("actions: unknown purpose %q", purpose)
	}
	email := strings.TrimSpace(u.Email)
	if email == "" || strings.ContainsAny(email, "\r\n") {
		return ErrNoEmail
	}
	now := s.now()
	if !o.IgnoreLimit {
		n, err := s.Store.CountActionTokens(ctx, rl.Name, u.ID, purpose, now.Add(-time.Hour))
		if err != nil {
			return err
		}
		if n >= MaxPerHour {
			return ErrRateLimited
		}
	}
	rb := make([]byte, 32)
	if _, err := rand.Read(rb); err != nil {
		return err
	}
	raw := base64.RawURLEncoding.EncodeToString(rb)
	err := s.Store.PutActionToken(ctx, core.ActionToken{
		TokenHash: Hash(raw), Realm: rl.Name, UserID: u.ID, Purpose: purpose,
		Email: email, CreatedAt: now, ExpiresAt: now.Add(ttl(purpose)),
	})
	if err != nil {
		return err
	}
	disp := rl.DisplayName
	if disp == "" {
		disp = rl.Name
	}
	hours := int(ttl(purpose) / time.Hour)
	msg, err := mail.Render(kindFor(purpose), mail.TemplateData{
		Realm: disp, Username: u.Username, Link: s.Link(rl.Name, purpose, raw), Hours: hours})
	if err != nil {
		return err
	}
	msg.To = email
	if err := s.Mailer.Send(ctx, msg); err != nil {
		// Nobody can use a link that was never delivered.
		_, _ = s.Store.ConsumeActionToken(ctx, Hash(raw))
		return fmt.Errorf("actions: send: %w", err)
	}
	return nil
}

// Notify emails a security notification (for example mail.KindPasswordChanged)
// to the address on file. It carries no token and is not counted against the
// action-token rate limit; it is sent once and never retried. via describes
// how the change happened ("reset link", "an administrator").
func (s *Service) Notify(ctx context.Context, rl core.Realm, u core.User, kind mail.Kind, via string) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	email := strings.TrimSpace(u.Email)
	if email == "" || strings.ContainsAny(email, "\r\n") {
		return ErrNoEmail
	}
	disp := rl.DisplayName
	if disp == "" {
		disp = rl.Name
	}
	msg, err := mail.Render(kind, mail.TemplateData{Realm: disp, Username: u.Username,
		When: s.now().UTC().Format("2006-01-02 15:04:05 UTC"), Via: via})
	if err != nil {
		return err
	}
	msg.To = email
	if err := s.Mailer.Send(ctx, msg); err != nil {
		return fmt.Errorf("actions: notify: %w", err)
	}
	return nil
}

// Redeem consumes a token. It returns ErrInvalidToken for every failure that
// is the link's fault: unknown, already used, expired, wrong realm or
// purpose, user gone or disabled, or the address changed since it was sent.
// Other errors are infrastructure failures.
func (s *Service) Redeem(ctx context.Context, realm, raw, purpose string) (core.ActionToken, core.User, error) {
	if s == nil || s.Store == nil || raw == "" || len(raw) > 256 {
		return core.ActionToken{}, core.User{}, ErrInvalidToken
	}
	t, err := s.Store.ConsumeActionToken(ctx, Hash(raw))
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return core.ActionToken{}, core.User{}, ErrInvalidToken
		}
		return core.ActionToken{}, core.User{}, err
	}
	if t.Realm != realm || t.Purpose != purpose || !s.now().Before(t.ExpiresAt) {
		return core.ActionToken{}, core.User{}, ErrInvalidToken
	}
	u, err := s.Store.GetUser(ctx, realm, t.UserID)
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return core.ActionToken{}, core.User{}, ErrInvalidToken
		}
		return core.ActionToken{}, core.User{}, err
	}
	if !u.Enabled || !strings.EqualFold(strings.TrimSpace(u.Email), t.Email) {
		return core.ActionToken{}, core.User{}, ErrInvalidToken
	}
	return t, u, nil
}
