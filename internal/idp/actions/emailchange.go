// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package actions

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	netmail "net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/mail"
)

// Self-service email change. The account keeps its current address until the
// user opens a link sent to the NEW address. The pending change is an action
// token with purpose ActionChangeEmail whose Email column holds
// "<new>\x1f<old>": binding the old address means the link dies if an
// administrator (or anyone else) changed the address in the meantime. Neither
// address can contain \x1f (ValidateNewEmail accepts bare addresses only), so
// the split is unambiguous.

// ActionChangeEmail is the purpose of a pending self-service email change.
const ActionChangeEmail = "change_email"

// ChangeEmailTTL is how long the confirmation link lasts.
const ChangeEmailTTL = 2 * time.Hour

const changeSep = "\x1f"

// ErrBadEmail: the requested address is not acceptable.
var ErrBadEmail = errors.New("actions: invalid email address")

// ValidateNewEmail returns the normalised bare address or ErrBadEmail. Display
// names, comments, control characters and over-long input are all refused.
func ValidateNewEmail(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 254 {
		return "", ErrBadEmail
	}
	for _, r := range s {
		if r < 0x21 || r == 0x7f || r == '<' || r == '>' || r == ',' || r == ';' || r == '"' {
			return "", ErrBadEmail
		}
	}
	a, err := netmail.ParseAddress(s)
	if err != nil || a.Address != s || a.Name != "" {
		return "", ErrBadEmail
	}
	at := strings.LastIndex(s, "@")
	if at < 1 || !strings.Contains(s[at+1:], ".") {
		return "", ErrBadEmail
	}
	return s, nil
}

func (s *Service) displayRealm(rl core.Realm) string {
	if rl.DisplayName != "" {
		return rl.DisplayName
	}
	return rl.Name
}

func ctl(v string) bool { return strings.ContainsAny(v, "\r\n\x00") }

// SendEmailChange issues a confirmation link bound to the user's current
// address and emails it to newEmail only. Earlier pending changes of the user
// are withdrawn. Rate limiting is the caller's job (the user-level limiter
// cannot be derived from stored tokens because older ones are deleted here).
func (s *Service) SendEmailChange(ctx context.Context, rl core.Realm, u core.User, newEmail string) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	newEmail, err := ValidateNewEmail(newEmail)
	if err != nil {
		return err
	}
	if ctl(u.Email) || ctl(rl.Name) || ctl(s.displayRealm(rl)) || ctl(u.Username) {
		return ErrNoEmail
	}
	if _, err := s.Store.DeleteActionTokens(ctx, rl.Name, u.ID, ActionChangeEmail); err != nil {
		return err
	}
	rb := make([]byte, 32)
	if _, err := rand.Read(rb); err != nil {
		return err
	}
	raw := base64.RawURLEncoding.EncodeToString(rb)
	now := s.now()
	err = s.Store.PutActionToken(ctx, core.ActionToken{
		TokenHash: Hash(raw), Realm: rl.Name, UserID: u.ID, Purpose: ActionChangeEmail,
		Email: newEmail + changeSep + strings.TrimSpace(u.Email), CreatedAt: now, ExpiresAt: now.Add(ChangeEmailTTL),
	})
	if err != nil {
		return err
	}
	link := strings.TrimRight(s.BaseURL, "/") + "/realms/" + url.PathEscape(rl.Name) +
		"/login-actions/confirm-email-change?token=" + url.QueryEscape(raw)
	msg, err := s.Compose(ctx, rl, mail.KindChangeEmail, mail.TemplateData{Username: u.Username, Link: link,
		Hours: int(ChangeEmailTTL / time.Hour)})
	if err != nil {
		_, _ = s.Store.ConsumeActionToken(ctx, Hash(raw))
		return err
	}
	msg.To = newEmail
	if err := s.Mailer.Send(ctx, msg); err != nil {
		_, _ = s.Store.ConsumeActionToken(ctx, Hash(raw))
		return fmt.Errorf("actions: send: %w", err)
	}
	return nil
}

// RedeemEmailChange consumes a confirmation link. It returns the new address
// and the user (still carrying the OLD address) or ErrInvalidToken for every
// failure that is the link's fault, including the address on the account
// having changed since the link was issued.
func (s *Service) RedeemEmailChange(ctx context.Context, realm, raw string) (string, core.User, error) {
	if s == nil || s.Store == nil || raw == "" || len(raw) > 256 {
		return "", core.User{}, ErrInvalidToken
	}
	t, err := s.Store.ConsumeActionToken(ctx, Hash(raw))
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return "", core.User{}, ErrInvalidToken
		}
		return "", core.User{}, err
	}
	if t.Realm != realm || t.Purpose != ActionChangeEmail || !s.now().Before(t.ExpiresAt) {
		return "", core.User{}, ErrInvalidToken
	}
	newEmail, oldEmail, ok := strings.Cut(t.Email, changeSep)
	if !ok || newEmail == "" {
		return "", core.User{}, ErrInvalidToken
	}
	u, err := s.Store.GetUser(ctx, realm, t.UserID)
	if err != nil {
		if errors.Is(err, idp.ErrNotFound) {
			return "", core.User{}, ErrInvalidToken
		}
		return "", core.User{}, err
	}
	if !u.Enabled || strings.TrimSpace(u.Email) != oldEmail {
		return "", core.User{}, ErrInvalidToken
	}
	return newEmail, u, nil
}

// NotifyEmailChange tells the OLD address about a change. done=false: a change
// was requested (not yet applied); done=true: the address was replaced. The
// new address is shown masked, and no message carries a link.
func (s *Service) NotifyEmailChange(ctx context.Context, rl core.Realm, oldEmail, username, newEmail string, done bool) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	oldEmail = strings.TrimSpace(oldEmail)
	if oldEmail == "" || ctl(oldEmail) || ctl(username) || ctl(s.displayRealm(rl)) {
		return ErrNoEmail
	}
	kind := mail.KindEmailChangeRequested
	if done {
		kind = mail.KindEmailChanged
	}
	msg, err := s.Compose(ctx, rl, kind, mail.TemplateData{Username: username, NewEmail: MaskEmail(newEmail),
		When: s.now().UTC().Format("2006-01-02 15:04:05 UTC")})
	if err != nil {
		return fmt.Errorf("actions: notify: %w", err)
	}
	msg.To = oldEmail
	if err := s.Mailer.Send(ctx, msg); err != nil {
		return fmt.Errorf("actions: notify: %w", err)
	}
	return nil
}

// MaskEmail shows enough of an address to recognise it, not to harvest it:
// "a***@example.com".
func MaskEmail(e string) string {
	at := strings.LastIndex(e, "@")
	if at < 1 {
		return "***"
	}
	return e[:1] + "***" + e[at:]
}
