// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package idp

import (
	"context"
	"errors"
)

// Backend is what the console API needs from the identity backend holder:
// the current Provider (nil when not connected), its connection details, and
// a way to reconnect with new credentials.
type Backend interface {
	// Client returns the current Provider, or a true nil interface when none
	// is configured.
	Client() Provider
	// Config returns the backend URL and admin user for display.
	Config() (url, user string)
	// Reconfigure reconnects with new credentials.
	Reconfigure(ctx context.Context, url, user, password string) error
}

// UserMailer is implemented by providers that can email a user a
// single-use link: one to verify the address on file, one to reset the
// password. The link goes only to that address and is never returned. It is
// optional, like SecretCreator and UserImporter, and is not part of Provider.
//
// Errors: ErrEmailNotConfigured when the backend has no mail transport,
// ErrRateLimited when the user was mailed too often recently; other
// rejections (no address on file, disabled user: 400; unknown user: 404)
// are a *StatusError.
type UserMailer interface {
	SendVerifyEmail(ctx context.Context, realm, userID string) error
	SendResetEmail(ctx context.Context, realm, userID string) error
}

var (
	// ErrEmailNotConfigured: the identity backend has no SMTP configured.
	ErrEmailNotConfigured = errors.New("idp: email is not configured on the identity backend")
	// ErrRateLimited: too many emails were sent to this user recently.
	ErrRateLimited = errors.New("idp: too many emails sent to this user recently, try again later")
)

// ErrBackendFixed is returned by Reconfigure on a StaticBackend.
var ErrBackendFixed = errors.New("backend is configured by the environment")

// StaticBackend holds a Provider fixed at construction.
type StaticBackend struct {
	p         Provider
	url, user string
}

var _ Backend = (*StaticBackend)(nil)

// NewStaticBackend wraps p. A nil p yields a backend whose Client() is nil.
func NewStaticBackend(p Provider, url, user string) *StaticBackend {
	return &StaticBackend{p: p, url: url, user: user}
}

// Client returns the fixed provider, or a true nil interface.
func (b *StaticBackend) Client() Provider {
	if b.p == nil {
		return nil
	}
	return b.p
}

// Config returns the URL and user given at construction.
func (b *StaticBackend) Config() (string, string) { return b.url, b.user }

// Reconfigure always fails: the backend is fixed by the environment.
func (b *StaticBackend) Reconfigure(context.Context, string, string, string) error {
	return ErrBackendFixed
}
