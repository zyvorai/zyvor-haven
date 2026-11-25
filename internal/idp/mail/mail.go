// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package mail sends the few transactional emails haven-idp needs (verify an
// address, reset a password). The OIDC provider depends only on Sender.
package mail

import "context"

// Message is a plain-text email. HTML is optional; when set the message is
// sent multipart/alternative.
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Sender delivers a message. Implementations must be safe for concurrent use
// and must never log the message body (it carries live links).
type Sender interface {
	Send(ctx context.Context, m Message) error
}

// Kind selects a template.
type Kind string

const (
	KindVerifyEmail   Kind = "verify_email"
	KindResetPassword Kind = "reset_password"
	// KindPasswordChanged is a security notification. It never carries a link.
	KindPasswordChanged Kind = "password_changed"
	// KindChangeEmail is the confirmation link sent to a new address.
	KindChangeEmail Kind = "change_email"
	// KindEmailChangeRequested and KindEmailChanged are notices to the old
	// address. They never carry a link.
	KindEmailChangeRequested Kind = "email_change_requested"
	KindEmailChanged         Kind = "email_changed"
	// KindCIBAApproval asks a user to approve a decoupled (CIBA) request.
	KindCIBAApproval Kind = "ciba_approval"
)

// TemplateData is everything a template may use.
type TemplateData struct {
	Realm    string // display name
	Username string
	Link     string // the single-use action URL
	Hours    int    // validity in whole hours (minimum 1)
	When     string // notifications: UTC timestamp text; optional
	Via      string // notifications: "reset link" or "an administrator"; optional

	Lang     string // catalogue language; "" or unsupported is English
	NewEmail string // email change notices: the new address, masked

	// Decoupled approval requests only.
	Client    string
	Binding   string // message chosen by the client; shown quoted
	Scope     string
	Resources []string
	Minutes   int
}
