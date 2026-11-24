// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package mail

import (
	"context"
	"log/slog"
	"strings"
)

// SenderFunc adapts a function to Sender.
type SenderFunc func(ctx context.Context, m Message) error

// Send implements Sender.
func (f SenderFunc) Send(ctx context.Context, m Message) error { return f(ctx, m) }

// Multi sends to every sender, trying all even after a failure, and returns
// the first error.
func Multi(senders ...Sender) Sender {
	return SenderFunc(func(ctx context.Context, m Message) error {
		var first error
		for _, s := range senders {
			if s == nil {
				continue
			}
			if err := s.Send(ctx, m); err != nil && first == nil {
				first = err
			}
		}
		return first
	})
}

// LogSender logs the recipient domain and subject only; never the local
// part, body or link. It delivers nothing.
func LogSender(logger *slog.Logger) Sender {
	if logger == nil {
		logger = slog.Default()
	}
	return SenderFunc(func(ctx context.Context, m Message) error {
		domain := ""
		if i := strings.LastIndexByte(m.To, '@'); i >= 0 {
			domain = strings.TrimRight(m.To[i+1:], "> ")
		}
		logger.InfoContext(ctx, "mail: message", "to_domain", domain, "subject", m.Subject)
		return nil
	})
}
