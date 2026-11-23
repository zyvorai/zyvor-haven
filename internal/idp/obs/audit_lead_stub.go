// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package obs

import (
	"errors"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
)

// STUB: the lead deletes this file at merge; the real audit*.go provides both.

// AuditOptions configures an audit sink.
type AuditOptions struct {
	Logger        *slog.Logger
	Registerer    prometheus.Registerer
	WebhookSecret string
}

// NewAuditSink builds a sink from a spec (stdout, file:PATH, webhook:URL).
func NewAuditSink(spec string, opts AuditOptions) (AuditSink, error) {
	return nil, errors.New("audit sinks not built yet")
}
