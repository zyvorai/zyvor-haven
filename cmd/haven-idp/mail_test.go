// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp/mail"
)

func TestBuildMailer(t *testing.T) {
	if m, err := buildMailer(Config{}); m != nil || err != nil {
		t.Errorf("unconfigured: %v %v", m, err)
	}
	for name, c := range map[string]Config{
		"from without host": {SMTPFrom: "a@b.c"},
		"user without host": {SMTPUser: "u"},
		"host without from": {SMTPHost: "smtp.example.org"},
	} {
		if _, err := buildMailer(c); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	m, err := buildMailer(Config{SMTPHost: "smtp.example.org", SMTPFrom: "Haven <no-reply@example.org>"})
	if err != nil || m == nil {
		t.Errorf("valid config: %v %v", m, err)
	}
	// Plaintext AUTH to a remote host is refused by the mail package.
	if _, err := buildMailer(Config{SMTPHost: "smtp.example.org", SMTPFrom: "a@b.c", SMTPUser: "u", SMTPPassword: "p", SMTPTLS: "none"}); err == nil {
		t.Error("AUTH over plaintext to a remote host was accepted")
	}
}

func TestDevMailboxEscapes(t *testing.T) {
	o := mail.NewOutbox(10)
	_ = o.Send(context.Background(), mail.Message{To: "a@x.org", Subject: "<script>alert(1)</script>",
		Text: "go: https://idp.example/realms/r/login-actions/reset-password?token=abc\n"})
	w := httptest.NewRecorder()
	devMailHandler(o).ServeHTTP(w, httptest.NewRequest("GET", "/dev/mail", nil))
	b := w.Body.String()
	if strings.Contains(b, "<script>alert") || !strings.Contains(b, `href="https://idp.example/realms/r/login-actions/reset-password?token=abc"`) {
		t.Errorf("unexpected page: %s", b)
	}
}
