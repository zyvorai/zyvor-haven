// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package mail

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func TestRenderTexts(t *testing.T) {
	for _, k := range []Kind{KindVerifyEmail, KindResetPassword} {
		m, err := Render(k, TemplateData{Realm: "Acme", Username: "alice", Link: "https://idp.example.com/a?t=1&x=2", Hours: 24})
		if err != nil {
			t.Fatal(err)
		}
		if m.To != "" || m.Subject == "" || m.HTML == "" {
			t.Fatalf("%v: %+v", k, m)
		}
		if !strings.Contains(m.Text, "\nhttps://idp.example.com/a?t=1&x=2\n") {
			t.Fatalf("link not on own line: %q", m.Text)
		}
		if !strings.Contains(m.Text, "24 hours") || !strings.Contains(m.Text, "ignore this email") {
			t.Fatalf("text: %q", m.Text)
		}
		if strings.Contains(m.HTML, "<img") {
			t.Fatal("html must not contain images")
		}
	}
	m, _ := Render(KindVerifyEmail, TemplateData{Realm: "A", Link: "http://h/x", Hours: 0})
	if !strings.Contains(m.Text, "1 hour.") {
		t.Fatalf("min 1 hour: %q", m.Text)
	}
}

func TestRenderEscapesHTML(t *testing.T) {
	m, err := Render(KindResetPassword, TemplateData{
		Realm: "<script>alert(1)</script>", Username: `"><img src=x onerror=alert(2)>`,
		Link: "https://idp.example.com/r?t=a&b=\"c\"", Hours: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"<script>", "<img src=x", `"><img`} {
		if strings.Contains(m.HTML, bad) {
			t.Fatalf("unescaped %q in HTML: %s", bad, m.HTML)
		}
	}
	if !strings.Contains(m.HTML, "&lt;script&gt;") {
		t.Fatalf("expected escaped realm: %s", m.HTML)
	}
	if strings.Count(m.HTML, `href="`) != 1 || strings.Contains(m.HTML, `"c"`) {
		t.Fatalf("link attribute not safely escaped: %s", m.HTML)
	}
	// text/template is not HTML-escaped, and that is fine for a plain part.
	if !strings.Contains(m.Text, "<script>") {
		t.Fatalf("text part should be verbatim")
	}
}

func TestRenderRefusesBadLinksAndKinds(t *testing.T) {
	for _, l := range []string{"javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,x", "ftp://h/x", "//h/x", "/relative", "", "https://", "https://h/x\r\nBcc: a@b", "https://h/\x00"} {
		if _, err := Render(KindVerifyEmail, TemplateData{Realm: "R", Link: l, Hours: 1}); err == nil {
			t.Errorf("link %q accepted", l)
		}
	}
	if _, err := Render(Kind("nope"), TemplateData{Realm: "R", Link: "https://h/x", Hours: 1}); err == nil {
		t.Error("unknown kind accepted")
	}
	if _, err := Render(KindVerifyEmail, TemplateData{Realm: "R\r\nBcc: x", Link: "https://h/x", Hours: 1}); err == nil {
		t.Error("control chars in realm accepted")
	}
}

func TestOutbox(t *testing.T) {
	o := NewOutbox(3)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		o.Send(ctx, Message{To: fmt.Sprintf("u%d@x.com", i%2), Subject: fmt.Sprint(i)})
	}
	ms := o.Messages()
	if len(ms) != 3 || ms[0].Subject != "4" || ms[2].Subject != "2" {
		t.Fatalf("%+v", ms)
	}
	if m, ok := o.Last("U0@x.com"); !ok || m.Subject != "4" {
		t.Fatalf("last: %+v %v", m, ok)
	}
	if _, ok := o.Last("none@x.com"); ok {
		t.Fatal("unexpected")
	}
	o.Clear()
	if len(o.Messages()) != 0 {
		t.Fatal("not cleared")
	}
	var zero Outbox
	zero.Send(ctx, Message{})
	if NewOutbox(0).max != 100 || len(zero.Messages()) != 1 {
		t.Fatal("defaults")
	}
}

func TestOutboxConcurrent(t *testing.T) {
	o := NewOutbox(10)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				o.Send(context.Background(), Message{To: "a@b.com"})
				o.Messages()
				o.Last("a@b.com")
			}
		}()
	}
	wg.Wait()
	if len(o.Messages()) != 10 {
		t.Fatal("bound violated")
	}
}

func TestMulti(t *testing.T) {
	e1, e2 := errors.New("first"), errors.New("second")
	var called int
	ok := SenderFunc(func(context.Context, Message) error { called++; return nil })
	s := Multi(
		SenderFunc(func(context.Context, Message) error { called++; return e1 }),
		ok,
		SenderFunc(func(context.Context, Message) error { called++; return e2 }),
	)
	if err := s.Send(context.Background(), Message{}); err != e1 || called != 3 {
		t.Fatalf("err=%v called=%d", err, called)
	}
	if err := Multi().Send(context.Background(), Message{}); err != nil {
		t.Fatal(err)
	}
}

func TestLogSenderNoSecrets(t *testing.T) {
	var buf bytes.Buffer
	s := LogSender(slog.New(slog.NewTextHandler(&buf, nil)))
	err := s.Send(context.Background(), Message{
		To: "alice@example.org", Subject: "Verify", Text: "https://secret.example/tok123", HTML: "<a href=tok123>",
	})
	if err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "example.org") || !strings.Contains(out, "Verify") {
		t.Fatalf("log: %s", out)
	}
	for _, bad := range []string{"alice", "tok123", "secret.example"} {
		if strings.Contains(out, bad) {
			t.Fatalf("log leaks %q: %s", bad, out)
		}
	}
}
