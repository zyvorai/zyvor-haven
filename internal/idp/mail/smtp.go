// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package mail

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"
)

// SMTPConfig configures the SMTP sender.
type SMTPConfig struct {
	Host     string
	Port     int // default: 587 (starttls), 465 (implicit), 25 (none)
	Username string
	Password string
	From     string // RFC 5322 address, e.g. "Haven <no-reply@example.com>"
	// TLS is "starttls" (default), "implicit" or "none". AUTH is only ever
	// sent over TLS, except TLS=="none" to a loopback host.
	TLS                string
	Timeout            time.Duration // whole-session budget; default 30s
	InsecureSkipVerify bool          // disables certificate verification; testing only
	HeloName           string        // EHLO name; default "localhost"
}

type smtpSender struct {
	cfg  SMTPConfig
	from *mail.Address
}

// NewSMTP validates cfg and returns an SMTP Sender.
func NewSMTP(cfg SMTPConfig) (Sender, error) {
	if cfg.Host == "" || strings.ContainsAny(cfg.Host, " \t\r\n/") {
		return nil, errors.New("mail: smtp host is empty or invalid")
	}
	switch cfg.TLS {
	case "":
		cfg.TLS = "starttls"
	case "starttls", "implicit", "none":
	default:
		return nil, fmt.Errorf("mail: smtp tls mode %q must be starttls, implicit or none", cfg.TLS)
	}
	if cfg.Port == 0 {
		switch cfg.TLS {
		case "implicit":
			cfg.Port = 465
		case "none":
			cfg.Port = 25
		default:
			cfg.Port = 587
		}
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("mail: smtp port %d out of range", cfg.Port)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.HeloName == "" {
		cfg.HeloName = "localhost"
	}
	if hasCtl(cfg.HeloName) || strings.Contains(cfg.HeloName, " ") {
		return nil, errors.New("mail: invalid smtp helo name")
	}
	if cfg.Username != "" || cfg.Password != "" {
		if cfg.TLS == "none" && !isLoopback(cfg.Host) {
			return nil, errors.New("mail: refusing smtp AUTH over a plaintext connection to a non-loopback host")
		}
	}
	from, err := parseAddr(cfg.From)
	if err != nil {
		return nil, fmt.Errorf("mail: invalid From: %w", err)
	}
	return &smtpSender{cfg: cfg, from: from}, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func hasCtl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// parseAddr parses one RFC 5322 mailbox, rejecting control characters (so CR
// and LF can never reach a header or the SMTP envelope) and non-ASCII
// addresses.
func parseAddr(s string) (*mail.Address, error) {
	if hasCtl(s) {
		return nil, errors.New("address contains control characters")
	}
	a, err := mail.ParseAddress(strings.TrimSpace(s))
	if err != nil {
		return nil, errors.New("address does not parse")
	}
	if hasCtl(a.Address) || strings.ContainsAny(a.Address, "<>,;\"") {
		return nil, errors.New("address contains forbidden characters")
	}
	for i := 0; i < len(a.Address); i++ {
		if a.Address[i] >= 0x80 {
			return nil, errors.New("non-ASCII addresses are not supported")
		}
	}
	return a, nil
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func writeQP(w io.Writer, body string) error {
	qw := quotedprintable.NewWriter(w)
	if _, err := qw.Write([]byte(body)); err != nil {
		return err
	}
	return qw.Close()
}

// build validates m and renders the RFC 5322 message (CRLF line endings).
// It returns the bytes and the validated recipient address.
func (s *smtpSender) build(m Message, now time.Time) ([]byte, string, error) {
	to, err := parseAddr(m.To)
	if err != nil {
		return nil, "", fmt.Errorf("mail: invalid To: %w", err)
	}
	if hasCtl(m.Subject) {
		return nil, "", errors.New("mail: subject contains control characters")
	}
	domain := s.from.Address[strings.LastIndexByte(s.from.Address, '@')+1:]
	id, err := randHex(16)
	if err != nil {
		return nil, "", err
	}

	var b strings.Builder
	hdr := func(k, v string) { b.WriteString(k + ": " + v + "\r\n") }
	hdr("Date", now.Format(time.RFC1123Z))
	hdr("Message-ID", "<"+id+"@"+domain+">")
	hdr("From", s.from.String())
	hdr("To", (&mail.Address{Address: to.Address}).String())
	hdr("Subject", mime.QEncoding.Encode("utf-8", m.Subject))
	hdr("MIME-Version", "1.0")
	hdr("Auto-Submitted", "auto-generated")

	if m.HTML == "" {
		hdr("Content-Type", `text/plain; charset="utf-8"`)
		hdr("Content-Transfer-Encoding", "quoted-printable")
		b.WriteString("\r\n")
		if err := writeQP(&b, m.Text); err != nil {
			return nil, "", err
		}
		return []byte(b.String()), to.Address, nil
	}

	var body strings.Builder
	mw := multipart.NewWriter(&body)
	hdr("Content-Type", `multipart/alternative; boundary="`+mw.Boundary()+`"`)
	b.WriteString("\r\n")
	for _, p := range []struct{ ct, text string }{
		{`text/plain; charset="utf-8"`, m.Text},
		{`text/html; charset="utf-8"`, m.HTML},
	} {
		pw, err := mw.CreatePart(textproto.MIMEHeader{
			"Content-Type":              {p.ct},
			"Content-Transfer-Encoding": {"quoted-printable"},
		})
		if err != nil {
			return nil, "", err
		}
		if err := writeQP(pw, p.text); err != nil {
			return nil, "", err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, "", err
	}
	b.WriteString(body.String())
	return []byte(b.String()), to.Address, nil
}

// Send implements Sender. Invalid messages are rejected before any network
// activity.
func (s *smtpSender) Send(ctx context.Context, m Message) error {
	data, rcpt, err := s.build(m, time.Now())
	if err != nil {
		return err
	}
	if err := s.deliver(ctx, rcpt, data); err != nil {
		return fmt.Errorf("mail: smtp send via %s:%d: %w", s.cfg.Host, s.cfg.Port, err)
	}
	return nil
}

func (s *smtpSender) deliver(ctx context.Context, rcpt string, data []byte) error {
	cfg := s.cfg
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	deadline := time.Now().Add(cfg.Timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	dctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	var d net.Dialer
	raw, err := d.DialContext(dctx, "tcp", addr)
	if err != nil {
		return err
	}
	// Closing the connection unblocks any in-flight I/O when the context ends.
	stop := context.AfterFunc(dctx, func() { _ = raw.Close() })
	defer stop()
	defer func() { _ = raw.Close() }()
	_ = raw.SetDeadline(deadline)

	tlsCfg := &tls.Config{
		ServerName: cfg.Host,
		MinVersion: tls.VersionTLS12,
		// #nosec G402 -- explicit operator opt-in for lab SMTP servers; verification is on by default
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // explicit opt-in
	}
	conn := raw
	if cfg.TLS == "implicit" {
		tc := tls.Client(raw, tlsCfg)
		if err := tc.HandshakeContext(dctx); err != nil {
			return ctxErr(dctx, err)
		}
		conn = tc
	}
	c, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return ctxErr(dctx, err)
	}
	defer func() { _ = c.Close() }()
	if err := s.session(c, tlsCfg, rcpt, data); err != nil {
		return ctxErr(dctx, err)
	}
	return nil
}

func (s *smtpSender) session(c *smtp.Client, tlsCfg *tls.Config, rcpt string, data []byte) error {
	cfg := s.cfg
	if err := c.Hello(cfg.HeloName); err != nil {
		return err
	}
	secure := cfg.TLS == "implicit"
	if cfg.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("server does not offer STARTTLS; refusing to continue in plaintext")
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			return err
		}
		secure = true
	}
	if cfg.Username != "" {
		if !secure && !isLoopback(cfg.Host) {
			return errors.New("refusing AUTH over plaintext")
		}
		if ok, _ := c.Extension("AUTH"); !ok {
			return errors.New("server does not offer AUTH")
		}
		// net/smtp's PlainAuth also refuses non-TLS unless loopback.
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)); err != nil {
			return errors.New("authentication failed: " + redact(err.Error(), cfg.Password))
		}
	}
	if err := c.Mail(s.from.Address); err != nil {
		return err
	}
	if err := c.Rcpt(rcpt); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	// net/smtp's DATA writer performs dot-stuffing; do not stuff here.
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func redact(s, secret string) string {
	if secret == "" {
		return s
	}
	return strings.ReplaceAll(s, secret, "[redacted]")
}

func ctxErr(ctx context.Context, err error) error {
	if ce := ctx.Err(); ce != nil {
		return fmt.Errorf("%w (%v)", ce, err)
	}
	return err
}
