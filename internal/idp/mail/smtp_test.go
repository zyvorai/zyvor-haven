// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package mail

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	stdmail "net/mail"
	"strings"
	"sync"
	"testing"
	"time"
)

func selfSigned(t testing.TB) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

type fakeSrv struct {
	ln       net.Listener
	mode     string // "starttls", "implicit", "none"
	noStart  bool   // starttls mode but do not advertise STARTTLS
	hang     bool   // accept and say nothing
	cert     tls.Certificate
	mu       sync.Mutex
	cmds     []string
	authLine string
	from     string
	rcpts    []string
	data     []byte
	wire     []byte // DATA as received, still dot-stuffed
	conns    int
}

func newFakeSrv(t *testing.T, mode string, opts ...string) *fakeSrv {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSrv{ln: ln, mode: mode, cert: selfSigned(t)}
	for _, o := range opts {
		s.hang = s.hang || o == "hang"
		s.noStart = s.noStart || o == "nostarttls"
	}
	t.Cleanup(func() { ln.Close() })
	go s.loop()
	return s
}

func (s *fakeSrv) port() int { return s.ln.Addr().(*net.TCPAddr).Port }

func (s *fakeSrv) loop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns++
		s.mu.Unlock()
		go s.serve(c)
	}
}

func (s *fakeSrv) snapshot() (cmds []string, auth, from string, rcpts []string, data []byte, conns int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.cmds...), s.authLine, s.from, append([]string(nil), s.rcpts...), append([]byte(nil), s.data...), s.conns
}

func (s *fakeSrv) serve(raw net.Conn) {
	defer raw.Close()
	if s.hang {
		io.Copy(io.Discard, raw)
		return
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{s.cert}}
	var conn net.Conn = raw
	if s.mode == "implicit" {
		conn = tls.Server(raw, cfg)
	}
	r := bufio.NewReader(conn)
	reply := func(f string) { io.WriteString(conn, f+"\r\n") }
	secure := s.mode == "implicit"
	reply("220 fake ESMTP")
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		verb := strings.ToUpper(line)
		s.mu.Lock()
		if strings.HasPrefix(verb, "AUTH ") {
			s.authLine = line
			s.cmds = append(s.cmds, "AUTH")
		} else {
			s.cmds = append(s.cmds, line)
		}
		s.mu.Unlock()
		switch {
		case strings.HasPrefix(verb, "EHLO"):
			io.WriteString(conn, "250-fake\r\n")
			if s.mode == "starttls" && !secure && !s.noStart {
				io.WriteString(conn, "250-STARTTLS\r\n")
			}
			io.WriteString(conn, "250 AUTH PLAIN\r\n")
		case verb == "STARTTLS":
			reply("220 go ahead")
			tc := tls.Server(raw, cfg)
			if err := tc.Handshake(); err != nil {
				return
			}
			conn = tc
			r = bufio.NewReader(conn)
			secure = true
		case strings.HasPrefix(verb, "AUTH PLAIN"):
			reply("235 ok")
		case strings.HasPrefix(verb, "MAIL FROM:"):
			s.mu.Lock()
			s.from = line
			s.mu.Unlock()
			reply("250 ok")
		case strings.HasPrefix(verb, "RCPT TO:"):
			s.mu.Lock()
			s.rcpts = append(s.rcpts, line)
			s.mu.Unlock()
			reply("250 ok")
		case verb == "DATA":
			reply("354 go")
			var buf, wire bytes.Buffer
			for {
				l, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if l == ".\r\n" {
					break
				}
				wire.WriteString(l)
				buf.WriteString(strings.TrimPrefix(l, "."))
			}
			s.mu.Lock()
			s.data = buf.Bytes()
			s.wire = wire.Bytes()
			s.mu.Unlock()
			reply("250 queued")
		case verb == "QUIT":
			reply("221 bye")
			return
		default:
			reply("250 ok")
		}
	}
}

func cfgFor(s *fakeSrv) SMTPConfig {
	return SMTPConfig{
		Host: "127.0.0.1", Port: s.port(), From: "Haven <no-reply@example.com>",
		TLS: s.mode, InsecureSkipVerify: true, Timeout: 5 * time.Second,
	}
}

func TestSendSTARTTLSAuthMultipart(t *testing.T) {
	srv := newFakeSrv(t, "starttls")
	cfg := cfgFor(srv)
	cfg.Username, cfg.Password = "user", "s3cret-pw"
	snd, err := NewSMTP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	subj := "Vérifiez votre adresse ✓"
	text := "Hello\n.leading dot line\nlink: https://x.example/a?b=c&d=é\n"
	err = snd.Send(context.Background(), Message{To: "alice@example.org", Subject: subj, Text: text, HTML: "<p>Hi <b>there</b></p>"})
	if err != nil {
		t.Fatal(err)
	}
	cmds, auth, from, rcpts, data, _ := srv.snapshot()
	// STARTTLS must precede AUTH.
	idx := func(p string) int {
		for i, c := range cmds {
			if strings.HasPrefix(strings.ToUpper(c), p) {
				return i
			}
		}
		return -1
	}
	if idx("STARTTLS") < 0 || idx("AUTH") < idx("STARTTLS") {
		t.Fatalf("AUTH not after STARTTLS: %v", cmds)
	}
	raw, _ := base64.StdEncoding.DecodeString(strings.Fields(auth)[2])
	if string(raw) != "\x00user\x00s3cret-pw" {
		t.Fatalf("bad auth payload %q", raw)
	}
	if !strings.Contains(from, "<no-reply@example.com>") || len(rcpts) != 1 || !strings.Contains(rcpts[0], "<alice@example.org>") {
		t.Fatalf("envelope: %q %v", from, rcpts)
	}

	msg, err := stdmail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	dec := new(mime.WordDecoder)
	gotSubj, err := dec.DecodeHeader(msg.Header.Get("Subject"))
	if err != nil || gotSubj != subj {
		t.Fatalf("subject %q err %v", gotSubj, err)
	}
	if strings.Contains(msg.Header.Get("Subject"), "é") {
		t.Fatal("subject not RFC 2047 encoded")
	}
	for _, h := range []string{"Date", "Message-ID", "From", "To", "MIME-Version"} {
		if msg.Header.Get(h) == "" {
			t.Fatalf("missing header %s", h)
		}
	}
	if _, err := msg.Header.Date(); err != nil {
		t.Fatal(err)
	}
	if a, _ := stdmail.ParseAddress(msg.Header.Get("To")); a == nil || a.Address != "alice@example.org" {
		t.Fatalf("To %q", msg.Header.Get("To"))
	}
	mt, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || mt != "multipart/alternative" {
		t.Fatalf("content-type %q %v", mt, err)
	}
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var parts []string
	for {
		p, err := mr.NextRawPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if p.Header.Get("Content-Transfer-Encoding") != "quoted-printable" {
			t.Fatal("part not quoted-printable")
		}
		b, err := io.ReadAll(quotedprintable.NewReader(p))
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, string(b))
	}
	if len(parts) != 2 {
		t.Fatalf("parts: %d", len(parts))
	}
	// QP decoding yields CRLF; dot-stuffing must be reversed exactly once.
	if got := strings.ReplaceAll(parts[0], "\r\n", "\n"); got != text {
		t.Fatalf("text part %q != %q", got, text)
	}
	if !strings.Contains(parts[1], "<b>there</b>") {
		t.Fatalf("html part %q", parts[1])
	}
}

func TestSendPlainTextImplicitTLS(t *testing.T) {
	srv := newFakeSrv(t, "implicit")
	snd, err := NewSMTP(cfgFor(srv))
	if err != nil {
		t.Fatal(err)
	}
	if err := snd.Send(context.Background(), Message{To: "bob@example.org", Subject: "plain", Text: "body\n"}); err != nil {
		t.Fatal(err)
	}
	_, _, _, _, data, _ := srv.snapshot()
	msg, err := stdmail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(msg.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("content-type %q", msg.Header.Get("Content-Type"))
	}
	b, _ := io.ReadAll(quotedprintable.NewReader(msg.Body))
	if strings.TrimSpace(string(b)) != "body" {
		t.Fatalf("body %q", b)
	}
}

func TestCertificateVerificationOn(t *testing.T) {
	srv := newFakeSrv(t, "starttls")
	cfg := cfgFor(srv)
	cfg.InsecureSkipVerify = false // self-signed cert must be rejected
	snd, _ := NewSMTP(cfg)
	err := snd.Send(context.Background(), Message{To: "a@example.org", Subject: "s", Text: "t"})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected certificate error, got %v", err)
	}
	_, _, from, _, _, _ := srv.snapshot()
	if from != "" {
		t.Fatal("mail was transmitted despite failed verification")
	}
}

func TestNoSTARTTLSNoDowngrade(t *testing.T) {
	srv := newFakeSrv(t, "starttls", "nostarttls")
	cfg := cfgFor(srv)
	cfg.Username, cfg.Password = "user", "pw-secret"
	snd, _ := NewSMTP(cfg)
	err := snd.Send(context.Background(), Message{To: "a@example.org", Subject: "s", Text: "t"})
	if err == nil {
		t.Fatal("expected refusal")
	}
	if strings.Contains(err.Error(), "pw-secret") {
		t.Fatal("password leaked in error")
	}
	cmds, auth, _, _, _, _ := srv.snapshot()
	if auth != "" {
		t.Fatalf("AUTH sent in plaintext: %v", cmds)
	}
}

func TestNewSMTPValidation(t *testing.T) {
	ok := SMTPConfig{Host: "smtp.example.com", From: "no-reply@example.com"}
	if _, err := NewSMTP(ok); err != nil {
		t.Fatal(err)
	}
	cases := map[string]SMTPConfig{
		"no host":           {From: "a@b.com"},
		"bad from":          {Host: "h", From: "not an address"},
		"empty from":        {Host: "h"},
		"crlf from":         {Host: "h", From: "a@b.com\r\nBcc: x@y.com"},
		"bad tls":           {Host: "h", From: "a@b.com", TLS: "weird"},
		"bad port":          {Host: "h", From: "a@b.com", Port: 70000},
		"plain auth remote": {Host: "smtp.example.com", From: "a@b.com", TLS: "none", Username: "u", Password: "p"},
	}
	for name, c := range cases {
		if _, err := NewSMTP(c); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// Explicit plaintext AUTH to loopback is allowed.
	if _, err := NewSMTP(SMTPConfig{Host: "127.0.0.1", From: "a@b.com", TLS: "none", Username: "u", Password: "p"}); err != nil {
		t.Errorf("loopback plaintext auth: %v", err)
	}
	// Password must not appear in config errors.
	_, err := NewSMTP(SMTPConfig{Host: "smtp.example.com", From: "a@b.com", TLS: "none", Username: "u", Password: "hunter2"})
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("err %v", err)
	}
}

func TestPlainLoopbackAuthWorks(t *testing.T) {
	srv := newFakeSrv(t, "none")
	cfg := cfgFor(srv)
	cfg.Username, cfg.Password = "u", "p"
	snd, err := NewSMTP(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := snd.Send(context.Background(), Message{To: "a@example.org", Subject: "s", Text: "t"}); err != nil {
		t.Fatal(err)
	}
}

func TestHeaderInjectionRejectedBeforeNetwork(t *testing.T) {
	srv := newFakeSrv(t, "starttls")
	snd, err := NewSMTP(cfgFor(srv))
	if err != nil {
		t.Fatal(err)
	}
	bad := []Message{
		{To: "a@example.org\r\nBcc: evil@example.com", Subject: "s", Text: "t"},
		{To: "a@example.org\nBcc: evil@example.com", Subject: "s", Text: "t"},
		{To: "a@example.org>\r\nRCPT TO:<evil@example.com", Subject: "s", Text: "t"},
		{To: "a@example.org, evil@example.com", Subject: "s", Text: "t"},
		{To: "", Subject: "s", Text: "t"},
		{To: "not-an-address", Subject: "s", Text: "t"},
		{To: "a@example.org", Subject: "hi\r\nBcc: evil@example.com", Text: "t"},
		{To: "a@example.org", Subject: "hi\nBcc: evil@example.com", Text: "t"},
		{To: "a@example.org", Subject: "hi\rBcc: evil@example.com", Text: "t"},
	}
	for i, m := range bad {
		if err := snd.Send(context.Background(), m); err == nil {
			t.Errorf("case %d: expected rejection", i)
		}
	}
	_, _, _, _, _, conns := srv.snapshot()
	if conns != 0 {
		t.Fatalf("server saw %d connections; injection attempts must not reach it", conns)
	}
}

func TestTimeoutHonoured(t *testing.T) {
	srv := newFakeSrv(t, "starttls", "hang")
	cfg := cfgFor(srv)
	cfg.Timeout = 300 * time.Millisecond
	snd, _ := NewSMTP(cfg)
	start := time.Now()
	err := snd.Send(context.Background(), Message{To: "a@example.org", Subject: "s", Text: "t"})
	if err == nil {
		t.Fatal("expected timeout")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("took %v", el)
	}
}

func TestContextCancelHonoured(t *testing.T) {
	srv := newFakeSrv(t, "starttls", "hang")
	snd, _ := NewSMTP(cfgFor(srv)) // 5s timeout; ctx is shorter
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := snd.Send(ctx, Message{To: "a@example.org", Subject: "s", Text: "t"})
	if err == nil {
		t.Fatal("expected error")
	}
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("took %v", el)
	}
}

func TestDotStuffingNotDoubled(t *testing.T) {
	srv := newFakeSrv(t, "implicit")
	snd, _ := NewSMTP(cfgFor(srv))
	if err := snd.Send(context.Background(), Message{To: "a@example.org", Subject: "s", Text: "a\n.\n..x\n"}); err != nil {
		t.Fatal(err)
	}
	srv.mu.Lock()
	data := srv.wire
	srv.mu.Unlock()
	// The server's reader stops at the lone "." terminator, so a doubled or
	// missing stuffing would truncate or alter the body. QP encodes a line
	// of "." as-is, so the wire form carries exactly one stuffed dot.
	if !bytes.Contains(data, []byte("\r\n..\r\n")) || !bytes.Contains(data, []byte("\r\n...x")) {
		t.Fatalf("unexpected wire data %q", data)
	}
}

// FuzzHeaderInjection: whatever To/Subject are, a built message must parse to
// exactly the expected header set (no injected headers or body break).
func FuzzHeaderInjection(f *testing.F) {
	for _, s := range []string{"a@b.com", "a@b.com\r\nBcc: x@y.z", "x\nBcc: y", "é@b.com", "\"a b\"@c.com"} {
		f.Add(s, s)
	}
	s := &smtpSender{from: &stdmail.Address{Name: "Haven", Address: "no-reply@example.com"}}
	allowed := map[string]bool{"Date": true, "Message-Id": true, "From": true, "To": true, "Subject": true,
		"Mime-Version": true, "Auto-Submitted": true, "Content-Type": true, "Content-Transfer-Encoding": true}
	f.Fuzz(func(t *testing.T, to, subject string) {
		data, rcpt, err := s.build(Message{To: to, Subject: subject, Text: "x"}, time.Unix(0, 0))
		if err != nil {
			return
		}
		if hasCtl(rcpt) {
			t.Fatalf("control chars in envelope recipient %q", rcpt)
		}
		msg, err := stdmail.ReadMessage(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("unparseable: %v", err)
		}
		for k := range msg.Header {
			if !allowed[k] {
				t.Fatalf("injected header %q (to=%q subject=%q)", k, to, subject)
			}
		}
		if got, err := new(mime.WordDecoder).DecodeHeader(msg.Header.Get("Subject")); err != nil || strings.TrimSpace(got) != strings.TrimSpace(subject) { // header parsing trims edge whitespace
			t.Fatalf("subject round trip %q -> %q (%v)", subject, got, err)
		}
	})
}
