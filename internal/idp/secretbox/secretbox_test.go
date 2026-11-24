// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package secretbox

import (
	"bytes"
	"strings"
	"testing"
)

func mustBox(t *testing.T, keys ...string) *Box {
	t.Helper()
	var ks [][]byte
	for _, k := range keys {
		b, err := ParseKey(k)
		if err != nil {
			t.Fatal(err)
		}
		ks = append(ks, b)
	}
	b, err := New(ks...)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundtripAndBinding(t *testing.T) {
	b := mustBox(t, GenerateKey())
	s := b.Seal([]byte("JBSWY3DPEHPK3PXP"), "totp|realm|u1")
	if strings.Contains(s, "JBSWY3DP") {
		t.Fatal("plaintext visible in the sealed form")
	}
	if pt, err := b.Open(s, "totp|realm|u1"); err != nil || !bytes.Equal(pt, []byte("JBSWY3DPEHPK3PXP")) {
		t.Fatalf("roundtrip: %v %q", err, pt)
	}
	for name, ctx := range map[string]string{"other user": "totp|realm|u2", "other purpose": "idp|realm|u1", "empty": ""} {
		if _, err := b.Open(s, ctx); err == nil {
			t.Errorf("opened with the wrong context (%s)", name)
		}
	}
	if s2 := b.Seal([]byte("x"), "c"); s2 == b.Seal([]byte("x"), "c") {
		t.Error("two seals of the same message are identical: nonce reuse")
	}
}

func TestTamperWrongKeyAndGarbage(t *testing.T) {
	b := mustBox(t, GenerateKey())
	s := b.Seal([]byte("secret"), "c")
	flip := s[:len(s)-3] + "AAA"
	for name, in := range map[string]string{"tampered": flip, "garbage": "nope", "no prefix": s[3:], "empty": "", "truncated": s[:10]} {
		if _, err := b.Open(in, "c"); err != ErrOpen {
			t.Errorf("%s: got %v, want ErrOpen", name, err)
		}
	}
	if _, err := mustBox(t, GenerateKey()).Open(s, "c"); err != ErrOpen {
		t.Error("another key opened the message")
	}
}

func TestRotation(t *testing.T) {
	oldK, newK := GenerateKey(), GenerateKey()
	sealedOld := mustBox(t, oldK).Seal([]byte("v"), "c")
	rot := mustBox(t, newK, oldK) // new key seals, old key still opens
	if pt, err := rot.Open(sealedOld, "c"); err != nil || string(pt) != "v" {
		t.Fatalf("rotated box cannot open old data: %v", err)
	}
	if _, err := mustBox(t, oldK).Open(rot.Seal([]byte("v"), "c"), "c"); err == nil {
		t.Error("old-key-only box opened data sealed with the new key")
	}
}

func TestParseKey(t *testing.T) {
	k := GenerateKey()
	if _, err := ParseKey(k); err != nil {
		t.Errorf("generated key rejected: %v", err)
	}
	hexKey := strings.Repeat("ab", 32)
	if b, err := ParseKey(hexKey); err != nil || len(b) != 32 {
		t.Errorf("hex key: %v", err)
	}
	for _, bad := range []string{"", "short", strings.Repeat("a", 63), "!!!!"} {
		if _, err := ParseKey(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, err := New([]byte("short")); err == nil {
		t.Error("short key accepted by New")
	}
	if _, err := ParseKeys(" , "); err == nil {
		t.Error("empty key list accepted")
	}
}
