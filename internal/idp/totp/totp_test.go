// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package totp

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

var rfcSecret = []byte("12345678901234567890")

// RFC 4226 appendix D.
func TestHOTPVectors(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		if got := HOTP(SHA1, rfcSecret, uint64(i), 6); got != w {
			t.Errorf("HOTP(%d) = %s, want %s", i, got, w)
		}
	}
}

// RFC 6238 appendix B (8 digits; the SHA256/SHA512 seeds are longer).
func TestTOTPVectors(t *testing.T) {
	secrets := map[Algorithm][]byte{
		SHA1:   rfcSecret,
		SHA256: []byte("12345678901234567890123456789012"),
		SHA512: []byte("1234567890123456789012345678901234567890123456789012345678901234"),
	}
	times := []int64{59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000}
	want := map[Algorithm][]string{
		SHA1:   {"94287082", "07081804", "14050471", "89005924", "69279037", "65353130"},
		SHA256: {"46119246", "68084774", "67062674", "91819424", "90698825", "77737706"},
		SHA512: {"90693936", "25091201", "99943326", "93441116", "38618901", "47863826"},
	}
	for alg, sec := range secrets {
		for i, ts := range times {
			got := HOTP(alg, sec, uint64(ts/30), 8)
			if got != want[alg][i] {
				t.Errorf("alg %d t=%d: %s, want %s", alg, ts, got, want[alg][i])
			}
		}
	}
	// The 6-digit default is the low 6 digits of the 8-digit value.
	if got := Code(rfcSecret, time.Unix(59, 0)); got != "287082" {
		t.Errorf("Code at t=59 = %s", got)
	}
}

func TestVerifySkewWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cur := StepAt(now)
	cases := []struct {
		name string
		step int64
		ok   bool
	}{
		{"two steps back", cur - 2, false},
		{"one step back", cur - 1, true},
		{"current", cur, true},
		{"one step ahead", cur + 1, true},
		{"two steps ahead", cur + 2, false},
	}
	for _, c := range cases {
		step, ok := Verify(rfcSecret, CodeAt(rfcSecret, c.step), now, 0)
		if ok != c.ok || (ok && step != c.step) {
			t.Errorf("%s: ok=%v step=%d, want ok=%v step=%d", c.name, ok, step, c.ok, c.step)
		}
	}
	// Edges of the step: the last second of the step and the first of the next.
	edge := time.Unix(cur*30+29, 0)
	if _, ok := Verify(rfcSecret, CodeAt(rfcSecret, cur+1), edge, 0); !ok {
		t.Error("code of the next step rejected at the end of the current one")
	}
	if _, ok := Verify(rfcSecret, CodeAt(rfcSecret, cur-1), time.Unix((cur+1)*30, 0), 0); ok {
		t.Error("code from two steps ago accepted at the start of a step")
	}
}

func TestVerifyReplayProtection(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cur := StepAt(now)
	code := CodeAt(rfcSecret, cur)
	step, ok := Verify(rfcSecret, code, now, 0)
	if !ok || step != cur {
		t.Fatalf("fresh code rejected: %v %d", ok, step)
	}
	if _, ok := Verify(rfcSecret, code, now, step); ok {
		t.Error("code accepted again after its step was recorded")
	}
	// A code from an OLDER step than the last used one is rejected too.
	if _, ok := Verify(rfcSecret, CodeAt(rfcSecret, cur-1), now, cur); ok {
		t.Error("older step accepted after a newer one was used")
	}
	// But a newer step is fine.
	if _, ok := Verify(rfcSecret, CodeAt(rfcSecret, cur+1), now, cur); !ok {
		t.Error("newer step rejected")
	}
}

func TestVerifyInputs(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	good := CodeAt(rfcSecret, StepAt(now))
	for in, want := range map[string]bool{
		good:                              true,
		good[:3] + " " + good[3:]:         true,
		good[:3] + "-" + good[3:]:         true,
		" " + good + " ":                  true,
		good[:5]:                          false,
		good + "0":                        false,
		"":                                false,
		"abcdef":                          false,
		"１２３４５６":                          false, // full-width digits
		strings.Repeat("9", 1000):         false,
		good[:5] + string(rune(0)) + "1":  false,
		"-" + strings.Repeat(" ", 10_000): false,
	} {
		if _, ok := Verify(rfcSecret, in, now, 0); ok != want {
			t.Errorf("Verify(%q) = %v, want %v", in, ok, want)
		}
	}
}

func TestVerifyNearEpoch(t *testing.T) {
	// No negative steps, no panic.
	if _, ok := Verify(rfcSecret, "000000", time.Unix(0, 0), 0); ok && CodeAt(rfcSecret, 0) != "000000" {
		t.Error("unexpected accept")
	}
	// lastUsedStep 0 means "none used yet", so step 0 (1970) never verifies;
	// step 1 does, and no negative step is ever computed.
	if _, ok := Verify(rfcSecret, CodeAt(rfcSecret, 1), time.Unix(0, 0), 0); !ok {
		t.Error("step 1 rejected at the epoch")
	}
	if StepAt(time.Unix(-100, 0)) != 0 {
		t.Error("negative time must clamp to step 0")
	}
}

func TestSeedEncoding(t *testing.T) {
	s := NewSeed()
	if len(s) != SeedSize {
		t.Fatalf("seed size %d", len(s))
	}
	enc := EncodeSeed(s)
	if strings.Contains(enc, "=") || len(enc) != 32 {
		t.Errorf("encoding %q: want 32 chars, no padding", enc)
	}
	for _, v := range []string{enc, strings.ToLower(enc), enc[:8] + " " + enc[8:16] + "-" + enc[16:]} {
		back, err := DecodeSeed(v)
		if err != nil || string(back) != string(s) {
			t.Errorf("roundtrip %q: %v", v, err)
		}
	}
	if string(NewSeed()) == string(s) {
		t.Error("two seeds equal")
	}
	if _, err := DecodeSeed("not base32 !!"); err == nil {
		t.Error("garbage decoded")
	}
}

func TestURI(t *testing.T) {
	seed := rfcSecret
	got := URI("Acme Corp: SSO", "alice+test@example.com", seed)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		t.Fatalf("bad uri %s", got)
	}
	if !strings.HasPrefix(got, "otpauth://totp/Acme%20Corp%3A%20SSO:alice%2Btest%40example.com?") {
		t.Errorf("label not escaped as expected: %s", got)
	}
	q := u.Query()
	if q.Get("issuer") != "Acme Corp: SSO" || q.Get("secret") != EncodeSeed(seed) ||
		q.Get("algorithm") != "SHA1" || q.Get("digits") != "6" || q.Get("period") != "30" {
		t.Errorf("query: %v", q)
	}
	// Hostile input cannot inject parameters or break the label.
	evil := URI("x&secret=AAAA", "a/b?c=d#e", seed)
	eu, err := url.Parse(evil)
	if err != nil {
		t.Fatal(err)
	}
	if eu.Query().Get("secret") != EncodeSeed(seed) || len(eu.Query()["secret"]) != 1 {
		t.Errorf("parameter injection: %s", evil)
	}
	if eu.Fragment != "" || strings.Count(evil, "#") != 0 {
		t.Errorf("fragment injected: %s", evil)
	}
	if noIssuer := URI("", "bob", seed); !strings.HasPrefix(noIssuer, "otpauth://totp/bob?") || strings.Contains(noIssuer, "issuer=") {
		t.Errorf("no issuer: %s", noIssuer)
	}
}

func TestRecoveryCodes(t *testing.T) {
	codes := NewRecoveryCodes(RecoveryCount)
	if len(codes) != 10 {
		t.Fatal(len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != 11 || c[5] != '-' {
			t.Errorf("format %q", c)
		}
		for _, r := range strings.ReplaceAll(c, "-", "") {
			if !strings.ContainsRune(recoveryAlphabet, r) {
				t.Errorf("symbol %q outside the alphabet in %q", r, c)
			}
		}
		if strings.ContainsAny(c, "01IOilo") {
			t.Errorf("ambiguous symbol in %q", c)
		}
		if seen[c] {
			t.Errorf("duplicate %q", c)
		}
		seen[c] = true
		h1, ok := HashRecovery(c)
		h2, _ := HashRecovery(strings.ToLower(strings.ReplaceAll(c, "-", " ")))
		if !ok || h1 != h2 || len(h1) != 64 || strings.Contains(h1, strings.ReplaceAll(c, "-", "")) {
			t.Errorf("hash of %q: %q %q", c, h1, h2)
		}
	}
	for _, bad := range []string{"", "ABCDE-FGHJ", "ABCDE-FGHJK-L", "0BCDE-FGHJK", "ABCDE-FGHJ!", "ABCDE-FGHIK"} {
		if _, ok := HashRecovery(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
	if a, _ := HashRecovery("ABCDE-FGHJK"); a == "" {
		t.Error("valid code rejected")
	}
}

// Property: every code Code() makes is accepted at its own time, the matched
// step is the right one and replaying it fails.
func TestPropertyCodeVerifies(t *testing.T) {
	for i := 0; i < 500; i++ {
		seed := NewSeed()
		now := time.Unix(int64(1_000_000_000+i*7919), 0)
		code := Code(seed, now)
		if len(code) != Digits {
			t.Fatalf("len %d", len(code))
		}
		step, ok := Verify(seed, code, now, 0)
		if !ok || step != StepAt(now) {
			t.Fatalf("own code rejected (seed %x)", seed)
		}
		if _, ok := Verify(seed, code, now, step); ok {
			t.Fatal("replay accepted")
		}
	}
}

func FuzzVerify(f *testing.F) {
	for _, s := range []string{"", "123456", "12 34 56", "abcdef", "１２３４５６", "000000", "-1-2-3-4-5-6"} {
		f.Add(s, int64(1_700_000_000), int64(0))
	}
	f.Fuzz(func(t *testing.T, code string, ts, last int64) {
		step, ok := Verify(rfcSecret, code, time.Unix(ts, 0), last)
		if ok {
			if norm, valid := NormalizeCode(code); !valid || CodeAt(rfcSecret, step) != norm {
				t.Fatalf("accepted %q for step %d", code, step)
			}
			if step <= last {
				t.Fatalf("step %d <= last %d accepted", step, last)
			}
			if d := step - StepAt(time.Unix(ts, 0)); d < -Skew || d > Skew {
				t.Fatalf("step %d outside the skew window", step)
			}
		}
	})
}

func FuzzDecodeAndRecovery(f *testing.F) {
	f.Add("JBSWY3DPEHPK3PXP")
	f.Add("ABCDE-FGHJK")
	f.Fuzz(func(t *testing.T, s string) {
		if b, err := DecodeSeed(s); err == nil {
			if _, err := DecodeSeed(EncodeSeed(b)); err != nil {
				t.Fatal(err)
			}
		}
		if n, ok := NormalizeRecovery(s); ok && len(n) != recoveryLen {
			t.Fatalf("normalised %q has length %d", s, len(n))
		}
		_ = URI(s, s, rfcSecret)
	})
}
