// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package password

import (
	"strings"
	"testing"
)

func TestRoundtripAndRehash(t *testing.T) {
	h := New(TestParams)
	enc, err := h.Hash("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("format: %s", enc)
	}
	if ok, re := h.Verify("s3cret", enc); !ok || re {
		t.Fatalf("ok=%v re=%v", ok, re)
	}
	if ok, _ := h.Verify("wrong", enc); ok {
		t.Fatal("wrong password accepted")
	}
	stronger := New(Params{Memory: 128, Time: 2, Threads: 1})
	if ok, re := stronger.Verify("s3cret", enc); !ok || !re {
		t.Fatalf("want ok+rehash, got %v %v", ok, re)
	}
	a, _ := h.Hash("s3cret")
	if a == enc {
		t.Fatal("salt not random")
	}
}

func TestDefaultParamsFormat(t *testing.T) {
	enc, _ := New(Params{}).Hash("x")
	if !strings.HasPrefix(enc, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatal(enc)
	}
}

func TestMalformedNeverPanics(t *testing.T) {
	h := New(TestParams)
	good, _ := h.Hash("pw")
	for _, s := range []string{
		"", "$", "$$$$$", "garbage", "$argon2id$", "$argon2i$v=19$m=64,t=1,p=1$AAAA$AAAA",
		"$argon2id$v=18$m=64,t=1,p=1$AAAA$AAAAAAAA", "$argon2id$v=x$m=64,t=1,p=1$AAAA$AAAAAAAA",
		"$argon2id$v=19$m=0,t=1,p=1$AAAA$AAAAAAAA", "$argon2id$v=19$m=64,t=0,p=1$AAAA$AAAAAAAA",
		"$argon2id$v=19$m=64,t=1,p=0$AAAA$AAAAAAAA", "$argon2id$v=19$m=99999999999,t=1,p=1$AAAA$AAAAAAAA",
		"$argon2id$v=19$m=262145,t=1,p=1$AAAA$AAAAAAAA", "$argon2id$v=19$m=64,t=1$AAAA$AAAAAAAA",
		"$argon2id$v=19$t=1,m=64,p=1$AAAA$AAAAAAAA", "$argon2id$v=19$m=64,t=1,p=1$!!$AAAAAAAA",
		"$argon2id$v=19$m=64,t=1,p=1$AAAA$!!", "$argon2id$v=19$m=64,t=1,p=1$$AAAAAAAA",
		"$argon2id$v=19$m=64,t=1,p=1$AAAA$", good + "$extra", good[:len(good)-3],
	} {
		if ok, re := h.Verify("pw", s); ok || re {
			t.Errorf("%q accepted", s)
		}
	}
}

func TestCheckPolicy(t *testing.T) {
	tests := []struct {
		policy, pw string
		ok         bool
	}{
		{"", "x", true},
		{"length(8)", "12345678", true},
		{"length(8)", "1234567", false},
		{"length(8) and digits(2)", "abcdefg12", true},
		{"length(8) and digits(2)", "abcdefgh1", false},
		{"upperCase(1) and lowerCase(1) and specialChars(1)", "aB!", true},
		{"upperCase(1) and lowerCase(1) and specialChars(1)", "aB1", false},
		{"upperCase(2)", "Ab", false},
		{"lowerCase(2)", "AB", false},
		{"length(3) and bogus(9) and length(x)", "abc", true},
		{"length(4)", "äöüß", true},
	}
	for _, tc := range tests {
		err := CheckPolicy(tc.policy, tc.pw)
		if (err == nil) != tc.ok {
			t.Errorf("%q %q: err=%v", tc.policy, tc.pw, err)
		}
	}
}
