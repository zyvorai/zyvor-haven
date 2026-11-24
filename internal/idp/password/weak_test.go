// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package password

import (
	"bytes"
	"crypto/sha1" //nolint:gosec
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommonListSize(t *testing.T) {
	if n := CommonListSize(); n < 10000 {
		t.Fatalf("list has %d entries, want >= 10000", n)
	}
}

func TestEveryListEntryRejected(t *testing.T) {
	for w := range commonList() {
		if !IsCommon(w) {
			t.Fatalf("list entry %q not rejected", w)
		}
		if err := CheckPolicy("notCommon()", w); err == nil {
			t.Fatalf("policy accepted list entry %q", w)
		}
	}
}

func TestIsCommonNormalisation(t *testing.T) {
	cases := []struct {
		pw   string
		want bool
	}{
		{"password", true},
		{"PASSWORD", true},
		{"  Password  ", true},
		{"password1", true},
		{"password!!!", true},
		{"Password123!", true}, // 3 stripped is "123" then "!" is 4th, but exact entry password123! exists
		{"password1234", true}, // password1234 is itself an entry
		{"p@ssw0rd", true},
		{"P@$$w0rd", true},
		{"p4ssw0rd9", true}, // fold + strip 1
		{"1ove", true},      // 1->l folds to "love"
		{"", false},
		{"   ", false},
		{"xK9#mQ2vLp7z", false},
		{"correct horse battery staple", false},
		{"passwordX", false}, // letters are never stripped
		{"password98765432", false},
		{"pa", false},
	}
	for _, c := range cases {
		if got := IsCommon(c.pw); got != c.want {
			t.Errorf("IsCommon(%q) = %v, want %v", c.pw, got, c.want)
		}
	}
}

func TestStripBounds(t *testing.T) {
	// "dragon" + 3 symbols is stripped; + 4 non-list symbols is not.
	if !IsCommon("dragon~^&") {
		t.Error("3 trailing symbols should be stripped")
	}
	if IsCommon("dragon~^&*") {
		t.Error("4 trailing symbols must not be stripped")
	}
}

func TestLeetMapping(t *testing.T) {
	// 0->o 1->l|i 3->e 4->a 5->s 7->t @->a $->s
	if got := leetFold("01345 7@$", 'l'); got != "oleas tas" {
		t.Errorf("fold = %q", got)
	}
	if got := leetFold("1", 'i'); got != "i" {
		t.Errorf("1->i variant = %q", got)
	}
	for _, w := range []string{"dr4g0n", "m0nk3y", "sunsh1ne", "l3tm31n"} {
		if !IsCommon(w) {
			t.Errorf("leet variant %q should be rejected", w)
		}
	}
}

func TestPolicyParsing(t *testing.T) {
	good := "Xq7!vLm2#Rt9"
	for _, p := range []string{
		"notCommon()", "notCommon", "NOTCOMMON()", " notCommon ( ) ",
		"length(12) and notCommon() and notPersonal()",
		"length(12)  and   digits(1) and notcommon()",
	} {
		if err := CheckPolicy(p, "password"); err == nil && strings.Contains(strings.ToLower(p), "notcommon") {
			t.Errorf("%q accepted password", p)
		}
		if err := CheckPolicy(p, good); err != nil {
			t.Errorf("%q rejected good password: %v", p, err)
		}
	}
	if err := CheckPolicy("length(12) and notCommon()", "password"); err == nil || !strings.Contains(err.Error(), "length(12)") {
		t.Errorf("length should fail first, got %v", err)
	}
	if err := CheckPolicy("length(8) and notCommon()", "password"); err == nil || !strings.Contains(err.Error(), "too common") {
		t.Errorf("want too common, got %v", err)
	}
}

func TestUnknownTermsStillIgnored(t *testing.T) {
	for _, p := range []string{"notReused()", "frobnicate(3)", "notCommonish()", "forceExpiredPasswordChange(365)", ""} {
		if err := CheckPolicy(p, "password"); err != nil {
			t.Errorf("%q should be ignored, got %v", p, err)
		}
	}
}

func TestErrorsNeverEchoPassword(t *testing.T) {
	pw := "Sup3rUniqueSecret"
	SetBreachFilter(buildFilter(t, []string{pw}, 0.001))
	t.Cleanup(func() { SetBreachFilter(nil) })
	for _, p := range []string{"notBreached()", "notCommon()", "notPersonal()"} {
		for _, pwd := range []string{pw, "dragon", "sup3runiquesecret"} {
			err := CheckPolicyFor(p, pwd, Personal{Username: "sup3runique"})
			if err == nil {
				continue
			}
			msg := strings.ToLower(err.Error())
			sum := sha1.Sum([]byte(pwd)) //nolint:gosec
			if strings.Contains(msg, strings.ToLower(pwd)) || strings.Contains(msg, hex.EncodeToString(sum[:])) {
				t.Errorf("error leaks password/hash: %q", err)
			}
		}
	}
}

func TestPersonal(t *testing.T) {
	p := Personal{Username: "jdoe42", Email: "Jane.Doe@example.com", FirstName: "Jane", LastName: "Do"}
	cases := []struct {
		pw   string
		want bool
	}{
		{"xx-JDOE42-xx", true},
		{"my.jane.doe-pass", true},
		{"JANEiscool", true},
		{"Pa$$jane", true}, // folds to "passjane", which contains jane
		{"nothing-related-9", false},
		{"doe", false},     // last name "Do" too short
		{"example", false}, // email domain not used
	}
	for _, c := range cases {
		err := CheckPolicyFor("notPersonal()", c.pw, p)
		if (err != nil) != c.want {
			t.Errorf("notPersonal(%q) err=%v want reject=%v", c.pw, err, c.want)
		}
	}
	if err := CheckPolicyFor("notPersonal()", "jdoe42", Personal{}); err != nil {
		t.Error("empty Personal must accept")
	}
	if err := CheckPolicy("notPersonal()", "jdoe42"); err != nil {
		t.Error("CheckPolicy has no user context and must accept")
	}
	if err := CheckPolicyFor("length(4)", "jdoe42", p); err != nil {
		t.Error("notPersonal must be opt-in")
	}
	err := CheckPolicyFor("notPersonal()", "jdoe42", p)
	if err == nil || !strings.Contains(err.Error(), "contains your name or email") {
		t.Errorf("message: %v", err)
	}
}

// --- bloom ---

func buildFilter(t testing.TB, pws []string, fp float64) *Bloom {
	t.Helper()
	data, err := BuildBreachFilter(strings.NewReader(strings.Join(pws, "\n")), fp)
	if err != nil {
		t.Fatal(err)
	}
	b, err := UnmarshalBloom(data)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBloomNoFalseNegativesAndFPRate(t *testing.T) {
	const n = 20000
	for _, fp := range []float64{0.01, 0.001} {
		pws := make([]string, n)
		for i := range pws {
			pws[i] = fmt.Sprintf("breached-%d-%x", i, rand.Int63())
		}
		b := buildFilter(t, pws, fp)
		for _, p := range pws {
			if !b.Has(p) {
				t.Fatalf("false negative for %q", p)
			}
		}
		const probes = 200000
		hits := 0
		for i := 0; i < probes; i++ {
			if b.Has(fmt.Sprintf("absent-%d", i)) {
				hits++
			}
		}
		got := float64(hits) / probes
		t.Logf("fp target %.4f measured %.5f (m=%d bits, k=%d, %d bytes)", fp, got, b.Bits(), b.K(), b.Bits()/8)
		if got > fp*2 {
			t.Errorf("measured FP %.5f exceeds 2x target %.4f", got, fp)
		}
	}
}

func FuzzBloomNoFalseNegatives(f *testing.F) {
	f.Add("a", "b", "c")
	f.Add("", "password", "\x00\xff")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		in := []string{a, b, c}
		// lines cannot contain newlines or be empty; those are separate inputs
		var lines []string
		for _, s := range in {
			for _, l := range strings.Split(s, "\n") {
				l = strings.TrimRight(l, "\r")
				if l != "" {
					lines = append(lines, l)
				}
			}
		}
		if len(lines) == 0 {
			return
		}
		data, err := BuildBreachFilter(strings.NewReader(strings.Join(lines, "\n")), 0.01)
		if err != nil {
			t.Fatal(err)
		}
		bf, err := UnmarshalBloom(data)
		if err != nil {
			t.Fatal(err)
		}
		for _, l := range lines {
			d, _ := parseCorpusLine(l)
			if !bf.HasDigest(d) {
				t.Fatalf("false negative for %q", l)
			}
		}
	})
}

func TestBuildInputFormats(t *testing.T) {
	sum := sha1.Sum([]byte("hunter2")) //nolint:gosec
	hexd := strings.ToUpper(hex.EncodeToString(sum[:]))
	in := "plain-text-pw\r\n" + hexd + "\n" + hexd[:0] + strings.ToLower(hex.EncodeToString(sum[:])) + ":12345\n\n"
	b := buildFilter(t, strings.Split(in, "\n"), 0.001)
	if !b.Has("plain-text-pw") || !b.Has("hunter2") {
		t.Error("plaintext and digest lines must both be queryable by plaintext")
	}
	if b.Has("hunter3") {
		t.Error("unexpected hit")
	}
	if _, err := BuildBreachFilter(strings.NewReader("\n\n"), 0.01); err == nil {
		t.Error("empty input must error")
	}
	for _, fp := range []float64{0, 1, -1} {
		if _, err := BuildBreachFilter(strings.NewReader("x"), fp); err == nil {
			t.Errorf("fp %v must error", fp)
		}
	}
}

func TestBloomSerialiseAndLoad(t *testing.T) {
	data, err := BuildBreachFilter(strings.NewReader("alpha\nbeta\n"), 0.01)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "f.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	b, err := LoadBreachFilter(path)
	if err != nil {
		t.Fatal(err)
	}
	re, _ := b.MarshalBinary()
	if !bytes.Equal(re, data) || b.Len() != 2 {
		t.Error("round trip differs")
	}
	for _, bad := range [][]byte{nil, []byte("junk"), data[:len(data)-1], append(append([]byte{}, data...), 0), append([]byte(bloomMagic), 0, 0)} {
		if _, err := UnmarshalBloom(bad); err == nil {
			t.Errorf("accepted corrupt filter of len %d", len(bad))
		}
	}
	if _, err := LoadBreachFilter(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Error("missing file must error")
	}
}

func TestNotBreachedNoopWithoutFilterAndWithFilter(t *testing.T) {
	SetBreachFilter(nil)
	if err := CheckPolicy("notBreached()", "hunter2"); err != nil {
		t.Fatalf("no filter registered must accept: %v", err)
	}
	SetBreachFilter(buildFilter(t, []string{"hunter2"}, 0.0001))
	t.Cleanup(func() { SetBreachFilter(nil) })
	err := CheckPolicy("length(4) and notBreached()", "hunter2")
	if err == nil || !strings.Contains(err.Error(), "known breach") {
		t.Fatalf("want breach error, got %v", err)
	}
	if err := CheckPolicy("notBreached()", "a-different-pw-1"); err != nil {
		t.Fatalf("unlisted pw rejected: %v", err)
	}
	if err := CheckPolicy("length(4)", "hunter2"); err != nil {
		t.Fatal("notBreached must be opt-in")
	}
}

func TestSetBreachFilterConcurrent(t *testing.T) {
	b := buildFilter(t, []string{"x"}, 0.01)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 2000; i++ {
			SetBreachFilter(b)
			SetBreachFilter(nil)
		}
		close(done)
	}()
	for i := 0; i < 2000; i++ {
		_ = CheckPolicy("notBreached()", "x")
	}
	<-done
	SetBreachFilter(nil)
}

// --- benchmarks ---

func BenchmarkIsCommonMiss(b *testing.B) {
	CommonListSize()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsCommon("Xq7!vLm2#Rt9zz1")
	}
}

func BenchmarkIsCommonLeetMiss(b *testing.B) {
	CommonListSize()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsCommon("l3tm31n-and-h4v3n-0k9")
	}
}

func BenchmarkCheckPolicyFull(b *testing.B) {
	CommonListSize()
	p := Personal{Username: "jdoe42", Email: "jane@example.com", FirstName: "Jane", LastName: "Doe"}
	for i := 0; i < b.N; i++ {
		_ = CheckPolicyFor("length(12) and digits(1) and notCommon() and notPersonal() and notBreached()", "Xq7!vLm2#Rt9zz1", p)
	}
}
