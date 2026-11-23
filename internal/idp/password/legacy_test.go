// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package password

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

type vector struct {
	Algorithm  string `json:"algorithm"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
	KeyLen     int    `json:"keyLen"`
	Password   string `json:"password"`
	Salt       string `json:"salt_b64_padded"`
	Value      string `json:"value_b64_padded"`
	PHC        string `json:"phc"`
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	b, err := os.ReadFile("testdata/pbkdf2_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(b, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 20 {
		t.Fatalf("only %d vectors", len(vs))
	}
	return vs
}

func TestPBKDF2IndependentVectors(t *testing.T) {
	h := New(TestParams)
	for _, v := range loadVectors(t) {
		name := fmt.Sprintf("%s/%d/%q", v.Algorithm, v.Iterations, v.Password)
		t.Run(name, func(t *testing.T) {
			// Via FromKeycloak (padded base64, as in the export).
			got, err := FromKeycloak(KeycloakCredential{Algorithm: v.Algorithm, Iterations: v.Iterations, Salt: v.Salt, Value: v.Value})
			if err != nil {
				t.Fatal(err)
			}
			if got != v.PHC {
				t.Fatalf("FromKeycloak = %s, want %s", got, v.PHC)
			}
			// Unpadded input is accepted too and yields the same string.
			got2, err := FromKeycloak(KeycloakCredential{Algorithm: v.Algorithm, Iterations: v.Iterations,
				Salt: strings.TrimRight(v.Salt, "="), Value: strings.TrimRight(v.Value, "=")})
			if err != nil || got2 != v.PHC {
				t.Fatalf("unpadded: %v %s", err, got2)
			}
			for _, enc := range []string{v.PHC} { // equal to the converter output, asserted above
				if err := ValidateEncoded(enc); err != nil {
					t.Fatal(err)
				}
				if ok, re := h.Verify(v.Password, enc); !ok || !re {
					t.Fatalf("right password: ok=%v rehash=%v", ok, re)
				}
				if ok, re := h.Verify(v.Password+"x", enc); ok || re {
					t.Fatalf("wrong password: ok=%v rehash=%v", ok, re)
				}
				if ok, _ := h.Verify("", enc); ok {
					t.Fatal("empty password accepted")
				}
			}
		})
	}
}

func TestKeycloakKeyLengthFollowsValue(t *testing.T) {
	for _, v := range loadVectors(t) {
		raw, _ := base64.StdEncoding.DecodeString(v.Value)
		if len(raw) != v.KeyLen {
			t.Fatalf("vector keyLen %d != decoded %d", v.KeyLen, len(raw))
		}
	}
}

func argonVector(t *testing.T, typ string, mem, iter, par uint32, pw string) (KeycloakCredential, []byte, []byte) {
	t.Helper()
	salt := []byte("0123456789abcdef")
	var key []byte
	if typ == "id" {
		key = argon2.IDKey([]byte(pw), salt, iter, mem, uint8(par), 32)
	} else {
		key = argon2.Key([]byte(pw), salt, iter, mem, uint8(par), 32)
	}
	return KeycloakCredential{
		Algorithm: "argon2", Iterations: int(iter),
		Salt: base64.StdEncoding.EncodeToString(salt), Value: base64.StdEncoding.EncodeToString(key),
		Extra: map[string][]string{"memory": {fmt.Sprint(mem)}, "parallelism": {fmt.Sprint(par)}, "type": {typ},
			"version": {"19"}, "hashLength": {"32"}},
	}, salt, key
}

func TestArgon2KeycloakMapping(t *testing.T) {
	h := New(TestParams)
	for _, typ := range []string{"id", "i"} {
		// Distinct memory/iterations/parallelism so a swapped mapping cannot verify.
		c, salt, key := argonVector(t, typ, 1024, 3, 2, "S3cret-pass-1")
		got, err := FromKeycloak(c)
		if err != nil {
			t.Fatal(err)
		}
		want := fmt.Sprintf("$argon2%s$v=19$m=1024,t=3,p=2$%s$%s", typ, enc.EncodeToString(salt), enc.EncodeToString(key))
		if got != want {
			t.Fatalf("%s: got %s want %s", typ, got, want)
		}
		ok, re := h.Verify("S3cret-pass-1", got)
		if !ok {
			t.Fatalf("%s: right password rejected", typ)
		}
		if typ == "i" && !re {
			t.Fatal("argon2i must need rehash")
		}
		// argon2id with params stronger than TestParams: no rehash needed.
		if typ == "id" && re {
			t.Fatal("argon2id with stronger params should not need rehash")
		}
		if ok, _ := h.Verify("wrong", got); ok {
			t.Fatalf("%s: wrong password accepted", typ)
		}
		// i and id must not be interchangeable.
		other := strings.Replace(got, "$argon2"+typ+"$", "$argon2"+map[string]string{"id": "i", "i": "id"}[typ]+"$", 1)
		if ok, _ := h.Verify("S3cret-pass-1", other); ok {
			t.Fatalf("%s: verified under the other variant", typ)
		}
	}
}

func TestArgon2KeycloakErrors(t *testing.T) {
	base, _, _ := argonVector(t, "id", 1024, 3, 2, "pw")
	mut := func(f func(c *KeycloakCredential)) KeycloakCredential {
		c := base
		c.Extra = map[string][]string{}
		for k, v := range base.Extra {
			c.Extra[k] = v
		}
		f(&c)
		return c
	}
	cases := map[string]KeycloakCredential{
		"type d":          mut(func(c *KeycloakCredential) { c.Extra["type"] = []string{"d"} }),
		"type missing":    mut(func(c *KeycloakCredential) { delete(c.Extra, "type") }),
		"bad version":     mut(func(c *KeycloakCredential) { c.Extra["version"] = []string{"16"} }),
		"memory huge":     mut(func(c *KeycloakCredential) { c.Extra["memory"] = []string{"4194304"} }),
		"memory nan":      mut(func(c *KeycloakCredential) { c.Extra["memory"] = []string{"lots"} }),
		"par huge":        mut(func(c *KeycloakCredential) { c.Extra["parallelism"] = []string{"17"} }),
		"iter huge":       mut(func(c *KeycloakCredential) { c.Iterations = 21 }),
		"iter zero":       mut(func(c *KeycloakCredential) { c.Iterations = 0 }),
		"hashLength lies": mut(func(c *KeycloakCredential) { c.Extra["hashLength"] = []string{"16"} }),
		"two values":      mut(func(c *KeycloakCredential) { c.Extra["memory"] = []string{"1024", "2048"} }),
		"bad base64":      mut(func(c *KeycloakCredential) { c.Salt = "!!!" }),
		"short salt":      mut(func(c *KeycloakCredential) { c.Salt = "AAAA" }),
	}
	for name, c := range cases {
		if _, err := FromKeycloak(c); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
}

func TestFromKeycloakErrors(t *testing.T) {
	salt := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	val := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	secretSalt := "c2VjcmV0LXNhbHQtMTIzNDU2"
	for name, c := range map[string]KeycloakCredential{
		"unknown alg":   {Algorithm: "bcrypt", Iterations: 10, Salt: salt, Value: val},
		"iter too low":  {Algorithm: "pbkdf2-sha256", Iterations: 999, Salt: salt, Value: val},
		"iter too high": {Algorithm: "pbkdf2-sha256", Iterations: 2_000_001, Salt: salt, Value: val},
		"iter negative": {Algorithm: "pbkdf2-sha256", Iterations: -5, Salt: salt, Value: val},
		"short value":   {Algorithm: "pbkdf2-sha256", Iterations: 27500, Salt: salt, Value: "AAAA"},
		"long salt":     {Algorithm: "pbkdf2-sha256", Iterations: 27500, Salt: base64.StdEncoding.EncodeToString(make([]byte, 65)), Value: val},
		"bad salt":      {Algorithm: "pbkdf2-sha256", Iterations: 27500, Salt: secretSalt + "$$", Value: val},
		"bad value":     {Algorithm: "pbkdf2-sha256", Iterations: 27500, Salt: secretSalt, Value: "not base64 value!"},
	} {
		_, err := FromKeycloak(c)
		if err == nil {
			t.Errorf("%s: want error", name)
			continue
		}
		for _, leak := range []string{c.Salt, c.Value} {
			if len(leak) > 3 && strings.Contains(err.Error(), leak) {
				t.Errorf("%s: error leaks salt/value: %v", name, err)
			}
		}
	}
}

func TestVerifyArgon2idRehashRules(t *testing.T) {
	weak := New(Params{Memory: 64, Time: 1, Threads: 1})
	strong := New(Params{Memory: 128, Time: 2, Threads: 1})
	we, _ := weak.Hash("pw")
	se, _ := strong.Hash("pw")
	if ok, re := weak.Verify("pw", we); !ok || re {
		t.Fatal("same params must not rehash")
	}
	if ok, re := strong.Verify("pw", we); !ok || !re {
		t.Fatal("weaker stored params must rehash")
	}
	if ok, re := weak.Verify("pw", se); !ok || re {
		t.Fatal("stronger stored params must not rehash")
	}
}

func goodPBKDF2(t *testing.T) string {
	t.Helper()
	for _, v := range loadVectors(t) {
		if v.Algorithm == "pbkdf2-sha256" && v.Iterations == 27500 {
			return v.PHC
		}
	}
	t.Fatal("no vector")
	return ""
}

func TestRejectsMalformedAndTampered(t *testing.T) {
	h := New(TestParams)
	good := goodPBKDF2(t)
	parts := strings.Split(good, "$") // "", scheme, i=, salt, hash
	rebuild := func(p ...string) string { return strings.Join(p, "$") }
	a2id, _ := h.Hash("pw")
	huge := strings.Repeat("A", 100000)

	bad := []string{
		"", "$", "$$$$$", "garbage", "$pbkdf2-sha256$", good[:len(good)/4],
		good + "AA", good + "$extra", good + "=",
		rebuild("", "pbkdf2-sha256", "i=27500", parts[3]),             // missing hash
		rebuild("", "pbkdf2-md5", parts[2], parts[3], parts[4]),       // unknown scheme
		rebuild("", "pbkdf2", parts[2], parts[3], parts[4]),           // ambiguous name
		rebuild("", "pbkdf2-sha256", "27500", parts[3], parts[4]),     // no i=
		rebuild("", "pbkdf2-sha256", "i=-1", parts[3], parts[4]),      // negative
		rebuild("", "pbkdf2-sha256", "i=+27500", parts[3], parts[4]),  // sign
		rebuild("", "pbkdf2-sha256", "i=999", parts[3], parts[4]),     // low
		rebuild("", "pbkdf2-sha256", "i=2000001", parts[3], parts[4]), // high
		rebuild("", "pbkdf2-sha256", "i=99999999999999999999", parts[3], parts[4]),
		rebuild("", "pbkdf2-sha256", parts[2], parts[3]+"==", parts[4]),      // padded
		rebuild("", "pbkdf2-sha256", parts[2], parts[3], parts[4]+"="),       // padded
		rebuild("", "pbkdf2-sha256", parts[2], "!!!!", parts[4]),             // not base64
		rebuild("", "pbkdf2-sha256", parts[2], "", parts[4]),                 // empty salt
		rebuild("", "pbkdf2-sha256", parts[2], "AAAAAAAAAA", parts[4]),       // 7-byte salt
		rebuild("", "pbkdf2-sha256", parts[2], huge, parts[4]),               // oversized salt
		rebuild("", "pbkdf2-sha256", parts[2], parts[3], huge),               // oversized hash
		rebuild("", "pbkdf2-sha256", parts[2], parts[3], "AAAAAAAAAAAAAAAA"), // 12-byte hash
		rebuild("", "pbkdf2-sha256", parts[2], parts[3], enc.EncodeToString(make([]byte, 129))),
		rebuild("", "pbkdf2-sha256", parts[2], enc.EncodeToString(make([]byte, 65)), parts[4]),
		strings.Replace(a2id, "v=19", "v=16", 1),
		strings.Replace(a2id, "m=64", "m=1048577", 1),
		strings.Replace(a2id, "m=64", "m=4294967296", 1),
		strings.Replace(a2id, "m=64", "m=7", 1), // m < 8p
		strings.Replace(a2id, "t=1", "t=21", 1),
		strings.Replace(a2id, "t=1", "t=0", 1),
		strings.Replace(a2id, "p=1", "p=17", 1),
		strings.Replace(a2id, "p=1", "p=0", 1),
		strings.Replace(a2id, "$argon2id$", "$argon2d$", 1),
		strings.Replace(a2id, "$argon2id$", "$argon2$", 1),
		strings.Replace(a2id, "m=64,t=1,p=1", "m=64,p=1,t=1", 1),
		strings.Replace(a2id, "m=64,t=1,p=1", "m=64,t=1", 1),
		"$argon2id$v=19$m=64,t=1,p=1$" + huge + "$" + huge,
		strings.Repeat("$", 5000),
	}
	for _, s := range bad {
		if err := ValidateEncoded(s); err == nil {
			t.Errorf("ValidateEncoded accepted %q", s)
		}
		for _, pw := range []string{"", "pw", "S3cret-pass-1"} {
			if ok, re := h.Verify(pw, s); ok || re {
				t.Errorf("Verify(%q) = %v,%v on %.80q", pw, ok, re, s)
			}
		}
	}
	// Limits are inclusive: the boundary values themselves are valid.
	salt, key := enc.EncodeToString(make([]byte, 8)), enc.EncodeToString(make([]byte, 16))
	for _, s := range []string{
		"$pbkdf2-sha1$i=1000$" + salt + "$" + key,
		"$pbkdf2-sha512$i=2000000$" + enc.EncodeToString(make([]byte, 64)) + "$" + enc.EncodeToString(make([]byte, 128)),
		"$argon2i$v=19$m=1048576,t=20,p=16$" + salt + "$" + key,
		"$argon2id$v=19$m=8,t=1,p=1$" + salt + "$" + key,
	} {
		if err := ValidateEncoded(s); err != nil {
			t.Errorf("boundary rejected: %.60s: %v", s, err)
		}
	}
}

func TestTamperedHashFailsVerification(t *testing.T) {
	h := New(TestParams)
	for _, v := range loadVectors(t) {
		if v.Iterations > 30000 {
			continue
		}
		parts := strings.Split(v.PHC, "$")
		raw, _ := enc.DecodeString(parts[4])
		for _, i := range []int{0, len(raw) / 2, len(raw) - 1} {
			raw[i] ^= 0x01
			parts[4] = enc.EncodeToString(raw)
			if ok, re := h.Verify(v.Password, strings.Join(parts, "$")); ok || re {
				t.Fatalf("tampered hash accepted (byte %d)", i)
			}
			raw[i] ^= 0x01
		}
		// Changed iteration count or salt must fail too.
		it := strings.Replace(v.PHC, fmt.Sprintf("i=%d", v.Iterations), fmt.Sprintf("i=%d", v.Iterations+1), 1)
		if ok, _ := h.Verify(v.Password, it); ok {
			t.Fatal("changed iterations accepted")
		}
	}
	// A hash for the right password under the wrong digest name must fail.
	g := goodPBKDF2(t)
	if ok, _ := h.Verify("S3cret-pass-1", strings.Replace(g, "pbkdf2-sha256", "pbkdf2-sha512", 1)); ok {
		t.Fatal("wrong digest accepted")
	}
}

func FuzzValidateEncoded(f *testing.F) {
	seeds, _ := os.ReadFile("testdata/pbkdf2_vectors.json")
	var vs []vector
	_ = json.Unmarshal(seeds, &vs)
	for _, v := range vs {
		f.Add(v.PHC)
	}
	f.Add("$argon2id$v=19$m=64,t=1,p=1$MDEyMzQ1Njc4OWFiY2RlZg$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY")
	f.Add("$argon2i$v=19$m=1048577,t=1,p=1$AAAAAAAAAAA$AAAA")
	f.Add("$pbkdf2-sha1$i=1$$")
	f.Fuzz(func(t *testing.T, s string) {
		ph, err := parseEncoded(s)
		if err != nil {
			return
		}
		// Anything accepted must respect every limit.
		if len(ph.salt) < minSalt || len(ph.salt) > maxSalt || len(ph.want) < minHash || len(ph.want) > maxHash {
			t.Fatalf("accepted out-of-range lengths: %q", s)
		}
		switch ph.scheme {
		case schemeArgon2id, schemeArgon2i:
			if ph.m > maxArgonMemory || ph.t > maxArgonTime || ph.p > maxArgonThreads || ph.m < 8*ph.p || ph.t == 0 {
				t.Fatalf("accepted out-of-range argon2: %q", s)
			}
		default:
			if ph.iter < minPBKDF2Iter || ph.iter > maxPBKDF2Iter {
				t.Fatalf("accepted out-of-range pbkdf2: %q", s)
			}
		}
	})
}

func FuzzVerify(f *testing.F) {
	vs := []vector{}
	seeds, _ := os.ReadFile("testdata/pbkdf2_vectors.json")
	_ = json.Unmarshal(seeds, &vs)
	for _, v := range vs {
		f.Add("S3cret-pass-1", v.PHC)
	}
	f.Add("pw", "$argon2id$v=19$m=64,t=1,p=1$MDEyMzQ1Njc4OWFiY2RlZg$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY")
	f.Add("", "$argon2i$v=19$m=8,t=1,p=1$MDEyMzQ1Njc4OWFiY2RlZg$MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY")
	h := New(TestParams)
	f.Fuzz(func(t *testing.T, pw, encoded string) {
		// Keep the fuzzer fast: skip valid-but-expensive hashes (the limits
		// themselves are covered by TestRejectsMalformedAndTampered).
		if ph, err := parseEncoded(encoded); err == nil && (ph.m > 4096 || ph.t > 3 || ph.iter > 30000) {
			return
		}
		ok, re := h.Verify(pw, encoded)
		if re && !ok {
			t.Fatal("needsRehash without ok")
		}
		if ok && ValidateEncoded(encoded) != nil {
			t.Fatal("verified a hash that does not validate")
		}
	})
}
