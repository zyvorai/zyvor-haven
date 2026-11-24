// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package webauthn_test

import (
	"bytes"
	"errors"
	"testing"

	. "github.com/zyvorai/haven/internal/idp/webauthn"
	wt "github.com/zyvorai/haven/internal/idp/webauthn/webauthntest"
)

const (
	rpID   = "idp.example.com"
	origin = "https://idp.example.com"
)

var rp = RP{ID: rpID, Origins: []string{origin}}

var algs = []struct {
	name string
	alg  int
}{{"ES256", AlgES256}, {"EdDSA", AlgEdDSA}, {"RS256", AlgRS256}}

func chal() []byte { return []byte("0123456789abcdef0123456789abcdef") }

func register(t *testing.T, a *wt.Authenticator) *Registration {
	t.Helper()
	cd, obj := a.Create(chal(), origin)
	reg, err := VerifyRegistration(rp, chal(), cd, obj, true)
	if err != nil {
		t.Fatalf("registration: %v", err)
	}
	return reg
}

func cred(reg *Registration) Credential {
	return Credential{ID: reg.CredentialID, PublicKey: reg.PublicKey, SignCount: reg.SignCount, BackupEligible: reg.BackupEligible}
}

func TestRegistrationAndAssertionAllAlgs(t *testing.T) {
	for _, tc := range algs {
		for _, format := range []string{"none", "packed"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				a := wt.New(tc.alg, rpID)
				a.Fmt = format
				a.BE, a.BS = true, true
				reg := register(t, a)
				if !bytes.Equal(reg.CredentialID, a.CredID) || reg.Alg != tc.alg || !reg.BackupEligible || !reg.BackupState || !reg.UserVerified || reg.Format != format {
					t.Fatalf("bad registration result: %+v", reg)
				}
				if !bytes.Equal(reg.PublicKey, a.COSEKey()) {
					t.Fatal("public key is not the original COSE bytes")
				}
				cd, ad, sig := a.Get(chal(), origin)
				res, err := VerifyAssertion(rp, chal(), cd, ad, sig, cred(reg), true)
				if err != nil || res.SignCount != 1 || !res.UserVerified || !res.BackupState {
					t.Fatalf("assertion: %v %+v", err, res)
				}
			})
		}
	}
}

func TestRegistrationNegatives(t *testing.T) {
	good := func() *wt.Authenticator { return wt.New(AlgES256, rpID) }
	type tc struct {
		name string
		run  func() error
	}
	tamper := func(typ string, o string, ch []byte, mut func(a *wt.Authenticator)) func() error {
		return func() error {
			a := good()
			if mut != nil {
				mut(a)
			}
			cd, obj := a.Create(chal(), origin)
			if typ != "" || o != "" || ch != nil {
				if typ == "" {
					typ = "webauthn.create"
				}
				if o == "" {
					o = origin
				}
				if ch == nil {
					ch = chal()
				}
				cd = wt.ClientData(typ, ch, o)
			}
			_, err := VerifyRegistration(rp, chal(), cd, obj, true)
			return err
		}
	}
	cases := []tc{
		{"wrong origin", tamper("", "https://evil.example", nil, nil)},
		{"origin with other port", tamper("", "https://idp.example.com:8443", nil, nil)},
		{"origin with other scheme", tamper("", "http://idp.example.com", nil, nil)},
		{"wrong challenge", tamper("", "", []byte("another challenge value 0123456789"), nil)},
		{"wrong type", tamper("webauthn.get", "", nil, nil)},
		{"wrong rpId", tamper("", "", nil, func(a *wt.Authenticator) { a.RPID = "evil.example.com" })},
		{"missing UP", tamper("", "", nil, func(a *wt.Authenticator) { a.UP = false })},
		{"missing UV when required", tamper("", "", nil, func(a *wt.Authenticator) { a.UV = false })},
		{"BS without BE", tamper("", "", nil, func(a *wt.Authenticator) { a.BS = true })},
	}
	for _, c := range cases {
		err := c.run()
		if err == nil || !errors.Is(err, ErrVerification) && !errors.Is(err, ErrCBOR) {
			t.Errorf("%s: accepted or wrong error: %v", c.name, err)
		}
	}

	// Attestation statements.
	a := good()
	cd := wt.ClientData("webauthn.create", chal(), origin)
	build := func(fmtName string, stmt []byte, ad []byte) []byte {
		return wt.Map(wt.Pair{K: wt.Text("fmt"), V: wt.Text(fmtName)}, wt.Pair{K: wt.Text("attStmt"), V: stmt},
			wt.Pair{K: wt.Text("authData"), V: wt.Bytes(ad)})
	}
	_, obj := a.Create(chal(), origin)
	v, _ := DecodeCBOR(obj)
	ad := v.(Map)["authData"].([]byte)
	for name, o := range map[string][]byte{
		"x5c present": build("packed", wt.Map(wt.Pair{K: wt.Text("alg"), V: wt.Int(-7)}, wt.Pair{K: wt.Text("sig"), V: wt.Bytes([]byte{1})},
			wt.Pair{K: wt.Text("x5c"), V: wt.Array(wt.Bytes([]byte{1, 2, 3}))}), ad),
		"ecdaa present": build("packed", wt.Map(wt.Pair{K: wt.Text("alg"), V: wt.Int(-7)}, wt.Pair{K: wt.Text("sig"), V: wt.Bytes([]byte{1})},
			wt.Pair{K: wt.Text("ecdaaKeyId"), V: wt.Bytes([]byte{1})}), ad),
		"x5c on none":        build("none", wt.Map(wt.Pair{K: wt.Text("x5c"), V: wt.Array()}), ad),
		"none with stmt":     build("none", wt.Map(wt.Pair{K: wt.Text("foo"), V: wt.Int(1)}), ad),
		"tpm format":         build("tpm", wt.Map(), ad),
		"android-key":        build("android-key", wt.Map(), ad),
		"apple":              build("apple", wt.Map(), ad),
		"packed bad sig":     build("packed", wt.Map(wt.Pair{K: wt.Text("alg"), V: wt.Int(-7)}, wt.Pair{K: wt.Text("sig"), V: wt.Bytes([]byte{0x30, 0x03, 2, 1, 1})}), ad),
		"packed alg differs": build("packed", wt.Map(wt.Pair{K: wt.Text("alg"), V: wt.Int(-257)}, wt.Pair{K: wt.Text("sig"), V: wt.Bytes([]byte{1})}), ad),
		"packed no sig":      build("packed", wt.Map(wt.Pair{K: wt.Text("alg"), V: wt.Int(-7)}), ad),
	} {
		if _, err := VerifyRegistration(rp, chal(), cd, o, true); !errors.Is(err, ErrVerification) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Self attestation signed by a DIFFERENT key with matching alg is invalid.
	a2 := good()
	a2.Fmt = "packed"
	_, obj2 := a2.Create(chal(), origin)
	v2, _ := DecodeCBOR(obj2)
	m2 := v2.(Map)
	forged := build("packed", wt.Map(wt.Pair{K: wt.Text("alg"), V: wt.Int(-7)}, wt.Pair{K: wt.Text("sig"), V: wt.Bytes(m2["attStmt"].(Map)["sig"].([]byte))}), ad)
	if _, err := VerifyRegistration(rp, chal(), cd, forged, true); err == nil {
		t.Error("packed signature from another key/authData accepted")
	}
	// Truncated and garbage attestation objects.
	for n := 0; n < len(obj); n += 7 {
		if _, err := VerifyRegistration(rp, chal(), cd, obj[:n], true); err == nil {
			t.Errorf("truncated attestationObject (%d bytes) accepted", n)
		}
	}
	// UV not required: accepted without UV.
	b := good()
	b.UV = false
	cd2, obj3 := b.Create(chal(), origin)
	if _, err := VerifyRegistration(rp, chal(), cd2, obj3, false); err != nil {
		t.Errorf("registration without UV refused when UV is not required: %v", err)
	}
	// No origins configured: nothing is allowed.
	cd3, obj4 := good().Create(chal(), origin)
	if _, err := VerifyRegistration(RP{ID: rpID}, chal(), cd3, obj4, true); err == nil {
		t.Error("empty origin list accepted")
	}
	// Cross-origin / topOrigin.
	for _, extra := range []string{`,"crossOrigin":true`, `,"topOrigin":"https://evil.example"`} {
		raw := []byte(`{"type":"webauthn.create","challenge":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY","origin":"` + origin + `"` + extra + `}`)
		if _, err := VerifyRegistration(rp, chal(), raw, obj3, false); err == nil {
			t.Errorf("clientData %s accepted", extra)
		}
	}
}

func TestAssertionNegatives(t *testing.T) {
	for _, tc := range algs {
		t.Run(tc.name, func(t *testing.T) {
			a := wt.New(tc.alg, rpID)
			reg := register(t, a)
			c := cred(reg)
			cd, ad, sig := a.Get(chal(), origin)
			if _, err := VerifyAssertion(rp, chal(), cd, ad, sig, c, true); err != nil {
				t.Fatalf("baseline: %v", err)
			}
			flip := func(b []byte, i int) []byte { o := append([]byte(nil), b...); o[i] ^= 0x01; return o }
			bad := map[string]func() error{
				"wrong origin": func() error {
					_, err := VerifyAssertion(rp, chal(), wt.ClientData("webauthn.get", chal(), "https://evil.example"), ad, sig, c, true)
					return err
				},
				"wrong challenge": func() error {
					_, err := VerifyAssertion(rp, []byte("some other challenge 0123456789abc"), cd, ad, sig, c, true)
					return err
				},
				"empty challenge": func() error {
					_, err := VerifyAssertion(rp, nil, wt.ClientData("webauthn.get", nil, origin), ad, sig, c, true)
					return err
				},
				"wrong type (create)": func() error {
					_, err := VerifyAssertion(rp, chal(), wt.ClientData("webauthn.create", chal(), origin), ad, sig, c, true)
					return err
				},
				"bad signature": func() error {
					_, err := VerifyAssertion(rp, chal(), cd, ad, flip(sig, len(sig)-1), c, true)
					return err
				},
				"tampered authData (counter)": func() error {
					_, err := VerifyAssertion(rp, chal(), cd, flip(ad, 36), sig, c, true)
					return err
				},
				"tampered authData (flags)": func() error {
					_, err := VerifyAssertion(rp, chal(), cd, flip(ad, 32), sig, c, true)
					return err
				},
				"tampered clientData": func() error {
					_, err := VerifyAssertion(rp, chal(), append(append([]byte(nil), cd[:len(cd)-1]...), []byte(`,"x":1}`)...), ad, sig, c, true)
					return err
				},
				"wrong rpId": func() error {
					o := wt.New(tc.alg, "evil.example.com")
					o.CredID = a.CredID
					cd2, ad2, sig2 := o.Get(chal(), origin)
					_, err := VerifyAssertion(rp, chal(), cd2, ad2, sig2, cred(reg), true)
					return err
				},
				"other key": func() error {
					o := wt.New(tc.alg, rpID)
					cd2, ad2, sig2 := o.Get(chal(), origin)
					_, err := VerifyAssertion(rp, chal(), cd2, ad2, sig2, c, true)
					return err
				},
				"alg mismatch": func() error { // stored key of another algorithm cannot verify this signature
					o := wt.New(map[int]int{AlgES256: AlgEdDSA, AlgEdDSA: AlgRS256, AlgRS256: AlgES256}[tc.alg], rpID)
					_, err := VerifyAssertion(rp, chal(), cd, ad, sig, Credential{ID: c.ID, PublicKey: o.COSEKey()}, true)
					return err
				},
				"missing UP": func() error {
					a.UP = false
					defer func() { a.UP = true }()
					cd2, ad2, sig2 := a.Get(chal(), origin)
					_, err := VerifyAssertion(rp, chal(), cd2, ad2, sig2, Credential{ID: c.ID, PublicKey: c.PublicKey}, false)
					return err
				},
				"missing UV when required": func() error {
					a.UV = false
					defer func() { a.UV = true }()
					cd2, ad2, sig2 := a.Get(chal(), origin)
					_, err := VerifyAssertion(rp, chal(), cd2, ad2, sig2, Credential{ID: c.ID, PublicKey: c.PublicKey}, true)
					return err
				},
				"backup eligibility flipped": func() error {
					a.BE = true
					defer func() { a.BE = false }()
					cd2, ad2, sig2 := a.Get(chal(), origin)
					_, err := VerifyAssertion(rp, chal(), cd2, ad2, sig2, Credential{ID: c.ID, PublicKey: c.PublicKey}, true)
					return err
				},
				"empty signature": func() error {
					_, err := VerifyAssertion(rp, chal(), cd, ad, nil, c, true)
					return err
				},
				"truncated authData": func() error {
					_, err := VerifyAssertion(rp, chal(), cd, ad[:20], sig, c, true)
					return err
				},
				"trailing bytes in authData": func() error {
					_, err := VerifyAssertion(rp, chal(), cd, append(append([]byte(nil), ad...), 0), sig, c, true)
					return err
				},
				"garbage stored key": func() error {
					_, err := VerifyAssertion(rp, chal(), cd, ad, sig, Credential{PublicKey: []byte{0xa0}}, true)
					return err
				},
			}
			for name, f := range bad {
				if err := f(); !errors.Is(err, ErrVerification) {
					t.Errorf("%s: want a verification error, got %v", name, err)
				}
			}
			// UV not required: an assertion without UV is fine.
			a.UV = false
			cd2, ad2, sig2 := a.Get(chal(), origin)
			if _, err := VerifyAssertion(rp, chal(), cd2, ad2, sig2, c, false); err != nil {
				t.Errorf("UV-less assertion refused when UV is not required: %v", err)
			}
		})
	}
}

func TestSignCount(t *testing.T) {
	a := wt.New(AlgES256, rpID)
	reg := register(t, a)
	c := cred(reg)
	get := func() (cd, ad, sig []byte) { return a.Get(chal(), origin) }

	// Increasing counters are fine.
	for i := 1; i <= 3; i++ {
		cd, ad, sig := get()
		res, err := VerifyAssertion(rp, chal(), cd, ad, sig, c, true)
		if err != nil || res.SignCount != uint32(i) {
			t.Fatalf("assertion %d: %v %+v", i, err, res)
		}
		c.SignCount = res.SignCount
	}
	// Equal or lower counter with a genuine signature: possible clone.
	for _, n := range []uint32{3, 2, 1} {
		a.SignCount, a.Counting = n, false
		cd, ad, sig := get()
		res, err := VerifyAssertion(rp, chal(), cd, ad, sig, c, true)
		if !errors.Is(err, ErrCounterRegression) || res == nil {
			t.Errorf("presented %d, stored %d: %v", n, c.SignCount, err)
		}
		if errors.Is(err, ErrVerification) {
			t.Error("a counter regression is not a plain verification failure")
		}
	}
	// A bad signature with a regressed counter is a plain failure, never a clone flag.
	a.SignCount = 1
	cd, ad, sig := get()
	sig[len(sig)-1] ^= 1
	if _, err := VerifyAssertion(rp, chal(), cd, ad, sig, c, true); errors.Is(err, ErrCounterRegression) || err == nil {
		t.Errorf("forged assertion must fail as a verification error: %v", err)
	}
	// Authenticators that always send 0 are allowed, before and after.
	z := wt.New(AlgES256, rpID)
	z.Counting = false
	zr := register(t, z)
	zc := cred(zr)
	for i := 0; i < 3; i++ {
		cd, ad, sig := z.Get(chal(), origin)
		if _, err := VerifyAssertion(rp, chal(), cd, ad, sig, zc, true); err != nil {
			t.Fatalf("zero counter refused: %v", err)
		}
	}
	// Stored 0 and presented non-zero is a counter starting up: fine.
	z.SignCount, z.Counting = 7, false
	cd, ad, sig = z.Get(chal(), origin)
	if _, err := VerifyAssertion(rp, chal(), cd, ad, sig, zc, true); err != nil {
		t.Fatalf("counter starting up refused: %v", err)
	}
	// Stored non-zero and presented 0 is allowed by the rule above (both must be non-zero to flag).
	z.SignCount = 0
	cd, ad, sig = z.Get(chal(), origin)
	if _, err := VerifyAssertion(rp, chal(), cd, ad, sig, Credential{ID: zc.ID, PublicKey: zc.PublicKey, SignCount: 7}, true); err != nil {
		t.Fatalf("presented 0 with stored 7: %v", err)
	}
}

func TestCredentialIDLimits(t *testing.T) {
	for _, n := range []int{0, 15, 1024, 5000} {
		a := wt.New(AlgES256, rpID)
		a.CredID = bytes.Repeat([]byte{7}, n)
		cd, obj := a.Create(chal(), origin)
		if _, err := VerifyRegistration(rp, chal(), cd, obj, true); err == nil {
			t.Errorf("credential id of %d bytes accepted", n)
		}
	}
	a := wt.New(AlgES256, rpID)
	a.CredID = bytes.Repeat([]byte{7}, 1023)
	cd, obj := a.Create(chal(), origin)
	if _, err := VerifyRegistration(rp, chal(), cd, obj, true); err != nil {
		t.Errorf("1023 byte credential id refused: %v", err)
	}
}

func TestParseCOSEKeyRejects(t *testing.T) {
	a := wt.New(AlgES256, rpID)
	good := a.COSEKey()
	if _, err := ParseCOSEKey(good); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCOSEKey(append(append([]byte(nil), good...), 0)); err == nil {
		t.Error("trailing byte after COSE key accepted")
	}
	pt := func(k int64, v []byte) wt.Pair { return wt.Pair{K: wt.Int(k), V: v} }
	x := bytes.Repeat([]byte{1}, 32)
	for name, k := range map[string][]byte{
		"not on curve":  wt.Map(pt(1, wt.Int(2)), pt(3, wt.Int(-7)), pt(-1, wt.Int(1)), pt(-2, wt.Bytes(x)), pt(-3, wt.Bytes(x))),
		"P-384 curve":   wt.Map(pt(1, wt.Int(2)), pt(3, wt.Int(-7)), pt(-1, wt.Int(2)), pt(-2, wt.Bytes(x)), pt(-3, wt.Bytes(x))),
		"short coord":   wt.Map(pt(1, wt.Int(2)), pt(3, wt.Int(-7)), pt(-1, wt.Int(1)), pt(-2, wt.Bytes(x[:31])), pt(-3, wt.Bytes(x))),
		"RS1 alg":       wt.Map(pt(1, wt.Int(3)), pt(3, wt.Int(-65535)), pt(-1, wt.Bytes(x)), pt(-2, wt.Bytes([]byte{1, 0, 1}))),
		"small RSA":     wt.Map(pt(1, wt.Int(3)), pt(3, wt.Int(-257)), pt(-1, wt.Bytes(bytes.Repeat([]byte{0xff}, 128))), pt(-2, wt.Bytes([]byte{1, 0, 1}))),
		"even exponent": wt.Map(pt(1, wt.Int(3)), pt(3, wt.Int(-257)), pt(-1, wt.Bytes(bytes.Repeat([]byte{0xff}, 256))), pt(-2, wt.Bytes([]byte{2}))),
		"kty/alg mix":   wt.Map(pt(1, wt.Int(1)), pt(3, wt.Int(-7)), pt(-1, wt.Int(1)), pt(-2, wt.Bytes(x))),
		"Ed448 crv":     wt.Map(pt(1, wt.Int(1)), pt(3, wt.Int(-8)), pt(-1, wt.Int(7)), pt(-2, wt.Bytes(x))),
		"no alg":        wt.Map(pt(1, wt.Int(2)), pt(-1, wt.Int(1))),
		"not a map":     wt.Int(1),
	} {
		if _, err := ParseCOSEKey(k); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}
