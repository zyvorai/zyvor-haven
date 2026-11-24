// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package webauthntest is a software WebAuthn authenticator for tests: it
// builds real authenticator data, CBOR attestation objects, clientDataJSON and
// signatures with crypto/ecdsa, crypto/rsa and crypto/ed25519. It is only
// imported by tests.
package webauthntest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
)

// Authenticator is a virtual authenticator holding ONE credential. Fields are
// knobs a test can change between calls to produce negative cases.
type Authenticator struct {
	Alg        int
	CredID     []byte
	UserHandle []byte
	AAGUID     [16]byte
	RPID       string // rp id hashed into authData
	SignCount  uint32
	Counting   bool // increment SignCount on each assertion
	UP, UV     bool
	BE, BS     bool
	Fmt        string // "none" (default) or "packed"
	priv       crypto.Signer
}

// New makes an authenticator for rpID with a fresh key of the given COSE alg.
func New(alg int, rpID string) *Authenticator {
	a := &Authenticator{Alg: alg, RPID: rpID, UP: true, UV: true, Counting: true, Fmt: "none",
		CredID: randBytes(32), UserHandle: randBytes(16)}
	switch alg {
	case -7:
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		a.priv = k
	case -8:
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		a.priv = k
	case -257:
		k, _ := rsa.GenerateKey(rand.Reader, 2048)
		a.priv = k
	default:
		panic("webauthntest: unsupported alg")
	}
	return a
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

// ---- minimal CBOR encoder (canonical: sorted keys, minimal lengths) ----

func head(major byte, n uint64) []byte {
	switch {
	case n < 24:
		return []byte{major<<5 | byte(n)}
	case n < 256:
		return []byte{major<<5 | 24, byte(n)}
	case n < 65536:
		return []byte{major<<5 | 25, byte(n >> 8), byte(n)} // #nosec G115 -- test encoder: n is range-checked by the switch and test credential IDs are far below 64 KiB
	default:
		b := []byte{major<<5 | 26, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(b[1:], uint32(n)) // #nosec G115 -- test encoder: n is range-checked by the switch and test credential IDs are far below 64 KiB
		return b
	}
}

// Int encodes an integer.
func Int(v int64) []byte {
	if v >= 0 {
		return head(0, uint64(v))
	}
	return head(1, uint64(-1-v))
}

// Bytes encodes a byte string.
func Bytes(b []byte) []byte { return append(head(2, uint64(len(b))), b...) }

// Text encodes a text string.
func Text(s string) []byte { return append(head(3, uint64(len(s))), s...) }

// Array encodes an array of already-encoded items.
func Array(items ...[]byte) []byte {
	out := head(4, uint64(len(items)))
	for _, i := range items {
		out = append(out, i...)
	}
	return out
}

// Pair is an encoded key/value for Map.
type Pair struct{ K, V []byte }

// Map encodes a map; pairs are emitted in the order given (no sorting, so
// tests can also build non-canonical or duplicate-key maps).
func Map(pairs ...Pair) []byte {
	out := head(5, uint64(len(pairs)))
	for _, p := range pairs {
		out = append(out, p.K...)
		out = append(out, p.V...)
	}
	return out
}

// COSEKey returns the COSE_Key encoding of the authenticator's public key.
func (a *Authenticator) COSEKey() []byte {
	switch k := a.priv.(type) {
	case *ecdsa.PrivateKey:
		raw, _ := k.PublicKey.Bytes()
		return Map(Pair{Int(1), Int(2)}, Pair{Int(3), Int(-7)}, Pair{Int(-1), Int(1)},
			Pair{Int(-2), Bytes(raw[1:33])}, Pair{Int(-3), Bytes(raw[33:65])})
	case ed25519.PrivateKey:
		return Map(Pair{Int(1), Int(1)}, Pair{Int(3), Int(-8)}, Pair{Int(-1), Int(6)},
			Pair{Int(-2), Bytes(k.Public().(ed25519.PublicKey))})
	case *rsa.PrivateKey:
		e := big.NewInt(int64(k.E)).Bytes()
		return Map(Pair{Int(1), Int(3)}, Pair{Int(3), Int(-257)},
			Pair{Int(-1), Bytes(k.N.Bytes())}, Pair{Int(-2), Bytes(e)})
	}
	panic("unreachable")
}

func (a *Authenticator) flags(at bool) byte {
	var f byte
	if a.UP {
		f |= 0x01
	}
	if a.UV {
		f |= 0x04
	}
	if a.BE {
		f |= 0x08
	}
	if a.BS {
		f |= 0x10
	}
	if at {
		f |= 0x40
	}
	return f
}

func (a *Authenticator) authData(at bool) []byte {
	h := sha256.Sum256([]byte(a.RPID))
	out := append([]byte(nil), h[:]...)
	out = append(out, a.flags(at))
	var sc [4]byte
	binary.BigEndian.PutUint32(sc[:], a.SignCount)
	out = append(out, sc[:]...)
	if at {
		out = append(out, a.AAGUID[:]...)
		out = append(out, byte(len(a.CredID)>>8), byte(len(a.CredID))) // #nosec G115 -- test encoder: n is range-checked by the switch and test credential IDs are far below 64 KiB
		out = append(out, a.CredID...)
		out = append(out, a.COSEKey()...)
	}
	return out
}

// ClientData builds clientDataJSON.
func ClientData(typ string, challenge []byte, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": base64.RawURLEncoding.EncodeToString(challenge),
		"origin": origin, "crossOrigin": false})
	return b
}

func (a *Authenticator) sign(msg []byte) []byte {
	var sig []byte
	switch k := a.priv.(type) {
	case *ecdsa.PrivateKey:
		h := sha256.Sum256(msg)
		sig, _ = ecdsa.SignASN1(rand.Reader, k, h[:])
	case ed25519.PrivateKey:
		sig = ed25519.Sign(k, msg)
	case *rsa.PrivateKey:
		h := sha256.Sum256(msg)
		sig, _ = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
	}
	return sig
}

// Create performs a registration ceremony and returns clientDataJSON and the
// attestationObject.
func (a *Authenticator) Create(challenge []byte, origin string) (clientDataJSON, attestationObject []byte) {
	cd := ClientData("webauthn.create", challenge, origin)
	ad := a.authData(true)
	stmt := Map()
	if a.Fmt == "packed" {
		h := sha256.Sum256(cd)
		stmt = Map(Pair{Text("alg"), Int(int64(a.Alg))}, Pair{Text("sig"), Bytes(a.sign(append(append([]byte(nil), ad...), h[:]...)))})
	}
	obj := Map(Pair{Text("fmt"), Text(a.Fmt)}, Pair{Text("attStmt"), stmt}, Pair{Text("authData"), Bytes(ad)})
	return cd, obj
}

// Get performs an authentication ceremony and returns clientDataJSON,
// authenticatorData and the signature.
func (a *Authenticator) Get(challenge []byte, origin string) (clientDataJSON, authenticatorData, sig []byte) {
	if a.Counting {
		a.SignCount++
	}
	cd := ClientData("webauthn.get", challenge, origin)
	ad := a.authData(false)
	h := sha256.Sum256(cd)
	return cd, ad, a.sign(append(append([]byte(nil), ad...), h[:]...))
}
