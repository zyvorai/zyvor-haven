// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
)

// COSE algorithm identifiers we accept.
const (
	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

// COSE key parameters (RFC 9052/9053).
const (
	coseKty = 1
	coseAlg = 3
	// EC2 / OKP
	coseCrv = -1
	coseX   = -2
	coseY   = -3
	// RSA
	coseN = -1
	coseE = -2
)

const minRSABits = 2048

// COSEKey is a parsed credential public key. Raw is the original COSE bytes:
// that is what we store, so the key can be re-parsed and nothing is lost.
type COSEKey struct {
	Alg int
	Raw []byte
	pub crypto.PublicKey
}

// ParseCOSEKey parses an ES256 (P-256), RS256 (>= 2048 bit) or EdDSA
// (Ed25519) COSE_Key and requires b to hold exactly one key.
func ParseCOSEKey(b []byte) (*COSEKey, error) {
	v, err := DecodeCBOR(b)
	if err != nil {
		return nil, err
	}
	return coseFromValue(v, b)
}

func coseFromValue(v any, raw []byte) (*COSEKey, error) {
	m, ok := v.(Map)
	if !ok {
		return nil, errors.New("webauthn: COSE key is not a map")
	}
	kty, ok1 := m[int64(coseKty)].(int64)
	alg, ok2 := m[int64(coseAlg)].(int64)
	if !ok1 || !ok2 {
		return nil, errors.New("webauthn: COSE key lacks kty or alg")
	}
	k := &COSEKey{Alg: int(alg), Raw: append([]byte(nil), raw...)}
	switch {
	case alg == AlgES256 && kty == 2:
		if crv, _ := m[int64(coseCrv)].(int64); crv != 1 {
			return nil, errors.New("webauthn: ES256 key is not on P-256")
		}
		x, _ := m[int64(coseX)].([]byte)
		y, _ := m[int64(coseY)].([]byte)
		if len(x) != 32 || len(y) != 32 {
			return nil, errors.New("webauthn: bad P-256 coordinates")
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, append(x, y...)...))
		if err != nil {
			return nil, errors.New("webauthn: P-256 point is not on the curve")
		}
		k.pub = pub
	case alg == AlgEdDSA && kty == 1:
		if crv, _ := m[int64(coseCrv)].(int64); crv != 6 {
			return nil, errors.New("webauthn: EdDSA key is not Ed25519")
		}
		x, _ := m[int64(coseX)].([]byte)
		if len(x) != ed25519.PublicKeySize {
			return nil, errors.New("webauthn: bad Ed25519 key length")
		}
		k.pub = ed25519.PublicKey(append([]byte(nil), x...))
	case alg == AlgRS256 && kty == 3:
		n, _ := m[int64(coseN)].([]byte)
		e, _ := m[int64(coseE)].([]byte)
		if len(n) == 0 || n[0] == 0 || len(n)*8 < minRSABits || len(n) > 512 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("webauthn: unacceptable RSA key size")
		}
		ev := new(big.Int).SetBytes(e).Int64()
		if ev < 3 || ev%2 == 0 {
			return nil, errors.New("webauthn: unacceptable RSA exponent")
		}
		k.pub = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(ev)}
	default:
		return nil, fmt.Errorf("webauthn: unsupported key (kty %d, alg %d)", kty, alg)
	}
	return k, nil
}

// Verify checks sig over msg (authData || sha256(clientDataJSON)).
func (k *COSEKey) Verify(msg, sig []byte) bool {
	switch pub := k.pub.(type) {
	case *ecdsa.PublicKey:
		h := sha256.Sum256(msg)
		return ecdsa.VerifyASN1(pub, h[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(pub, msg, sig)
	case *rsa.PublicKey:
		h := sha256.Sum256(msg)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, h[:], sig) == nil
	}
	return false
}
