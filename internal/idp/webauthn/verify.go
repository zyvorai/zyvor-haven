// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package webauthn

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
)

// Authenticator data flags (WebAuthn level 3, 6.1).
const (
	FlagUP = 0x01
	FlagUV = 0x04
	FlagBE = 0x08
	FlagBS = 0x10
	FlagAT = 0x40
	FlagED = 0x80
)

const (
	maxClientData   = 4096
	maxAuthData     = 8192
	maxAttestation  = 16384
	maxCredentialID = 1023 // WebAuthn: credential ids are at most 1023 bytes
	minCredentialID = 16   // spec recommends >= 16 bytes of entropy; shorter ids are refused
	maxSignature    = 1024
)

// ErrVerification is wrapped by every verification failure. Its text is for
// logs: do not show it to the user (it would be an oracle).
var ErrVerification = errors.New("webauthn: verification failed")

// ErrCounterRegression is returned (wrapped, together with a result) when an
// otherwise valid assertion presents a signature counter that did not
// increase: the credential may have been cloned.
var ErrCounterRegression = errors.New("webauthn: signature counter did not increase")

func vErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrVerification, fmt.Sprintf(format, a...))
}

// RP identifies the relying party.
type RP struct {
	ID      string   // e.g. "idp.example.com" (no scheme, no port)
	Origins []string // exact allowed origins, e.g. "https://idp.example.com"
}

// AuthData is parsed authenticator data.
type AuthData struct {
	RPIDHash       [32]byte
	Flags          byte
	SignCount      uint32
	AAGUID         []byte // 16 bytes, only when AT
	CredentialID   []byte // only when AT
	PublicKey      *COSEKey
	UserPresent    bool
	UserVerified   bool
	BackupEligible bool
	BackupState    bool
}

// ParseAuthData parses authenticator data strictly: no trailing bytes.
func ParseAuthData(b []byte) (*AuthData, error) {
	if len(b) < 37 || len(b) > maxAuthData {
		return nil, vErr("authenticator data has bad length")
	}
	ad := &AuthData{Flags: b[32], SignCount: binary.BigEndian.Uint32(b[33:37])}
	copy(ad.RPIDHash[:], b[:32])
	ad.UserPresent = ad.Flags&FlagUP != 0
	ad.UserVerified = ad.Flags&FlagUV != 0
	ad.BackupEligible = ad.Flags&FlagBE != 0
	ad.BackupState = ad.Flags&FlagBS != 0
	if ad.BackupState && !ad.BackupEligible {
		return nil, vErr("backup state set on a credential that is not backup eligible")
	}
	rest := b[37:]
	if ad.Flags&FlagAT != 0 {
		if len(rest) < 18 {
			return nil, vErr("attested credential data truncated")
		}
		ad.AAGUID = append([]byte(nil), rest[:16]...)
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if n < minCredentialID || n > maxCredentialID || n > len(rest) {
			return nil, vErr("credential id length %d is not acceptable", n)
		}
		ad.CredentialID = append([]byte(nil), rest[:n]...)
		rest = rest[n:]
		v, used, err := DecodeCBORPrefix(rest)
		if err != nil {
			return nil, err
		}
		key, err := coseFromValue(v, rest[:used])
		if err != nil {
			return nil, err
		}
		ad.PublicKey = key
		rest = rest[used:]
	}
	if ad.Flags&FlagED != 0 {
		if _, err := DecodeCBOR(rest); err != nil { // extensions: must be exactly one item
			return nil, err
		}
		rest = nil
	}
	if len(rest) != 0 {
		return nil, vErr("unexpected trailing bytes in authenticator data")
	}
	return ad, nil
}

type clientData struct {
	Type        string  `json:"type"`
	Challenge   string  `json:"challenge"`
	Origin      string  `json:"origin"`
	CrossOrigin *bool   `json:"crossOrigin"`
	TopOrigin   *string `json:"topOrigin"`
}

func (rp RP) checkClientData(raw []byte, wantType string, challenge []byte) error {
	if len(raw) == 0 || len(raw) > maxClientData {
		return vErr("clientDataJSON has bad length")
	}
	var cd clientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return vErr("clientDataJSON is not valid JSON")
	}
	if cd.Type != wantType {
		return vErr("wrong ceremony type")
	}
	got, err := base64.RawURLEncoding.DecodeString(cd.Challenge)
	if err != nil || len(challenge) == 0 || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return vErr("challenge mismatch")
	}
	if !slices.Contains(rp.Origins, cd.Origin) || cd.Origin == "" {
		return vErr("origin is not allowed")
	}
	// Our pages are never framed (frame-ancestors 'none'); a cross-origin
	// ceremony means something is wrong.
	if (cd.CrossOrigin != nil && *cd.CrossOrigin) || cd.TopOrigin != nil {
		return vErr("cross-origin ceremony refused")
	}
	return nil
}

func (rp RP) checkAuthData(ad *AuthData, requireUV bool) error {
	if rp.ID == "" {
		return vErr("relying party id not configured")
	}
	want := sha256.Sum256([]byte(rp.ID))
	if subtle.ConstantTimeCompare(ad.RPIDHash[:], want[:]) != 1 {
		return vErr("rpIdHash mismatch")
	}
	if !ad.UserPresent {
		return vErr("user presence flag not set")
	}
	if requireUV && !ad.UserVerified {
		return vErr("user verification required but not performed")
	}
	return nil
}

// Registration is the outcome of a verified registration ceremony.
type Registration struct {
	CredentialID   []byte
	PublicKey      []byte // the original COSE_Key bytes
	Alg            int
	SignCount      uint32
	AAGUID         []byte
	BackupEligible bool
	BackupState    bool
	UserVerified   bool
	Format         string // "none" or "packed" (self attestation)
}

// VerifyRegistration verifies the response of navigator.credentials.create().
// challenge is the raw challenge the server issued (single use is the
// caller's job). Attestation: "none" and "packed" self attestation are
// accepted; anything that carries a certificate chain (x5c, ecdaaKeyId) or
// another format is refused, because accepting it unverified would be
// pretending to check something we do not check.
func VerifyRegistration(rp RP, challenge, clientDataJSON, attestationObject []byte, requireUV bool) (*Registration, error) {
	if err := rp.checkClientData(clientDataJSON, "webauthn.create", challenge); err != nil {
		return nil, err
	}
	if len(attestationObject) == 0 || len(attestationObject) > maxAttestation {
		return nil, vErr("attestationObject has bad length")
	}
	v, err := DecodeCBOR(attestationObject)
	if err != nil {
		return nil, err
	}
	m, ok := v.(Map)
	if !ok {
		return nil, vErr("attestationObject is not a map")
	}
	fmtName, _ := m["fmt"].(string)
	authRaw, _ := m["authData"].([]byte)
	stmt, _ := m["attStmt"].(Map)
	if fmtName == "" || authRaw == nil || stmt == nil {
		return nil, vErr("attestationObject is missing fmt, authData or attStmt")
	}
	ad, err := ParseAuthData(authRaw)
	if err != nil {
		return nil, err
	}
	if err := rp.checkAuthData(ad, requireUV); err != nil {
		return nil, err
	}
	if ad.Flags&FlagAT == 0 || ad.PublicKey == nil {
		return nil, vErr("no attested credential data")
	}
	reg := &Registration{CredentialID: ad.CredentialID, PublicKey: ad.PublicKey.Raw, Alg: ad.PublicKey.Alg,
		SignCount: ad.SignCount, AAGUID: ad.AAGUID, BackupEligible: ad.BackupEligible, BackupState: ad.BackupState,
		UserVerified: ad.UserVerified, Format: fmtName}
	if _, has := stmt["x5c"]; has {
		return nil, vErr("attestation with a certificate chain is not supported")
	}
	if _, has := stmt["ecdaaKeyId"]; has {
		return nil, vErr("ECDAA attestation is not supported")
	}
	switch fmtName {
	case "none":
		if len(stmt) != 0 {
			return nil, vErr("attestation format none must have an empty statement")
		}
	case "packed":
		alg, ok := stmt["alg"].(int64)
		sig, ok2 := stmt["sig"].([]byte)
		if !ok || !ok2 || len(stmt) != 2 || len(sig) == 0 || len(sig) > maxSignature {
			return nil, vErr("malformed packed attestation statement")
		}
		if int(alg) != ad.PublicKey.Alg { // self attestation signs with the credential key itself
			return nil, vErr("packed attestation algorithm does not match the credential key")
		}
		hash := sha256.Sum256(clientDataJSON)
		if !ad.PublicKey.Verify(append(append([]byte(nil), authRaw...), hash[:]...), sig) {
			return nil, vErr("packed self attestation signature is invalid")
		}
	default:
		return nil, vErr("attestation format %q is not supported", fmtName)
	}
	return reg, nil
}

// Credential is what we stored at registration.
type Credential struct {
	ID             []byte
	PublicKey      []byte // COSE bytes
	SignCount      uint32
	BackupEligible bool
}

// Assertion is the outcome of a verified authentication ceremony.
type Assertion struct {
	SignCount    uint32
	BackupState  bool
	UserVerified bool
}

// VerifyAssertion verifies the response of navigator.credentials.get(). On a
// counter regression it returns the result together with an error wrapping
// ErrCounterRegression: the signature was genuine but the credential may be a
// clone, and the caller must refuse the login and flag the credential.
func VerifyAssertion(rp RP, challenge, clientDataJSON, authenticatorData, sig []byte, cred Credential, requireUV bool) (*Assertion, error) {
	if err := rp.checkClientData(clientDataJSON, "webauthn.get", challenge); err != nil {
		return nil, err
	}
	if len(sig) == 0 || len(sig) > maxSignature {
		return nil, vErr("signature has bad length")
	}
	ad, err := ParseAuthData(authenticatorData)
	if err != nil {
		return nil, err
	}
	if ad.Flags&FlagAT != 0 {
		return nil, vErr("assertion carries attested credential data")
	}
	if err := rp.checkAuthData(ad, requireUV); err != nil {
		return nil, err
	}
	key, err := ParseCOSEKey(cred.PublicKey)
	if err != nil {
		return nil, vErr("stored credential key is unusable")
	}
	hash := sha256.Sum256(clientDataJSON)
	if !key.Verify(append(append([]byte(nil), authenticatorData...), hash[:]...), sig) {
		return nil, vErr("signature is invalid")
	}
	if ad.BackupEligible != cred.BackupEligible {
		return nil, vErr("backup eligibility changed")
	}
	res := &Assertion{SignCount: ad.SignCount, BackupState: ad.BackupState, UserVerified: ad.UserVerified}
	if cred.SignCount != 0 && ad.SignCount != 0 && ad.SignCount <= cred.SignCount {
		return res, fmt.Errorf("%w: stored %d, presented %d", ErrCounterRegression, cred.SignCount, ad.SignCount)
	}
	return res, nil
}
