// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package havencli

import (
	"encoding/json"
	"errors"
)

// VerifyJWT checks the ES256 or RS256 signature of a compact JWT against a
// JWKS document and returns the algorithm. It checks NO claims.
func VerifyJWT(raw string, jwks []byte) (string, error) {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		return "", errors.New("JWKS is not valid JSON")
	}
	return verifySignature(raw, set.Keys)
}

// DecodeJWT splits a compact JWT into header and claims WITHOUT verifying it.
func DecodeJWT(raw string) (header, claims map[string]any, err error) { return decodeClaims(raw) }
