// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package password

import (
	"errors"
	"strings"
)

// LEAD-OWNED TEMPORARY STUB. The real ValidateEncoded (with legacy hash
// verification) is implemented by another agent; the lead deletes this file
// at merge, together with the LegacyStub skip in the admin import test.

// LegacyStub is true while this stub is the implementation.
const LegacyStub = true

// ValidateEncoded reports whether encoded is an accepted stored-hash encoding.
func ValidateEncoded(encoded string) error {
	for _, p := range []string{"$argon2id$", "$argon2i$", "$pbkdf2-"} {
		if strings.HasPrefix(encoded, p) {
			return nil
		}
	}
	return errors.New("unsupported password hash encoding")
}
