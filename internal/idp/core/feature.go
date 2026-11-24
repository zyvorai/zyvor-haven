// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

// Feature stores. Core features (realms, users, sessions...) are methods on
// Store. Newer features define their OWN small interface next to the feature
// (for example a device-code store) and the stores implement it in separate
// files; handlers reach it with StoreAs. A store that does not implement the
// interface simply does not offer the feature, and the handler must fail
// closed (feature off), never panic.

// Unwrapper is implemented by Store decorators (audit, metrics) so StoreAs can
// see through them.
type Unwrapper interface{ Unwrap() Store }

// StoreAs finds an implementation of T in st or in any store it wraps.
func StoreAs[T any](st Store) (T, bool) {
	for st != nil {
		if t, ok := st.(T); ok {
			return t, true
		}
		u, ok := st.(Unwrapper)
		if !ok {
			break
		}
		st = u.Unwrap()
	}
	var zero T
	return zero, false
}
