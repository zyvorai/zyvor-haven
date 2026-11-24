// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package idp

// NativeStore is implemented by providers that talk to haven-idp's own Admin
// API (as opposed to a generic provider). Time Machine undo is only offered on them: the
// IdP records its own ADMIN_* audit events for every change the undo makes.
type NativeStore interface {
	IsNative() bool
}

// IsNative reports whether p is backed by haven-idp.
func IsNative(p Provider) bool {
	n, ok := p.(NativeStore)
	return ok && n.IsNative()
}
