// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package storetest

import (
	"testing"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Case is a conformance case contributed by a feature. A feature that adds a
// feature store (see core.StoreAs) registers its cases from an init() with
// Register, in its own file. Cases must skip, not fail, when the store under
// test does not implement the feature interface.
type Case struct {
	Name string
	Fn   func(t *testing.T, st core.Store)
}

var extraCases []Case

// Register adds feature cases to Run.
func Register(cases ...Case) { extraCases = append(extraCases, cases...) }
