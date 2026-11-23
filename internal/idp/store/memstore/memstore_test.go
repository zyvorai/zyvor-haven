// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore_test

import (
	"testing"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
	"github.com/zyvorai/haven/internal/idp/store/storetest"
)

func TestConformance(t *testing.T) {
	storetest.Run(t, func(*testing.T) core.Store { return memstore.New() })
}
