// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package sessions

import (
	"context"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Ended finishes sessions that the store already removed in the same atomic
// step that created their successor (the concurrent session limit): refresh
// tokens are revoked and clients are notified, exactly as for End.
func (s *Service) Ended(ctx context.Context, realm string, removed []core.Session) {
	for _, sess := range removed {
		s.after(ctx, realm, sess)
	}
}
