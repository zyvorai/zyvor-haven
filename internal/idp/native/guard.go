// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package native

import (
	"context"
	"net/http"

	"github.com/zyvorai/haven/internal/idp"
)

// EvaluateGuard asks the server's Guard gate about a proposed realm or client
// write without applying it (POST /realms/{r}/guard/evaluate).
func (c *Client) EvaluateGuard(ctx context.Context, realm, kind string, body any) (idp.GuardVerdict, error) {
	var v idp.GuardVerdict
	in := map[string]any{"kind": kind, "body": body}
	err := c.call(ctx, http.MethodPost, realmPath(realm)+"/guard/evaluate", in, &v)
	return v, err
}

var _ idp.GuardEvaluator = (*Client)(nil)
