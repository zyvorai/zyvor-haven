// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package native

import "github.com/zyvorai/haven/internal/idp"

var _ idp.NativeStore = (*Client)(nil)

// IsNative marks the client as a haven-idp backend (see idp.NativeStore).
func (c *Client) IsNative() bool { return true }
