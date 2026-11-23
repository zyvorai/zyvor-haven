// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

//go:build !nativeidp

package main

import (
	"errors"

	"github.com/zyvorai/haven/internal/idp"
)

func newNativeBackend() (idp.Backend, error) {
	return nil, errors.New("native backend not compiled in")
}
