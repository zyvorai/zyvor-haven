// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package idp

import (
	"errors"
	"fmt"
	"testing"
)

func TestCheckStatus(t *testing.T) {
	if err := CheckStatus(204, nil, nil); err != nil {
		t.Fatalf("2xx must succeed, got %v", err)
	}
	transport := errors.New("dial tcp: refused")
	if err := CheckStatus(0, nil, transport); err != transport || AsStatus(err) != nil {
		t.Fatalf("transport error must pass through unchanged, got %v", err)
	}
	for code, want := range map[int]error{404: ErrNotFound, 409: ErrConflict} {
		err := fmt.Errorf("wrapped: %w", CheckStatus(code, []byte("x"), nil))
		if !errors.Is(err, want) {
			t.Errorf("%d should match %v", code, want)
		}
		if se := AsStatus(err); se == nil || se.Code != code || string(se.Body) != "x" {
			t.Errorf("%d: AsStatus lost code/body: %+v", code, se)
		}
	}
	if err := CheckStatus(500, nil, nil); errors.Is(err, ErrNotFound) || errors.Is(err, ErrConflict) {
		t.Error("500 must not match sentinels")
	}
}
