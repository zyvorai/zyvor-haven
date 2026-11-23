// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package configcode

// TEMPORARY stubs for the engine signatures so gate/render/CLI compile in
// isolation. The lead deletes this file at merge time.

import (
	"context"
	"errors"
	"io"

	"github.com/zyvorai/haven/internal/idp"
)

var ErrNotImplemented = errors.New("configcode: not implemented (stub)")

func Parse(r io.Reader) (*Spec, error) { return nil, ErrNotImplemented }
func Marshal(s *Spec) ([]byte, error)  { return nil, ErrNotImplemented }
func (s *Spec) Validate() error        { return nil }
func Read(ctx context.Context, p idp.Provider, realm string) (*Spec, error) {
	return nil, ErrNotImplemented
}
func Diff(desired, live *Spec, o Options) *Plan { return &Plan{Realm: desired.Realm} }
func Apply(ctx context.Context, p idp.Provider, plan *Plan, desired *Spec) (*ApplyResult, error) {
	return nil, ErrNotImplemented
}
