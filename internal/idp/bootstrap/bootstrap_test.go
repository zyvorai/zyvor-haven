// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package bootstrap

import (
	"context"
	"testing"

	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

func TestRunIsIdempotentAndKeepsChangedPassword(t *testing.T) {
	ctx := context.Background()
	st := memstore.New()
	h := password.New(password.TestParams)
	sg := keys.New(st, keys.Options{})
	o := Options{Realm: "platform", AdminUser: "admin", AdminPassword: "first-password-1", RedirectURIs: []string{"https://c/cb"}}

	r, err := Run(ctx, st, h, sg, o)
	if err != nil || !r.RealmCreated || !r.UserCreated || !r.ClientCreated {
		t.Fatalf("first run: %+v %v", r, err)
	}
	u, _ := st.GetUserByUsername(ctx, "platform", "ADMIN") // case-insensitive
	if ok, _ := h.Verify("first-password-1", u.PasswordHash); !ok {
		t.Fatal("admin password not set")
	}

	// An operator changes the password; a restart with the old env must not undo it.
	changed, _ := h.Hash("operator-changed-2")
	u.PasswordHash = changed
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	r, err = Run(ctx, st, h, sg, o)
	if err != nil || r.RealmCreated || r.UserCreated || r.ClientCreated {
		t.Fatalf("second run must create nothing: %+v %v", r, err)
	}
	u, _ = st.GetUserByUsername(ctx, "platform", "admin")
	if ok, _ := h.Verify("operator-changed-2", u.PasswordHash); !ok {
		t.Fatal("restart reset the operator's password")
	}
	keysOut, _ := sg.JWKS(ctx, "platform")
	if len(keysOut) == 0 {
		t.Fatal("no signing key published")
	}
}

func TestRunDisabledWithoutRealm(t *testing.T) {
	st := memstore.New()
	if r, err := Run(context.Background(), st, password.New(password.TestParams), keys.New(st, keys.Options{}), Options{}); err != nil || r != (Result{}) {
		t.Fatalf("empty realm must be a no-op: %+v %v", r, err)
	}
}
