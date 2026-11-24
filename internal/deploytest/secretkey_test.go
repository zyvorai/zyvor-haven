// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package deploytest

import (
	"testing"

	"github.com/zyvorai/haven/internal/idp/secretbox"
)

// haven-idp refuses to start when HAVEN_IDP_SECRET_KEY is set but unparseable,
// so a placeholder in a shipped overlay must still be a valid 32-byte key.
func TestDevOverlaySecretKeyIsAValidKey(t *testing.T) {
	var found bool
	for _, o := range run(t, "kubectl", "kustomize", "deploy/overlays/dev") {
		if o.kind() != "Secret" || o.name() != "platform-idp" {
			continue
		}
		found = true
		v := str(m(o["stringData"])["secret-key"])
		if v == "" {
			t.Fatal("dev overlay Secret platform-idp has no secret-key")
		}
		if k, err := secretbox.ParseKey(v); err != nil || len(k) != 32 {
			t.Fatalf("dev overlay secret-key does not parse as a 32-byte key (the IdP would crash-loop): %v", err)
		}
	}
	if !found {
		t.Fatal("dev overlay has no platform-idp Secret")
	}
}
