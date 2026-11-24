// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package keys

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

func TestVerifyAllowExpired(t *testing.T) {
	ctx := context.Background()
	s, _, clk := setup(t)
	ev, ok := s.(core.ExpiredVerifier)
	if !ok {
		t.Fatal("signer does not implement core.ExpiredVerifier")
	}
	tok, _ := s.Sign(ctx, "r", claimsAt(clk, time.Minute))
	clk.add(24 * time.Hour)
	if _, err := s.Verify(ctx, "r", tok); err == nil {
		t.Fatal("Verify accepted expired token")
	}
	c, err := ev.VerifyAllowExpired(ctx, "r", tok)
	if err != nil || c["sub"] != "u1" {
		t.Fatalf("expired token rejected: %v %v", c, err)
	}
	p := strings.Split(tok, ".")
	sig := b64d(t, p[2])
	sig[0] ^= 1
	if _, err := ev.VerifyAllowExpired(ctx, "r", p[0]+"."+p[1]+"."+base64.RawURLEncoding.EncodeToString(sig)); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("bad signature accepted: %v", err)
	}
	pl := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"evil","exp":1}`))
	if _, err := ev.VerifyAllowExpired(ctx, "r", p[0]+"."+pl+"."+p[2]); err == nil {
		t.Fatal("tampered payload accepted")
	}
	var h map[string]any
	_ = json.Unmarshal(b64d(t, p[0]), &h)
	h["alg"] = "none"
	hb, _ := json.Marshal(h)
	if _, err := ev.VerifyAllowExpired(ctx, "r", base64.RawURLEncoding.EncodeToString(hb)+"."+p[1]+"."+p[2]); err == nil {
		t.Fatal("alg none accepted")
	}
	if _, err := ev.VerifyAllowExpired(ctx, "other", tok); err == nil {
		t.Fatal("token verified in another realm")
	}
}
