// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/keys"
	"github.com/zyvorai/haven/internal/idp/password"
	"github.com/zyvorai/haven/internal/idp/store/memstore"
)

const legacyPW = "S3cret-pass-1"

// realEnv wires the real memstore, key signer and argon2 hasher.
func realEnv(t *testing.T) (*env, *memstore.Store) {
	t.Helper()
	ctx := context.Background()
	st := memstore.New()
	if err := st.CreateRealm(ctx, core.Realm{Name: "r", Enabled: true, BruteForceProtection: true,
		RefreshTokenRotation: true, AccessTokenTTL: 5 * time.Minute, RefreshTokenTTL: time.Hour}); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateClient(ctx, core.Client{Realm: "r", ClientID: "app", Enabled: true, Public: true,
		AuthCodeFlow: true, RedirectURIs: []string{cb}}); err != nil {
		t.Fatal(err)
	}
	signer := keys.New(st, keys.Options{})
	if err := signer.EnsureKey(ctx, "r"); err != nil {
		t.Fatal(err)
	}
	h := New(Config{Store: st, Signer: signer, Hasher: password.New(password.TestParams),
		BaseURL: "https://idp.example", CSRFKey: []byte("0123456789abcdef0123456789abcdef")})
	return &env{t: t, h: h}, st
}

func legacyPBKDF2SHA256(t *testing.T, pw string) string {
	t.Helper()
	salt := []byte("0123456789abcdef")
	dk, err := pbkdf2.Key(sha256.New, pw, salt, 27500, 32)
	if err != nil {
		t.Fatal(err)
	}
	e := base64.RawStdEncoding
	return fmt.Sprintf("$pbkdf2-sha256$i=27500$%s$%s", e.EncodeToString(salt), e.EncodeToString(dk))
}

func legacyArgon2i(pw string) string {
	salt := []byte("0123456789abcdef")
	key := argon2.Key([]byte(pw), salt, 2, 256, 1, 32)
	e := base64.RawStdEncoding
	return fmt.Sprintf("$argon2i$v=19$m=256,t=2,p=1$%s$%s", e.EncodeToString(salt), e.EncodeToString(key))
}

func TestLegacyHashesUpgradeOnLogin(t *testing.T) {
	cases := []struct {
		name, user, prefix string
		hash               func(t *testing.T) string
	}{
		{"pbkdf2-sha256", "kc-pbkdf2", "$pbkdf2-sha256$", func(t *testing.T) string { return legacyPBKDF2SHA256(t, legacyPW) }},
		{"argon2i", "kc-argon2i", "$argon2i$", func(*testing.T) string { return legacyArgon2i(legacyPW) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, st := realEnv(t)
			ctx := context.Background()
			legacy := tc.hash(t)
			if !strings.HasPrefix(legacy, tc.prefix) {
				t.Fatal(legacy)
			}
			if err := st.CreateUser(ctx, core.User{Realm: "r", Username: tc.user, Email: tc.user + "@x", Enabled: true,
				EmailVerified: true, PasswordHash: legacy}); err != nil {
				t.Fatal(err)
			}
			stored := func() string {
				u, err := st.GetUserByUsername(ctx, "r", tc.user)
				if err != nil {
					t.Fatal(err)
				}
				return u.PasswordHash
			}
			q := authQuery(nil)

			// Wrong password: rejected, hash untouched.
			if w := e.login(q, tc.user, legacyPW+"x"); w.Code == 302 {
				t.Fatalf("wrong password accepted: status %d", w.Code)
			}
			if got := stored(); got != legacy {
				t.Fatalf("wrong password changed the stored hash: %q", got)
			}

			// Right password: code issued, hash upgraded to argon2id.
			w := e.login(q, tc.user, legacyPW)
			if w.Code != 302 {
				t.Fatalf("login status %d: %s", w.Code, w.Body)
			}
			loc, _ := url.Parse(w.Header().Get("Location"))
			code := loc.Query().Get("code")
			if code == "" {
				t.Fatalf("no code in %s", loc)
			}
			up := stored()
			if !strings.HasPrefix(up, "$argon2id$") || up == legacy {
				t.Fatalf("hash not upgraded: %.30q", up)
			}
			// The authorization code really redeems against the real signer.
			if status, body, _ := e.tokenReq(codeForm(code), "", ""); status != 200 || body["access_token"] == nil {
				t.Fatalf("token exchange: %d %v", status, body)
			}

			// Second login with the same password works and leaves the (now
			// current) hash alone.
			if w := e.login(q, tc.user, legacyPW); w.Code != 302 {
				t.Fatalf("second login status %d", w.Code)
			}
			if got := stored(); got != up {
				t.Fatal("hash changed although it was already current")
			}
			if ok, re := password.New(password.TestParams).Verify(legacyPW, up); !ok || re {
				t.Fatalf("upgraded hash: ok=%v rehash=%v", ok, re)
			}

			// Wrong password after the upgrade: still rejected, hash untouched.
			if w := e.login(q, tc.user, legacyPW+"x"); w.Code == 302 {
				t.Fatalf("wrong password accepted after upgrade: %d", w.Code)
			}
			if got := stored(); got != up {
				t.Fatal("wrong password changed the upgraded hash")
			}
		})
	}
}
