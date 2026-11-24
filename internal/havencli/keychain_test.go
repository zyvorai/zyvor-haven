// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package havencli

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/keychain"
)

// fakeVault is an in-memory Keychain.
type fakeVault struct {
	items   map[string]string
	off     bool
	failSet bool
}

func newVault() *fakeVault { return &fakeVault{items: map[string]string{}} }

func (v *fakeVault) Available() bool { return !v.off }
func (v *fakeVault) GetBlob(_ context.Context, svc, acct string) (string, error) {
	if x, ok := v.items[svc+"/"+acct]; ok {
		return x, nil
	}
	return "", keychain.ErrNotFound
}
func (v *fakeVault) SetBlob(_ context.Context, svc, acct, s string) error {
	if v.failSet {
		return errors.New("keychain locked")
	}
	v.items[svc+"/"+acct] = s
	return nil
}
func (v *fakeVault) DeleteBlob(_ context.Context, svc, acct string) error {
	delete(v.items, svc+"/"+acct)
	return nil
}

func credsText(t *testing.T, te *testEnv) string {
	t.Helper()
	b, err := os.ReadFile(te.home + "/haven/credentials.json")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestLoginKeychainKeepsTokensOutOfTheFile(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	v := newVault()
	te.env.Vault = v
	if c := te.run(loginArgs(f, "--keychain")...); c != 0 {
		t.Fatal(te.errb.String())
	}
	p := loadProfile(t, te, "default")
	if !p.Keychain || p.AccessToken == "" || p.RefreshToken == "" || p.IDToken == "" {
		t.Fatalf("tokens must come back from the Keychain: %+v", p)
	}
	file := credsText(t, te)
	for _, secret := range []string{p.AccessToken, p.RefreshToken, p.IDToken} {
		if strings.Contains(file, secret) {
			t.Fatalf("a token leaked into credentials.json:\n%s", file)
		}
	}
	if !strings.Contains(file, `"keychain": true`) {
		t.Errorf("profile not marked as Keychain-backed:\n%s", file)
	}
	if len(v.items) != 1 {
		t.Errorf("keychain items = %d", len(v.items))
	}
	for _, it := range v.items {
		if strings.Contains(it, p.AccessToken) {
			t.Error("tokens must be encoded in the item, not stored raw")
		}
	}
	assertNoSecrets(t, f, te.out.String(), te.errb.String())
}

func TestKeychainTokenRefreshRotationAndLogout(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	v := newVault()
	te.env.Vault = v
	if c := te.run(loginArgs(f, "--keychain")...); c != 0 {
		t.Fatal(te.errb.String())
	}
	before := loadProfile(t, te, "default")
	expireAccess(t, te)
	te.out.Reset()
	if c := te.run("token"); c != 0 {
		t.Fatal(te.errb.String())
	}
	after := loadProfile(t, te, "default")
	if !after.Keychain || after.RefreshToken == before.RefreshToken || f.refreshCalls != 1 {
		t.Fatalf("rotation through the Keychain failed: %+v refreshes=%d", after, f.refreshCalls)
	}
	if strings.Contains(credsText(t, te), after.RefreshToken) {
		t.Fatal("rotated refresh token leaked into the file")
	}
	if c := te.run("logout"); c != 0 {
		t.Fatal(te.errb.String())
	}
	if len(v.items) != 0 {
		t.Errorf("logout left %d Keychain items behind", len(v.items))
	}
	if loadProfile(t, te, "default") != nil {
		t.Error("profile survived logout")
	}
}

func TestKeychainFallsBackToFileWhenUnavailable(t *testing.T) {
	f := newFake(t, false)
	for name, vault := range map[string]Vault{"nil": nil, "off": &fakeVault{items: map[string]string{}, off: true}} {
		te := newEnv(t, t.TempDir())
		te.env.Vault = vault
		if c := te.run(loginArgs(f, "--keychain")...); c != 0 {
			t.Fatalf("%s: %s", name, te.errb.String())
		}
		p := loadProfile(t, te, "default")
		if p.Keychain || !strings.Contains(credsText(t, te), p.RefreshToken) {
			t.Errorf("%s: expected the 0600 file fallback", name)
		}
		if !strings.Contains(te.errb.String(), "credentials file instead") {
			t.Errorf("%s: no fallback warning: %s", name, te.errb.String())
		}
	}
}

func TestKeychainIsOptIn(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	v := newVault()
	te.env.Vault = v
	mustLogin(t, f, te)
	if len(v.items) != 0 || loadProfile(t, te, "default").Keychain {
		t.Fatal("the Keychain must not be used without --keychain")
	}
}

func TestKeychainWriteFailureDoesNotLeakToFile(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	v := newVault()
	v.failSet = true
	te.env.Vault = v
	if c := te.run(loginArgs(f, "--keychain")...); c == 0 {
		t.Fatal("login must fail when the Keychain write fails")
	}
	if b, err := os.ReadFile(te.home + "/haven/credentials.json"); err == nil && strings.Contains(string(b), "access_token") {
		t.Fatalf("tokens fell back to the file silently:\n%s", b)
	}
}

func TestKeychainProfileWithoutKeychainFailsClosed(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	te.env.Vault = newVault()
	if c := te.run(loginArgs(f, "--keychain")...); c != 0 {
		t.Fatal(te.errb.String())
	}
	te.env.Vault = nil // same file, but now on a machine without a Keychain
	te.errb.Reset()
	if c := te.run("token"); c == 0 || !strings.Contains(te.errb.String(), "Keychain") {
		t.Fatalf("exit %d, stderr %q", c, te.errb.String())
	}
}

func TestKeychainMissingItemMeansLoggedOut(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	v := newVault()
	te.env.Vault = v
	if c := te.run(loginArgs(f, "--keychain")...); c != 0 {
		t.Fatal(te.errb.String())
	}
	expireAccess(t, te)
	v.items = map[string]string{} // the user deleted it in Keychain Access
	if c := te.run("token"); c != ExitNotLoggedIn {
		t.Fatalf("exit %d: %s", c, te.errb.String())
	}
}

func TestSwitchingBackToFileDeletesKeychainItem(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	v := newVault()
	te.env.Vault = v
	if c := te.run(loginArgs(f, "--keychain")...); c != 0 {
		t.Fatal(te.errb.String())
	}
	if c := te.run(loginArgs(f)...); c != 0 {
		t.Fatal(te.errb.String())
	}
	if len(v.items) != 0 {
		t.Errorf("stale Keychain item after re-login without --keychain: %d", len(v.items))
	}
}
