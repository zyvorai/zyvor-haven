// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package havencli

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/zyvorai/haven/internal/keychain"
)

// Profile is one stored login. The tokens are secrets: they live only in the
// 0600 credentials file and are never printed except by "haven token" and
// "haven exec-credential", which write them to stdout on purpose.
type Profile struct {
	Issuer       string    `json:"issuer"`
	ClientID     string    `json:"client_id"`
	Scopes       string    `json:"scopes,omitempty"`
	CAFile       string    `json:"ca_file,omitempty"`
	AccessToken  string    `json:"access_token,omitempty"`
	AccessExpiry time.Time `json:"access_expires_at,omitzero"`
	IDToken      string    `json:"id_token,omitempty"`
	IDExpiry     time.Time `json:"id_expires_at,omitzero"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitzero"`
	// Keychain marks a profile whose tokens live in the macOS Keychain instead
	// of this file (opt-in: `haven login --keychain`). The file then keeps only
	// the non-secret metadata and expiry times.
	Keychain bool `json:"keychain,omitempty"`
}

// Vault is the secret store behind `--keychain`; *keychain.Client implements it.
type Vault interface {
	Available() bool
	GetBlob(ctx context.Context, service, account string) (string, error)
	SetBlob(ctx context.Context, service, account, secret string) error
	DeleteBlob(ctx context.Context, service, account string) error
}

const keychainService = "haven-cli"

// tokenSet is what goes into the Keychain for a profile.
type tokenSet struct {
	AccessToken  string `json:"a,omitempty"`
	IDToken      string `json:"i,omitempty"`
	RefreshToken string `json:"r,omitempty"`
}

type credsFile struct {
	Version  int                 `json:"version"`
	Profiles map[string]*Profile `json:"profiles"`
}

var profileNameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func validProfileName(n string) error {
	if !profileNameRE.MatchString(n) {
		return usageErrorf("invalid --profile %q (use letters, digits, '.', '_' or '-', at most 64)", n)
	}
	return nil
}

// store is the credentials file in the haven config directory.
type store struct {
	dir   string
	warn  io.Writer
	vault Vault // nil when the platform has no Keychain
}

// configDir resolves $XDG_CONFIG_HOME/haven, falling back to ~/.config/haven.
func configDir(env *Env) (string, error) {
	if x := env.Getenv("XDG_CONFIG_HOME"); x != "" && filepath.IsAbs(x) {
		return filepath.Join(x, "haven"), nil
	}
	home, err := env.UserHomeDir()
	if err != nil || home == "" {
		return "", errors.New("cannot determine the config directory: set XDG_CONFIG_HOME or HOME")
	}
	return filepath.Join(home, ".config", "haven"), nil
}

func newStore(env *Env) (*store, error) {
	d, err := configDir(env)
	if err != nil {
		return nil, err
	}
	return &store{dir: d, warn: env.Stderr, vault: env.Vault}, nil
}

func (s *store) path() string     { return filepath.Join(s.dir, "credentials.json") }
func (s *store) lockPath() string { return filepath.Join(s.dir, "credentials.lock") }

// ensureDir creates the directory 0700 and tightens an existing looser one.
func (s *store) ensureDir() error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	if runtimeHasUnixModes() {
		if fi, err := os.Stat(s.dir); err == nil && fi.Mode().Perm()&0o077 != 0 {
			_, _ = fmt.Fprintf(s.warn, "haven: warning: %s was accessible to other users (mode %04o); tightening to 0700\n", s.dir, fi.Mode().Perm())
			if err := os.Chmod(s.dir, 0o700); err != nil { // #nosec G302 -- directory: needs the execute bit; 0700 is owner-only
				return err
			}
		}
	}
	return nil
}

// load reads the file. A missing file is an empty store. A group/world
// accessible file is accepted with a warning and chmod'ed to 0600 (we choose
// repair over refusing, so a stray umask does not lock the user out; the
// tokens were already on disk either way).
func (s *store) load() (*credsFile, error) {
	fi, err := os.Lstat(s.path())
	if errors.Is(err, fs.ErrNotExist) {
		return &credsFile{Version: 1, Profiles: map[string]*Profile{}}, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file; refusing to read it", s.path())
	}
	if runtimeHasUnixModes() && fi.Mode().Perm()&0o077 != 0 {
		_, _ = fmt.Fprintf(s.warn, "haven: warning: %s was accessible to other users (mode %04o); tightening to 0600\n", s.path(), fi.Mode().Perm())
		if err := os.Chmod(s.path(), 0o600); err != nil {
			return nil, err
		}
	}
	b, err := os.ReadFile(s.path())
	if err != nil {
		return nil, err
	}
	var f credsFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("%s is not valid JSON; fix or remove it", s.path())
	}
	if f.Profiles == nil {
		f.Profiles = map[string]*Profile{}
	}
	for name, p := range f.Profiles {
		if p != nil && p.Keychain {
			if err := s.loadTokens(name, p); err != nil {
				return nil, err
			}
		}
	}
	return &f, nil
}

func (s *store) vaultReady(name string) error {
	if s.vault == nil || !s.vault.Available() {
		return fmt.Errorf("profile %q keeps its tokens in the macOS Keychain, which is not available here; run `haven login --profile %s` again", name, name)
	}
	return nil
}

// loadTokens fills p's tokens from the Keychain. A missing item leaves them
// empty (the profile then reads as expired and asks for a new login).
func (s *store) loadTokens(name string, p *Profile) error {
	if err := s.vaultReady(name); err != nil {
		return err
	}
	raw, err := s.vault.GetBlob(context.Background(), keychainService, name)
	if errors.Is(err, keychain.ErrNotFound) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading the Keychain item for profile %q: %w", name, err)
	}
	b, err := base64.StdEncoding.DecodeString(raw)
	var ts tokenSet
	if err != nil || json.Unmarshal(b, &ts) != nil {
		return fmt.Errorf("the Keychain item for profile %q is damaged; run `haven login --profile %s` again", name, name)
	}
	p.AccessToken, p.IDToken, p.RefreshToken = ts.AccessToken, ts.IDToken, ts.RefreshToken
	return nil
}

// onDiskKeychainProfiles lists the profile names the file currently marks as
// Keychain-backed (errors are ignored: this is only used for cleanup).
func (s *store) onDiskKeychainProfiles() []string {
	b, err := os.ReadFile(s.path())
	if err != nil {
		return nil
	}
	var f credsFile
	if json.Unmarshal(b, &f) != nil {
		return nil
	}
	var out []string
	for n, p := range f.Profiles {
		if p != nil && p.Keychain {
			out = append(out, n)
		}
	}
	return out
}

// save writes atomically: temp file in the same directory (0600), fsync, rename.
func (s *store) save(f *credsFile) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	f.Version = 1
	stale := s.onDiskKeychainProfiles()
	disk := &credsFile{Version: 1, Profiles: make(map[string]*Profile, len(f.Profiles))}
	for name, p := range f.Profiles {
		if p == nil || !p.Keychain {
			disk.Profiles[name] = p
			continue
		}
		if err := s.vaultReady(name); err != nil {
			return err
		}
		raw, err := json.Marshal(tokenSet{AccessToken: p.AccessToken, IDToken: p.IDToken, RefreshToken: p.RefreshToken}) // #nosec G117 -- tokens go only to the credential vault, never to the plain config file or logs
		if err != nil {
			return err
		}
		if err := s.vault.SetBlob(context.Background(), keychainService, name, base64.StdEncoding.EncodeToString(raw)); err != nil {
			return fmt.Errorf("storing tokens in the Keychain for profile %q: %w", name, err)
		}
		c := *p // the file keeps no secrets for this profile
		c.AccessToken, c.IDToken, c.RefreshToken = "", "", ""
		disk.Profiles[name] = &c
	}
	b, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".credentials-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(name)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil && runtimeHasUnixModes() {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, s.path()); err != nil {
		return err
	}
	ok = true
	// Remove Keychain items of profiles that were deleted or moved back to the file.
	for _, name := range stale {
		if p := f.Profiles[name]; p != nil && p.Keychain {
			continue
		}
		if s.vault == nil || !s.vault.Available() {
			continue
		}
		if err := s.vault.DeleteBlob(context.Background(), keychainService, name); err != nil {
			_, _ = fmt.Fprintf(s.warn, "haven: warning: could not delete the Keychain item for profile %q (%v); remove service %q account %q in Keychain Access\n", name, err, keychainService, name)
		}
	}
	return nil
}

// withLock runs fn holding the exclusive credentials lock. fn must re-read the
// store itself: another process may have changed it while we waited.
func (s *store) withLock(ctx context.Context, fn func() error) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	unlock, err := lockFile(ctx, s.lockPath(), 60*time.Second)
	if err != nil {
		return err
	}
	defer unlock()
	return fn()
}

// profile returns a copy of the named profile, or a notLoggedIn error.
func (s *store) profile(name string) (*Profile, error) {
	f, err := s.load()
	if err != nil {
		return nil, err
	}
	p := f.Profiles[name]
	if p == nil {
		return nil, notLoggedInf("not logged in (profile %q): run `haven login --issuer URL --client-id ID`", name)
	}
	c := *p
	return &c, nil
}

// update loads, applies fn and saves, under the lock.
func (s *store) update(ctx context.Context, fn func(*credsFile) error) error {
	return s.withLock(ctx, func() error {
		f, err := s.load()
		if err != nil {
			return err
		}
		if err := fn(f); err != nil {
			return err
		}
		return s.save(f)
	})
}
