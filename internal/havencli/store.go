// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package havencli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"
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
	dir  string
	warn io.Writer
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
	return &store{dir: d, warn: env.Stderr}, nil
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
			fmt.Fprintf(s.warn, "haven: warning: %s was accessible to other users (mode %04o); tightening to 0700\n", s.dir, fi.Mode().Perm())
			if err := os.Chmod(s.dir, 0o700); err != nil {
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
		fmt.Fprintf(s.warn, "haven: warning: %s was accessible to other users (mode %04o); tightening to 0600\n", s.path(), fi.Mode().Perm())
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
	return &f, nil
}

// save writes atomically: temp file in the same directory (0600), fsync, rename.
func (s *store) save(f *credsFile) error {
	if err := s.ensureDir(); err != nil {
		return err
	}
	f.Version = 1
	b, err := json.MarshalIndent(f, "", "  ")
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
