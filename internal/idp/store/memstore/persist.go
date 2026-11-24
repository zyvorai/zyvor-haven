// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Persistence for `haven-idp dev --persist DIR`: the whole store is written as
// one JSON snapshot (state.json) by a background saver and on shutdown, and
// read back at start. Writes are atomic (temp file in the same directory,
// fsync, rename, fsync of the directory) so a crash leaves the previous
// snapshot intact; the file and directory are private to the owner (0600 /
// 0700) because the snapshot holds password hashes, signing keys and sealed
// TOTP seeds. Short-lived rows (authorization codes, device codes, WebAuthn
// challenges, rate-limit windows, federation login states) are NOT persisted.
//
// Feature stores keep their rows in side tables. The built-in ones register
// below; a feature added later opts in with RegisterPersist from an init().

// StateFile is the snapshot's file name inside the persistence directory.
const StateFile = "state.json"

const snapshotVersion = 1

type snapshot struct {
	Version  int                          `json:"version"`
	Realms   map[string]core.Realm        `json:"realms,omitempty"`
	Users    map[string]core.User         `json:"users,omitempty"`
	Clients  map[string]core.Client       `json:"clients,omitempty"`
	Roles    map[string]core.Role         `json:"roles,omitempty"`
	Groups   map[string]core.Group        `json:"groups,omitempty"`
	Keys     map[string]core.SigningKey   `json:"keys,omitempty"`
	Refresh  map[string]core.RefreshToken `json:"refresh,omitempty"`
	Actions  map[string]core.ActionToken  `json:"actions,omitempty"`
	Sessions map[string]core.Session      `json:"sessions,omitempty"`
	Events   []core.Event                 `json:"events,omitempty"`
	Extra    map[string]json.RawMessage   `json:"extra,omitempty"`
}

type persistHook struct {
	save func(*Store) (any, error)
	load func(*Store, json.RawMessage) error
}

var (
	hookMu sync.Mutex
	hooks  = map[string]persistHook{}
)

// RegisterPersist lets a feature store include its side tables in snapshots.
// save returns a JSON-marshalable value (nil = nothing to save); load receives
// it back into a fresh store. Call from an init() in this package.
func RegisterPersist(name string, save func(*Store) (any, error), load func(*Store, json.RawMessage) error) {
	hookMu.Lock()
	defer hookMu.Unlock()
	hooks[name] = persistHook{save: save, load: load}
}

// Snapshot serialises the persistent part of the store.
func (s *Store) Snapshot() ([]byte, error) {
	s.mu.Lock()
	sn := snapshot{
		Version: snapshotVersion,
		Realms:  copyMap(s.realms), Users: copyMap(s.users), Clients: copyMap(s.clients),
		Roles: copyMap(s.roles), Groups: copyMap(s.groups), Keys: copyMap(s.keys),
		Refresh: copyMap(s.refresh), Actions: copyMap(s.actions), Sessions: copyMap(s.sess),
		Events: append([]core.Event(nil), s.events...),
	}
	s.mu.Unlock()

	hookMu.Lock()
	names := make([]string, 0, len(hooks))
	for n := range hooks {
		names = append(names, n)
	}
	sort.Strings(names)
	hs := make([]persistHook, len(names))
	for i, n := range names {
		hs[i] = hooks[n]
	}
	hookMu.Unlock()
	for i, n := range names {
		v, err := hs[i].save(s)
		if err != nil {
			return nil, fmt.Errorf("memstore: snapshot %s: %w", n, err)
		}
		if v == nil {
			continue
		}
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("memstore: snapshot %s: %w", n, err)
		}
		if sn.Extra == nil {
			sn.Extra = map[string]json.RawMessage{}
		}
		sn.Extra[n] = raw
	}
	return json.Marshal(sn)
}

// Restore loads a snapshot into the store, replacing persistent state, then
// drops anything that expired while the process was down.
func (s *Store) Restore(b []byte) error {
	var sn snapshot
	if err := json.Unmarshal(b, &sn); err != nil {
		return fmt.Errorf("memstore: snapshot is not valid JSON: %w", err)
	}
	if sn.Version != snapshotVersion {
		return fmt.Errorf("memstore: snapshot version %d is not supported (want %d)", sn.Version, snapshotVersion)
	}
	s.mu.Lock()
	s.realms, s.users, s.clients = orEmpty(sn.Realms), orEmpty(sn.Users), orEmpty(sn.Clients)
	s.roles, s.groups, s.keys = orEmpty(sn.Roles), orEmpty(sn.Groups), orEmpty(sn.Keys)
	s.refresh, s.actions, s.sess = orEmpty(sn.Refresh), orEmpty(sn.Actions), orEmpty(sn.Sessions)
	s.events = sn.Events
	s.mu.Unlock()

	hookMu.Lock()
	hs := make(map[string]persistHook, len(hooks))
	for n, h := range hooks {
		hs[n] = h
	}
	hookMu.Unlock()
	for n, raw := range sn.Extra {
		h, ok := hs[n]
		if !ok {
			continue // written by a newer build; ignore rather than fail dev start
		}
		if err := h.load(s, raw); err != nil {
			return fmt.Errorf("memstore: restore %s: %w", n, err)
		}
	}
	_, err := s.PurgeExpired(context.Background(), time.Now())
	return err
}

func copyMap[V any](m map[string]V) map[string]V {
	out := make(map[string]V, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func orEmpty[V any](m map[string]V) map[string]V {
	if m == nil {
		return map[string]V{}
	}
	return m
}

// ---- built-in feature tables ----

func init() {
	RegisterPersist("mfa", func(s *Store) (any, error) {
		m := s.mfa()
		m.mu.Lock()
		defer m.mu.Unlock()
		return struct {
			Creds    map[string]core.TOTPCredential `json:"creds"`
			Recovery map[string]map[string]bool     `json:"recovery"`
			Policy   map[string]core.MFAPolicy      `json:"policy"`
		}{copyMap(m.creds), copyMap(m.recovery), copyMap(m.policy)}, nil
	}, func(s *Store, raw json.RawMessage) error {
		var v struct {
			Creds    map[string]core.TOTPCredential `json:"creds"`
			Recovery map[string]map[string]bool     `json:"recovery"`
			Policy   map[string]core.MFAPolicy      `json:"policy"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		m := s.mfa()
		m.mu.Lock()
		defer m.mu.Unlock()
		m.creds, m.recovery, m.policy = orEmpty(v.Creds), orEmpty(v.Recovery), orEmpty(v.Policy)
		return nil
	})

	RegisterPersist("federation", func(s *Store) (any, error) {
		d := s.fed()
		d.mu.Lock()
		defer d.mu.Unlock()
		return struct {
			Providers map[string]core.FedProvider `json:"providers"`
			Links     map[string]core.FedLink     `json:"links"`
		}{copyMap(d.providers), copyMap(d.links)}, nil
	}, func(s *Store, raw json.RawMessage) error {
		var v struct {
			Providers map[string]core.FedProvider `json:"providers"`
			Links     map[string]core.FedLink     `json:"links"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		d := s.fed()
		d.mu.Lock()
		defer d.mu.Unlock()
		d.providers, d.links = orEmpty(v.Providers), orEmpty(v.Links)
		return nil
	})

	RegisterPersist("passkeys", func(s *Store) (any, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.pkInit()
		return struct {
			Creds    map[string]core.Passkey `json:"creds"`
			Handles  map[string]string       `json:"handles"`
			ByHandle map[string]string       `json:"byHandle"`
			Policy   map[string]bool         `json:"policy"`
		}{copyMap(s.pk.creds), copyMap(s.pk.handles), copyMap(s.pk.byHandle), copyMap(s.pk.policy)}, nil
	}, func(s *Store, raw json.RawMessage) error {
		var v struct {
			Creds    map[string]core.Passkey `json:"creds"`
			Handles  map[string]string       `json:"handles"`
			ByHandle map[string]string       `json:"byHandle"`
			Policy   map[string]bool         `json:"policy"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		s.pkInit()
		s.pk.creds, s.pk.handles, s.pk.byHandle, s.pk.policy = orEmpty(v.Creds), orEmpty(v.Handles), orEmpty(v.ByHandle), orEmpty(v.Policy)
		return nil
	})

	RegisterPersist("dcr", func(s *Store) (any, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		d := s.dcrLocked()
		return struct {
			IATs     map[string]core.InitialAccessToken `json:"iats"`
			Regs     map[string]core.RegisteredClient   `json:"regs"`
			Policies map[string]core.RegistrationPolicy `json:"policies"`
		}{copyMap(d.iats), copyMap(d.regs), copyMap(d.policies)}, nil
	}, func(s *Store, raw json.RawMessage) error {
		var v struct {
			IATs     map[string]core.InitialAccessToken `json:"iats"`
			Regs     map[string]core.RegisteredClient   `json:"regs"`
			Policies map[string]core.RegistrationPolicy `json:"policies"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		d := s.dcrLocked()
		d.iats, d.regs, d.policies = orEmpty(v.IATs), orEmpty(v.Regs), orEmpty(v.Policies)
		return nil
	})

	RegisterPersist("rolegrants", func(s *Store) (any, error) {
		g := s.gstate()
		g.mu.Lock()
		defer g.mu.Unlock()
		type row struct {
			core.RoleGrant
			RealmID string `json:"realmId"`
			Noticed bool   `json:"noticed"`
		}
		rows := make([]row, len(g.rows))
		for i, r := range g.rows {
			rows[i] = row{r.RoleGrant, r.realmID, r.noticed}
		}
		pol := make(map[string]core.GrantPolicy, len(g.policies))
		for k, p := range g.policies {
			pol[k] = p.p
		}
		return struct {
			Rows     []row                       `json:"rows"`
			Policies map[string]core.GrantPolicy `json:"policies"`
		}{rows, pol}, nil
	}, func(s *Store, raw json.RawMessage) error {
		type row struct {
			core.RoleGrant
			RealmID string `json:"realmId"`
			Noticed bool   `json:"noticed"`
		}
		var v struct {
			Rows     []row                       `json:"rows"`
			Policies map[string]core.GrantPolicy `json:"policies"`
		}
		if err := json.Unmarshal(raw, &v); err != nil {
			return err
		}
		g := s.gstate()
		g.mu.Lock()
		defer g.mu.Unlock()
		g.rows = g.rows[:0]
		for _, r := range v.Rows {
			g.rows = append(g.rows, &grantRow{RoleGrant: r.RoleGrant, realmID: r.RealmID, noticed: r.Noticed})
		}
		g.policies = map[string]policyRow{}
		for k, p := range v.Policies {
			g.policies[k] = policyRow{p: p}
		}
		return nil
	})
}

// ---- the file-backed saver ----

// Persister keeps a Store's snapshot in a directory.
type Persister struct {
	Store *Store
	dir   string

	mu   sync.Mutex
	last []byte
}

// ErrDirNotPrivate: the persistence directory exists but other users can
// access it. The snapshot holds credentials, so we refuse instead of
// changing the permissions of a directory we did not create.
var ErrDirNotPrivate = errors.New("memstore: persistence directory is accessible by other users (chmod 700 it, or pick a new directory)")

// EnsurePrivateDir creates dir with mode 0700 when missing and returns its
// cleaned path. An existing directory must not be accessible by group/other
// (ErrDirNotPrivate); its permissions are never changed.
func EnsurePrivateDir(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("memstore: empty persistence directory")
	}
	dir = filepath.Clean(dir)
	fi, err := os.Stat(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return "", err
		}
	case err != nil:
		return "", err
	case !fi.IsDir():
		return "", fmt.Errorf("memstore: %s is not a directory", dir)
	case fi.Mode().Perm()&0o077 != 0:
		return "", ErrDirNotPrivate
	}
	return dir, nil
}

// OpenPersistent loads dir/state.json into a new Store (creating dir with mode
// 0700 when missing) and returns it with its Persister. A snapshot that cannot
// be read is an error: it is never silently replaced.
func OpenPersistent(dir string) (*Store, *Persister, error) {
	dir, err := EnsurePrivateDir(dir)
	if err != nil {
		return nil, nil, err
	}
	st := New()
	p := &Persister{Store: st, dir: dir}
	b, err := os.ReadFile(filepath.Join(dir, StateFile)) // #nosec G304 -- operator-chosen directory
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return nil, nil, err
	default:
		if err := st.Restore(b); err != nil {
			return nil, nil, fmt.Errorf("%w (file: %s; move it aside to start fresh)", err, filepath.Join(dir, StateFile))
		}
		p.last = nil // force a first save so expired rows are not resurrected
	}
	return st, p, nil
}

// Dir is the persistence directory.
func (p *Persister) Dir() string { return p.dir }

// Save writes a snapshot if anything changed since the last one.
func (p *Persister) Save() error {
	b, err := p.Store.Snapshot()
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if bytes.Equal(b, p.last) {
		return nil
	}
	if err := WriteFileAtomic(filepath.Join(p.dir, StateFile), b); err != nil {
		return err
	}
	p.last = b
	return nil
}

// Run saves every interval until ctx ends, then once more. Errors go to onErr.
func (p *Persister) Run(ctx context.Context, interval time.Duration, onErr func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := p.Save(); err != nil && onErr != nil {
				onErr(err)
			}
			return
		case <-t.C:
			if err := p.Save(); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}

// WriteFileAtomic writes data to path with mode 0600: a temp file in the same
// directory is written and fsynced, renamed over path, and the directory is
// fsynced. A crash leaves either the old or the new file, never a mix.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(path)+"-*") // created 0600
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	if d, err := os.Open(dir); err == nil { // #nosec G304 -- same directory as path
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
