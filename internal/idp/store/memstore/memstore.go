// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package memstore is an in-memory core.Store for tests and dev mode.
package memstore

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// Store is a mutex-protected in-memory core.Store.
type Store struct {
	mu      sync.Mutex
	realms  map[string]core.Realm // key: lower(name)
	users   map[string]core.User  // key: id
	clients map[string]core.Client
	roles   map[string]core.Role
	groups  map[string]core.Group
	keys    map[string]core.SigningKey // key: realm + "\x00" + kid
	codes   map[string]core.AuthCode
	refresh map[string]core.RefreshToken
	actions map[string]core.ActionToken
	sess    map[string]core.Session // key: id
	events  []core.Event
	rates   map[string]rateWindow
	pk      passkeyState // passkeys.go
}

type rateWindow struct {
	end   time.Time
	count int
}

var _ core.Store = (*Store)(nil)

// New returns an empty Store.
func New() *Store {
	return &Store{
		realms:  map[string]core.Realm{},
		users:   map[string]core.User{},
		clients: map[string]core.Client{},
		roles:   map[string]core.Role{},
		groups:  map[string]core.Group{},
		keys:    map[string]core.SigningKey{},
		codes:   map[string]core.AuthCode{},
		refresh: map[string]core.RefreshToken{},
		actions: map[string]core.ActionToken{},
		sess:    map[string]core.Session{},
		rates:   map[string]rateWindow{},
	}
}

func lc(s string) string { return strings.ToLower(s) }

func cs(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return slices.Clone(s)
}

func cb(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return slices.Clone(b)
}

func cu(u core.User) core.User {
	u.PendingActions, u.Roles, u.Groups = cs(u.PendingActions), cs(u.Roles), cs(u.Groups)
	return u
}

func cc(c core.Client) core.Client {
	c.RedirectURIs, c.Origins = cs(c.RedirectURIs), cs(c.Origins)
	return c
}

func ck(k core.SigningKey) core.SigningKey {
	k.PrivatePEM, k.PublicJWK = cb(k.PrivatePEM), cb(k.PublicJWK)
	return k
}

func nf(what string) error  { return fmt.Errorf("%s: %w", what, idp.ErrNotFound) }
func dup(what string) error { return fmt.Errorf("%s: %w", what, idp.ErrConflict) }

// needRealm requires the realm to exist under exactly this name; child
// records reference the realm's canonical name.
func (s *Store) needRealm(name string) error {
	if r, ok := s.realms[lc(name)]; !ok || r.Name != name {
		return nf("realm " + name)
	}
	return nil
}

// Realms

func (s *Store) CreateRealm(_ context.Context, r core.Realm) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.realms[lc(r.Name)]; ok {
		return dup("realm " + r.Name)
	}
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	s.realms[lc(r.Name)] = r
	return nil
}

func (s *Store) GetRealm(_ context.Context, name string) (core.Realm, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.realms[lc(name)]
	if !ok {
		return core.Realm{}, nf("realm " + name)
	}
	return r, nil
}

func (s *Store) ListRealms(context.Context) ([]core.Realm, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]core.Realm, 0, len(s.realms))
	for _, r := range s.realms {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// UpdateRealm replaces every field except ID, Name and CreatedAt.
func (s *Store) UpdateRealm(_ context.Context, r core.Realm) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.realms[lc(r.Name)]
	if !ok {
		return nf("realm " + r.Name)
	}
	r.ID, r.Name, r.CreatedAt = old.ID, old.Name, old.CreatedAt
	s.realms[lc(r.Name)] = r
	return nil
}

func (s *Store) DeleteRealm(_ context.Context, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.realms[lc(name)]
	if !ok {
		return nf("realm " + name)
	}
	delete(s.realms, lc(name))
	n := r.Name
	s.pkDrop(n, "")
	for k, v := range s.sess {
		if v.Realm == n {
			delete(s.sess, k)
		}
	}
	for k, v := range s.users {
		if v.Realm == n {
			delete(s.users, k)
		}
	}
	for k, v := range s.clients {
		if v.Realm == n {
			delete(s.clients, k)
		}
	}
	for k, v := range s.roles {
		if v.Realm == n {
			delete(s.roles, k)
		}
	}
	for k, v := range s.groups {
		if v.Realm == n {
			delete(s.groups, k)
		}
	}
	for k, v := range s.keys {
		if v.Realm == n {
			delete(s.keys, k)
		}
	}
	for k, v := range s.codes {
		if v.Realm == n {
			delete(s.codes, k)
		}
	}
	for k, v := range s.refresh {
		if v.Realm == n {
			delete(s.refresh, k)
		}
	}
	for k, v := range s.actions {
		if v.Realm == n {
			delete(s.actions, k)
		}
	}
	s.events = slices.DeleteFunc(s.events, func(e core.Event) bool { return e.Realm == n })
	return nil
}

// Users

func (s *Store) userByName(realm, username string) (core.User, bool) {
	for _, u := range s.users {
		if u.Realm == realm && lc(u.Username) == lc(username) {
			return u, true
		}
	}
	return core.User{}, false
}

func (s *Store) CreateUser(_ context.Context, u core.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(u.Realm); err != nil {
		return err
	}
	if u.ID == "" {
		u.ID = uuid.NewString()
	}
	if _, ok := s.users[u.ID]; ok {
		return dup("user id " + u.ID)
	}
	if _, ok := s.userByName(u.Realm, u.Username); ok {
		return dup("user " + u.Username)
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now().UTC()
	}
	s.users[u.ID] = cu(u)
	return nil
}

func (s *Store) GetUser(_ context.Context, realm, id string) (core.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok || u.Realm != realm {
		return core.User{}, nf("user " + id)
	}
	return cu(u), nil
}

func (s *Store) GetUserByUsername(_ context.Context, realm, username string) (core.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.userByName(realm, username)
	if !ok {
		return core.User{}, nf("user " + username)
	}
	return cu(u), nil
}

// ListUsers returns users ordered by username; search is a case-insensitive
// substring match on username, email and names. limit <= 0 means no limit.
func (s *Store) ListUsers(_ context.Context, realm, search string, offset, limit int) ([]core.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	q := lc(search)
	all := []core.User{}
	for _, u := range s.users {
		if u.Realm != realm {
			continue
		}
		if q != "" && !strings.Contains(lc(u.Username), q) && !strings.Contains(lc(u.Email), q) &&
			!strings.Contains(lc(u.FirstName), q) && !strings.Contains(lc(u.LastName), q) {
			continue
		}
		all = append(all, cu(u))
	}
	sort.Slice(all, func(i, j int) bool {
		a, b := lc(all[i].Username), lc(all[j].Username)
		if a != b {
			return a < b
		}
		return all[i].ID < all[j].ID
	})
	if offset < 0 {
		offset = 0
	}
	if offset >= len(all) {
		return []core.User{}, nil
	}
	all = all[offset:]
	if limit > 0 && limit < len(all) {
		all = all[:limit]
	}
	return all, nil
}

// UpdateUser replaces every field except ID, Realm and CreatedAt.
func (s *Store) UpdateUser(_ context.Context, u core.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.users[u.ID]
	if !ok || old.Realm != u.Realm {
		return nf("user " + u.ID)
	}
	if o, ok := s.userByName(u.Realm, u.Username); ok && o.ID != u.ID {
		return dup("user " + u.Username)
	}
	u.CreatedAt = old.CreatedAt
	s.users[u.ID] = cu(u)
	return nil
}

func (s *Store) DeleteUser(_ context.Context, realm, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[id]
	if !ok || u.Realm != realm {
		return nf("user " + id)
	}
	delete(s.users, id)
	s.pkDrop(realm, id)
	for k, v := range s.sess {
		if v.Realm == realm && v.UserID == id {
			delete(s.sess, k)
		}
	}
	return nil
}

// Clients

func (s *Store) clientByClientID(realm, cid string) (core.Client, bool) {
	for _, c := range s.clients {
		if c.Realm == realm && c.ClientID == cid {
			return c, true
		}
	}
	return core.Client{}, false
}

func (s *Store) CreateClient(_ context.Context, c core.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(c.Realm); err != nil {
		return err
	}
	if c.ID == "" {
		c.ID = uuid.NewString()
	}
	if _, ok := s.clients[c.ID]; ok {
		return dup("client id " + c.ID)
	}
	if _, ok := s.clientByClientID(c.Realm, c.ClientID); ok {
		return dup("client " + c.ClientID)
	}
	if c.CreatedAt.IsZero() {
		c.CreatedAt = time.Now().UTC()
	}
	s.clients[c.ID] = cc(c)
	return nil
}

func (s *Store) GetClient(_ context.Context, realm, id string) (core.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok || c.Realm != realm {
		return core.Client{}, nf("client " + id)
	}
	return cc(c), nil
}

func (s *Store) GetClientByClientID(_ context.Context, realm, clientID string) (core.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clientByClientID(realm, clientID)
	if !ok {
		return core.Client{}, nf("client " + clientID)
	}
	return cc(c), nil
}

func (s *Store) ListClients(_ context.Context, realm string) ([]core.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.Client{}
	for _, c := range s.clients {
		if c.Realm == realm {
			out = append(out, cc(c))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClientID < out[j].ClientID })
	return out, nil
}

// UpdateClient replaces every field except ID, Realm and CreatedAt.
func (s *Store) UpdateClient(_ context.Context, c core.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, ok := s.clients[c.ID]
	if !ok || old.Realm != c.Realm {
		return nf("client " + c.ID)
	}
	if o, ok := s.clientByClientID(c.Realm, c.ClientID); ok && o.ID != c.ID {
		return dup("client " + c.ClientID)
	}
	c.CreatedAt = old.CreatedAt
	s.clients[c.ID] = cc(c)
	return nil
}

func (s *Store) DeleteClient(_ context.Context, realm, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok || c.Realm != realm {
		return nf("client " + id)
	}
	delete(s.clients, id)
	return nil
}

// Roles and groups

func (s *Store) CreateRole(_ context.Context, r core.Role) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(r.Realm); err != nil {
		return err
	}
	if r.ID == "" {
		r.ID = uuid.NewString()
	}
	for _, o := range s.roles {
		if o.ID == r.ID || (o.Realm == r.Realm && o.Name == r.Name) {
			return dup("role " + r.Name)
		}
	}
	s.roles[r.ID] = r
	return nil
}

func (s *Store) ListRoles(_ context.Context, realm string) ([]core.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.Role{}
	for _, r := range s.roles {
		if r.Realm == realm {
			out = append(out, r)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) CreateGroup(_ context.Context, g core.Group) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(g.Realm); err != nil {
		return err
	}
	if g.ID == "" {
		g.ID = uuid.NewString()
	}
	for _, o := range s.groups {
		if o.ID == g.ID || (o.Realm == g.Realm && o.Path == g.Path) {
			return dup("group " + g.Path)
		}
	}
	s.groups[g.ID] = g
	return nil
}

func (s *Store) ListGroups(_ context.Context, realm string) ([]core.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.Group{}
	for _, g := range s.groups {
		if g.Realm == realm {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

// Signing keys

// PutSigningKey inserts or replaces the key identified by (realm, KID).
func (s *Store) PutSigningKey(_ context.Context, k core.SigningKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(k.Realm); err != nil {
		return err
	}
	if k.CreatedAt.IsZero() {
		k.CreatedAt = time.Now().UTC()
	}
	s.keys[k.Realm+"\x00"+k.KID] = ck(k)
	return nil
}

// ListSigningKeys returns active keys first, then newest first.
func (s *Store) ListSigningKeys(_ context.Context, realm string) ([]core.SigningKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.SigningKey{}
	for _, k := range s.keys {
		if k.Realm == realm {
			out = append(out, ck(k))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Active != b.Active {
			return a.Active
		}
		if !a.CreatedAt.Equal(b.CreatedAt) {
			return a.CreatedAt.After(b.CreatedAt)
		}
		return a.KID < b.KID
	})
	return out, nil
}

// Authorization codes

func (s *Store) PutAuthCode(_ context.Context, c core.AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(c.Realm); err != nil {
		return err
	}
	if _, ok := s.codes[c.CodeHash]; ok {
		return dup("auth code")
	}
	s.codes[c.CodeHash] = c
	return nil
}

func (s *Store) ConsumeAuthCode(_ context.Context, codeHash string) (core.AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[codeHash]
	if !ok {
		return core.AuthCode{}, nf("auth code")
	}
	delete(s.codes, codeHash)
	return c, nil
}

// Refresh tokens

func (s *Store) PutRefreshToken(_ context.Context, t core.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(t.Realm); err != nil {
		return err
	}
	if _, ok := s.refresh[t.TokenHash]; ok {
		return dup("refresh token")
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	s.refresh[t.TokenHash] = t
	return nil
}

func (s *Store) GetRefreshToken(_ context.Context, tokenHash string) (core.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[tokenHash]
	if !ok {
		return core.RefreshToken{}, nf("refresh token")
	}
	return t, nil
}

func (s *Store) MarkRefreshUsed(_ context.Context, tokenHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[tokenHash]
	if !ok {
		return nf("refresh token")
	}
	if t.Used {
		return dup("refresh token already used")
	}
	t.Used = true
	s.refresh[tokenHash] = t
	return nil
}

func (s *Store) RevokeRefreshFamily(_ context.Context, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.refresh {
		if t.FamilyID == familyID {
			t.Revoked = true
			s.refresh[k] = t
		}
	}
	return nil
}

// RevokeUserRefreshTokens revokes every refresh token of the user.
func (s *Store) RevokeUserRefreshTokens(_ context.Context, realm, userID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, t := range s.refresh {
		if t.Realm == realm && t.UserID == userID && !t.Revoked {
			t.Revoked = true
			s.refresh[k] = t
			n++
		}
	}
	return n, nil
}

// Action tokens

func (s *Store) PutActionToken(_ context.Context, t core.ActionToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(t.Realm); err != nil {
		return err
	}
	if _, ok := s.actions[t.TokenHash]; ok {
		return dup("action token")
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now().UTC()
	}
	s.actions[t.TokenHash] = t
	return nil
}

func (s *Store) ConsumeActionToken(_ context.Context, tokenHash string) (core.ActionToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.actions[tokenHash]
	if !ok {
		return core.ActionToken{}, nf("action token")
	}
	delete(s.actions, tokenHash)
	return t, nil
}

func (s *Store) DeleteActionTokens(_ context.Context, realm, userID, purpose string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, t := range s.actions {
		if t.Realm == realm && t.UserID == userID && t.Purpose == purpose {
			delete(s.actions, k)
			n++
		}
	}
	return n, nil
}

func (s *Store) CountActionTokens(_ context.Context, realm, userID, purpose string, since time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, t := range s.actions {
		if t.Realm == realm && t.UserID == userID && t.Purpose == purpose && !t.CreatedAt.Before(since) {
			n++
		}
	}
	return n, nil
}

// Sessions

func cses(x core.Session) core.Session { x.Clients = cs(x.Clients); return x }

func (s *Store) PutSession(_ context.Context, x core.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(x.Realm); err != nil {
		return err
	}
	for _, o := range s.sess {
		if o.ID == x.ID || o.CookieHash == x.CookieHash {
			return dup("session")
		}
	}
	if x.CreatedAt.IsZero() {
		x.CreatedAt = time.Now().UTC()
	}
	s.sess[x.ID] = cses(x)
	return nil
}

func (s *Store) GetSession(_ context.Context, realm, id string) (core.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if x, ok := s.sess[id]; ok && x.Realm == realm {
		return cses(x), nil
	}
	return core.Session{}, nf("session")
}

func (s *Store) GetSessionByCookie(_ context.Context, realm, cookieHash string) (core.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, x := range s.sess {
		if x.Realm == realm && x.CookieHash == cookieHash {
			return cses(x), nil
		}
	}
	return core.Session{}, nf("session")
}

func (s *Store) TouchSession(_ context.Context, realm, id string, lastSeen, idleExpires time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sess[id]
	if !ok || x.Realm != realm {
		return nf("session")
	}
	x.LastSeen, x.IdleExpires = lastSeen, idleExpires
	s.sess[id] = x
	return nil
}

func (s *Store) AddSessionClient(_ context.Context, realm, id, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sess[id]
	if !ok || x.Realm != realm {
		return nf("session")
	}
	if !slices.Contains(x.Clients, clientID) {
		x.Clients = append(slices.Clone(x.Clients), clientID)
		s.sess[id] = x
	}
	return nil
}

func (s *Store) ListSessions(_ context.Context, realm, userID string, limit int) ([]core.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	out := []core.Session{}
	for _, x := range s.sess {
		if x.Realm == realm && (userID == "" || x.UserID == userID) {
			out = append(out, cses(x))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.After(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *Store) TakeSession(_ context.Context, realm, id string) (core.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	x, ok := s.sess[id]
	if !ok || x.Realm != realm {
		return core.Session{}, nf("session")
	}
	delete(s.sess, id)
	return cses(x), nil
}

func (s *Store) TakeUserSessions(_ context.Context, realm, userID string) ([]core.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []core.Session{}
	for k, x := range s.sess {
		if x.Realm == realm && x.UserID == userID {
			out = append(out, cses(x))
			delete(s.sess, k)
		}
	}
	return out, nil
}

func (s *Store) RevokeSessionRefreshTokens(_ context.Context, realm, sessionID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, t := range s.refresh {
		if t.Realm == realm && t.SessionID == sessionID && !t.Revoked && !hasScope(t.Scope, "offline_access") {
			t.Revoked = true
			s.refresh[k] = t
			n++
		}
	}
	return n, nil
}

func hasScope(scope, want string) bool { return slices.Contains(strings.Fields(scope), want) }

// Events

func (s *Store) AppendEvent(_ context.Context, e core.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.needRealm(e.Realm); err != nil {
		return err
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	s.events = append(s.events, e)
	return nil
}

// ListEvents returns the newest events first; limit <= 0 means 100.
func (s *Store) ListEvents(_ context.Context, realm string, limit int) ([]core.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	out := []core.Event{}
	// Walk backwards so later appends win ties in the stable sort.
	for i := len(s.events) - 1; i >= 0; i-- {
		if s.events[i].Realm == realm {
			out = append(out, s.events[i])
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// HitRateLimit implements core.Store (fixed window, mutex-atomic).
func (s *Store) HitRateLimit(_ context.Context, key string, now time.Time, window time.Duration, max int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	w, ok := s.rates[key]
	if !ok || !w.end.After(now) {
		w = rateWindow{end: now.Add(window)}
	}
	if w.count <= max {
		w.count++
	}
	s.rates[key] = w
	return w.count <= max, nil
}

// PurgeExpired deletes auth codes, refresh tokens, action tokens and finished
// rate-limit windows that expired at or before now.
func (s *Store) PurgeExpired(_ context.Context, now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, c := range s.codes {
		if !c.ExpiresAt.After(now) {
			delete(s.codes, k)
			n++
		}
	}
	for k, t := range s.refresh {
		if !t.ExpiresAt.After(now) {
			delete(s.refresh, k)
			n++
		}
	}
	for k, t := range s.actions {
		if !t.ExpiresAt.After(now) {
			delete(s.actions, k)
			n++
		}
	}
	for k, w := range s.rates {
		if !w.end.After(now) {
			delete(s.rates, k)
			n++
		}
	}
	for k, x := range s.sess {
		if !x.ExpiresAt.After(now) || !x.IdleExpires.After(now) {
			delete(s.sess, k)
			n++
		}
	}
	return n, nil
}
