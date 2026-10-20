// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"os"
	"strings"
	"sync"
	"time"
)

type Session struct {
	Token     string    `json:"-"`
	User      string    `json:"user"`
	Role      string    `json:"role"`
	Auth      string    `json:"auth"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type Store struct {
	mu     sync.RWMutex
	ttl    time.Duration
	active map[string]Session
	// Optional runtime override for local console login (set via Settings).
	localUser string
	localPass string
	hasLocal  bool
}

func NewStoreFromEnv() *Store {
	return &Store{
		ttl:    12 * time.Hour,
		active: map[string]Session{},
	}
}

// SetLocalCreds overrides env-based console credentials until process restart.
func (s *Store) SetLocalCreds(user, pass string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.localUser = user
	s.localPass = pass
	s.hasLocal = user != "" && pass != ""
}

func (s *Store) LocalUsername() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.hasLocal {
		return s.localUser
	}
	u, _, ok := LocalCreds()
	if ok {
		return u
	}
	return "admin"
}

func (s *Store) MatchLocal(user, pass string) bool {
	s.mu.RLock()
	has := s.hasLocal
	lu, lp := s.localUser, s.localPass
	s.mu.RUnlock()
	if has {
		if len(user) != len(lu) || len(pass) != len(lp) {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(user), []byte(lu)) == 1 &&
			subtle.ConstantTimeCompare([]byte(pass), []byte(lp)) == 1
	}
	return MatchLocal(user, pass)
}

func (s *Store) Issue(user, role, method string) Session {
	raw := make([]byte, 24)
	_, _ = rand.Read(raw)
	token := base64.RawURLEncoding.EncodeToString(raw)
	sess := Session{
		Token:     token,
		User:      user,
		Role:      role,
		Auth:      method,
		ExpiresAt: time.Now().Add(s.ttl),
	}
	now := time.Now()
	s.mu.Lock()
	// Sweep expired sessions that were never looked up again.
	for k, v := range s.active {
		if now.After(v.ExpiresAt) {
			delete(s.active, k)
		}
	}
	s.active[token] = sess
	s.mu.Unlock()
	return sess
}

func (s *Store) Get(token string) (Session, bool) {
	s.mu.RLock()
	sess, ok := s.active[token]
	s.mu.RUnlock()
	if !ok {
		return Session{}, false
	}
	if time.Now().After(sess.ExpiresAt) {
		// Drop expired sessions so the map does not grow without bound.
		s.mu.Lock()
		if cur, ok := s.active[token]; ok && time.Now().After(cur.ExpiresAt) {
			delete(s.active, token)
		}
		s.mu.Unlock()
		return Session{}, false
	}
	return sess, true
}

func (s *Store) Revoke(token string) {
	s.mu.Lock()
	delete(s.active, token)
	s.mu.Unlock()
}

func LocalCreds() (user, pass string, ok bool) {
	user = os.Getenv("HAVEN_CONSOLE_USER")
	pass = os.Getenv("HAVEN_CONSOLE_PASSWORD")
	if user == "" || pass == "" {
		// Fall back to Keycloak admin env if set (lab deploy).
		user = os.Getenv("KEYCLOAK_ADMIN_USER")
		pass = os.Getenv("KEYCLOAK_ADMIN_PASSWORD")
		if user == "" || pass == "" {
			return "", "", false
		}
	}
	return user, pass, true
}

func MatchLocal(user, pass string) bool {
	u, p, ok := LocalCreds()
	if !ok {
		return false
	}
	if len(user) != len(u) || len(pass) != len(p) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(user), []byte(u)) == 1 &&
		subtle.ConstantTimeCompare([]byte(pass), []byte(p)) == 1
}

func LabDemoEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("HAVEN_LAB_LOGIN")))
	return v == "1" || v == "true" || v == "yes"
}

func MatchLabDemo(user, pass string) bool {
	return LabDemoEnabled() && user == "demo" && pass == "demo"
}

func NewTokenID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
