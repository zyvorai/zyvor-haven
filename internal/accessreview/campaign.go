// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package accessreview

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	ActionCertify = "certify"
	ActionRevoke  = "revoke"
	ActionDefer   = "defer"

	StatusOpen   = "open"
	StatusClosed = "closed"

	maxCampaignBytes = 32 << 20
)

var (
	idRe       = regexp.MustCompile(`^ar-[a-f0-9]{16}$`)
	reviewerRe = regexp.MustCompile(`^[A-Za-z0-9@._+-]{1,128}$`)
)

type Decision struct {
	Action    string    `json:"action"`
	Reviewer  string    `json:"reviewer"`
	Note      string    `json:"note,omitempty"`
	DecidedAt time.Time `json:"decidedAt"`
}

type CampaignItem struct {
	Item
	Decision *Decision `json:"decision,omitempty"`
}

type Campaign struct {
	ID         string         `json:"id"`
	Realm      string         `json:"realm"`
	SnapshotID string         `json:"snapshotId,omitempty"`
	Status     string         `json:"status"`
	CreatedAt  time.Time      `json:"createdAt"`
	CreatedBy  string         `json:"createdBy"`
	ClosedAt   *time.Time     `json:"closedAt,omitempty"`
	Items      []CampaignItem `json:"items"`
	// History is append-only: every decision, including superseded ones.
	History []HistoryEntry `json:"history"`
	Summary BreakGlass     `json:"breakGlass"`
}

type HistoryEntry struct {
	Username string   `json:"username"`
	Decision Decision `json:"decision"`
}

type Progress struct {
	Total, Certified, Revoked, Deferred, Pending int
}

func (c Campaign) Progress() Progress {
	p := Progress{Total: len(c.Items)}
	for _, it := range c.Items {
		switch {
		case it.Decision == nil:
			p.Pending++
		case it.Decision.Action == ActionCertify:
			p.Certified++
		case it.Decision.Action == ActionRevoke:
			p.Revoked++
		default:
			p.Deferred++
		}
	}
	return p
}

// RevokeWorkItems lists usernames a reviewer asked to have access removed.
func (c Campaign) RevokeWorkItems() []string {
	out := []string{}
	for _, it := range c.Items {
		if it.Decision != nil && it.Decision.Action == ActionRevoke {
			out = append(out, it.Username)
		}
	}
	sort.Strings(out)
	return out
}

// Store persists campaigns as 0600 JSON files under root/access-reviews.
type Store struct {
	dir string
	mu  sync.Mutex
	now func() time.Time
}

func NewStore(root string) *Store {
	return &Store{dir: filepath.Join(root, "access-reviews"), now: func() time.Time { return time.Now().UTC() }}
}

func (s *Store) path(id string) (string, error) {
	if !idRe.MatchString(id) {
		return "", ErrNotFound
	}
	return filepath.Join(s.dir, id+".json"), nil
}

// Create opens a campaign for every account in the report that holds access.
func (s *Store) Create(rep Report, createdBy string) (Campaign, error) {
	if !reviewerRe.MatchString(createdBy) {
		return Campaign{}, errors.New("a valid session user is required")
	}
	if strings.TrimSpace(rep.Realm) == "" {
		return Campaign{}, errors.New("realm is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if entries, _ := os.ReadDir(s.dir); len(entries) >= MaxCampaignsStore {
		return Campaign{}, fmt.Errorf("campaign limit of %d reached; delete old campaigns first", MaxCampaignsStore)
	}
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Campaign{}, err
	}
	c := Campaign{
		ID: "ar-" + hex.EncodeToString(raw[:]), Realm: rep.Realm, SnapshotID: rep.SnapshotID,
		Status: StatusOpen, CreatedAt: s.now(), CreatedBy: createdBy, History: []HistoryEntry{},
		Summary: rep.BreakGlass,
	}
	for _, it := range rep.Items {
		if len(it.RealmRoles)+len(it.Groups) == 0 {
			continue // break-glass account without access: reported, nothing to certify
		}
		c.Items = append(c.Items, CampaignItem{Item: it})
	}
	if len(c.Items) == 0 {
		return Campaign{}, errors.New("no accounts with access to review")
	}
	return c, s.write(c)
}

// Decide records a reviewer decision. Decisions may be changed until the
// campaign closes; the earlier decision stays in History.
func (s *Store) Decide(id, username, action, reviewer, note string) (Campaign, error) {
	switch action {
	case ActionCertify, ActionRevoke, ActionDefer:
	default:
		return Campaign{}, fmt.Errorf("action must be %s, %s or %s", ActionCertify, ActionRevoke, ActionDefer)
	}
	if !reviewerRe.MatchString(reviewer) {
		return Campaign{}, errors.New("a valid session user is required")
	}
	note = strings.TrimSpace(note)
	if len(note) > MaxNoteLen {
		return Campaign{}, fmt.Errorf("note is limited to %d bytes", MaxNoteLen)
	}
	if action == ActionRevoke && note == "" {
		return Campaign{}, errors.New("a note is required when revoking")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.read(id)
	if err != nil {
		return Campaign{}, err
	}
	if c.Status != StatusOpen {
		return Campaign{}, errors.New("campaign is closed")
	}
	for i := range c.Items {
		if c.Items[i].Username != username {
			continue
		}
		if c.Items[i].Flags != nil && containsFlag(c.Items[i].Flags, "break-glass") && action == ActionRevoke {
			return Campaign{}, errors.New("break-glass accounts cannot be revoked through a review; change them through your emergency-access procedure")
		}
		d := Decision{Action: action, Reviewer: reviewer, Note: note, DecidedAt: s.now()}
		c.Items[i].Decision = &d
		c.History = append(c.History, HistoryEntry{Username: username, Decision: d})
		return c, s.write(c)
	}
	return Campaign{}, fmt.Errorf("user %q is not part of this campaign", username)
}

// Close finalises a campaign once every account is certified or revoked.
func (s *Store) Close(id string) (Campaign, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.read(id)
	if err != nil {
		return Campaign{}, err
	}
	if c.Status == StatusClosed {
		return c, nil
	}
	if p := c.Progress(); p.Pending+p.Deferred > 0 {
		return Campaign{}, fmt.Errorf("%d account(s) still pending or deferred", p.Pending+p.Deferred)
	}
	now := s.now()
	c.Status, c.ClosedAt = StatusClosed, &now
	return c, s.write(c)
}

func (s *Store) Get(id string) (Campaign, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read(id)
}

// List returns campaigns newest first, optionally for one realm.
func (s *Store) List(realm string) ([]Campaign, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries, err := os.ReadDir(s.dir)
	if errors.Is(err, os.ErrNotExist) {
		return []Campaign{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Campaign{}
	for _, e := range entries {
		id := strings.TrimSuffix(e.Name(), ".json")
		if e.IsDir() || !idRe.MatchString(id) {
			continue
		}
		c, err := s.read(id)
		if err != nil || (realm != "" && c.Realm != realm) {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) read(id string) (Campaign, error) {
	p, err := s.path(id)
	if err != nil {
		return Campaign{}, err
	}
	fi, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return Campaign{}, ErrNotFound
	}
	if err != nil {
		return Campaign{}, err
	}
	if fi.Size() > maxCampaignBytes {
		return Campaign{}, errors.New("campaign file too large")
	}
	// #nosec G304 -- path is built from a validated campaign id under the store directory
	raw, err := os.ReadFile(p)
	if err != nil {
		return Campaign{}, err
	}
	var c Campaign
	if err := json.Unmarshal(raw, &c); err != nil {
		return Campaign{}, err
	}
	return c, nil
}

func (s *Store) write(c Campaign) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return err
	}
	p, err := s.path(c.ID)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, ".haven-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(append(raw, '\n')); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	return os.Rename(name, p)
}

func containsFlag(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}
