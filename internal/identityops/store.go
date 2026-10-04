// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package identityops

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/keycloak"
)

const schemaVersion = 1

// RealmSnapshot is an immutable, portable recovery point for a Keycloak realm.
// Secrets are intentionally not captured. Client secrets are rotated and managed
// through Credential Center instead of being stored in Time Machine snapshots.
type UserAccess struct {
	Username   string   `json:"username"`
	RealmRoles []string `json:"realmRoles,omitempty"`
	Groups     []string `json:"groups,omitempty"`
}

type RealmSnapshot struct {
	SchemaVersion     int                         `json:"schemaVersion"`
	ID                string                      `json:"id"`
	Realm             string                      `json:"realm"`
	CreatedAt         time.Time                   `json:"createdAt"`
	Reason            string                      `json:"reason,omitempty"`
	Fingerprint       string                      `json:"fingerprint"`
	RealmConfig       keycloak.Realm              `json:"realmConfig"`
	Clients           []keycloak.Client           `json:"clients"`
	Users             []keycloak.User             `json:"users"`
	Roles             []keycloak.Role             `json:"roles"`
	Groups            []keycloak.Group            `json:"groups"`
	IdentityProviders []keycloak.IdentityProvider `json:"identityProviders"`
	UserAccess        []UserAccess                `json:"userAccess,omitempty"`
	PartialExport     json.RawMessage             `json:"partialExport,omitempty"`
}

type SnapshotSummary struct {
	ID          string    `json:"id"`
	Realm       string    `json:"realm"`
	CreatedAt   time.Time `json:"createdAt"`
	Reason      string    `json:"reason,omitempty"`
	Fingerprint string    `json:"fingerprint"`
	Clients     int       `json:"clients"`
	Users       int       `json:"users"`
	Roles       int       `json:"roles"`
	Groups      int       `json:"groups"`
	Providers   int       `json:"providers"`
}

type RotationRecord struct {
	Realm            string    `json:"realm"`
	ClientID         string    `json:"clientId"`
	ClientUUID       string    `json:"clientUuid"`
	LastRotatedAt    time.Time `json:"lastRotatedAt"`
	OverlapAvailable bool      `json:"overlapAvailable"`
	RotationID       string    `json:"rotationId"`
}

type Store struct {
	root string
	mu   sync.Mutex
}

var (
	defaultStore *Store
	defaultOnce  sync.Once
)

func DefaultStore() *Store {
	defaultOnce.Do(func() {
		root := strings.TrimSpace(os.Getenv("HAVEN_DATA_DIR"))
		if root == "" {
			root = filepath.Join(os.TempDir(), "haven")
		}
		defaultStore = NewStore(root)
	})
	return defaultStore
}

func NewStore(root string) *Store {
	return &Store{root: root}
}

func (s *Store) Root() string { return s.root }

func (s *Store) snapshotsDir() string  { return filepath.Join(s.root, "time-machine") }
func (s *Store) rotationsPath() string { return filepath.Join(s.root, "credential-rotations.json") }

func (s *Store) SaveSnapshot(in RealmSnapshot) (RealmSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.TrimSpace(in.Realm) == "" {
		return RealmSnapshot{}, errors.New("realm is required")
	}
	if in.CreatedAt.IsZero() {
		in.CreatedAt = time.Now().UTC()
	}
	in.SchemaVersion = schemaVersion
	sanitizeSnapshot(&in)
	if in.Fingerprint == "" {
		fp, err := Fingerprint(in)
		if err != nil {
			return RealmSnapshot{}, err
		}
		in.Fingerprint = fp
	}
	if in.ID == "" {
		short := in.Fingerprint
		if len(short) > 12 {
			short = short[:12]
		}
		in.ID = fmt.Sprintf("%s-%s-%s", safeName(in.Realm), in.CreatedAt.Format("20060102T150405.000000000Z"), short)
	}

	dir := s.snapshotsDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return RealmSnapshot{}, err
	}
	path := filepath.Join(dir, safeName(in.ID)+".json")
	if _, err := os.Stat(path); err == nil {
		return RealmSnapshot{}, fmt.Errorf("snapshot %s already exists", in.ID)
	}
	if err := atomicJSON(path, in, 0o600); err != nil {
		return RealmSnapshot{}, err
	}
	return in, nil
}

func (s *Store) GetSnapshot(id string) (RealmSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out RealmSnapshot
	if strings.TrimSpace(id) == "" {
		return out, errors.New("snapshot id is required")
	}
	raw, err := os.ReadFile(filepath.Join(s.snapshotsDir(), safeName(id)+".json"))
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return RealmSnapshot{}, err
	}
	return out, nil
}

func (s *Store) DeleteSnapshot(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(id) == "" {
		return errors.New("snapshot id is required")
	}
	return os.Remove(filepath.Join(s.snapshotsDir(), safeName(id)+".json"))
}

func (s *Store) ListSnapshots(realm string) ([]SnapshotSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.snapshotsDir())
	if errors.Is(err, os.ErrNotExist) {
		return []SnapshotSummary{}, nil
	}
	if err != nil {
		return nil, err
	}

	out := make([]SnapshotSummary, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.snapshotsDir(), entry.Name()))
		if err != nil {
			continue
		}
		var snap RealmSnapshot
		if json.Unmarshal(raw, &snap) != nil {
			continue
		}
		if realm != "" && snap.Realm != realm {
			continue
		}
		out = append(out, SnapshotSummary{
			ID: snap.ID, Realm: snap.Realm, CreatedAt: snap.CreatedAt, Reason: snap.Reason,
			Fingerprint: snap.Fingerprint, Clients: len(snap.Clients), Users: len(snap.Users),
			Roles: len(snap.Roles), Groups: len(snap.Groups), Providers: len(snap.IdentityProviders),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *Store) RecordRotation(rec RotationRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if rec.Realm == "" || rec.ClientUUID == "" {
		return errors.New("realm and clientUuid are required")
	}
	if rec.LastRotatedAt.IsZero() {
		rec.LastRotatedAt = time.Now().UTC()
	}
	if rec.RotationID == "" {
		rec.RotationID = fmt.Sprintf("rot-%d", rec.LastRotatedAt.UnixNano())
	}

	records, _ := s.readRotationsLocked()
	replaced := false
	for i := range records {
		if records[i].Realm == rec.Realm && records[i].ClientUUID == rec.ClientUUID {
			records[i] = rec
			replaced = true
			break
		}
	}
	if !replaced {
		records = append(records, rec)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].Realm == records[j].Realm {
			return records[i].ClientID < records[j].ClientID
		}
		return records[i].Realm < records[j].Realm
	})
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return err
	}
	return atomicJSON(s.rotationsPath(), records, 0o600)
}

func (s *Store) Rotation(realm, clientUUID string) (RotationRecord, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	records, _ := s.readRotationsLocked()
	for _, rec := range records {
		if rec.Realm == realm && rec.ClientUUID == clientUUID {
			return rec, true
		}
	}
	return RotationRecord{}, false
}

func (s *Store) ClearOverlap(realm, clientUUID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	records, err := s.readRotationsLocked()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	for i := range records {
		if records[i].Realm == realm && records[i].ClientUUID == clientUUID {
			records[i].OverlapAvailable = false
		}
	}
	if err := os.MkdirAll(s.root, 0o700); err != nil {
		return err
	}
	return atomicJSON(s.rotationsPath(), records, 0o600)
}

func (s *Store) readRotationsLocked() ([]RotationRecord, error) {
	raw, err := os.ReadFile(s.rotationsPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []RotationRecord{}, nil
		}
		return nil, err
	}
	var out []RotationRecord
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func Fingerprint(in RealmSnapshot) (string, error) {
	clone := in
	clone.ID = ""
	clone.CreatedAt = time.Time{}
	clone.Reason = ""
	clone.Fingerprint = ""
	clone.SchemaVersion = schemaVersion
	sanitizeSnapshot(&clone)

	raw, err := json.Marshal(clone)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func sanitizeSnapshot(s *RealmSnapshot) {
	// Do not retain secrets or server-generated IDs. Their presence makes snapshots
	// unnecessarily sensitive and fingerprints unstable across clean restores.
	s.RealmConfig.ID = ""
	for i := range s.Clients {
		s.Clients[i].ID = ""
		s.Clients[i].Secret = ""
	}
	for i := range s.Users {
		s.Users[i].ID = ""
	}
	for i := range s.Roles {
		s.Roles[i].ID = ""
	}
	for i := range s.Groups {
		s.Groups[i].ID = ""
	}

	sort.Slice(s.Clients, func(i, j int) bool { return s.Clients[i].ClientID < s.Clients[j].ClientID })
	sort.Slice(s.Users, func(i, j int) bool { return s.Users[i].Username < s.Users[j].Username })
	sort.Slice(s.Roles, func(i, j int) bool { return s.Roles[i].Name < s.Roles[j].Name })
	sort.Slice(s.Groups, func(i, j int) bool { return s.Groups[i].Path < s.Groups[j].Path })
	sort.Slice(s.IdentityProviders, func(i, j int) bool { return s.IdentityProviders[i].Alias < s.IdentityProviders[j].Alias })
	for i := range s.UserAccess {
		sort.Strings(s.UserAccess[i].RealmRoles)
		sort.Strings(s.UserAccess[i].Groups)
	}
	sort.Slice(s.UserAccess, func(i, j int) bool { return s.UserAccess[i].Username < s.UserAccess[j].Username })
	if len(s.PartialExport) > 0 {
		s.PartialExport = SanitizePartialExport(s.PartialExport)
	}
}

// SanitizePartialExport canonicalizes Keycloak's native partial export and removes
// credential-like fields before the snapshot is persisted.
func SanitizePartialExport(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil
	}
	redactSecrets(value)
	if obj, ok := value.(map[string]any); ok {
		obj["policy"] = "SKIP"
		delete(obj, "id")
		delete(obj, "realm")
	}
	out, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return json.RawMessage(out)
}

func redactSecrets(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			lower := strings.ToLower(k)
			if strings.Contains(lower, "secret") || strings.Contains(lower, "password") || strings.Contains(lower, "credential") {
				delete(x, k)
				continue
			}
			redactSecrets(child)
		}
	case []any:
		for _, child := range x {
			redactSecrets(child)
		}
	}
}

func safeName(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	out := strings.Trim(b.String(), ".-")
	if out == "" {
		return "unknown"
	}
	return out
}

func atomicJSON(path string, v any, mode os.FileMode) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".haven-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
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
	return os.Rename(tmpName, path)
}
