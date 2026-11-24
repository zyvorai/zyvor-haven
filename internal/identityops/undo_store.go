// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package identityops

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Undo journal: one JSON file (mode 0600) per applied undo, written BEFORE the
// first change is made (outcome "started") and completed afterwards, so an
// undo that is interrupted still leaves a record. It holds names and statuses
// only: never secrets, passwords or tokens.

// Undo outcomes.
const (
	OutcomeStarted   = "started"
	OutcomeCompleted = "completed"
	OutcomeFailed    = "failed" // a step failed; later steps did not run
)

// UndoRecord is one audited undo.
type UndoRecord struct {
	ID                string     `json:"id"`
	Time              time.Time  `json:"time"`
	Actor             string     `json:"actor"`
	SnapshotID        string     `json:"snapshotId"`
	Realm             string     `json:"realm"`
	LiveFingerprint   string     `json:"liveFingerprintBefore"`
	Outcome           string     `json:"outcome"`
	Steps             []UndoStep `json:"steps"`
	FinishedAt        time.Time  `json:"finishedAt,omitempty"`
	RemainingFindings int        `json:"remainingChanges,omitempty"`
}

func (s *Store) undoDir() string { return filepath.Join(s.root, "time-machine-undo") }

// NewUndoRecord builds the "started" record for a plan.
func NewUndoRecord(actor string, plan UndoPlan) (UndoRecord, error) {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		return UndoRecord{}, err
	}
	now := time.Now().UTC()
	return UndoRecord{
		ID: now.Format("20060102T150405Z") + "-" + hex.EncodeToString(b[:]), Time: now,
		Actor: actor, SnapshotID: plan.SnapshotID, Realm: plan.Realm, LiveFingerprint: plan.LiveFingerprint,
		Outcome: OutcomeStarted, Steps: plan.Steps,
	}, nil
}

// SaveUndo writes (or replaces) a record atomically.
func (s *Store) SaveUndo(r UndoRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.ID == "" || safeName(r.ID) != r.ID {
		return errors.New("invalid undo id")
	}
	return atomicJSON(filepath.Join(s.undoDir(), r.ID+".json"), r, 0o600)
}

// ListUndos returns records newest first, optionally for one realm.
func (s *Store) ListUndos(realm string) ([]UndoRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ents, err := os.ReadDir(s.undoDir())
	if errors.Is(err, os.ErrNotExist) {
		return []UndoRecord{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []UndoRecord{}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(s.undoDir(), e.Name()))
		if err != nil {
			continue
		}
		var r UndoRecord
		if json.Unmarshal(raw, &r) != nil || (realm != "" && r.Realm != realm) {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}
