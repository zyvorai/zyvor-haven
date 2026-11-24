// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/zyvorai/haven/internal/identityops"
	"github.com/zyvorai/haven/internal/idp"
)

// Time Machine undo (native backend only).
//
//	POST /api/v1/time-machine/snapshots/{id}/undo
//	GET  /api/v1/time-machine/undos[?realm=]
//
// The request selects entries of the snapshot's change set (what
// GET .../snapshots/{id}/diff reports). It defaults to a dry run that returns
// the plan and the live fingerprint; applying needs "dryRun": false AND the
// fingerprint from that preview, so a plan is only ever applied to the realm
// state the operator looked at.

var undoMu sync.Mutex // one undo at a time per server

// undoStore is the snapshot/journal store; tests replace it.
var undoStore = identityops.DefaultStore

type undoRequest struct {
	All             bool                    `json:"all"`
	Changes         []identityops.ChangeRef `json:"changes"`
	DryRun          *bool                   `json:"dryRun"` // nil = true
	LiveFingerprint string                  `json:"liveFingerprint"`
}

func (s *Server) UndoTimeMachineSnapshot(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var body undoRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	dry := body.DryRun == nil || *body.DryRun
	if s.KC == nil || s.backendClient() == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "no identity backend is connected"})
		return
	}
	prov := s.kc()
	if !idp.IsNative(prov) {
		writeJSON(w, http.StatusNotImplemented, map[string]any{"error": "undo is only available on the native haven-idp backend"})
		return
	}
	store := undoStore()
	snap, err := store.GetSnapshot(id)
	if err != nil {
		status := http.StatusInternalServerError
		if os.IsNotExist(err) {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]any{"error": "snapshot not found"})
		return
	}
	if !dry {
		if !undoMu.TryLock() {
			writeJSON(w, http.StatusConflict, map[string]any{"error": "another undo is running"})
			return
		}
		defer undoMu.Unlock()
		if strings.TrimSpace(body.LiveFingerprint) == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "preview first: send the liveFingerprint from a dry run"})
			return
		}
	}
	live, err := s.captureRealmSnapshot(r, snap.Realm, "live")
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": "cannot read the live realm"})
		return
	}
	diff, err := identityops.Diff(snap, live)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "diff failed"})
		return
	}
	sel := body.Changes
	if body.All {
		sel = identityops.AllChanges(diff)
	}
	_, adminClient := s.KC.Config()
	plan, err := identityops.PlanUndo(snap, diff, sel, []string{adminClient, "haven-admin"})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if dry {
		writeJSON(w, http.StatusOK, map[string]any{"dryRun": true, "executable": plan.Executable(), "plan": plan})
		return
	}
	if body.LiveFingerprint != diff.LiveFingerprint {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error": "the realm changed since the preview; preview again", "liveFingerprint": diff.LiveFingerprint})
		return
	}
	if plan.Executable() == 0 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "nothing in the selection can be undone", "plan": plan})
		return
	}
	actor := "unknown"
	if sess, ok := s.sessionFromRequest(r); ok && sess.User != "" {
		actor = sess.User
	}
	// Audit first: no record, no change.
	rec, err := identityops.NewUndoRecord(actor, plan)
	if err == nil {
		err = store.SaveUndo(rec)
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "cannot write the audit record; nothing was changed"})
		return
	}
	done := identityops.ApplyUndo(r.Context(), prov, snap, plan)
	rec.Steps, rec.Outcome, rec.FinishedAt = done.Steps, identityops.OutcomeCompleted, time.Now().UTC()
	for _, st := range done.Steps {
		if st.Status == identityops.StatusFailed {
			rec.Outcome = identityops.OutcomeFailed
		}
	}
	if after, cerr := s.captureRealmSnapshot(r, snap.Realm, "live"); cerr == nil {
		if d2, derr := identityops.Diff(snap, after); derr == nil {
			rec.RemainingFindings = len(identityops.AllChanges(d2))
		}
	}
	saveErr := store.SaveUndo(rec)
	status := http.StatusOK
	if rec.Outcome == identityops.OutcomeFailed {
		status = http.StatusBadGateway
	}
	out := map[string]any{"dryRun": false, "undoId": rec.ID, "outcome": rec.Outcome, "plan": done, "remainingChanges": rec.RemainingFindings}
	if saveErr != nil {
		out["warning"] = "the final audit record could not be written; the started record is on disk"
	}
	writeJSON(w, status, out)
}

func (s *Server) ListTimeMachineUndos(w http.ResponseWriter, r *http.Request) {
	items, err := undoStore().ListUndos(strings.TrimSpace(r.URL.Query().Get("realm")))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "cannot read the undo journal"})
		return
	}
	writeJSON(w, http.StatusOK, items)
}
