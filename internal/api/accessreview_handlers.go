// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/zyvorai/haven/internal/accessreview"
	"github.com/zyvorai/haven/internal/identityops"
)

func accessReviewStore() *accessreview.Store {
	return accessreview.NewStore(identityops.DefaultStore().Root())
}

// liveAccessReport captures the realm and analyses it. Nothing is persisted.
func (s *Server) liveAccessReport(w http.ResponseWriter, r *http.Request, realm, breakGlass string) (accessreview.Report, bool) {
	realm = strings.TrimSpace(realm)
	if realm == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "realm is required"})
		return accessreview.Report{}, false
	}
	snap, err := s.captureRealmSnapshot(r, realm, "access-review")
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error()})
		return accessreview.Report{}, false
	}
	rep, err := accessreview.Analyze(snap, accessreview.Options{BreakGlassPattern: breakGlass})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return accessreview.Report{}, false
	}
	return rep, true
}

// AccessReviewReport is GET /api/v1/access-review?realm=&breakGlass=.
func (s *Server) AccessReviewReport(w http.ResponseWriter, r *http.Request) {
	rep, ok := s.liveAccessReport(w, r, r.URL.Query().Get("realm"), r.URL.Query().Get("breakGlass"))
	if ok {
		writeJSON(w, http.StatusOK, rep)
	}
}

func (s *Server) ListAccessReviewCampaigns(w http.ResponseWriter, r *http.Request) {
	items, err := accessReviewStore().List(strings.TrimSpace(r.URL.Query().Get("realm")))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) CreateAccessReviewCampaign(w http.ResponseWriter, r *http.Request) {
	sess, _ := s.sessionFromRequest(r)
	var body struct {
		Realm      string `json:"realm"`
		BreakGlass string `json:"breakGlass"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	rep, ok := s.liveAccessReport(w, r, body.Realm, body.BreakGlass)
	if !ok {
		return
	}
	c, err := accessReviewStore().Create(rep, sess.User)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func accessReviewSubroutes(s *Server) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/api/v1/access-review/campaigns/")
		parts := strings.Split(strings.Trim(path, "/"), "/")
		if len(parts) == 0 || parts[0] == "" || len(parts) > 2 {
			http.NotFound(w, r)
			return
		}
		id := parts[0]
		switch {
		case len(parts) == 1 && r.Method == http.MethodGet:
			c, err := accessReviewStore().Get(id)
			writeCampaign(w, http.StatusOK, c, err)
		case len(parts) == 2 && parts[1] == "decisions" && r.Method == http.MethodPost:
			s.decideAccessReview(w, r, id)
		case len(parts) == 2 && parts[1] == "close" && r.Method == http.MethodPost:
			c, err := accessReviewStore().Close(id)
			writeCampaign(w, http.StatusOK, c, err)
		default:
			http.NotFound(w, r)
		}
	}
}

func (s *Server) decideAccessReview(w http.ResponseWriter, r *http.Request, id string) {
	sess, _ := s.sessionFromRequest(r)
	var body struct {
		Username string `json:"username"`
		Action   string `json:"action"`
		Note     string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	// The reviewer is always the authenticated session user, never client input.
	c, err := accessReviewStore().Decide(id, body.Username, body.Action, sess.User, body.Note)
	writeCampaign(w, http.StatusOK, c, err)
}

func writeCampaign(w http.ResponseWriter, status int, c accessreview.Campaign, err error) {
	switch {
	case errors.Is(err, accessreview.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "campaign not found"})
	case err != nil:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
	default:
		writeJSON(w, status, map[string]any{"campaign": c, "progress": c.Progress(), "revokeWorkItems": c.RevokeWorkItems()})
	}
}
