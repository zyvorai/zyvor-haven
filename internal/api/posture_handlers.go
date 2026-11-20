// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"net/http"
	"strings"

	"github.com/zyvorai/haven/internal/keycloak"
	"github.com/zyvorai/haven/internal/posture"
)

func (s *Server) SecurityPosture(w http.ResponseWriter, r *http.Request) {
	report, ok := s.buildSecurityPosture(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *Server) SecurityPostureSARIF(w http.ResponseWriter, r *http.Request) {
	report, ok := s.buildSecurityPosture(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="haven-guard.sarif"`)
	writeJSON(w, http.StatusOK, posture.ToSARIF(report))
}

func (s *Server) buildSecurityPosture(w http.ResponseWriter, r *http.Request) (posture.Report, bool) {
	kc := s.kc()
	if kc == nil {
		writeKCError(w, http.StatusServiceUnavailable, "Keycloak is not connected", nil)
		return posture.Report{}, false
	}

	realms, err := kc.ListRealms(r.Context())
	if err != nil {
		writeKCError(w, http.StatusBadGateway, "failed to list realms: "+err.Error(), nil)
		return posture.Report{}, false
	}

	wanted := strings.TrimSpace(r.URL.Query().Get("realm"))
	includeMaster := r.URL.Query().Get("includeMaster") == "1" || strings.EqualFold(r.URL.Query().Get("includeMaster"), "true")
	selected := make([]keycloak.Realm, 0, len(realms))
	clients := map[string][]keycloak.Client{}

	for _, realm := range realms {
		if wanted != "" && realm.Realm != wanted {
			continue
		}
		if wanted == "" && realm.Realm == "master" && !includeMaster {
			continue
		}
		items, err := kc.ListClients(r.Context(), realm.Realm)
		if err != nil {
			writeKCError(w, http.StatusBadGateway, "failed to list clients for realm "+realm.Realm+": "+err.Error(), nil)
			return posture.Report{}, false
		}
		selected = append(selected, realm)
		clients[realm.Realm] = items
	}

	if wanted != "" && len(selected) == 0 {
		writeKCError(w, http.StatusNotFound, "realm not found: "+wanted, nil)
		return posture.Report{}, false
	}

	return posture.Evaluate(selected, clients, posture.Options{Baseline: r.URL.Query().Get("baseline")}), true
}
