// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"context"
	"net/http"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

const (
	defaultSessions = 100
	capSessions     = 500
	maxSessionScan  = 20000
)

func (a *api) sessionRoutes(m *http.ServeMux) {
	p := pathPrefix + "/realms/{r}"
	m.HandleFunc("GET "+p+"/sessions", a.listSessions)
	m.HandleFunc("GET "+p+"/users/{id}/sessions", a.listUserSessions)
	m.HandleFunc("DELETE "+p+"/sessions/{sid}", a.op("session", "delete", a.endSession))
	m.HandleFunc("DELETE "+p+"/users/{id}/sessions", a.op("session", "delete", a.endUserSessions))
}

// live reports whether s is still usable at now.
func live(s core.Session, now time.Time) bool {
	return now.Before(s.ExpiresAt) && now.Before(s.IdleExpires)
}

// liveSessions returns up to max live sessions, newest first. The store
// applies its limit before expired rows can be dropped, so the scan widens
// until enough live ones are found or the store has no more.
func (a *api) liveSessions(ctx context.Context, realm, userID string, max int) ([]core.Session, error) {
	now := a.cfg.Clock()
	for scan := max; ; scan *= 4 {
		scan = min(scan, maxSessionScan)
		all, err := a.cfg.Store.ListSessions(ctx, realm, userID, scan)
		if err != nil {
			return nil, err
		}
		out := make([]core.Session, 0, min(len(all), max))
		for _, s := range all {
			if live(s, now) {
				out = append(out, s)
				if len(out) == max {
					return out, nil
				}
			}
		}
		if len(all) < scan || scan >= maxSessionScan {
			return out, nil
		}
	}
}

func (a *api) sessionsToWire(ctx context.Context, realm string, in []core.Session) []idp.Session {
	names := map[string]string{}
	out := make([]idp.Session, 0, len(in))
	for _, s := range in {
		name, seen := names[s.UserID]
		if !seen {
			if u, err := a.cfg.Store.GetUser(ctx, realm, s.UserID); err == nil {
				name = u.Username
			}
			names[s.UserID] = name
		}
		exp := s.ExpiresAt
		if s.IdleExpires.Before(exp) {
			exp = s.IdleExpires
		}
		out = append(out, idp.Session{
			ID: s.ID, UserID: s.UserID, Username: name, IPAddress: s.IP, UserAgent: s.UserAgent,
			Start: s.CreatedAt, LastAccess: s.LastSeen, Expires: exp, Clients: append([]string{}, s.Clients...),
		})
	}
	return out
}

func (a *api) listSessions(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	a.writeSessions(w, r, rl, r.URL.Query().Get("userId"))
}

func (a *api) listUserSessions(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	if _, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id")); err != nil {
		a.fail(w, r, err)
		return
	}
	a.writeSessions(w, r, rl, r.PathValue("id"))
}

func (a *api) writeSessions(w http.ResponseWriter, r *http.Request, rl core.Realm, userID string) {
	if len(userID) > 200 {
		a.fail(w, r, bad("userId too long"))
		return
	}
	max, err := intParam(r, "max", defaultSessions, 1, capSessions)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	ss, err := a.liveSessions(r.Context(), rl.Name, userID, max)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, a.sessionsToWire(r.Context(), rl.Name, ss))
}

func (a *api) endSession(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	s, err := a.cfg.Sessions.End(r.Context(), rl.Name, r.PathValue("sid"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "ACTION", "session", s.ID)
	noContent(w)
}

func (a *api) endUserSessions(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	u, err := a.cfg.Store.GetUser(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	n, err := a.cfg.Sessions.EndUser(r.Context(), rl.Name, u.ID)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "ACTION", "user-sessions", u.Username)
	writeJSON(w, http.StatusOK, map[string]int{"ended": n})
}

// dropUserSessions ends every session of a user as a side effect of another
// change (disable, password reset, delete). Best effort: the primary change
// is already decided, so a failure is logged and never fails the call.
func (a *api) dropUserSessions(ctx context.Context, realm, userID string) {
	if _, err := a.cfg.Sessions.EndUser(ctx, realm, userID); err != nil {
		a.cfg.Logger.Error("admin: end user sessions", "realm", realm, "user", userID, "err", err.Error())
	}
}
