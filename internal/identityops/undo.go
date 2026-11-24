// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package identityops

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
)

// Time Machine undo: revert a selected part of the change set between a
// snapshot and the live realm. The change set is what Diff reports: names that
// were ADDED to the realm since the snapshot (undo = delete them) and names
// that were REMOVED since (undo = recreate them from the snapshot). Objects
// that exist in both but were edited are not detected by Diff and so are not
// reverted. Everything goes through idp.Provider, i.e. the haven-idp Admin API,
// so the IdP records its own ADMIN_* events for every step.

// Change kinds and directions.
const (
	KindClient   = "client"
	KindUser     = "user"
	KindRole     = "role"
	KindGroup    = "group"
	KindProvider = "provider"
	KindAccess   = "access"

	ChangeAdded   = "added"   // present live, absent in the snapshot
	ChangeRemoved = "removed" // present in the snapshot, absent live
)

// Step actions and statuses.
const (
	ActionDelete   = "delete"
	ActionRecreate = "recreate"
	ActionGrant    = "grant"

	StatusPlanned     = "planned"
	StatusDone        = "done"
	StatusFailed      = "failed"
	StatusNotRun      = "not_run" // an earlier step failed
	StatusSkipped     = "skipped"
	StatusUnsupported = "unsupported"

	maxUndoChanges = 500
	maxNameLen     = 512
)

// ChangeRef selects one entry of a diff.
type ChangeRef struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Change string `json:"change"` // ChangeAdded | ChangeRemoved
}

// UndoStep is one planned or executed operation.
type UndoStep struct {
	Kind   string `json:"kind"`
	Name   string `json:"name"`
	Change string `json:"change"`
	Action string `json:"action,omitempty"`
	Status string `json:"status"`
	Note   string `json:"note,omitempty"`
}

// UndoPlan is the preview and, after ApplyUndo, the result.
type UndoPlan struct {
	SnapshotID      string     `json:"snapshotId"`
	Realm           string     `json:"realm"`
	LiveFingerprint string     `json:"liveFingerprint"`
	Steps           []UndoStep `json:"steps"`
}

// Executable counts the steps that would change something.
func (p UndoPlan) Executable() int {
	n := 0
	for _, s := range p.Steps {
		if s.Status == StatusPlanned {
			n++
		}
	}
	return n
}

// AllChanges lists every entry of a diff as a selection.
func AllChanges(d SnapshotDiff) []ChangeRef {
	var out []ChangeRef
	add := func(kind string, cs ChangeSet) {
		for _, n := range cs.Added {
			out = append(out, ChangeRef{kind, n, ChangeAdded})
		}
		for _, n := range cs.Removed {
			out = append(out, ChangeRef{kind, n, ChangeRemoved})
		}
	}
	add(KindClient, d.Clients)
	add(KindUser, d.Users)
	add(KindRole, d.Roles)
	add(KindGroup, d.Groups)
	add(KindProvider, d.Providers)
	add(KindAccess, d.Access)
	return out
}

func setOf(cs ChangeSet, change string) map[string]bool {
	src := cs.Added
	if change == ChangeRemoved {
		src = cs.Removed
	}
	m := make(map[string]bool, len(src))
	for _, n := range src {
		m[n] = true
	}
	return m
}

func (d SnapshotDiff) set(kind string) (ChangeSet, bool) {
	switch kind {
	case KindClient:
		return d.Clients, true
	case KindUser:
		return d.Users, true
	case KindRole:
		return d.Roles, true
	case KindGroup:
		return d.Groups, true
	case KindProvider:
		return d.Providers, true
	case KindAccess:
		return d.Access, true
	}
	return ChangeSet{}, false
}

// PlanUndo validates the selection against the diff and builds the ordered
// plan. Only entries that really are in the diff can be selected; anything
// else is an error, so a request can never name arbitrary objects. protected
// lists client ids that must never be deleted (the credential this server
// itself uses to manage the realm).
func PlanUndo(snap RealmSnapshot, d SnapshotDiff, sel []ChangeRef, protected []string) (UndoPlan, error) {
	plan := UndoPlan{SnapshotID: snap.ID, Realm: snap.Realm, LiveFingerprint: d.LiveFingerprint}
	if len(sel) == 0 {
		return plan, errors.New("select at least one change")
	}
	if len(sel) > maxUndoChanges {
		return plan, fmt.Errorf("at most %d changes per undo", maxUndoChanges)
	}
	prot := map[string]bool{}
	for _, p := range protected {
		prot[p] = true
	}
	seen := map[ChangeRef]bool{}
	for _, c := range sel {
		if len(c.Name) > maxNameLen || len(c.Kind) > 32 {
			return plan, errors.New("invalid change")
		}
		if c.Change != ChangeAdded && c.Change != ChangeRemoved {
			return plan, fmt.Errorf("change must be %q or %q", ChangeAdded, ChangeRemoved)
		}
		cs, ok := d.set(c.Kind)
		if !ok {
			return plan, fmt.Errorf("unknown kind %q", c.Kind)
		}
		if !setOf(cs, c.Change)[c.Name] {
			return plan, fmt.Errorf("%s %q is not %s in this snapshot's change set (the realm may have changed; preview again)", c.Kind, c.Name, c.Change)
		}
		if seen[c] {
			continue
		}
		seen[c] = true
		plan.Steps = append(plan.Steps, planStep(c, prot))
	}
	sort.SliceStable(plan.Steps, func(i, j int) bool { return phase(plan.Steps[i]) < phase(plan.Steps[j]) })
	return plan, nil
}

func planStep(c ChangeRef, protected map[string]bool) UndoStep {
	s := UndoStep{Kind: c.Kind, Name: c.Name, Change: c.Change, Status: StatusPlanned}
	if c.Change == ChangeAdded {
		s.Action = ActionDelete
	} else {
		s.Action = ActionRecreate
		if c.Kind == KindAccess {
			s.Action = ActionGrant
		}
	}
	switch {
	case c.Kind == KindClient && c.Change == ChangeAdded && protected[c.Name]:
		s.Status, s.Note = StatusSkipped, "protected: this client is the credential used to manage the realm"
	case c.Kind == KindUser && c.Change == ChangeAdded && strings.HasPrefix(c.Name, "service-account-"):
		s.Status, s.Note = StatusSkipped, "service account users go with their client"
	case c.Kind == KindUser && c.Change == ChangeRemoved && strings.HasPrefix(c.Name, "service-account-"):
		s.Status, s.Note = StatusSkipped, "service account users come back with their client"
	case (c.Kind == KindRole || c.Kind == KindGroup) && c.Change == ChangeAdded:
		s.Status, s.Note = StatusUnsupported, "the Admin API cannot delete roles or groups"
	case c.Kind == KindAccess && c.Change == ChangeAdded:
		s.Status, s.Note = StatusUnsupported, "the Admin API cannot remove role mappings or group memberships"
	case c.Kind == KindAccess && c.Change == ChangeRemoved:
		if _, _, ok := splitAccess(c.Name); !ok {
			s.Status, s.Note = StatusUnsupported, "unrecognised access entry"
		}
	}
	return s
}

// phase orders steps: recreate dependencies first (roles, groups, providers,
// clients, users), then grants, then deletions (providers, clients, users).
func phase(s UndoStep) int {
	if s.Action == ActionDelete {
		return 20 + kindRank(s.Kind)
	}
	if s.Action == ActionGrant {
		return 10
	}
	return kindRank(s.Kind)
}

func kindRank(k string) int {
	switch k {
	case KindRole:
		return 0
	case KindGroup:
		return 1
	case KindProvider:
		return 2
	case KindClient:
		return 3
	case KindUser:
		return 4
	}
	return 5
}

// splitAccess parses "username role:X" / "username group:/path".
func splitAccess(name string) (user, ref string, ok bool) {
	for _, sep := range []string{" role:", " group:"} {
		if i := strings.LastIndex(name, sep); i > 0 {
			return name[:i], strings.TrimPrefix(name[i:], " "), true
		}
	}
	return "", "", false
}

// ApplyUndo executes the planned steps in order through p and returns the plan
// with statuses filled in. It stops at the first failure: the remaining steps
// are marked not_run. There is no rollback; the result says exactly what
// happened.
func ApplyUndo(ctx context.Context, p idp.Provider, snap RealmSnapshot, plan UndoPlan) UndoPlan {
	out := plan
	out.Steps = append([]UndoStep(nil), plan.Steps...)
	failed := false
	for i := range out.Steps {
		s := &out.Steps[i]
		if s.Status != StatusPlanned {
			continue
		}
		if failed {
			s.Status = StatusNotRun
			continue
		}
		note, err := execStep(ctx, p, snap, *s)
		switch {
		case err != nil:
			s.Status, s.Note = StatusFailed, errText(err)
			failed = true
		default:
			s.Status, s.Note = StatusDone, note
		}
	}
	return out
}

// errText keeps backend error bodies short and free of control characters.
func errText(err error) string {
	msg := err.Error()
	if se := idp.AsStatus(err); se != nil {
		msg = fmt.Sprintf("backend answered %d", se.Code)
		switch {
		case errors.Is(err, idp.ErrConflict):
			msg += " (already exists)"
		case errors.Is(err, idp.ErrNotFound):
			msg += " (not found)"
		}
	}
	msg = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, msg)
	if len(msg) > 200 {
		msg = msg[:200]
	}
	return msg
}

func execStep(ctx context.Context, p idp.Provider, snap RealmSnapshot, s UndoStep) (string, error) {
	realm := snap.Realm
	switch s.Kind {
	case KindClient:
		if s.Action == ActionDelete {
			cl, err := findClient(ctx, p, realm, s.Name)
			if err != nil {
				return "", err
			}
			return "", p.DeleteClient(ctx, realm, cl.ID)
		}
		for _, c := range snap.Clients {
			if c.ClientID == s.Name {
				c.ID, c.Secret = "", ""
				note := ""
				if !c.PublicClient {
					note = "confidential client: a new secret was generated; regenerate and distribute it"
				}
				return note, p.CreateClient(ctx, realm, c)
			}
		}
		return "", errors.New("client not found in the snapshot")
	case KindUser:
		if s.Action == ActionDelete {
			u, err := findUser(ctx, p, realm, s.Name)
			if err != nil {
				return "", err
			}
			return "", p.DeleteUser(ctx, realm, u.ID)
		}
		for _, u := range snap.Users {
			if u.Username == s.Name {
				u.ID = ""
				return "no password: set one or send a reset link", p.CreateUser(ctx, realm, u)
			}
		}
		return "", errors.New("user not found in the snapshot")
	case KindRole:
		for _, r := range snap.Roles {
			if r.Name == s.Name {
				r.ID = ""
				return "", p.CreateRole(ctx, realm, r)
			}
		}
		return "", errors.New("role not found in the snapshot")
	case KindGroup:
		for _, g := range snap.Groups {
			if groupKey(g) == s.Name {
				g.ID = ""
				return "", p.CreateGroup(ctx, realm, g)
			}
		}
		return "", errors.New("group not found in the snapshot")
	case KindProvider:
		if s.Action == ActionDelete {
			return "", p.DeleteIdentityProvider(ctx, realm, s.Name)
		}
		for _, ip := range snap.IdentityProviders {
			if ip.Alias == s.Name {
				ip.Config = withoutSecrets(ip.Config)
				return "secrets are not kept in snapshots: set the client secret again", p.CreateIdentityProvider(ctx, realm, ip)
			}
		}
		return "", errors.New("provider not found in the snapshot")
	case KindAccess:
		user, ref, ok := splitAccess(s.Name)
		if !ok {
			return "", errors.New("unrecognised access entry")
		}
		u, err := findUser(ctx, p, realm, user)
		if err != nil {
			return "", err
		}
		if name, isRole := strings.CutPrefix(ref, "role:"); isRole {
			roles, err := p.ListRoles(ctx, realm)
			if err != nil {
				return "", err
			}
			for _, r := range roles {
				if r.Name == name {
					return "", p.AddRealmRoleMappings(ctx, realm, u.ID, []idp.Role{r})
				}
			}
			return "", errors.New("role does not exist in the realm (select the role too)")
		}
		path := strings.TrimPrefix(ref, "group:")
		groups, err := p.ListGroups(ctx, realm)
		if err != nil {
			return "", err
		}
		for _, g := range groups {
			if groupKey(g) == path {
				return "", p.JoinGroup(ctx, realm, u.ID, g.ID)
			}
		}
		return "", errors.New("group does not exist in the realm (select the group too)")
	}
	return "", errors.New("unsupported kind")
}

func groupKey(g idp.Group) string {
	if g.Path != "" {
		return g.Path
	}
	return g.Name
}

func withoutSecrets(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		if strings.Contains(strings.ToLower(k), "secret") {
			continue
		}
		out[k] = v
	}
	return out
}

func findClient(ctx context.Context, p idp.Provider, realm, clientID string) (idp.Client, error) {
	cs, err := p.ListClients(ctx, realm)
	if err != nil {
		return idp.Client{}, err
	}
	for _, c := range cs {
		if c.ClientID == clientID && c.ID != "" {
			return c, nil
		}
	}
	return idp.Client{}, errors.New("client no longer exists")
}

func findUser(ctx context.Context, p idp.Provider, realm, username string) (idp.User, error) {
	us, err := p.ListAllUsers(ctx, realm)
	if err != nil {
		return idp.User{}, err
	}
	for _, u := range us {
		if u.Username == username && u.ID != "" {
			return u, nil
		}
	}
	return idp.User{}, errors.New("user no longer exists")
}
