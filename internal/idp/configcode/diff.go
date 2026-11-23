// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package configcode

import (
	"sort"
	"strconv"
	"strings"
)

// kv is one displayable field value.
type kv struct{ name, val string }

func sortedSet(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	n := 0
	for i, v := range out {
		if i == 0 || v != out[n-1] {
			out[n] = v
			n++
		}
	}
	return out[:n]
}

// canonical returns a deep copy with every list sorted (and URI lists
// deduplicated). No defaults are applied.
func canonical(s *Spec) *Spec {
	c := *s
	c.Roles = append([]Role(nil), s.Roles...)
	sort.SliceStable(c.Roles, func(i, j int) bool { return c.Roles[i].Name < c.Roles[j].Name })
	c.Groups = append([]Group(nil), s.Groups...)
	sort.SliceStable(c.Groups, func(i, j int) bool { return c.Groups[i].Name < c.Groups[j].Name })
	c.Clients = make([]Client, len(s.Clients))
	for i, cl := range s.Clients {
		cl.RedirectURIs = sortedSet(cl.RedirectURIs)
		cl.Origins = sortedSet(cl.Origins)
		c.Clients[i] = cl
	}
	sort.SliceStable(c.Clients, func(i, j int) bool { return c.Clients[i].ClientID < c.Clients[j].ClientID })
	if len(c.Roles) == 0 {
		c.Roles = nil
	}
	if len(c.Groups) == 0 {
		c.Groups = nil
	}
	if len(c.Clients) == 0 {
		c.Clients = nil
	}
	return &c
}

func boolPtr(b bool) *bool { return &b }

// normalized is canonical plus client defaults (enabled=true,
// authCodeFlow=!serviceAccount, requirePKCE=public).
func normalized(s *Spec) *Spec {
	c := canonical(s)
	for i := range c.Clients {
		cl := &c.Clients[i]
		if cl.Enabled == nil {
			cl.Enabled = boolPtr(true)
		}
		if cl.AuthCodeFlow == nil {
			cl.AuthCodeFlow = boolPtr(!cl.ServiceAccount)
		}
		if cl.RequirePKCE == nil {
			cl.RequirePKCE = boolPtr(cl.Public)
		}
	}
	return c
}

func bstr(p *bool) (string, bool) {
	if p == nil {
		return "", false
	}
	return strconv.FormatBool(*p), true
}

func istr(p *int) (string, bool) {
	if p == nil {
		return "", false
	}
	return strconv.Itoa(*p), true
}

// realmFields lists the managed (non-nil) realm-level fields in display order.
func realmFields(s *Spec) []kv {
	var out []kv
	put := func(name, v string, ok bool) {
		if ok {
			out = append(out, kv{name, v})
		}
	}
	put("displayName", s.DisplayName, s.DisplayName != "")
	v, ok := bstr(s.Enabled)
	put("enabled", v, ok)
	st := s.Settings
	v, ok = bstr(st.SelfRegistration)
	put("settings.selfRegistration", v, ok)
	v, ok = bstr(st.EmailVerificationRequired)
	put("settings.emailVerificationRequired", v, ok)
	v, ok = bstr(st.BruteForceProtection)
	put("settings.bruteForceProtection", v, ok)
	if st.TransportSecurity != nil {
		put("settings.transportSecurity", *st.TransportSecurity, true)
	}
	if st.PasswordPolicy != nil {
		put("settings.passwordPolicy", *st.PasswordPolicy, true)
	}
	v, ok = istr(st.AccessTokenSeconds)
	put("settings.accessTokenSeconds", v, ok)
	v, ok = istr(st.SessionIdleSeconds)
	put("settings.sessionIdleSeconds", v, ok)
	v, ok = bstr(st.AuthEvents)
	put("settings.authEvents", v, ok)
	v, ok = bstr(st.AdminEvents)
	put("settings.adminEvents", v, ok)
	v, ok = bstr(st.RefreshTokenRotation)
	put("settings.refreshTokenRotation", v, ok)
	return out
}

// clientFields lists every client field of a normalized client.
func clientFields(c Client) []kv {
	b := func(p *bool) string { s, _ := bstr(p); return s }
	return []kv{
		{"name", c.Name},
		{"enabled", b(c.Enabled)},
		{"public", strconv.FormatBool(c.Public)},
		{"serviceAccount", strconv.FormatBool(c.ServiceAccount)},
		{"authCodeFlow", b(c.AuthCodeFlow)},
		{"requirePKCE", b(c.RequirePKCE)},
		{"redirectUris", strings.Join(c.RedirectURIs, ", ")},
		{"origins", strings.Join(c.Origins, ", ")},
	}
}

func createFields(fs []kv) []FieldChange {
	var out []FieldChange
	for _, f := range fs {
		if f.val != "" {
			out = append(out, FieldChange{Field: f.name, New: f.val})
		}
	}
	return out
}

func diffFields(want, have []kv, strictMissing bool) []FieldChange {
	haveBy := map[string]string{}
	for _, f := range have {
		haveBy[f.name] = f.val
	}
	var out []FieldChange
	for _, f := range want {
		old, ok := haveBy[f.name]
		if ok && old == f.val {
			continue
		}
		if !ok && !strictMissing && f.val == "" {
			continue
		}
		out = append(out, FieldChange{Field: f.name, Old: old, New: f.val})
	}
	return out
}

// Diff computes the Plan that turns live into desired. live == nil means the
// realm does not exist. It is pure and deterministic.
//
// Order: realm, role creates (by name), group creates (by name), client
// creates/updates (by clientId), then client deletes (by clientId; only with
// Options.Prune). Roles and groups are never deleted in v1 because
// idp.Provider cannot delete them, and an existing role's description is not
// compared because it cannot be updated either.
func Diff(desired, live *Spec, o Options) *Plan {
	d := normalized(desired)
	plan := &Plan{Realm: d.Realm, Changes: []Change{}}
	var l *Spec
	if live == nil {
		plan.RealmMissing = true
	} else {
		l = normalized(live)
	}

	// Realm.
	want := realmFields(d)
	if l == nil {
		plan.Changes = append(plan.Changes, Change{Action: ActionCreate, Kind: KindOfRealm, Name: d.Realm, Fields: createFields(want)})
	} else if fc := diffFields(want, realmFields(l), true); len(fc) > 0 {
		plan.Changes = append(plan.Changes, Change{Action: ActionUpdate, Kind: KindOfRealm, Name: d.Realm, Fields: fc})
	}

	// Roles and groups: create-only.
	liveRoles, liveGroups, liveClients := map[string]bool{}, map[string]bool{}, map[string]Client{}
	if l != nil {
		for _, r := range l.Roles {
			liveRoles[r.Name] = true
		}
		for _, g := range l.Groups {
			liveGroups[g.Name] = true
		}
		for _, c := range l.Clients {
			liveClients[c.ClientID] = c
		}
	}
	for _, r := range d.Roles {
		if !liveRoles[r.Name] {
			var fc []FieldChange
			if r.Description != "" {
				fc = []FieldChange{{Field: "description", New: r.Description}}
			}
			plan.Changes = append(plan.Changes, Change{Action: ActionCreate, Kind: KindOfRole, Name: r.Name, Fields: fc})
		}
	}
	for _, g := range d.Groups {
		if !liveGroups[g.Name] {
			plan.Changes = append(plan.Changes, Change{Action: ActionCreate, Kind: KindOfGroup, Name: g.Name})
		}
	}

	// Clients.
	wantClient := map[string]bool{}
	for _, c := range d.Clients {
		wantClient[c.ClientID] = true
		cur, ok := liveClients[c.ClientID]
		if !ok {
			plan.Changes = append(plan.Changes, Change{Action: ActionCreate, Kind: KindOfClient, Name: c.ClientID, Fields: createFields(clientFields(c))})
			continue
		}
		if fc := diffFields(clientFields(c), clientFields(cur), true); len(fc) > 0 {
			plan.Changes = append(plan.Changes, Change{Action: ActionUpdate, Kind: KindOfClient, Name: c.ClientID, Fields: fc})
		}
	}
	if o.Prune && l != nil {
		for _, c := range l.Clients {
			if !wantClient[c.ClientID] && !isUnmanagedClient(c.ClientID) {
				plan.Changes = append(plan.Changes, Change{Action: ActionDelete, Kind: KindOfClient, Name: c.ClientID})
			}
		}
	}
	return plan
}
