// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package identityops

import "sort"

type ChangeSet struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

type SnapshotDiff struct {
	SnapshotID          string    `json:"snapshotId"`
	Realm               string    `json:"realm"`
	SnapshotFingerprint string    `json:"snapshotFingerprint"`
	LiveFingerprint     string    `json:"liveFingerprint"`
	Drifted             bool      `json:"drifted"`
	Clients             ChangeSet `json:"clients"`
	Users               ChangeSet `json:"users"`
	Roles               ChangeSet `json:"roles"`
	Groups              ChangeSet `json:"groups"`
	Providers           ChangeSet `json:"providers"`
	Access              ChangeSet `json:"access"`
	NativeConfigChanged bool      `json:"nativeConfigChanged"`
}

func Diff(snapshot, live RealmSnapshot) (SnapshotDiff, error) {
	sfp := snapshot.Fingerprint
	if sfp == "" {
		var err error
		sfp, err = Fingerprint(snapshot)
		if err != nil {
			return SnapshotDiff{}, err
		}
	}
	lfp, err := Fingerprint(live)
	if err != nil {
		return SnapshotDiff{}, err
	}

	sn, ln := snapshot.Neutral(), live.Neutral()
	return SnapshotDiff{
		SnapshotID:          snapshot.ID,
		Realm:               snapshot.Realm,
		SnapshotFingerprint: sfp,
		LiveFingerprint:     lfp,
		Drifted:             sfp != lfp,
		Clients:             diffNames(clientNames(sn), clientNames(ln)),
		Users:               diffNames(userNames(sn), userNames(ln)),
		Roles:               diffNames(roleNames(sn), roleNames(ln)),
		Groups:              diffNames(groupNames(sn), groupNames(ln)),
		Providers:           diffNames(providerNames(sn), providerNames(ln)),
		Access:              diffNames(accessNames(sn), accessNames(ln)),
		NativeConfigChanged: string(sn.PartialExport) != string(ln.PartialExport),
	}, nil
}

func diffNames(before, after []string) ChangeSet {
	a := make(map[string]struct{}, len(before))
	b := make(map[string]struct{}, len(after))
	for _, v := range before {
		a[v] = struct{}{}
	}
	for _, v := range after {
		b[v] = struct{}{}
	}
	out := ChangeSet{}
	for v := range b {
		if _, ok := a[v]; !ok {
			out.Added = append(out.Added, v)
		}
	}
	for v := range a {
		if _, ok := b[v]; !ok {
			out.Removed = append(out.Removed, v)
		}
	}
	sort.Strings(out.Added)
	sort.Strings(out.Removed)
	return out
}

func clientNames(s NeutralSnapshot) []string {
	out := make([]string, 0, len(s.Clients))
	for _, v := range s.Clients {
		out = append(out, v.ClientID)
	}
	return out
}
func userNames(s NeutralSnapshot) []string {
	out := make([]string, 0, len(s.Users))
	for _, v := range s.Users {
		out = append(out, v.Username)
	}
	return out
}
func roleNames(s NeutralSnapshot) []string {
	out := make([]string, 0, len(s.Roles))
	for _, v := range s.Roles {
		out = append(out, v.Name)
	}
	return out
}
func groupNames(s NeutralSnapshot) []string {
	out := make([]string, 0, len(s.Groups))
	for _, v := range s.Groups {
		if v.Path != "" {
			out = append(out, v.Path)
		} else {
			out = append(out, v.Name)
		}
	}
	return out
}
func providerNames(s NeutralSnapshot) []string {
	out := make([]string, 0, len(s.Providers))
	for _, v := range s.Providers {
		out = append(out, v.Alias)
	}
	return out
}

func accessNames(s NeutralSnapshot) []string {
	out := []string{}
	for _, access := range s.Access {
		for _, role := range access.RealmRoles {
			out = append(out, access.Username+" role:"+role)
		}
		for _, group := range access.Groups {
			out = append(out, access.Username+" group:"+group)
		}
	}
	return out
}
