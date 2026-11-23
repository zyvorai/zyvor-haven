// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package identityops

import (
	"encoding/json"

	"github.com/zyvorai/haven/internal/idmodel"
)

// NeutralSnapshot is the backend-neutral view of a RealmSnapshot. It is never
// persisted; RealmSnapshot keeps the on-disk JSON shape.
type NeutralSnapshot struct {
	ID            string
	Realm         string
	Fingerprint   string
	Config        idmodel.Realm
	Clients       []idmodel.Client
	Users         []idmodel.User
	Roles         []idmodel.Role
	Groups        []idmodel.Group
	Providers     []idmodel.FederationProvider
	Access        []idmodel.UserAccess
	PartialExport json.RawMessage
}

// Neutral converts the stored snapshot into idmodel types.
func (s RealmSnapshot) Neutral() NeutralSnapshot {
	n := NeutralSnapshot{
		ID: s.ID, Realm: s.Realm, Fingerprint: s.Fingerprint,
		Config:        idmodel.FromRealm(s.RealmConfig),
		Clients:       idmodel.FromClients(s.Clients),
		PartialExport: s.PartialExport,
	}
	for _, u := range s.Users {
		n.Users = append(n.Users, idmodel.FromUser(u))
	}
	for _, r := range s.Roles {
		n.Roles = append(n.Roles, idmodel.FromRole(r))
	}
	for _, g := range s.Groups {
		n.Groups = append(n.Groups, idmodel.FromGroup(g))
	}
	for _, p := range s.IdentityProviders {
		n.Providers = append(n.Providers, idmodel.FromIdentityProvider(p))
	}
	for _, a := range s.UserAccess {
		n.Access = append(n.Access, idmodel.UserAccess{Username: a.Username, RealmRoles: a.RealmRoles, Groups: a.Groups})
	}
	return n
}
