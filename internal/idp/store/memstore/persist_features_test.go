// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package memstore

import (
	"testing"

	"github.com/zyvorai/haven/internal/idp/core"
)

// The side tables of the feature stores survive a snapshot too.
func TestSnapshotCoversFeatureTables(t *testing.T) {
	a := New()
	a.mu.Lock()
	a.pkInit()
	a.pk.creds["demo\x00cid"] = core.Passkey{Realm: "demo", UserID: "u1"}
	a.pk.handles["demo\x00u1"] = "h"
	a.pk.byHandle["demo\x00h"] = "u1"
	a.pk.policy["demo"] = true
	a.dcrLocked().policies["demo"] = core.RegistrationPolicy{}
	a.mu.Unlock()
	f := a.fed()
	f.mu.Lock()
	f.providers["demo\x00idp"] = core.FedProvider{Realm: "demo", Alias: "idp"}
	f.links["demo\x00idp\x00sub"] = core.FedLink{Realm: "demo"}
	f.mu.Unlock()
	g := a.gstate()
	g.mu.Lock()
	g.rows = append(g.rows, &grantRow{RoleGrant: core.RoleGrant{}, realmID: "rid", noticed: true})
	g.policies["rid"] = policyRow{p: core.GrantPolicy{MaxDurationSeconds: 60}}
	g.mu.Unlock()
	m := a.mfa()
	m.mu.Lock()
	m.recovery["k"] = map[string]bool{"h1": true}
	m.policy["demo"] = core.MFAPolicy{RequireMFA: true}
	m.mu.Unlock()

	b, err := a.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	c := New()
	if err := c.Restore(b); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	okPK := len(c.pk.creds) == 1 && c.pk.handles["demo\x00u1"] == "h" && c.pk.byHandle["demo\x00h"] == "u1" && c.pk.policy["demo"]
	okDCR := len(c.dcrLocked().policies) == 1
	c.mu.Unlock()
	cf := c.fed()
	okFed := len(cf.providers) == 1 && len(cf.links) == 1
	cg := c.gstate()
	okGrant := len(cg.rows) == 1 && cg.rows[0].realmID == "rid" && cg.rows[0].noticed && cg.policies["rid"].p.MaxDurationSeconds == 60
	cm := c.mfa()
	okMFA := cm.recovery["k"]["h1"] && cm.policy["demo"].RequireMFA
	if !okPK || !okDCR || !okFed || !okGrant || !okMFA {
		t.Errorf("pk=%v dcr=%v fed=%v grants=%v mfa=%v", okPK, okDCR, okFed, okGrant, okMFA)
	}
}
