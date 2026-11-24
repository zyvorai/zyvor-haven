// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package storetest

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

func init() {
	Register(
		Case{"WorkloadIdentityLifecycle", workloadLifecycle},
		Case{"WorkloadIdentityUniqueness", workloadUnique},
		Case{"AgentLifecycle", agentLifecycle},
		Case{"AgentCredentialLifecycle", credLifecycle},
		Case{"AgentCredentialLimitConcurrent", credLimitConcurrent},
		Case{"AgentCredentialPurgeAndCascade", credPurgeCascade},
		Case{"AgentRealmIsolation", agentIsolation},
	)
}

func wlStore(t *testing.T, s core.Store) core.WorkloadStore {
	t.Helper()
	x, found := core.StoreAs[core.WorkloadStore](s)
	if !found {
		t.Skip("store has no WorkloadStore")
	}
	return x
}

func agStore(t *testing.T, s core.Store) core.AgentStore {
	t.Helper()
	x, found := core.StoreAs[core.AgentStore](s)
	if !found {
		t.Skip("store has no AgentStore")
	}
	return x
}

func mkWL(name, client string) core.WorkloadIdentity {
	return core.WorkloadIdentity{Realm: "acme", Name: name, ClientID: client, Issuer: "https://oidc.example/k8s",
		JWKSURI: "https://oidc.example/k8s/jwks", Audience: "haven", Subject: "system:serviceaccount:ns:" + name,
		AllowedScopes: []string{"read", "write"}, TTLSeconds: 600, Enabled: true, CreatedBy: "client:admin", CreatedAt: t0}
}

func workloadLifecycle(t *testing.T, s core.Store) {
	ws := wlStore(t, s)
	mkRealm(t, s, "acme")
	w, err := ws.CreateWorkloadIdentity(ctx, mkWL("api", "wl-api"))
	ok(t, err)
	if w.ID == "" {
		t.Fatal("no id")
	}
	got, err := ws.GetWorkloadIdentity(ctx, "acme", w.ID)
	ok(t, err)
	eq(t, got, w)
	byC, err := ws.GetWorkloadIdentityByClient(ctx, "acme", "wl-api")
	ok(t, err)
	eq(t, byC, w)
	// inline JWKS variant
	in := mkWL("job", "wl-job")
	in.JWKSURI, in.JWKS = "", `{"keys":[]}`
	j, err := ws.CreateWorkloadIdentity(ctx, in)
	ok(t, err)
	eq(t, j.JWKS, `{"keys":[]}`)
	l, err := ws.ListWorkloadIdentities(ctx, "acme")
	ok(t, err)
	if len(l) != 2 || l[0].Name != "api" || l[1].Name != "job" {
		t.Fatalf("list: %+v", l)
	}
	off, err := ws.SetWorkloadEnabled(ctx, "acme", w.ID, false)
	ok(t, err)
	if off.Enabled {
		t.Fatal("still enabled")
	}
	again, _ := ws.GetWorkloadIdentityByClient(ctx, "acme", "wl-api")
	if again.Enabled {
		t.Fatal("disable not persisted")
	}
	_, err = ws.SetWorkloadEnabled(ctx, "acme", "nope", true)
	is(t, err, idp.ErrNotFound)
	ok(t, ws.DeleteWorkloadIdentity(ctx, "acme", w.ID))
	is(t, ws.DeleteWorkloadIdentity(ctx, "acme", w.ID), idp.ErrNotFound)
	_, err = ws.GetWorkloadIdentityByClient(ctx, "acme", "wl-api")
	is(t, err, idp.ErrNotFound)
	_, err = ws.CreateWorkloadIdentity(ctx, core.WorkloadIdentity{Realm: "ghost", Name: "x", ClientID: "x", JWKSURI: "u", TTLSeconds: 60})
	is(t, err, idp.ErrNotFound)
}

func workloadUnique(t *testing.T, s core.Store) {
	ws := wlStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	_, err := ws.CreateWorkloadIdentity(ctx, mkWL("api", "wl-api"))
	ok(t, err)
	_, err = ws.CreateWorkloadIdentity(ctx, mkWL("api", "wl-other")) // same name
	is(t, err, idp.ErrConflict)
	_, err = ws.CreateWorkloadIdentity(ctx, mkWL("other", "wl-api")) // same client
	is(t, err, idp.ErrConflict)
	o := mkWL("api", "wl-api")
	o.Realm = "other"
	_, err = ws.CreateWorkloadIdentity(ctx, o) // other realm: free
	ok(t, err)
	_, err = ws.GetWorkloadIdentityByClient(ctx, "other", "wl-api")
	ok(t, err)
	l, _ := ws.ListWorkloadIdentities(ctx, "acme")
	if len(l) != 1 {
		t.Fatalf("realm leak: %+v", l)
	}
}

func mkAgent(name, client, owner string) core.Agent {
	return core.Agent{Realm: "acme", Name: name, Kind: "agent", ClientID: client, OwnerUserID: owner,
		AllowedScopes: []string{"mcp:read"}, AllowedRoles: []string{"dev"}, Audiences: []string{"https://mcp.example"},
		TokenTTL: 300, Enabled: true, CreatedBy: "client:admin", CreatedAt: t0}
}

func agentLifecycle(t *testing.T, s core.Store) {
	as := agStore(t, s)
	mkRealm(t, s, "acme")
	a, err := as.CreateAgent(ctx, mkAgent("bot", "agent-1", "u1"))
	ok(t, err)
	got, err := as.GetAgent(ctx, "acme", a.ID)
	ok(t, err)
	eq(t, got, a)
	byC, err := as.GetAgentByClient(ctx, "acme", "agent-1")
	ok(t, err)
	eq(t, byC, a)
	_, err = as.CreateAgent(ctx, mkAgent("bot", "agent-2", "u1"))
	is(t, err, idp.ErrConflict)
	_, err = as.CreateAgent(ctx, mkAgent("bot2", "agent-1", "u1"))
	is(t, err, idp.ErrConflict)
	_, err = as.CreateAgent(ctx, mkAgent("bot3", "agent-3", "u2"))
	ok(t, err)
	l, _ := as.ListAgents(ctx, "acme", "")
	mine, _ := as.ListAgents(ctx, "acme", "u1")
	if len(l) != 2 || len(mine) != 1 || mine[0].ID != a.ID {
		t.Fatalf("list %d mine %+v", len(l), mine)
	}
	off, err := as.SetAgentEnabled(ctx, "acme", a.ID, false)
	ok(t, err)
	if off.Enabled {
		t.Fatal("still enabled")
	}
	_, err = as.SetAgentEnabled(ctx, "acme", "nope", false)
	is(t, err, idp.ErrNotFound)
	ok(t, as.DeleteAgent(ctx, "acme", a.ID))
	is(t, as.DeleteAgent(ctx, "acme", a.ID), idp.ErrNotFound)
}

func mkCred(agent, hash string, ttl time.Duration) core.AgentCredential {
	return core.AgentCredential{Realm: "acme", AgentID: agent, SecretHash: hash, Scopes: []string{"mcp:read"},
		Note: "n", CreatedBy: "client:admin", CreatedAt: t0, ExpiresAt: t0.Add(ttl)}
}

func credLifecycle(t *testing.T, s core.Store) {
	as := agStore(t, s)
	mkRealm(t, s, "acme")
	a, err := as.CreateAgent(ctx, mkAgent("bot", "agent-1", "u1"))
	ok(t, err)
	c, err := as.CreateAgentCredential(ctx, mkCred(a.ID, "h1", time.Hour), 5, t0)
	ok(t, err)
	got, err := as.GetAgentCredentialBySecret(ctx, "acme", a.ID, "h1")
	ok(t, err)
	eq(t, got, c)
	_, err = as.GetAgentCredentialBySecret(ctx, "acme", "other-agent", "h1") // bound to its agent
	is(t, err, idp.ErrNotFound)
	_, err = as.GetAgentCredentialBySecret(ctx, "acme", a.ID, "nope")
	is(t, err, idp.ErrNotFound)
	_, err = as.CreateAgentCredential(ctx, mkCred(a.ID, "h1", time.Hour), 5, t0) // duplicate secret hash
	is(t, err, idp.ErrConflict)
	_, err = as.CreateAgentCredential(ctx, mkCred("ghost", "h9", time.Hour), 5, t0)
	is(t, err, idp.ErrNotFound)

	ok(t, as.TouchAgentCredential(ctx, "acme", a.ID, c.ID, t0.Add(time.Minute)))
	got, _ = as.GetAgentCredentialBySecret(ctx, "acme", a.ID, "h1")
	if !got.LastUsedAt.Equal(t0.Add(time.Minute)) {
		t.Fatalf("last used %v", got.LastUsedAt)
	}
	rv, err := as.RevokeAgentCredential(ctx, "acme", a.ID, c.ID, "client:admin", t0.Add(2*time.Minute))
	ok(t, err)
	if !rv.RevokedAt.Equal(t0.Add(2*time.Minute)) || rv.RevokedBy != "client:admin" || rv.Active(t0.Add(3*time.Minute)) {
		t.Fatalf("revoked: %+v", rv)
	}
	_, err = as.RevokeAgentCredential(ctx, "acme", a.ID, c.ID, "x", t0.Add(3*time.Minute))
	is(t, err, idp.ErrConflict)
	_, err = as.RevokeAgentCredential(ctx, "acme", a.ID, "nope", "x", t0)
	is(t, err, idp.ErrNotFound)
	// expired credentials cannot be revoked either (already over)
	e, _ := as.CreateAgentCredential(ctx, mkCred(a.ID, "h2", time.Minute), 5, t0)
	_, err = as.RevokeAgentCredential(ctx, "acme", a.ID, e.ID, "x", t0.Add(time.Hour))
	is(t, err, idp.ErrConflict)
	// revoke all
	for _, h := range []string{"h3", "h4"} {
		_, err := as.CreateAgentCredential(ctx, mkCred(a.ID, h, time.Hour), 5, t0)
		ok(t, err)
	}
	n, err := as.RevokeAgentCredentials(ctx, "acme", a.ID, "client:admin", t0.Add(time.Minute))
	ok(t, err)
	if n != 2 { // h3 and h4; h2 ended at +1m exactly, c was revoked earlier
		t.Fatalf("revoked %d", n)
	}
	l, _ := as.ListAgentCredentials(ctx, "acme", a.ID)
	if len(l) != 4 {
		t.Fatalf("list %d", len(l))
	}
	for _, x := range l {
		if x.Active(t0.Add(time.Minute)) {
			t.Fatalf("still active: %+v", x)
		}
	}
}

func credLimitConcurrent(t *testing.T, s core.Store) {
	as := agStore(t, s)
	mkRealm(t, s, "acme")
	a, err := as.CreateAgent(ctx, mkAgent("bot", "agent-1", "u1"))
	ok(t, err)
	var okN, limN, other atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := as.CreateAgentCredential(ctx, mkCred(a.ID, "h"+strconv.Itoa(i), time.Hour), 5, t0)
			switch err {
			case nil:
				okN.Add(1)
			case core.ErrCredentialLimit:
				limN.Add(1)
			default:
				other.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if okN.Load() != 5 || limN.Load() != 7 || other.Load() != 0 {
		t.Fatalf("ok %d limit %d other %d", okN.Load(), limN.Load(), other.Load())
	}
	// an ended credential frees a slot
	l, _ := as.ListAgentCredentials(ctx, "acme", a.ID)
	_, err = as.RevokeAgentCredential(ctx, "acme", a.ID, l[0].ID, "x", t0)
	ok(t, err)
	_, err = as.CreateAgentCredential(ctx, mkCred(a.ID, "hz", time.Hour), 5, t0)
	ok(t, err)
}

func credPurgeCascade(t *testing.T, s core.Store) {
	as := agStore(t, s)
	mkRealm(t, s, "acme")
	a, err := as.CreateAgent(ctx, mkAgent("bot", "agent-1", "u1"))
	ok(t, err)
	_, err = as.CreateAgentCredential(ctx, mkCred(a.ID, "short", time.Minute), 5, t0)
	ok(t, err)
	_, err = as.CreateAgentCredential(ctx, mkCred(a.ID, "long", 90*24*time.Hour), 5, t0)
	ok(t, err)
	n, err := as.PurgeAgentCredentials(ctx, t0.Add(time.Hour)) // short ended, within retention
	ok(t, err)
	if n != 0 {
		t.Fatalf("purged %d inside retention", n)
	}
	n, err = as.PurgeAgentCredentials(ctx, t0.Add(time.Minute+core.CredentialRetention))
	ok(t, err)
	if n != 1 {
		t.Fatalf("purged %d", n)
	}
	_, err = as.GetAgentCredentialBySecret(ctx, "acme", a.ID, "short")
	is(t, err, idp.ErrNotFound)
	_, err = as.GetAgentCredentialBySecret(ctx, "acme", a.ID, "long")
	ok(t, err)
	// deleting the agent deletes its credentials
	ok(t, as.DeleteAgent(ctx, "acme", a.ID))
	_, err = as.GetAgentCredentialBySecret(ctx, "acme", a.ID, "long")
	is(t, err, idp.ErrNotFound)
}

func agentIsolation(t *testing.T, s core.Store) {
	as := agStore(t, s)
	mkRealm(t, s, "acme")
	mkRealm(t, s, "other")
	a, err := as.CreateAgent(ctx, mkAgent("bot", "agent-1", "u1"))
	ok(t, err)
	_, err = as.GetAgent(ctx, "other", a.ID)
	is(t, err, idp.ErrNotFound)
	_, err = as.GetAgentByClient(ctx, "other", "agent-1")
	is(t, err, idp.ErrNotFound)
	_, err = as.CreateAgentCredential(ctx, core.AgentCredential{Realm: "other", AgentID: a.ID, SecretHash: "x",
		ExpiresAt: t0.Add(time.Hour)}, 5, t0)
	is(t, err, idp.ErrNotFound)
	ok2, _ := as.CreateAgentCredential(ctx, mkCred(a.ID, "hx", time.Hour), 5, t0)
	_, err = as.RevokeAgentCredential(ctx, "other", a.ID, ok2.ID, "x", t0)
	is(t, err, idp.ErrNotFound)
	_, err = as.GetAgentCredentialBySecret(ctx, "other", a.ID, "hx")
	is(t, err, idp.ErrNotFound)
	is(t, as.DeleteAgent(ctx, "other", a.ID), idp.ErrNotFound)
}
