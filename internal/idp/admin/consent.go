// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// Admin side of MCP clients and consent (docs/mcp-clients-and-consent.md):
// the per-realm consent / CIMD policy, remembered grants, consent receipts and
// the per-client / per-agent kill switch.

func init() {
	registerRoutes(func(a *api, m *http.ServeMux) {
		p := pathPrefix + "/realms/{r}"
		m.HandleFunc("GET "+p+"/consent-policy", a.getConsentPolicy)
		m.HandleFunc("PUT "+p+"/consent-policy", a.op("consent-policy", "update", a.putConsentPolicy))
		m.HandleFunc("GET "+p+"/consent-grants", a.listConsentGrants)
		m.HandleFunc("DELETE "+p+"/consent-grants/{id}", a.op("consent-grant", "delete", a.deleteConsentGrant))
		m.HandleFunc("GET "+p+"/consent-clients", a.listConsentClients)
		m.HandleFunc("GET "+p+"/consent-receipts", a.listConsentReceipts)
		m.HandleFunc("GET "+p+"/consent-receipts/verify", a.verifyConsentReceipts)
		m.HandleFunc("GET "+p+"/consent-blocks", a.listConsentBlocks)
		m.HandleFunc("POST "+p+"/consent/kill", a.op("consent-kill", "action", a.consentKill))
		m.HandleFunc("POST "+p+"/consent/unkill", a.op("consent-kill", "action", a.consentUnkill))
	})
}

func (a *api) consent(w http.ResponseWriter) (core.ConsentStore, bool) {
	st, ok := core.StoreAs[core.ConsentStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "consent is not available on this store")
	}
	return st, ok
}

var consentHostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

type consentPolicyBody struct {
	CIMDEnabled     bool     `json:"cimdEnabled"`
	CIMDHosts       []string `json:"cimdHosts"`
	RequireAll      bool     `json:"requireAll"`
	SkipClients     []string `json:"skipClients"`
	RememberCIMD    bool     `json:"rememberCimd"`
	GrantTTLSeconds int      `json:"grantTtlSeconds"`
}

func policyJSON(p core.ConsentPolicy) consentPolicyBody {
	b := consentPolicyBody{CIMDEnabled: p.CIMDEnabled, CIMDHosts: p.CIMDHosts, RequireAll: p.RequireAll,
		SkipClients: p.SkipClients, RememberCIMD: p.RememberCIMD, GrantTTLSeconds: int(p.GrantTTL() / time.Second)}
	if b.CIMDHosts == nil {
		b.CIMDHosts = []string{}
	}
	if b.SkipClients == nil {
		b.SkipClients = []string{}
	}
	return b
}

func (a *api) getConsentPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.consent(w)
	if !ok {
		return
	}
	p, err := st.GetConsentPolicy(r.Context(), rl.Name)
	if errors.Is(err, idp.ErrNotFound) {
		p, err = core.ConsentPolicy{Realm: rl.Name}, nil
	}
	if err != nil {
		a.fail(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, policyJSON(p))
}

// putConsentPolicy replaces the policy: omitted fields are false / empty / the
// default TTL, so a typo cannot silently keep an old setting on.
func (a *api) putConsentPolicy(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.consent(w)
	if !ok {
		return
	}
	var in consentPolicyBody
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if len(in.CIMDHosts) > core.MaxConsentHosts || len(in.SkipClients) > core.MaxConsentSkipClients {
		a.fail(w, r, bad("too many cimdHosts or skipClients"))
		return
	}
	for _, h := range in.CIMDHosts {
		if !consentHostRE.MatchString(h) {
			a.fail(w, r, bad("cimdHosts must be lower-case host names"))
			return
		}
	}
	for _, c := range in.SkipClients {
		if c == "" || !validText(c, 255) {
			a.fail(w, r, bad("invalid skipClients entry"))
			return
		}
	}
	if in.GrantTTLSeconds < 0 || time.Duration(in.GrantTTLSeconds)*time.Second > core.ConsentMaxGrantTTL {
		a.fail(w, r, bad("grantTtlSeconds must be between 0 and 31536000"))
		return
	}
	p := core.ConsentPolicy{Realm: rl.Name, CIMDEnabled: in.CIMDEnabled, CIMDHosts: in.CIMDHosts, RequireAll: in.RequireAll,
		SkipClients: in.SkipClients, RememberCIMD: in.RememberCIMD, GrantTTLSeconds: in.GrantTTLSeconds}
	if err := st.PutConsentPolicy(r.Context(), p); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "UPDATE", "consent-policy", rl.Name)
	writeJSON(w, http.StatusOK, policyJSON(p))
}

func grantJSON(g core.ConsentGrant) map[string]any {
	m := map[string]any{"id": g.ID, "userId": g.UserID, "clientId": g.ClientID, "clientName": g.ClientName,
		"scopes": nz(g.Scopes), "resources": nz(g.Resources), "createdAt": g.CreatedAt, "updatedAt": g.UpdatedAt, "expiresAt": g.ExpiresAt}
	if !g.RevokedAt.IsZero() {
		m["revokedAt"], m["revokedBy"] = g.RevokedAt, g.RevokedBy
	}
	return m
}

func nz(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func (a *api) listConsentGrants(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.consent(w)
	if !ok {
		return
	}
	q := r.URL.Query()
	limit, ok := a.limitParam(w, r, 100)
	if !ok {
		return
	}
	gs, err := st.ListConsentGrants(r.Context(), rl.Name, q.Get("userId"), q.Get("clientId"), q.Get("includeEnded") == "true",
		a.cfg.Clock().UTC(), limit)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(gs))
	for _, g := range gs {
		out = append(out, grantJSON(g))
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *api) limitParam(w http.ResponseWriter, r *http.Request, def int) (int, bool) {
	s := r.URL.Query().Get("limit")
	if s == "" {
		return def, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 1000 {
		a.fail(w, r, bad("limit must be between 1 and 1000"))
		return 0, false
	}
	return n, true
}

func (a *api) deleteConsentGrant(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.consent(w)
	if !ok {
		return
	}
	g, err := st.GetConsentGrant(r.Context(), rl.Name, r.PathValue("id"))
	if err != nil {
		a.fail(w, r, err)
		return
	}
	if _, err := core.RevokeConsent(r.Context(), st, g, "admin:"+actorOf(r), a.cfg.Clock().UTC()); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "DELETE", "consent-grant", g.ID)
	noContent(w)
}

func (a *api) listConsentClients(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.consent(w)
	if !ok {
		return
	}
	cs, err := st.ListConsentClients(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(cs))
	for _, c := range cs {
		out = append(out, map[string]any{"clientId": c.ClientID, "source": c.Source, "name": c.Name, "clientUri": c.ClientURI,
			"redirectUris": nz(c.RedirectURIs), "fetchedAt": c.FetchedAt, "expiresAt": c.ExpiresAt})
	}
	writeJSON(w, http.StatusOK, out)
}

func receiptJSON(c core.ConsentReceipt) map[string]any {
	return map[string]any{"seq": c.Seq, "time": c.Time, "type": c.Type, "userId": c.UserID, "clientId": c.ClientID,
		"clientName": c.ClientName, "scopes": nz(c.Scopes), "resources": nz(c.Resources), "actor": c.Actor, "detail": c.Detail,
		"prevHash": c.PrevHash, "hash": c.Hash}
}

func (a *api) listConsentReceipts(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.consent(w)
	if !ok {
		return
	}
	limit, ok := a.limitParam(w, r, 100)
	if !ok {
		return
	}
	var after int64
	if s := r.URL.Query().Get("afterSeq"); s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 0 {
			a.fail(w, r, bad("afterSeq must be a non-negative integer"))
			return
		}
		after = n
	}
	rs, err := st.ListConsentReceipts(r.Context(), rl.Name, r.URL.Query().Get("userId"), after, limit)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(rs))
	for _, c := range rs {
		out = append(out, receiptJSON(c))
	}
	writeJSON(w, http.StatusOK, out)
}

// verifyConsentReceipts walks the realm's whole chain and checks every link
// and hash. A chain that was edited, reordered or truncated in the middle
// reports where it first breaks; a truncated tail cannot be detected from the
// database alone (compare headHash with a copy you kept).
func (a *api) verifyConsentReceipts(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.consent(w)
	if !ok {
		return
	}
	var seq int64
	var prev string
	count := 0
	for {
		page, err := st.ListConsentReceipts(r.Context(), rl.Name, "", seq, 1000)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		if len(page) == 0 {
			break
		}
		if err := core.VerifyConsentChain(page, seq, prev); err != nil {
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "count": count, "error": err.Error()})
			return
		}
		count += len(page)
		seq, prev = page[len(page)-1].Seq, page[len(page)-1].Hash
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "count": count, "headSeq": seq, "headHash": prev})
}

func (a *api) listConsentBlocks(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.consent(w)
	if !ok {
		return
	}
	bs, err := st.ListConsentBlocks(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	out := make([]map[string]any, 0, len(bs))
	for _, b := range bs {
		out = append(out, map[string]any{"clientId": b.ClientID, "reason": b.Reason, "by": b.By, "at": b.At})
	}
	writeJSON(w, http.StatusOK, out)
}

type killBody struct {
	ClientID string `json:"clientId"`
	AgentID  string `json:"agentId"`
	Reason   string `json:"reason"`
}

// target resolves {clientId} xor {agentId} to a client id.
func (a *api) killTarget(w http.ResponseWriter, r *http.Request, rl core.Realm, in killBody) (string, bool) {
	if (in.ClientID == "") == (in.AgentID == "") {
		a.fail(w, r, bad("give exactly one of clientId and agentId"))
		return "", false
	}
	if in.AgentID == "" {
		if len(in.ClientID) > 2048 || !validText(in.ClientID, 2048) {
			a.fail(w, r, bad("invalid clientId"))
			return "", false
		}
		return in.ClientID, true
	}
	as, ok := core.StoreAs[core.AgentStore](a.cfg.Store)
	if !ok {
		notImplemented(w, "agent identities are not available on this store")
		return "", false
	}
	ag, err := as.GetAgent(r.Context(), rl.Name, in.AgentID)
	if err != nil {
		a.fail(w, r, err)
		return "", false
	}
	return ag.ClientID, true
}

// consentKill is the kill switch: it blocks the client (or the agent's client),
// disables it, and revokes its grants, refresh tokens and (for an agent) its
// credentials. Idempotent.
func (a *api) consentKill(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.consent(w)
	if !ok {
		return
	}
	var in killBody
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	if !validText(in.Reason, 255) {
		a.fail(w, r, bad("invalid reason"))
		return
	}
	cid, ok := a.killTarget(w, r, rl, in)
	if !ok {
		return
	}
	res, err := core.KillClient(r.Context(), a.cfg.Store, st, rl.Name, cid, "admin:"+actorOf(r), strings.TrimSpace(in.Reason), a.cfg.Clock().UTC())
	a.audit(r, rl, "ACTION", "consent-kill", cid)
	if err != nil {
		a.cfg.Logger.Error("admin: kill switch partially failed", "realm", rl.Name, "err", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "kill switch partially failed; repeat it", "result": res})
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *api) consentUnkill(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	st, ok := a.consent(w)
	if !ok {
		return
	}
	var in killBody
	if _, err := decode(r, &in); err != nil {
		a.fail(w, r, err)
		return
	}
	cid, ok := a.killTarget(w, r, rl, in)
	if !ok {
		return
	}
	if err := core.UnkillClient(r.Context(), a.cfg.Store, st, rl.Name, cid, "admin:"+actorOf(r), a.cfg.Clock().UTC()); err != nil {
		a.fail(w, r, err)
		return
	}
	a.audit(r, rl, "ACTION", "consent-unkill", cid)
	noContent(w)
}
