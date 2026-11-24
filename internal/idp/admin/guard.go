// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idmodel"
	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/configcode"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/posture"
)

// Guard as an admission gate: realm and client writes are scored by Haven
// Guard before they are applied. See docs/guard-gate.md.

const (
	// GuardModeOff disables the gate, GuardModeWarn applies the write and
	// reports, GuardModeEnforce refuses writes that add findings.
	GuardModeOff     = "off"
	GuardModeWarn    = "warn"
	GuardModeEnforce = "enforce"

	guardOverrideHeader = "X-Haven-Guard-Override"
	guardHeader         = "X-Haven-Guard"
	guardWaiverMax      = 1 << 20
	overrideMin         = 10
	overrideMax         = 300
)

// GuardConfig configures the Guard admission gate. The zero value is the
// default: warn mode, threshold high, no waivers, overrides allowed.
type GuardConfig struct {
	Mode       string // off | warn | enforce (default warn; unknown values enforce)
	Threshold  string // critical | high | medium | low (default high)
	WaiverFile string // posture waiver file (JSON, version 1); read on every evaluation
	// NoOverride refuses X-Haven-Guard-Override from service accounts
	// (client credentials tokens); human admin users may still override.
	NoOverride bool
}

func (g GuardConfig) mode() string {
	switch m := strings.ToLower(strings.TrimSpace(g.Mode)); m {
	case "":
		return GuardModeWarn
	case GuardModeOff, GuardModeWarn, GuardModeEnforce:
		return m
	}
	return GuardModeEnforce // a typo must not silently weaken the gate
}

func (g GuardConfig) threshold() posture.Severity {
	switch t := posture.Severity(strings.ToLower(strings.TrimSpace(g.Threshold))); t {
	case posture.SeverityCritical, posture.SeverityHigh, posture.SeverityMedium, posture.SeverityLow:
		return t
	}
	return posture.SeverityHigh
}

// Validate rejects unknown settings and an unreadable or invalid waiver file,
// so a misconfigured gate stops the server at startup instead of at the first
// write.
func (g GuardConfig) Validate(now time.Time) error {
	if m := strings.ToLower(strings.TrimSpace(g.Mode)); m != "" && m != GuardModeOff && m != GuardModeWarn && m != GuardModeEnforce {
		return fmt.Errorf("HAVEN_IDP_GUARD must be off, warn or enforce, got %q", g.Mode)
	}
	if t := strings.ToLower(strings.TrimSpace(g.Threshold)); t != "" && g.threshold() != posture.Severity(t) {
		return fmt.Errorf("HAVEN_IDP_GUARD_THRESHOLD must be critical, high, medium or low, got %q", g.Threshold)
	}
	if g.WaiverFile != "" {
		if _, err := g.waivers(now); err != nil {
			return fmt.Errorf("HAVEN_IDP_GUARD_WAIVERS: %w", err)
		}
	}
	return nil
}

func (g GuardConfig) waivers(now time.Time) ([]posture.Waiver, error) {
	if g.WaiverFile == "" {
		return nil, nil
	}
	f, err := os.Open(g.WaiverFile)
	if err != nil {
		return nil, fmt.Errorf("read waivers: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, guardWaiverMax+1))
	if err != nil {
		return nil, fmt.Errorf("read waivers: %w", err)
	}
	if len(raw) > guardWaiverMax {
		return nil, errors.New("waiver file is larger than 1 MiB")
	}
	return posture.ParseWaivers(raw, now)
}

// ---- state and evaluation ----

// guardState is a realm and its clients as Guard sees them. A nil realm is
// "does not exist yet" and has no findings.
type guardState struct {
	realm   *core.Realm
	clients []core.Client
}

func (s guardState) report() posture.Report {
	if s.realm == nil {
		return posture.Evaluate(nil, nil, posture.Options{})
	}
	wire := make([]idp.Client, len(s.clients))
	for i, c := range s.clients {
		wire[i] = clientToWire(c)
	}
	m := idmodel.FromRealm(realmToWire(*s.realm))
	return posture.Evaluate([]idmodel.Realm{m}, map[string][]idmodel.Client{m.Name: idmodel.FromClients(wire)}, posture.Options{})
}

// withClient returns the clients with c added, or replacing the one that has
// the same client id.
func withClient(cs []core.Client, c core.Client) []core.Client {
	out := make([]core.Client, 0, len(cs)+1)
	replaced := false
	for _, x := range cs {
		if x.ClientID == c.ClientID {
			out, replaced = append(out, c), true
			continue
		}
		out = append(out, x)
	}
	if !replaced {
		out = append(out, c)
	}
	return out
}

func guardFindings(fs []posture.Finding) []idp.GuardFinding {
	out := make([]idp.GuardFinding, 0, len(fs))
	for _, f := range fs {
		res := "realm/" + f.Realm
		if f.ClientID != "" {
			res = "client/" + f.Realm + "/" + f.ClientID
		}
		out = append(out, idp.GuardFinding{
			RuleID: f.RuleID, Severity: string(f.Severity), Title: f.Title,
			Resource: res, Detail: f.Evidence, Fix: f.Remediation,
		})
	}
	return out
}

// guard scores a proposed change. It is the single evaluation used by the
// write routes, the dry-run route and the native client, so the verdicts
// cannot differ. Findings are compared with configcode.DiffFindings, the
// same definition of "new" that gates `haven-idp config apply`.
func (a *api) guard(kind, resource string, before, after guardState) (v idp.GuardVerdict, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("guard evaluation panicked: %v", p)
		}
	}()
	now := a.cfg.Clock()
	ws, err := a.cfg.Guard.waivers(now)
	if err != nil {
		return v, err
	}
	rb, ra := before.report(), after.report()
	rb.ApplyWaivers(ws, now)
	ra.ApplyWaivers(ws, now)
	th := a.cfg.Guard.threshold()
	d := configcode.DiffFindings(rb.Findings, ra.Findings, th)
	mode := a.cfg.Guard.mode()
	v = idp.GuardVerdict{
		Mode: mode, Threshold: string(th), Kind: kind, Resource: resource,
		Blocked: guardFindings(d.Blocked), New: guardFindings(d.New), Fixed: guardFindings(d.Fixed),
		Waived: len(ra.Waived),
	}
	v.Allowed = mode != GuardModeEnforce || len(v.Blocked) == 0
	return v, nil
}

func maxSeverity(fs []idp.GuardFinding) string {
	order := []posture.Severity{posture.SeverityCritical, posture.SeverityHigh, posture.SeverityMedium, posture.SeverityLow, posture.SeverityInfo}
	for _, s := range order {
		for _, f := range fs {
			if f.Severity == string(s) {
				return f.Severity
			}
		}
	}
	return "none"
}

func ruleIDs(fs []idp.GuardFinding) string {
	seen := map[string]bool{}
	var ids []string
	for _, f := range fs {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			ids = append(ids, f.RuleID)
		}
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}

// ---- admission ----

// guardRealm is the gate for a realm create (cur nil) or update. Call it
// after validation and before the store write; false means a response has
// been written and the handler must return.
func (a *api) guardRealm(w http.ResponseWriter, r *http.Request, cur *core.Realm, next core.Realm) bool {
	return a.admit(w, r, "realm", next.Name, "", func() (guardState, guardState, error) {
		var clients []core.Client
		if cur != nil {
			var err error
			if clients, err = a.cfg.Store.ListClients(r.Context(), cur.Name); err != nil {
				return guardState{}, guardState{}, err
			}
		}
		return guardState{cur, clients}, guardState{&next, clients}, nil
	})
}

// guardClient is the gate for a client create or update (matched by client id).
func (a *api) guardClient(w http.ResponseWriter, r *http.Request, rl core.Realm, next core.Client) bool {
	return a.admit(w, r, "client", rl.Name, next.ClientID, func() (guardState, guardState, error) {
		clients, err := a.cfg.Store.ListClients(r.Context(), rl.Name)
		if err != nil {
			return guardState{}, guardState{}, err
		}
		return guardState{&rl, clients}, guardState{&rl, withClient(clients, next)}, nil
	})
}

// admit applies the configured mode to one proposed write.
func (a *api) admit(w http.ResponseWriter, r *http.Request, kind, realm, clientID string, build func() (guardState, guardState, error)) bool {
	mode := a.cfg.Guard.mode()
	if mode == GuardModeOff {
		return true
	}
	resource := kind + "/" + realm
	if clientID != "" {
		resource += "/" + clientID
	}
	v, err := a.evaluate(kind, resource, build)
	switch {
	case err != nil && mode == GuardModeWarn:
		a.cfg.Logger.Error("admin: guard unavailable, write allowed (warn mode)", "resource", resource, "err", err.Error())
		return true
	case err != nil:
		a.cfg.Logger.Error("admin: guard unavailable, write refused (enforce mode)", "resource", resource, "err", err.Error())
		reason, used, stop := a.override(w, r)
		if stop {
			return false
		}
		if used && a.guardEvent(r, realm, clientID, "GUARD_OVERRIDE", "kind="+kind+" rules=unavailable reason="+fmt.Sprintf("%q", reason)) {
			w.Header().Set(guardHeader, "unavailable override=1")
			return true
		}
		writeErr(w, http.StatusInternalServerError, "guard_unavailable")
		return false
	case len(v.Blocked) == 0:
		return true
	}
	hv := fmt.Sprintf("findings=%d max=%s", len(v.Blocked), maxSeverity(v.Blocked))
	rules := ruleIDs(v.Blocked)
	if mode == GuardModeWarn {
		w.Header().Set(guardHeader, hv)
		a.guardEvent(r, realm, clientID, "GUARD_WARN", "kind="+kind+" rules="+rules)
		return true
	}
	// enforce
	reason, used, stop := a.override(w, r)
	if stop {
		return false
	}
	if used {
		if !a.guardEvent(r, realm, clientID, "GUARD_OVERRIDE", "kind="+kind+" rules="+rules+" reason="+fmt.Sprintf("%q", reason)) {
			// An override that cannot be recorded is not honoured.
			writeErr(w, http.StatusInternalServerError, "guard_unavailable")
			return false
		}
		w.Header().Set(guardHeader, hv+" override=1")
		return true
	}
	a.guardEvent(r, realm, clientID, "GUARD_BLOCK", "kind="+kind+" rules="+rules)
	w.Header().Set(guardHeader, hv)
	body := map[string]any{
		"error": "guard_blocked", "findings": v.Blocked,
		"message": "this change would introduce findings at or above the " + v.Threshold + " threshold; fix them or see docs/guard-gate.md",
	}
	if !a.cfg.Guard.NoOverride || !strings.HasPrefix(actorOf(r), "client:") {
		body["override"] = "repeat the request with header " + guardOverrideHeader + ": <reason, 10-300 characters>; the override is audited"
	}
	writeJSON(w, http.StatusUnprocessableEntity, body)
	return false
}

// evaluate runs build and guard with panics contained.
func (a *api) evaluate(kind, resource string, build func() (guardState, guardState, error)) (v idp.GuardVerdict, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("guard evaluation panicked: %v", p)
		}
	}()
	before, after, err := build()
	if err != nil {
		return v, err
	}
	return a.guard(kind, resource, before, after)
}

// override reads X-Haven-Guard-Override. used means a valid reason came with
// an allowed caller; stop means a response was written (bad reason, or
// service accounts are denied overrides).
func (a *api) override(w http.ResponseWriter, r *http.Request) (reason string, used, stop bool) {
	vals := r.Header.Values(guardOverrideHeader)
	if len(vals) == 0 {
		return "", false, false
	}
	reason = strings.TrimSpace(strings.Join(vals, ","))
	if n := len([]rune(reason)); n < overrideMin || n > overrideMax || !validText(reason, 4*overrideMax) {
		writeErr(w, http.StatusBadRequest, "guard_override_invalid: "+guardOverrideHeader+" needs a reason of 10 to 300 characters")
		return "", false, true
	}
	if a.cfg.Guard.NoOverride && strings.HasPrefix(actorOf(r), "client:") {
		writeErr(w, http.StatusForbidden, "guard_override_denied: service accounts cannot override Guard")
		return "", false, true
	}
	return reason, true, false
}

// guardEvent records a Guard decision in the realm's event log (regardless
// of the realm's admin-events setting: these are security decisions). It
// reports whether the event was stored.
func (a *api) guardEvent(r *http.Request, realm, clientID, typ, detail string) bool {
	err := a.cfg.Store.AppendEvent(r.Context(), core.Event{
		Time: a.cfg.Clock().UTC(), Realm: realm, Type: typ, UserID: actorOf(r),
		ClientID: clientID, Detail: detail,
	})
	if err != nil {
		a.cfg.Logger.Error("admin: append guard event", "type", typ, "err", err.Error())
		return false
	}
	return true
}

// ---- routes: dry run and current findings ----

func init() {
	registerRoutes(func(a *api, m *http.ServeMux) {
		p := pathPrefix + "/realms/{r}/guard"
		m.HandleFunc("GET "+p, a.guardStatus)
		m.HandleFunc("POST "+p+"/evaluate", a.guardEvaluate)
	})
}

type guardEnvelope struct {
	Kind string          `json:"kind"`
	Body json.RawMessage `json:"body"`
}

// guardEvaluate answers what a write would do, without applying it.
func (a *api) guardEvaluate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("r")
	if !pathRealmRE.MatchString(name) {
		writeErr(w, http.StatusNotFound, "not found")
		return
	}
	var env guardEnvelope
	if _, err := decode(r, &env); err != nil {
		a.fail(w, r, err)
		return
	}
	inner := func(v any) (map[string]bool, error) {
		if len(env.Body) == 0 {
			return nil, bad("body is required")
		}
		return decode(&http.Request{Body: io.NopCloser(bytes.NewReader(env.Body))}, v)
	}
	var (
		before, after guardState
		resource      string
	)
	cur, err := a.cfg.Store.GetRealm(r.Context(), name)
	exists := err == nil
	if err != nil && !(errors.Is(err, idp.ErrNotFound) && env.Kind == "realm") {
		a.fail(w, r, err)
		return
	}
	switch env.Kind {
	case "realm":
		var in idp.Realm
		present, err := inner(&in)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		base := secureRealmDefaults(name)
		if exists {
			base = cur
			if in.Realm != "" && !strings.EqualFold(in.Realm, cur.Name) {
				a.fail(w, r, bad("realm name cannot be changed"))
				return
			}
		}
		next, err := applyRealm(base, in, present)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		var clients []core.Client
		if exists {
			if clients, err = a.cfg.Store.ListClients(r.Context(), name); err != nil {
				a.fail(w, r, err)
				return
			}
			before = guardState{&cur, clients}
		}
		after = guardState{&next, clients}
		resource = "realm/" + name
	case "client":
		var in idp.Client
		if _, err := inner(&in); err != nil {
			a.fail(w, r, err)
			return
		}
		next, err := clientFromWire(in)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		next.Realm = name
		clients, err := a.cfg.Store.ListClients(r.Context(), name)
		if err != nil {
			a.fail(w, r, err)
			return
		}
		before, after = guardState{&cur, clients}, guardState{&cur, withClient(clients, next)}
		resource = "client/" + name + "/" + next.ClientID
	default:
		a.fail(w, r, bad(`kind must be "realm" or "client"`))
		return
	}
	v, err := a.guard(env.Kind, resource, before, after)
	if err != nil {
		a.cfg.Logger.Error("admin: guard evaluate", "err", err.Error())
		writeErr(w, http.StatusInternalServerError, "guard_unavailable")
		return
	}
	writeJSON(w, http.StatusOK, v)
}

// guardStatus lists the realm's current findings, after waivers.
func (a *api) guardStatus(w http.ResponseWriter, r *http.Request) {
	rl, ok := a.realmOf(w, r)
	if !ok {
		return
	}
	clients, err := a.cfg.Store.ListClients(r.Context(), rl.Name)
	if err != nil {
		a.fail(w, r, err)
		return
	}
	now := a.cfg.Clock()
	ws, err := a.cfg.Guard.waivers(now)
	if err != nil {
		a.cfg.Logger.Error("admin: guard waivers", "err", err.Error())
		writeErr(w, http.StatusInternalServerError, "guard_unavailable")
		return
	}
	rep := guardState{&rl, clients}.report()
	rep.ApplyWaivers(ws, now)
	type waived struct {
		idp.GuardFinding
		Reason   string `json:"reason"`
		Approver string `json:"approver"`
		Expires  string `json:"expires"`
	}
	wv := []waived{}
	for _, x := range rep.Waived {
		wv = append(wv, waived{guardFindings([]posture.Finding{x.Finding})[0], x.Reason, x.Approver, x.Expires})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"realm": rl.Name, "mode": a.cfg.Guard.mode(), "threshold": string(a.cfg.Guard.threshold()),
		"score": rep.Score, "grade": rep.Grade,
		"findings": guardFindings(rep.Findings), "waived": wv,
		"expiredWaivers": len(rep.ExpiredWaivers),
	})
}
