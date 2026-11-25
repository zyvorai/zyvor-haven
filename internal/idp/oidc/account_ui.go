// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Pages of the account console. Everything shown is read for c.u only.

const (
	acctActivityMax   = 50
	acctOverviewMax   = 5
	acctEndedCredsMax = 5 // ended credentials still listed per agent
	acctTimeFormat    = "2 Jan 2006, 15:04 UTC"
)

// acctEventLabels is the allow-list of audit event types a user sees about
// themselves, with the words shown. Types not listed (administrative actions,
// token issuance noise, anything new) are never shown; the event Detail is not
// shown at all, because other code may put administrator names or internal
// identifiers there.
var acctEventLabels = map[string]string{ // #nosec G101 -- audit event type names and their UI labels, no credentials
	"LOGIN":                    "Signed in to an application",
	"LOGIN_ERROR":              "Failed sign-in attempt",
	"PASSKEY_LOGIN":            "Signed in with a passkey",
	"LOGOUT":                   "Signed out",
	"MFA_FAILED":               "Wrong two-step verification code",
	"MFA_FALLBACK":             "Used another sign-in method",
	"STEPUP_REQUIRED":          "Extra verification was required",
	"TOTP_ENROLLED":            "Two-step verification turned on",
	"TOTP_DISABLED":            "Two-step verification turned off",
	"TOTP_RESET":               "Two-step verification reset by an administrator",
	"RECOVERY_USED":            "Recovery code used",
	"RECOVERY_REGENERATED":     "New recovery codes generated",
	"PASSKEY_REGISTERED":       "Passkey added",
	"PASSKEY_REMOVED":          "Passkey removed",
	"PASSKEY_FAILED":           "Passkey check failed",
	"PASSKEY_CLONE_SUSPECTED":  "Possible copied passkey refused",
	"UPDATE_PASSWORD":          "Password changed",
	"UPDATE_PASSWORD_ERROR":    "Password change failed",
	"RESET_PASSWORD_REQUEST":   "Password reset requested",
	"RESET_PASSWORD":           "Password reset",
	"UPDATE_EMAIL_REQUEST":     "Email change requested",
	"UPDATE_EMAIL":             "Email address changed",
	"UPDATE_EMAIL_ERROR":       "Email change failed",
	"VERIFY_EMAIL":             "Email address confirmed",
	"CONSENT_GRANT":            "Application allowed",
	"CONSENT_DENY":             "Application refused",
	"CONSENT_REVOKE":           "Application access revoked",
	"DEVICE_APPROVE":           "Device sign-in approved",
	"DEVICE_DENY":              "Device sign-in refused",
	"CIBA_APPROVE":             "Approval request allowed",
	"CIBA_DENY":                "Approval request refused",
	"CODE_REPLAY":              "Reused sign-in code refused",
	"REFRESH_REUSE":            "Reused refresh token refused",
	"ROLE_GRANT_CREATED":       "Temporary role granted",
	"ROLE_GRANT_REVOKED":       "Temporary role removed",
	"ROLE_GRANT_EXPIRED":       "Temporary role expired",
	"AGENT_CREATE":             "Agent identity created",
	"AGENT_ENABLE":             "Agent identity enabled",
	"AGENT_DISABLE":            "Agent identity disabled",
	"AGENT_DELETE":             "Agent identity deleted",
	"AGENT_CREDENTIAL_ISSUED":  "Agent credential issued",
	"AGENT_CREDENTIAL_REVOKED": "Agent credential revoked",
	"AGENT_TOKEN_ERROR":        "Agent token refused",
	"ACCOUNT_REAUTH":           "Identity confirmed on the account page",
	"ACCOUNT_REAUTH_ERROR":     "Identity confirmation failed",
	"ACCOUNT_SESSION_REVOKED":  "A session was signed out",
	"ACCOUNT_SESSIONS_REVOKED": "All other sessions were signed out",
	"ACCOUNT_DEVICE_REMOVED":   "A known device was forgotten",
	"ACCOUNT_DEVICES_REMOVED":  "All known devices were forgotten",
	"ACCOUNT_ACTION_ERROR":     "Account change refused",
}

var acctEventTypes = func() []string {
	out := make([]string, 0, len(acctEventLabels))
	for k := range acctEventLabels {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}()

type acctNav struct {
	URL, Label string
	Current    bool
}

type acctStat struct {
	URL, Label string
	Count      int
}

type acctSessionRow struct {
	ID, Device, UA, IP, Started, Seen, Apps string
	Current                                 bool
}

type acctDeviceRow struct {
	Handle, First, Last string
	Current             bool
}

type acctAppRow struct {
	ID, Name, ClientID, Granted, Expires, Resources string
	Scopes                                          []scopeInfo
}

type acctCredRow struct {
	ID, Note, Scopes, Created, Expires, LastUsed, State string
	Active                                              bool
}

type acctAgentRow struct {
	ID, Name, ClientID, Scopes, Audiences string
	Enabled                               bool
	Active                                int
	Creds                                 []acctCredRow
}

type acctEventRow struct {
	When, What, App, IP string
	Bad                 bool
}

type acctView struct {
	Nonce, Title, Page, Realm, Username, Name, Email string
	CSRF, Action, Msg, Error, LogoutURL, Base        string
	Nav                                              []acctNav
	EmailVerified, EventsLogged                      bool

	// Recent: changes are allowed now. Reauth: show the confirmation panel.
	Recent, Reauth, ReauthPassword, ReauthCode bool

	Stats    []acctStat
	Sessions []acctSessionRow
	Others   int
	Devices  []acctDeviceRow
	// DevicesTracked: the realm's risk policy is on, so browsers are remembered.
	DevicesTracked bool
	Apps           []acctAppRow
	Agents         []acctAgentRow
	Events         []acctEventRow

	HasPassword, EmailChange, TOTP, TOTPOn, Passkeys bool
	PasskeyCount, RecoveryLeft                       int
	PasswordPolicy                                   string

	L Loc // ui.go: the realm's branding; the console's text is English
}

func acctTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.UTC().Format(acctTimeFormat)
}

// uaSummary turns a User-Agent into "Browser on System". It is a hint for the
// owner of the session only; the header is whatever the client chose to send.
func uaSummary(ua string) string {
	has := func(s string) bool { return strings.Contains(ua, s) }
	browser := ""
	switch {
	case has("Edg/"), has("EdgA/"), has("EdgiOS/"):
		browser = "Edge"
	case has("OPR/"):
		browser = "Opera"
	case has("Firefox/"), has("FxiOS/"):
		browser = "Firefox"
	case has("CriOS/"), has("Chrome/"):
		browser = "Chrome"
	case has("Safari/"):
		browser = "Safari"
	case has("curl/"):
		browser = "curl"
	}
	system := ""
	switch {
	case has("iPhone"):
		system = "iPhone"
	case has("iPad"):
		system = "iPad"
	case has("Android"):
		system = "Android"
	case has("Mac OS X"), has("Macintosh"):
		system = "macOS"
	case has("Windows"):
		system = "Windows"
	case has("CrOS"):
		system = "ChromeOS"
	case has("Linux"):
		system = "Linux"
	}
	switch {
	case browser != "" && system != "":
		return browser + " on " + system
	case browser != "":
		return browser
	case system != "":
		return "Browser on " + system
	}
	return "Unknown browser"
}

// ---- loaders ----

func (c *console) loadSessions(ctx context.Context, v *acctView) error {
	all, err := c.ownSessions(ctx)
	if err != nil {
		return err
	}
	now := c.p.now()
	names := map[string]string{}
	appName := func(id string) string {
		if n, ok := names[id]; ok {
			return n
		}
		n := id
		if cl, err := c.p.cfg.Store.GetClientByClientID(ctx, c.rl.Name, id); err == nil && cl.Name != "" {
			n = cl.Name
		}
		names[id] = n
		return n
	}
	for _, s := range all {
		if !now.Before(s.ExpiresAt) || !now.Before(s.IdleExpires) {
			continue
		}
		row := acctSessionRow{ID: s.ID, Device: uaSummary(s.UserAgent), UA: s.UserAgent, IP: s.IP,
			Started: acctTime(s.AuthTime), Seen: acctTime(s.LastSeen), Current: s.ID == c.sess.ID}
		apps := make([]string, 0, len(s.Clients))
		for _, id := range s.Clients {
			if id != deviceClientID {
				apps = append(apps, appName(id))
			}
		}
		row.Apps = strings.Join(apps, ", ")
		if !row.Current {
			v.Others++
			v.Sessions = append(v.Sessions, row)
			continue
		}
		v.Sessions = append([]acctSessionRow{row}, v.Sessions...) // this one first
	}
	return nil
}

func (c *console) loadDevices(ctx context.Context, v *acctView) error {
	st, ok := c.p.stepUpStore()
	if !ok {
		return nil
	}
	pol, err := st.GetStepUpPolicy(ctx, c.rl.Name)
	if err != nil {
		return err
	}
	v.DevicesTracked = pol.Enabled
	list, err := st.ListDevices(ctx, c.rl.Name, c.u.ID)
	if err != nil {
		return err
	}
	cur := ""
	if ck, err := c.r.Cookie(deviceCookie); err == nil && validDeviceCookie(ck.Value) {
		cur = deviceHash(ck.Value)
	}
	for _, d := range list {
		if d.UserID != c.u.ID {
			continue
		}
		v.Devices = append(v.Devices, acctDeviceRow{Handle: deviceHandle(c.rl.Name, c.u.ID, d.Hash),
			First: acctTime(d.FirstSeen), Last: acctTime(d.LastSeen), Current: d.Hash == cur})
	}
	return nil
}

func (c *console) loadApps(ctx context.Context, v *acctView) error {
	cs, ok := c.p.consentStore()
	if !ok {
		return nil
	}
	grants, err := cs.ListConsentGrants(ctx, c.rl.Name, c.u.ID, "", false, c.p.now(), 100)
	if err != nil {
		return err
	}
	for _, g := range grants {
		if g.UserID != c.u.ID {
			continue
		}
		row := acctAppRow{ID: g.ID, Name: g.ClientName, ClientID: g.ClientID, Granted: acctTime(g.UpdatedAt),
			Expires: acctTime(g.ExpiresAt), Resources: strings.Join(g.Resources, " ")}
		for _, s := range g.Scopes {
			d := scopeDesc[s]
			if d == "" {
				d = "use this permission"
			}
			row.Scopes = append(row.Scopes, scopeInfo{s, d})
		}
		v.Apps = append(v.Apps, row)
	}
	return nil
}

func (c *console) loadAgents(ctx context.Context, v *acctView) error {
	as, ok := core.StoreAs[core.AgentStore](c.p.cfg.Store)
	if !ok || c.u.ID == "" { // an empty owner would mean "all agents"
		return nil
	}
	agents, err := as.ListAgents(ctx, c.rl.Name, c.u.ID)
	if err != nil {
		return err
	}
	now := c.p.now()
	for _, a := range agents {
		if a.OwnerUserID != c.u.ID { // never rely on the store filter alone
			continue
		}
		creds, err := as.ListAgentCredentials(ctx, c.rl.Name, a.ID)
		if err != nil {
			return err
		}
		row := acctAgentRow{ID: a.ID, Name: a.Name, ClientID: a.ClientID, Enabled: a.Enabled,
			Scopes: strings.Join(a.AllowedScopes, " "), Audiences: strings.Join(a.Audiences, " ")}
		ended := 0
		for _, cr := range creds {
			cv := acctCredRow{ID: cr.ID, Note: cr.Note, Scopes: strings.Join(cr.Scopes, " "), Created: acctTime(cr.CreatedAt),
				Expires: acctTime(cr.ExpiresAt), LastUsed: acctTime(cr.LastUsedAt), Active: cr.Active(now), State: "Active"}
			switch {
			case cv.Active:
				row.Active++
			case ended >= acctEndedCredsMax:
				continue
			default:
				ended++
				cv.State = "Expired"
				if !cr.RevokedAt.IsZero() {
					cv.State = "Revoked"
				}
			}
			row.Creds = append(row.Creds, cv)
		}
		v.Agents = append(v.Agents, row)
	}
	return nil
}

func (c *console) loadEvents(ctx context.Context, v *acctView, limit int) error {
	v.EventsLogged = c.rl.AuthEventsLogged
	events, err := c.st.ListUserEvents(ctx, c.rl.Name, c.u.ID, acctEventTypes, limit)
	if err != nil {
		return err
	}
	for _, e := range events {
		label, ok := acctEventLabels[e.Type]
		if !ok || e.UserID != c.u.ID {
			continue
		}
		v.Events = append(v.Events, acctEventRow{When: acctTime(e.Time), What: label, App: e.ClientID, IP: e.IP,
			Bad: strings.HasSuffix(e.Type, "_ERROR") || strings.HasSuffix(e.Type, "_FAILED") ||
				e.Type == "CODE_REPLAY" || e.Type == "REFRESH_REUSE" || e.Type == "PASSKEY_CLONE_SUSPECTED"})
	}
	return nil
}

func (c *console) loadSecurity(ctx context.Context, v *acctView) error {
	v.EmailChange = c.p.actionsOn()
	if st, ok := c.p.mfaStore(); ok {
		v.TOTP = true
		cred, err := st.GetTOTP(ctx, c.rl.Name, c.u.ID)
		switch {
		case err == nil && cred.Confirmed:
			v.TOTPOn = true
			if v.RecoveryLeft, err = st.CountRecoveryCodes(ctx, c.rl.Name, c.u.ID); err != nil {
				return err
			}
		case err != nil && !isNotFound(err):
			return err
		}
	}
	if st, _, ok := c.p.passkeys(); ok {
		v.Passkeys = true
		creds, err := st.ListPasskeys(ctx, c.rl.Name, c.u.ID)
		if err != nil {
			return err
		}
		v.PasskeyCount = len(creds)
	}
	return nil
}

func (c *console) loadOverview(ctx context.Context, v *acctView) error {
	for _, load := range []func(context.Context, *acctView) error{c.loadSessions, c.loadDevices, c.loadApps, c.loadAgents, c.loadSecurity} {
		if err := load(ctx, v); err != nil {
			return err
		}
	}
	counts := map[string]int{"sessions": len(v.Sessions), "devices": len(v.Devices), "applications": len(v.Apps), "agents": len(v.Agents)}
	for _, d := range acctPages {
		n, ok := counts[d.slug]
		if ok && (d.on == nil || d.on(c.p)) {
			v.Stats = append(v.Stats, acctStat{URL: accountPath(c.rl.Name, d.slug), Label: d.nav, Count: n})
		}
	}
	return c.loadEvents(ctx, v, acctOverviewMax)
}

// render writes the current page with a fresh CSRF token bound to the session.
func (c *console) render(status int, msg, errMsg string) {
	p, rl := c.p, c.rl
	ctx := c.r.Context()
	// Realm branding (logo, accent, footer links) applies. The text is not in
	// the translation catalogue, so the page is declared English.
	l := p.loc(c.w)
	l.lang = ""
	v := &acctView{L: l, Title: c.def.title, Page: c.def.slug, Realm: l.RealmName(rl), Username: c.u.Username,
		Name: strings.TrimSpace(c.u.FirstName + " " + c.u.LastName), Email: c.u.Email, EmailVerified: c.u.EmailVerified,
		Msg: msg, Error: errMsg, Action: accountPath(rl.Name, c.def.slug), Base: accountPath(rl.Name, ""),
		LogoutURL: p.logoutPath(rl.Name), Recent: c.recent, HasPassword: c.u.PasswordHash != "",
		PasswordPolicy: rl.PasswordPolicy, ReauthPassword: c.reauth.Password, ReauthCode: c.reauth.Code}
	current := c.def.slug
	if current == "password" {
		current = "security"
	}
	for _, d := range acctPages {
		if d.nav == "" || (d.on != nil && !d.on(p)) {
			continue
		}
		v.Nav = append(v.Nav, acctNav{URL: accountPath(rl.Name, d.slug), Label: d.nav, Current: d.slug == current})
	}
	var err error
	actionable := false // is there anything on this page that needs recent authentication?
	switch c.def.slug {
	case "":
		err = c.loadOverview(ctx, v)
	case "sessions":
		err = c.loadSessions(ctx, v)
		actionable = v.Others > 0
	case "devices":
		err = c.loadDevices(ctx, v)
		actionable = len(v.Devices) > 0
	case "security":
		err = c.loadSecurity(ctx, v)
	case "password":
		actionable = v.HasPassword
	case "applications":
		err = c.loadApps(ctx, v)
		actionable = len(v.Apps) > 0
	case "agents":
		err = c.loadAgents(ctx, v)
		actionable = slices.ContainsFunc(v.Agents, func(a acctAgentRow) bool { return a.Active > 0 })
	case "activity":
		err = c.loadEvents(ctx, v, acctActivityMax)
	}
	if err != nil {
		c.fail("load "+c.def.title, err)
		return
	}
	v.Reauth = actionable && !c.recent

	csrf := p.newCSRF(acctCSRFScope(rl.Name, c.sess.ID))
	v.CSRF = csrf
	// #nosec G124 -- HttpOnly and SameSite are set; Secure follows p.secure (config-driven, off only for plain-HTTP dev installs)
	http.SetCookie(c.w, &http.Cookie{Name: acctCSRFCookie, Value: csrf, Path: accountPath(rl.Name, ""),
		HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(csrfTTL.Seconds())})
	v.Nonce = randToken(16)
	p.pageHeaders(c.w, v.Nonce)
	c.w.WriteHeader(status)
	if err := accountTmpl.Execute(c.w, v); err != nil {
		p.cfg.Logger.Error("oidc: account page", "err", err)
	}
}

// accountHidden are the hidden fields every account form carries.
const accountHidden = `<input type="hidden" name="csrf" value="{{$.CSRF}}">`

var accountTmpl = template.Must(template.New("account").Parse(withTheme(`<!doctype html>
<html<!--loc-->><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}} - Account</title>
<!--theme--></head><body><main class="console">
<header class="who"><!--hero:person--><p><strong>{{.Username}}</strong><span class="sub">{{.Realm}}</span></p></header>
<nav class="seg" aria-label="Account sections">{{range .Nav}}<a href="{{.URL}}"{{if .Current}} aria-current="page"{{end}}>{{.Label}}</a>{{end}}<a class="out" href="{{.LogoutURL}}">Sign out</a></nav>
<div class="content">
<h1>{{.Title}}</h1>
{{if .Msg}}<p class="ok" role="status">{{.Msg}}</p>{{end}}
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
{{if .Reauth}}<section class="panel confirm" aria-labelledby="confirm-title"><h2 id="confirm-title">Confirm it is you</h2>
{{if .ReauthPassword}}<p class="sub">Your sign-in is older than 10 minutes. Confirm your password{{if .ReauthCode}} and a two-step code{{end}} to make changes.</p>
<form method="post" action="{{.Action}}">` + accountHidden + `<input type="hidden" name="action" value="reauth"><input type="text" name="username" value="{{.Username}}" autocomplete="username" hidden readonly>
<label for="rpw">Password</label><input id="rpw" name="password" type="password" autocomplete="current-password" required maxlength="1024">
{{if .ReauthCode}}<label for="rcode">Authenticator or recovery code</label><input id="rcode" name="code" autocomplete="one-time-code" required maxlength="64">{{end}}
<button type="submit">Confirm</button></form>
{{else}}<p class="sub">Your sign-in is older than 10 minutes. To make changes, <a href="{{.LogoutURL}}">sign out</a>, sign in again to an application, then come back here.</p>{{end}}</section>{{end}}

{{if eq .Page ""}}
<section class="panel"><dl>
{{if .Name}}<dt>Name</dt><dd>{{.Name}}</dd>{{end}}
<dt>Username</dt><dd>{{.Username}}</dd>
<dt>Email</dt><dd>{{if .Email}}{{.Email}} <span class="badge{{if not .EmailVerified}} off{{end}}">{{if .EmailVerified}}Verified{{else}}Not verified{{end}}</span>{{else}}none{{end}}</dd>
{{if .TOTP}}<dt>Two-step verification</dt><dd><span class="badge{{if not .TOTPOn}} off{{end}}">{{if .TOTPOn}}On{{else}}Off{{end}}</span></dd>{{end}}
{{if .Passkeys}}<dt>Passkeys</dt><dd>{{.PasskeyCount}}</dd>{{end}}
</dl></section>
<div class="stats">{{range .Stats}}<a class="stat" href="{{.URL}}"><strong>{{.Count}}</strong><span>{{.Label}}</span></a>{{end}}</div>
<h2>Latest activity</h2>
{{template "events" .}}
<p class="sub"><a href="{{.Base}}/activity">See all recent activity</a></p>

{{else if eq .Page "sessions"}}
<p class="sub">Every browser or device where you are signed in. Signing one out also tells its applications to end their own session.</p>
{{range .Sessions}}<section class="panel"><h3>{{.Device}}{{if .Current}} <span class="badge">This device</span>{{end}}</h3>
<p class="meta">Signed in {{.Started}}<br>Last active {{.Seen}}<br>Address {{if .IP}}{{.IP}}{{else}}unknown{{end}}{{if .Apps}}<br>Applications: {{.Apps}}{{end}}</p>
{{if .UA}}<p class="meta ua">{{.UA}}</p>{{end}}
{{if .Current}}<p class="meta"><a href="{{$.LogoutURL}}">Sign out of this device</a></p>
{{else if $.Recent}}<form method="post" action="{{$.Action}}">` + accountHidden + `<input type="hidden" name="action" value="revoke"><input type="hidden" name="sid" value="{{.ID}}"><button type="submit" class="secondary">Sign out</button></form>{{end}}</section>
{{else}}<p>No active sessions.</p>{{end}}
{{if and .Recent .Others}}<form method="post" action="{{.Action}}">` + accountHidden + `<input type="hidden" name="action" value="revoke-others"><button type="submit">Sign out all other sessions</button></form>{{end}}
<p class="sub">Applications that were granted offline access keep it after a sign-out; remove it under Applications.</p>

{{else if eq .Page "devices"}}
<p class="sub">Browsers that completed a sign-in, remembered so that an unfamiliar one can be asked for extra verification. Forgetting a device does not sign it out.</p>
{{if not .DevicesTracked}}<p class="warn">This realm does not remember devices at the moment.</p>{{end}}
{{range .Devices}}<section class="panel"><h3>Remembered browser{{if .Current}} <span class="badge">This browser</span>{{end}}</h3>
<p class="meta">First seen {{.First}}<br>Last sign-in {{.Last}}</p>
{{if $.Recent}}<form method="post" action="{{$.Action}}">` + accountHidden + `<input type="hidden" name="action" value="forget"><input type="hidden" name="device" value="{{.Handle}}"><button type="submit" class="secondary">Forget</button></form>{{end}}</section>
{{else}}<p>No known devices.</p>{{end}}
{{if and .Recent .Devices}}<form method="post" action="{{.Action}}">` + accountHidden + `<input type="hidden" name="action" value="forget-all"><button type="submit" class="secondary">Forget all devices</button></form>{{end}}

{{else if eq .Page "security"}}
<section class="panel"><h3>Password</h3>
{{if .HasPassword}}<p class="meta">Change the password you sign in with.</p><a class="fed" href="{{.Base}}/password">Change password</a>
{{else}}<p class="meta">This account has no password here; you sign in another way.</p>{{end}}</section>
<section class="panel"><h3>Email address</h3>
<p class="meta">{{if .Email}}{{.Email}}{{else}}none{{end}}</p>
{{if .EmailChange}}<a class="fed" href="{{.Base}}/email">Change email address</a>{{else}}<p class="meta">Changing it here needs email to be set up on the server.</p>{{end}}</section>
{{if .TOTP}}<section class="panel"><h3>Two-step verification <span class="badge{{if not .TOTPOn}} off{{end}}">{{if .TOTPOn}}On{{else}}Off{{end}}</span></h3>
<p class="meta">{{if .TOTPOn}}Authenticator app. Recovery codes left: {{.RecoveryLeft}}.{{else}}Ask for a code from an authenticator app when you sign in.{{end}}</p>
<a class="fed" href="{{.Base}}/totp">{{if .TOTPOn}}Manage two-step verification{{else}}Set up two-step verification{{end}}</a></section>{{end}}
{{if .Passkeys}}<section class="panel"><h3>Passkeys</h3>
<p class="meta">{{if .PasskeyCount}}Registered: {{.PasskeyCount}}.{{else}}Sign in with your fingerprint, face or security key.{{end}}</p>
<a class="fed" href="{{.Base}}/passkeys">{{if .PasskeyCount}}Manage passkeys{{else}}Add a passkey{{end}}</a></section>{{end}}

{{else if eq .Page "password"}}
{{if not .HasPassword}}<p>This account has no password here; you sign in another way.</p>
{{else}}<p class="sub">Changing your password signs out your other sessions and makes applications ask for new tokens. Agent credentials are separate: revoke them under Agents.</p>
{{if .PasswordPolicy}}<p class="sub">Password rules: <code>{{.PasswordPolicy}}</code></p>{{end}}
{{if .Recent}}<section class="panel"><form method="post" action="{{.Action}}">` + accountHidden + `<input type="hidden" name="action" value="change"><input type="text" name="username" value="{{.Username}}" autocomplete="username" hidden readonly>
<label for="cur">Current password</label><input id="cur" name="current" type="password" autocomplete="current-password" required maxlength="1024">
<label for="npw">New password</label><input id="npw" name="password" type="password" autocomplete="new-password" required maxlength="1024">
<label for="cpw">Repeat new password</label><input id="cpw" name="confirm" type="password" autocomplete="new-password" required maxlength="1024">
<button type="submit">Change password</button></form></section>{{end}}{{end}}
<p class="sub"><a href="{{.Base}}/security">Back to sign-in and security</a></p>

{{else if eq .Page "applications"}}
<p class="sub">Applications you allowed to use your account.</p>
{{range .Apps}}<section class="panel"><h3>{{.Name}}</h3>
<p class="meta"><code>{{.ClientID}}</code></p>
<ul>{{range .Scopes}}<li class="meta"><code>{{.Name}}</code> {{.Desc}}</li>{{end}}</ul>
<p class="meta">{{if .Resources}}Services: {{.Resources}}<br>{{end}}Allowed {{.Granted}}<br>Expires {{.Expires}}</p>
{{if $.Recent}}<form method="post" action="{{$.Action}}">` + accountHidden + `<input type="hidden" name="action" value="revoke"><input type="hidden" name="grant_id" value="{{.ID}}"><button type="submit" class="secondary">Revoke access</button></form>{{end}}</section>
{{else}}<p>No applications currently have remembered access to your account.</p>{{end}}

{{else if eq .Page "agents"}}
<p class="sub">Non-human identities that act for you, and their credentials. Revoking a credential stops new tokens at once.</p>
{{range .Agents}}{{$a := .}}<section class="panel"><h3>{{.Name}} <span class="badge{{if not .Enabled}} off{{end}}">{{if .Enabled}}Enabled{{else}}Disabled{{end}}</span></h3>
<p class="meta"><code>{{.ClientID}}</code><br>Scopes: {{.Scopes}}{{if .Audiences}}<br>Audiences: {{.Audiences}}{{end}}</p>
<ul>{{range .Creds}}<li><p class="meta"><strong>{{if .Note}}{{.Note}}{{else}}Credential{{end}}</strong> <span class="badge{{if not .Active}} off{{end}}">{{.State}}</span><br><code>{{.ID}}</code><br>Scopes: {{.Scopes}}<br>Created {{.Created}}<br>Expires {{.Expires}}<br>Last used {{.LastUsed}}</p>
{{if and .Active $.Recent}}<form method="post" action="{{$.Action}}">` + accountHidden + `<input type="hidden" name="action" value="revoke"><input type="hidden" name="agent_id" value="{{$a.ID}}"><input type="hidden" name="credential_id" value="{{.ID}}"><button type="submit" class="secondary">Revoke credential</button></form>{{end}}</li>
{{else}}<li class="meta">No credentials.</li>{{end}}</ul>
{{if and (gt .Active 1) $.Recent}}<form method="post" action="{{$.Action}}">` + accountHidden + `<input type="hidden" name="action" value="revoke-all"><input type="hidden" name="agent_id" value="{{.ID}}"><button type="submit" class="secondary">Revoke all credentials</button></form>{{end}}</section>
{{else}}<p>You have no agent identities.</p>{{end}}

{{else if eq .Page "activity"}}
<p class="sub">The latest security events of your account. If something here was not you, sign out your other sessions and change your password.</p>
{{template "events" .}}
{{end}}
</div>
</main></body></html>
{{define "events"}}{{if not .EventsLogged}}<p class="warn">This realm does not currently record sign-in activity.</p>{{end}}
<ul class="events">{{range .Events}}<li><strong{{if .Bad}} class="err"{{end}}>{{.What}}</strong><span class="meta">{{.When}}{{if .App}} · {{.App}}{{end}}{{if .IP}} · {{.IP}}{{end}}</span></li>{{else}}<li class="meta">Nothing to show.</li>{{end}}</ul>{{end}}`)))
