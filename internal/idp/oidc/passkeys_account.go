// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
	"html/template"
	"net/http"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/webauthn"
)

const (
	pkCSRFCookie  = "haven_pk_csrf"
	pkReauthCook  = "haven_pk_reauth"
	pkMaxNameRune = 64
)

func registerPasskeyRoutes(p *Provider, mux *http.ServeMux) {
	mux.HandleFunc("GET /realms/{realm}/account/passkeys", p.pkAccount)
	mux.HandleFunc("POST /realms/{realm}/account/passkeys", p.pkAccount)
}

func pkAccountPath(realm string) string { return "/realms/" + realm + "/account/passkeys" }

type pkRegOptions struct {
	Challenge string `json:"challenge"`
	RP        struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"rp"`
	User struct {
		ID          string `json:"id"`
		Name        string `json:"name"`
		DisplayName string `json:"displayName"`
	} `json:"user"`
	PubKeyCredParams []struct {
		Type string `json:"type"`
		Alg  int    `json:"alg"`
	} `json:"pubKeyCredParams"`
	Timeout                int `json:"timeout"`
	AuthenticatorSelection struct {
		ResidentKey      string `json:"residentKey"`
		UserVerification string `json:"userVerification"`
	} `json:"authenticatorSelection"`
	ExcludeCredentials []pkDescriptor `json:"excludeCredentials"`
}

type pkCredView struct {
	ID, Name, Created, LastUsed string
	BackedUp, Eligible          bool
}

type pkAcctData struct {
	Nonce, CSRF, Realm, Action, Msg, Error, Username string
	Creds                                            []pkCredView
	Recent, Required                                 bool
	Opts, Token                                      string
	Script                                           template.JS
}

func (p *Provider) pkNotice(w http.ResponseWriter, status int, msg string) {
	p.simplePage(w, status, "Passkeys", msg)
}

func (p *Provider) pkAccount(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	name := r.PathValue("realm")
	rl, ok := p.realm(r.Context(), name)
	if !ok {
		p.errorPage(w, http.StatusNotFound, "Unknown realm.")
		return
	}
	st, rp, ok := p.passkeys()
	if !ok {
		p.pkNotice(w, http.StatusNotFound, "Passkeys are not available.")
		return
	}
	sess, ok := p.currentSession(r, rl)
	if !ok {
		p.pkNotice(w, http.StatusUnauthorized, "Sign in to an application of this realm first, then open this page again.")
		return
	}
	u, err := p.cfg.Store.GetUser(r.Context(), rl.Name, sess.UserID)
	if err != nil || !u.Enabled {
		if err != nil && !errors.Is(err, idp.ErrNotFound) {
			p.cfg.Logger.Error("oidc: load user", "err", err)
		}
		p.pkNotice(w, http.StatusUnauthorized, "Sign in to an application of this realm first, then open this page again.")
		return
	}
	if r.Method == http.MethodPost {
		p.pkAccountPost(w, r, rl, st, rp, sess, u)
		return
	}
	msg := map[string]string{"added": "Passkey added.", "renamed": "Passkey renamed.", "removed": "Passkey removed.", "reauth": "Confirmed. You can add or remove passkeys for the next 10 minutes."}[r.URL.Query().Get("m")]
	p.pkAccountPage(w, r, rl, st, rp, sess, u, http.StatusOK, msg, "")
}

func (p *Provider) pkAccountPage(w http.ResponseWriter, r *http.Request, rl core.Realm, st core.PasskeyStore, rp webauthn.RP, sess core.Session, u core.User, status int, msg, errMsg string) {
	ctx := r.Context()
	creds, err := st.ListPasskeys(ctx, rl.Name, u.ID)
	if err != nil {
		p.cfg.Logger.Error("oidc: list passkeys", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return
	}
	required, err := st.RealmRequiresPasskeys(ctx, rl.Name)
	if err != nil {
		p.cfg.Logger.Error("oidc: passkey policy", "err", err)
		p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		return
	}
	csrf := p.newCSRF(rl.Name + "|passkeys")
	// #nosec G124 -- HttpOnly and SameSite are set; Secure follows p.secure (config-driven, off only for plain-HTTP dev installs)
	http.SetCookie(w, &http.Cookie{Name: pkCSRFCookie, Value: csrf, Path: pkAccountPath(rl.Name),
		HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(csrfTTL.Seconds())})
	nonce := randToken(16)
	d := pkAcctData{Nonce: nonce, CSRF: csrf, Realm: rl.Name, Action: pkAccountPath(rl.Name), Msg: msg, Error: errMsg,
		Username: u.Username, Recent: p.pkRecent(r, rl, sess), Required: required, Script: pkScript}
	for _, c := range creds {
		v := pkCredView{ID: c.CredentialID, Name: c.Name, Created: c.CreatedAt.UTC().Format("2006-01-02"), LastUsed: "never",
			BackedUp: c.BackupState, Eligible: c.BackupEligible}
		if !c.LastUsedAt.IsZero() {
			v.LastUsed = c.LastUsedAt.UTC().Format("2006-01-02 15:04 UTC")
		}
		d.Creds = append(d.Creds, v)
	}
	if d.Recent && len(creds) < pkMaxPerUser {
		handle, err := st.UserHandle(ctx, rl.Name, u.ID, b64(randBytes(32)))
		if err != nil {
			p.cfg.Logger.Error("oidc: passkey user handle", "err", err)
			p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
			return
		}
		chal, tok := p.pkChallenge(rl.Name, u.ID, pkPurposeReg)
		var o pkRegOptions
		o.Challenge = b64(chal)
		o.RP.ID, o.RP.Name = rp.ID, rl.Name
		o.User.ID, o.User.Name = handle, u.Username
		o.User.DisplayName = strings.TrimSpace(u.FirstName + " " + u.LastName)
		if o.User.DisplayName == "" {
			o.User.DisplayName = u.Username
		}
		for _, alg := range []int{webauthn.AlgES256, webauthn.AlgEdDSA, webauthn.AlgRS256} {
			o.PubKeyCredParams = append(o.PubKeyCredParams, struct {
				Type string `json:"type"`
				Alg  int    `json:"alg"`
			}{"public-key", alg})
		}
		o.Timeout = 60000
		// Discoverable credential preferred, and user verification REQUIRED:
		// every stored passkey can then also be used to sign in without a
		// password, which demands UV.
		o.AuthenticatorSelection.ResidentKey, o.AuthenticatorSelection.UserVerification = "preferred", "required"
		o.ExcludeCredentials = pkDescriptors(creds)
		d.Opts, d.Token = mustJSON(o), tok
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Content-Security-Policy", pkCSP(nonce))
	w.WriteHeader(status)
	_ = pkAcctTmpl.Execute(w, d)
}

// pkRecent reports whether the user authenticated within pkRecentAuth: either
// the SSO session's own login, or a password confirmation on this page that is
// bound to this session.
func (p *Provider) pkRecent(r *http.Request, rl core.Realm, sess core.Session) bool {
	if p.now().Sub(sess.AuthTime) < pkRecentAuth {
		return true
	}
	ck, err := r.Cookie(pkReauthCook)
	if err != nil {
		return false
	}
	uid, payload, ok := p.checkPending(rl.Name, ck.Value, "pk-reauth")
	return ok && uid == sess.UserID && payload == sess.ID
}

func cleanName(s string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if unicode.IsControl(r) || r == utf8.RuneError {
			continue
		}
		b.WriteRune(r)
		if utf8.RuneCountInString(b.String()) >= pkMaxNameRune {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

var pkTransports = []string{"usb", "nfc", "ble", "internal", "hybrid", "smart-card"}

func cleanTransports(s string) []string {
	var out []string
	for _, t := range strings.Split(s, ",") {
		if slices.Contains(pkTransports, t) && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

func (p *Provider) pkAccountPost(w http.ResponseWriter, r *http.Request, rl core.Realm, st core.PasskeyStore, rp webauthn.RP, sess core.Session, u core.User) {
	if err := r.ParseForm(); err != nil {
		p.errorPage(w, http.StatusBadRequest, "Invalid request.")
		return
	}
	ctx := r.Context()
	tok := r.PostForm.Get("csrf")
	ck, err := r.Cookie(pkCSRFCookie)
	if err != nil || tok == "" || !hmac.Equal([]byte(ck.Value), []byte(tok)) || !p.checkCSRF(rl.Name+"|passkeys", tok) {
		p.errorPage(w, http.StatusForbidden, "Your session expired or the request was invalid. Go back and try again.")
		return
	}
	ip := p.clientIP(r)
	redirect := func(code string) {
		http.Redirect(w, r, pkAccountPath(rl.Name)+"?m="+code, http.StatusSeeOther) // #nosec G710 -- fixed in-realm account path and a code chosen by the handler, no user-supplied target
	}
	page := func(status int, msg string) {
		p.pkAccountPage(w, r, rl, st, rp, sess, u, status, "", msg)
	}
	needRecent := func() bool {
		if p.pkRecent(r, rl, sess) {
			return true
		}
		page(http.StatusForbidden, "Confirm your password to continue: your sign-in is older than 10 minutes.")
		return false
	}

	switch r.PostForm.Get("pk_action") {
	case "reauth":
		if !p.pkRate(ctx, rl.Name, "reauth-ip", ip, 10) || !p.pkRate(ctx, rl.Name, "reauth-user", u.ID, 5) {
			page(http.StatusTooManyRequests, "Too many attempts. Try again later.")
			return
		}
		pw := r.PostForm.Get("password")
		locked := rl.BruteForceProtection && !u.LockedUntil.IsZero() && p.now().Before(u.LockedUntil)
		good := false
		if u.PasswordHash != "" && pw != "" && len(pw) <= 1024 && !locked {
			good, _ = p.cfg.Hasher.Verify(pw, u.PasswordHash)
		} else {
			p.cfg.Hasher.Verify(pw, p.dummy())
		}
		if !good {
			p.event(ctx, rl, "PASSKEY_FAILED", u.ID, "", ip, "reauth_failed")
			page(http.StatusForbidden, "That password is not correct.")
			return
		}
		// #nosec G124 -- HttpOnly and SameSite are set; Secure follows p.secure (config-driven, off only for plain-HTTP dev installs)
		http.SetCookie(w, &http.Cookie{Name: pkReauthCook, Value: p.signPending(rl.Name, u.ID, "pk-reauth", sess.ID, pkRecentAuth),
			Path: pkAccountPath(rl.Name), HttpOnly: true, Secure: p.secure, SameSite: http.SameSiteStrictMode, MaxAge: int(pkRecentAuth.Seconds())})
		redirect("reauth")

	case "add":
		if !needRecent() {
			return
		}
		if !p.pkRate(ctx, rl.Name, "ip", ip, pkAssertPerIP) {
			page(http.StatusTooManyRequests, "Too many attempts. Try again later.")
			return
		}
		existing, err := st.ListPasskeys(ctx, rl.Name, u.ID)
		if err != nil {
			p.cfg.Logger.Error("oidc: list passkeys", "err", err)
			p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
			return
		}
		if len(existing) >= pkMaxPerUser {
			page(http.StatusBadRequest, "You have reached the maximum number of passkeys.")
			return
		}
		uid, chal, ok := p.pkOpen(ctx, st, rl.Name, r.PostForm.Get("pk_token"), pkPurposeReg)
		cd, ok1 := formB64(r, "pk_cd", 4096)
		att, ok2 := formB64(r, "pk_att", 16384)
		if !ok || uid != u.ID || !ok1 || !ok2 {
			p.event(ctx, rl, "PASSKEY_FAILED", u.ID, "", ip, "registration_request_invalid")
			page(http.StatusBadRequest, "The registration request was invalid or expired. Try again.")
			return
		}
		reg, err := webauthn.VerifyRegistration(rp, chal, cd, att, true)
		if err != nil {
			p.event(ctx, rl, "PASSKEY_FAILED", u.ID, "", ip, "registration_rejected")
			p.cfg.Logger.Info("oidc: passkey registration rejected", "realm", rl.Name, "reason", err.Error())
			page(http.StatusBadRequest, "That authenticator could not be registered (it must verify you, and attestation certificates are not supported).")
			return
		}
		nm := cleanName(r.PostForm.Get("name"))
		if nm == "" {
			nm = "Passkey"
		}
		credKey := b64(reg.CredentialID)
		err = st.AddPasskey(ctx, core.Passkey{Realm: rl.Name, UserID: u.ID, CredentialID: credKey, PublicKey: reg.PublicKey,
			SignCount: reg.SignCount, Transports: cleanTransports(r.PostForm.Get("pk_tr")), AAGUID: hex.EncodeToString(reg.AAGUID),
			Name: nm, BackupEligible: reg.BackupEligible, BackupState: reg.BackupState, CreatedAt: p.now()})
		switch {
		case errors.Is(err, idp.ErrConflict):
			page(http.StatusConflict, "That authenticator is already registered.")
			return
		case err != nil:
			p.cfg.Logger.Error("oidc: store passkey", "err", err)
			p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
			return
		}
		p.event(ctx, rl, "PASSKEY_REGISTERED", u.ID, "", ip, "credential "+pkShort(credKey))
		redirect("added")

	case "rename":
		nm := cleanName(r.PostForm.Get("name"))
		if nm == "" {
			page(http.StatusBadRequest, "Give the passkey a name.")
			return
		}
		if err := st.RenamePasskey(ctx, rl.Name, u.ID, r.PostForm.Get("cred"), nm); err != nil {
			if errors.Is(err, idp.ErrNotFound) {
				page(http.StatusNotFound, "Passkey not found.")
				return
			}
			p.cfg.Logger.Error("oidc: rename passkey", "err", err)
			p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
			return
		}
		redirect("renamed")

	case "delete":
		if !needRecent() {
			return
		}
		required, err := st.RealmRequiresPasskeys(ctx, rl.Name)
		if err != nil {
			p.cfg.Logger.Error("oidc: passkey policy", "err", err)
			p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
			return
		}
		credID := r.PostForm.Get("cred")
		switch err := st.DeletePasskey(ctx, rl.Name, u.ID, credID, required); {
		case errors.Is(err, idp.ErrNotFound):
			page(http.StatusNotFound, "Passkey not found.")
		case errors.Is(err, idp.ErrConflict):
			page(http.StatusConflict, "This realm requires passkeys: you cannot remove your last one.")
		case err != nil:
			p.cfg.Logger.Error("oidc: delete passkey", "err", err)
			p.errorPage(w, http.StatusInternalServerError, "Temporary error. Try again.")
		default:
			p.event(ctx, rl, "PASSKEY_REMOVED", u.ID, "", ip, "credential "+pkShort(credID))
			redirect("removed")
		}

	default:
		page(http.StatusBadRequest, "Unknown action.")
	}
}

var pkAcctTmpl = template.Must(template.New("pkacct").Parse(withTheme(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Passkeys</title>
<!--theme--></head><body><main class="wide">
<!--hero:fingerprint-->
<h1>Passkeys for {{.Username}}</h1>
<p class="sub">Realm {{.Realm}}. A passkey lets you sign in without a password, or confirm a password sign-in.</p>
{{if .Msg}}<p class="ok" role="status">{{.Msg}}</p>{{end}}
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
{{if .Required}}<p class="sub">This realm requires passkeys: your last passkey cannot be removed.</p>{{end}}
<ul>{{range .Creds}}<li><strong>{{.Name}}</strong><br>
<span class="sub">Added {{.Created}}, last used {{.LastUsed}}{{if .Eligible}}, {{if .BackedUp}}backed up (synced){{else}}can be backed up, not yet{{end}}{{else}}, device-bound{{end}}</span>
<form class="row" method="post" action="{{$.Action}}"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="pk_action" value="rename"><input type="hidden" name="cred" value="{{.ID}}">
<input name="name" value="{{.Name}}" maxlength="64" aria-label="Name"><button type="submit">Rename</button></form>
<form class="row" method="post" action="{{$.Action}}"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="pk_action" value="delete"><input type="hidden" name="cred" value="{{.ID}}">
<button type="submit">Remove</button></form></li>{{else}}<li class="sub">No passkeys yet.</li>{{end}}</ul>
{{if .Recent}}{{if .Opts}}<h2>Add a passkey</h2>
<form method="post" action="{{.Action}}" data-pk="create" data-opts="{{.Opts}}" hidden>
<input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="pk_action" value="add"><input type="hidden" name="pk_token" value="{{.Token}}">
<input type="hidden" name="pk_cd"><input type="hidden" name="pk_att"><input type="hidden" name="pk_tr">
<div class="row"><input name="name" placeholder="Name, e.g. Work laptop" maxlength="64" aria-label="Name for the new passkey"><button type="button">Add passkey</button></div>
<p class="err pk-err" role="alert" hidden></p></form>
<p class="err pk-no" role="alert" hidden>This browser does not support passkeys.</p>
<script nonce="{{.Nonce}}">{{.Script}}</script>{{end}}
{{else}}<h2>Confirm your password</h2>
<p class="sub">Your sign-in is older than 10 minutes. Confirm your password to add or remove passkeys.</p>
<form class="row" method="post" action="{{.Action}}"><input type="hidden" name="csrf" value="{{.CSRF}}"><input type="hidden" name="pk_action" value="reauth">
<input name="password" type="password" autocomplete="current-password" required maxlength="1024" aria-label="Password"><button type="submit">Confirm</button></form>{{end}}
</main></body></html>`)))
