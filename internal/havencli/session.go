// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package havencli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"time"
)

// freshOpts selects what fresh must return.
type freshOpts struct {
	name        string
	wantID      bool
	minValidity time.Duration
	net         netOpts
	// wantIssuer/wantClient, when set, must equal the stored profile (kubeconfig
	// exec stanzas name them explicitly).
	wantIssuer, wantClient string
}

func usable(p *Profile, wantID bool, min time.Duration, now time.Time) bool {
	if wantID {
		return p.IDToken != "" && p.IDExpiry.Sub(now) > min
	}
	return p.AccessToken != "" && (p.AccessExpiry.IsZero() || p.AccessExpiry.Sub(now) > min)
}

func (o freshOpts) check(p *Profile) error {
	if o.wantIssuer != "" && p.Issuer != o.wantIssuer {
		return notLoggedInf("profile %q is logged in to %s, not %s: run `haven login --issuer %s --client-id %s --profile %s`", o.name, p.Issuer, o.wantIssuer, o.wantIssuer, o.wantClient, o.name)
	}
	if o.wantClient != "" && p.ClientID != o.wantClient {
		return notLoggedInf("profile %q is logged in with client %q, not %q: run `haven login` again", o.name, p.ClientID, o.wantClient)
	}
	return nil
}

// fresh returns a profile whose requested token is valid for at least
// minValidity, refreshing it if needed. Refresh-token rotation makes the
// refresh single-use, so it happens under the cross-process lock and the
// profile is re-read after taking it: a concurrent caller that refreshed
// first leaves us a fresh token and we do not refresh again.
func (a *app) fresh(ctx context.Context, o freshOpts) (*Profile, error) {
	st, err := a.store()
	if err != nil {
		return nil, err
	}
	p, err := st.profile(o.name)
	if err != nil {
		return nil, err
	}
	if err := o.check(p); err != nil {
		return nil, err
	}
	if usable(p, o.wantID, o.minValidity, a.env.Now()) {
		return p, nil
	}
	var out *Profile
	err = st.withLock(ctx, func() error {
		f, err := st.load()
		if err != nil {
			return err
		}
		cur := f.Profiles[o.name]
		if cur == nil {
			return notLoggedInf("not logged in (profile %q): run `haven login --issuer URL --client-id ID`", o.name)
		}
		if err := o.check(cur); err != nil {
			return err
		}
		if usable(cur, o.wantID, o.minValidity, a.env.Now()) {
			c := *cur
			out = &c
			return nil
		}
		np, err := a.refresh(ctx, o, cur)
		if err != nil {
			var dead *notLoggedInError
			if errors.As(err, &dead) {
				delete(f.Profiles, o.name) // the refresh token is dead: drop the credentials
				if serr := st.save(f); serr != nil {
					return serr
				}
			}
			return err
		}
		f.Profiles[o.name] = np
		if err := st.save(f); err != nil {
			return fmt.Errorf("saving refreshed credentials: %w", err)
		}
		out = np
		return nil
	})
	return out, err
}

// refresh performs the refresh_token grant for p (caller holds the lock).
func (a *app) refresh(ctx context.Context, o freshOpts, p *Profile) (*Profile, error) {
	now := a.env.Now()
	if p.RefreshToken == "" {
		if !p.AccessExpiry.IsZero() && now.After(p.AccessExpiry) || o.wantID {
			return nil, notLoggedInf("the session has expired and there is no refresh token: run `haven login --issuer %s --client-id %s --profile %s`", p.Issuer, p.ClientID, o.name)
		}
		c := *p
		return &c, nil // still valid, just closer to expiry than asked
	}
	no := o.net
	if no.CAFile == "" {
		no.CAFile = p.CAFile
	}
	cl, err := newOIDC(p.Issuer, no, a.env.Stderr)
	if err != nil {
		return nil, err
	}
	d, err := cl.discover(ctx)
	if err != nil {
		return nil, err
	}
	if d.TokenEndpoint == "" {
		return nil, errors.New("the issuer does not advertise a token_endpoint")
	}
	tr, err := cl.tokenRequest(ctx, d.TokenEndpoint, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {p.RefreshToken}, "client_id": {p.ClientID}})
	if err != nil {
		var te *tokenError
		if errors.As(err, &te) && te.Code == "invalid_grant" {
			return nil, notLoggedInf("the session expired or was revoked (refresh token rejected): run `haven login --issuer %s --client-id %s --profile %s`", p.Issuer, p.ClientID, o.name)
		}
		return nil, fmt.Errorf("refreshing the token: %w", err)
	}
	np := *p
	np.AccessToken = tr.AccessToken
	np.AccessExpiry = time.Time{}
	if tr.ExpiresIn > 0 {
		np.AccessExpiry = now.Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	if tr.RefreshToken != "" { // rotation: the old one is now invalid
		np.RefreshToken = tr.RefreshToken
	}
	if tr.IDToken != "" {
		res, err := cl.checkIDToken(ctx, d, tr.IDToken, p.ClientID, now)
		if err != nil {
			return nil, fmt.Errorf("rejecting the refreshed ID token: %w", err)
		}
		np.IDToken, np.IDExpiry = tr.IDToken, claimTime(res.Claims, "exp")
	}
	np.UpdatedAt = now
	if o.wantID && !usable(&np, true, 0, now) {
		return nil, errors.New("the server returned no usable ID token on refresh (is the openid scope granted?)")
	}
	return &np, nil
}

func (a *app) cmdToken(ctx context.Context, args []string) error {
	fs := newFlags("token")
	var c common
	c.bind(fs)
	idTok := fs.Bool("id-token", false, "print the ID token instead of the access token")
	minV := fs.Duration("min-validity", 60*time.Second, "refresh when the token expires within this duration")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := validProfileName(c.profile); err != nil {
		return err
	}
	p, err := a.fresh(ctx, freshOpts{name: c.profile, wantID: *idTok, minValidity: *minV, net: c.net})
	if err != nil {
		return err
	}
	tok := p.AccessToken
	if *idTok {
		tok = p.IDToken
	}
	_, _ = fmt.Fprintln(a.env.Stdout, tok)
	return nil
}

type execCredential struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Status     struct {
		Token               string `json:"token"`
		ExpirationTimestamp string `json:"expirationTimestamp"`
	} `json:"status"`
}

// cmdExecCredential is the kubectl client-go exec plugin. It never prompts:
// kubectl captures stdout, so when there is no session it fails with exit 3.
func (a *app) cmdExecCredential(ctx context.Context, args []string) error {
	fs := newFlags("exec-credential")
	var c common
	c.bind(fs)
	issuer := fs.String("issuer", "", "issuer URL the profile must be logged in to (required)")
	clientID := fs.String("client-id", "", "client_id the profile must have been logged in with (required)")
	minV := fs.Duration("min-validity", 60*time.Second, "refresh when the ID token expires within this duration")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *issuer == "" || *clientID == "" {
		return usageErrorf("exec-credential needs --issuer and --client-id")
	}
	if err := validProfileName(c.profile); err != nil {
		return err
	}
	p, err := a.fresh(ctx, freshOpts{name: c.profile, wantID: true, minValidity: *minV, net: c.net, wantIssuer: *issuer, wantClient: *clientID})
	if err != nil {
		return err
	}
	var ec execCredential
	ec.APIVersion, ec.Kind = "client.authentication.k8s.io/v1", "ExecCredential"
	ec.Status.Token = p.IDToken
	ec.Status.ExpirationTimestamp = p.IDExpiry.UTC().Format(time.RFC3339)
	b, err := json.Marshal(ec)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(a.env.Stdout, "%s\n", b)
	return nil
}

func (a *app) cmdWhoami(ctx context.Context, args []string) error {
	fs := newFlags("whoami")
	var c common
	c.bind(fs)
	asJSON := fs.Bool("json", false, "machine readable output")
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := validProfileName(c.profile); err != nil {
		return err
	}
	p, err := a.fresh(ctx, freshOpts{name: c.profile, minValidity: 30 * time.Second, net: c.net})
	if err != nil {
		return err
	}
	no := c.net
	if no.CAFile == "" {
		no.CAFile = p.CAFile
	}
	cl, err := newOIDC(p.Issuer, no, a.env.Stderr)
	if err != nil {
		return err
	}
	d, err := cl.discover(ctx)
	if err != nil {
		return err
	}
	rep := map[string]any{
		"profile": c.profile, "issuer": p.Issuer, "client_id": p.ClientID,
	}
	if !p.AccessExpiry.IsZero() {
		rep["access_token_expires_at"] = p.AccessExpiry.UTC().Format(time.RFC3339)
	}
	var idClaims map[string]any
	if p.IDToken != "" {
		// Zero time: an expired ID token is still worth displaying.
		res, err := cl.checkIDToken(ctx, d, p.IDToken, p.ClientID, time.Time{})
		if err != nil {
			rep["id_token_error"] = err.Error()
			_, idClaims, _ = decodeClaims(p.IDToken)
			rep["id_token_signature_verified"] = false
		} else {
			idClaims = res.Claims
			rep["id_token_signature_verified"] = res.Verified
			if res.Verified {
				rep["id_token_signature_alg"] = res.Alg
			} else {
				rep["id_token_signature_note"] = res.Note
			}
		}
		rep["id_token_claims"] = idClaims
		if !p.IDExpiry.IsZero() {
			rep["id_token_expires_at"] = p.IDExpiry.UTC().Format(time.RFC3339)
		}
	}
	ui, uerr := cl.userinfo(ctx, d.UserinfoEndpoint, p.AccessToken)
	if uerr != nil {
		rep["userinfo_error"] = uerr.Error()
	} else {
		rep["userinfo"] = ui
		if s, ok := ui["sub"].(string); ok && idClaims != nil && s != claimStr(idClaims, "sub") {
			rep["userinfo_error"] = "userinfo sub does not match the ID token sub"
		}
	}
	out := a.env.Stdout
	if *asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}
	_, _ = fmt.Fprintf(out, "Profile:  %s\nIssuer:   %s\nClient:   %s\n", c.profile, p.Issuer, p.ClientID)
	if who := identity(idClaims); who != "" {
		_, _ = fmt.Fprintf(out, "Identity: %s\n", who)
	}
	if t, ok := rep["access_token_expires_at"]; ok {
		_, _ = fmt.Fprintf(out, "Access token expires: %v\n", t)
	}
	if p.IDToken != "" {
		verified, _ := rep["id_token_signature_verified"].(bool)
		switch {
		case verified:
			_, _ = fmt.Fprintf(out, "ID token signature: verified against the issuer's JWKS (%v)\n", rep["id_token_signature_alg"])
		default:
			n1, _ := rep["id_token_signature_note"].(string)
			e1, _ := rep["id_token_error"].(string)
			reason := n1 + e1
			_, _ = fmt.Fprintf(out, "ID token signature: NOT verified (%s); the claims below are decoded, not trusted\n", clean(reason, 200))
		}
		_, _ = fmt.Fprintln(out, "\nID token claims:")
		printClaims(out, idClaims)
	}
	_, _ = fmt.Fprintln(out)
	if uerr != nil {
		_, _ = fmt.Fprintf(out, "Userinfo: failed: %s\n", clean(uerr.Error(), 200))
	} else {
		_, _ = fmt.Fprintln(out, "Userinfo:")
		printClaims(out, ui)
		if e, ok := rep["userinfo_error"]; ok {
			_, _ = fmt.Fprintf(out, "  warning: %v\n", e)
		}
	}
	return nil
}

type writer interface{ Write([]byte) (int, error) }

func printClaims(w writer, m map[string]any) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		var v string
		switch x := m[k].(type) {
		case string:
			v = x
		default:
			b, _ := json.Marshal(x)
			v = string(b)
		}
		_, _ = fmt.Fprintf(w, "  %-20s %s\n", clean(k, 40), clean(v, 200))
	}
}

func (a *app) cmdLogout(ctx context.Context, args []string) error {
	fs := newFlags("logout")
	var c common
	c.bind(fs)
	if err := parse(fs, args); err != nil {
		return err
	}
	if err := validProfileName(c.profile); err != nil {
		return err
	}
	st, err := a.store()
	if err != nil {
		return err
	}
	p, err := st.profile(c.profile)
	if err != nil {
		var ne *notLoggedInError
		if errors.As(err, &ne) {
			_, _ = fmt.Fprintf(a.env.Stdout, "Profile %q is not logged in; nothing to do.\n", c.profile)
			return nil
		}
		return err
	}
	// Best effort remote revocation; local deletion always happens.
	revoked := false
	if err := a.revokeRemote(ctx, c.net, p); err != nil {
		_, _ = fmt.Fprintf(a.env.Stderr, "haven: warning: could not revoke at the server (%s); deleting local credentials anyway\n", clean(err.Error(), 200))
	} else {
		revoked = true
	}
	if err := st.update(ctx, func(f *credsFile) error { delete(f.Profiles, c.profile); return nil }); err != nil {
		return err
	}
	if revoked {
		_, _ = fmt.Fprintf(a.env.Stdout, "Logged out of profile %q: token revoked and local credentials deleted.\n", c.profile)
	} else {
		_, _ = fmt.Fprintf(a.env.Stdout, "Logged out of profile %q: local credentials deleted (server revocation did not succeed).\n", c.profile)
	}
	return nil
}

func (a *app) revokeRemote(ctx context.Context, n netOpts, p *Profile) error {
	tok, hint := p.RefreshToken, "refresh_token"
	if tok == "" {
		tok, hint = p.AccessToken, "access_token"
	}
	if tok == "" {
		return errors.New("no token to revoke")
	}
	if n.CAFile == "" {
		n.CAFile = p.CAFile
	}
	cl, err := newOIDC(p.Issuer, n, a.env.Stderr)
	if err != nil {
		return err
	}
	d, err := cl.discover(ctx)
	if err != nil {
		return err
	}
	if d.RevocationEndpoint == "" {
		return errors.New("the issuer advertises no revocation_endpoint")
	}
	return cl.revoke(ctx, d.RevocationEndpoint, p.ClientID, tok, hint)
}
