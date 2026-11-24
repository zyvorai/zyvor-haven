// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package havencli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"time"
)

const defaultScope = "openid offline_access profile email"

func (a *app) cmdLogin(ctx context.Context, args []string) error {
	fs := newFlags("login")
	var c common
	c.bind(fs)
	issuer := fs.String("issuer", "", "issuer URL (required)")
	clientID := fs.String("client-id", "", "OAuth client_id of a public client with the device grant enabled (required)")
	scope := fs.String("scope", defaultScope, "space separated scopes")
	noBrowser := fs.Bool("no-browser", false, "do not try to open a browser")
	useKeychain := fs.Bool("keychain", false, "keep the tokens in the macOS Keychain instead of the credentials file")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *issuer == "" || *clientID == "" {
		return usageErrorf("login needs --issuer and --client-id")
	}
	if err := validProfileName(c.profile); err != nil {
		return err
	}
	cl, err := newOIDC(*issuer, c.net, a.env.Stderr)
	if err != nil {
		return err
	}
	st, err := a.store()
	if err != nil {
		return err
	}
	d, err := cl.discover(ctx)
	if err != nil {
		return err
	}
	da, err := cl.deviceAuthorize(ctx, d.DeviceAuthorizationEndpoint, *clientID, *scope)
	if err != nil {
		return err
	}
	if d.TokenEndpoint == "" {
		return errors.New("the issuer does not advertise a token_endpoint")
	}

	out := a.env.Stdout
	fmt.Fprintf(out, "To sign in, open this page in any browser:\n\n    %s\n\nand enter the code:\n\n    %s\n\n", clean(da.VerificationURI, 300), clean(da.UserCode, 64))
	fmt.Fprintf(out, "The code expires in %s.\n", (time.Duration(da.ExpiresIn) * time.Second).Round(time.Second))
	if !*noBrowser && da.VerificationURIComplete != "" && a.env.OpenBrowser != nil {
		if err := a.env.OpenBrowser(da.VerificationURIComplete); err != nil {
			fmt.Fprintln(out, "(could not open a browser here; open the page above by hand)")
		} else {
			fmt.Fprintln(out, "Opening your browser; the code is pre-filled.")
		}
	}
	fmt.Fprintln(out, "Waiting for you to approve the sign-in (Ctrl-C to cancel)...")

	tr, err := a.pollToken(ctx, cl, d.TokenEndpoint, *clientID, da)
	if err != nil {
		return err
	}
	now := a.env.Now()
	p := &Profile{Issuer: cl.issuer.String(), ClientID: *clientID, Scopes: *scope,
		AccessToken: tr.AccessToken, RefreshToken: tr.RefreshToken, UpdatedAt: now}
	if tr.ExpiresIn > 0 {
		p.AccessExpiry = now.Add(time.Duration(tr.ExpiresIn) * time.Second)
	}
	if *useKeychain {
		if a.env.Vault != nil && a.env.Vault.Available() {
			p.Keychain = true
		} else {
			fmt.Fprintln(a.env.Stderr, "haven: warning: --keychain needs macOS; storing the tokens in the 0600 credentials file instead")
		}
	}
	if c.net.CAFile != "" {
		if abs, err := filepath.Abs(c.net.CAFile); err == nil {
			p.CAFile = abs
		}
	}
	var claims map[string]any
	if tr.IDToken != "" {
		res, err := cl.checkIDToken(ctx, d, tr.IDToken, *clientID, now)
		if err != nil {
			return fmt.Errorf("rejecting the sign-in: %w", err)
		}
		if !res.Verified {
			fmt.Fprintf(a.env.Stderr, "haven: warning: ID token signature not verified (%s)\n", res.Note)
		}
		claims = res.Claims
		p.IDToken = tr.IDToken
		p.IDExpiry = claimTime(claims, "exp")
	} else {
		fmt.Fprintln(a.env.Stderr, "haven: warning: the server returned no ID token (is the openid scope allowed?); `haven exec-credential` will not work")
	}
	if tr.RefreshToken == "" {
		fmt.Fprintln(a.env.Stderr, "haven: warning: no refresh token was issued; you will have to log in again when the access token expires")
	}
	if err := st.update(ctx, func(f *credsFile) error { f.Profiles[c.profile] = p; return nil }); err != nil {
		return fmt.Errorf("saving credentials: %w", err)
	}

	who := identity(claims)
	if who == "" {
		who = "(no identity claims in the ID token)"
	}
	fmt.Fprintf(out, "\nLogged in as %s\n", who)
	fmt.Fprintf(out, "Issuer:  %s\nProfile: %s\n", p.Issuer, c.profile)
	if !p.AccessExpiry.IsZero() {
		fmt.Fprintf(out, "Access token valid until %s\n", p.AccessExpiry.Local().Format(time.RFC3339))
	}
	return nil
}

func identity(claims map[string]any) string {
	u, e := clean(claimStr(claims, "preferred_username"), 100), clean(claimStr(claims, "email"), 100)
	switch {
	case u != "" && e != "":
		return u + " <" + e + ">"
	case u != "":
		return u
	case e != "":
		return e
	}
	return clean(claimStr(claims, "sub"), 100)
}

// pollToken implements RFC 8628 section 3.5.
func (a *app) pollToken(ctx context.Context, cl *oidc, endpoint, clientID string, da *deviceAuth) (*tokenResp, error) {
	interval := time.Duration(da.Interval) * time.Second
	deadline := a.env.Now().Add(time.Duration(da.ExpiresIn) * time.Second)
	form := func() url.Values {
		return url.Values{"grant_type": {grantDevice}, "device_code": {da.DeviceCode}, "client_id": {clientID}}
	}
	transient := 0
	for {
		if err := a.env.Sleep(ctx, interval); err != nil {
			return nil, err
		}
		if !a.env.Now().Before(deadline) {
			return nil, errors.New("the code expired before you approved it; run `haven login` again")
		}
		tr, err := cl.tokenRequest(ctx, endpoint, form())
		if err == nil {
			return tr, nil
		}
		var te *tokenError
		if !errors.As(err, &te) {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if transient++; transient > 3 {
				return nil, fmt.Errorf("polling the token endpoint failed: %w", err)
			}
			continue
		}
		transient = 0
		switch te.Code {
		case "authorization_pending":
		case "slow_down":
			interval += 5 * time.Second
		case "access_denied":
			return nil, errors.New("the sign-in was denied")
		case "expired_token":
			return nil, errors.New("the code expired before you approved it; run `haven login` again")
		default:
			return nil, fmt.Errorf("token endpoint refused the login: %s", te)
		}
	}
}
