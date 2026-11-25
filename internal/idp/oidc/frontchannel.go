// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
)

// OIDC Front-Channel Logout 1.0 (docs/sso-and-logout.md). When a browser signs
// out, the sign-out page loads each application's frontchannel_logout_uri in a
// hidden, sandboxed iframe, with iss and sid. Only that one page may frame
// anything, and only the exact origins it needs.

const (
	fcMaxFrames     = 20
	fcRedirectDelay = 5 // seconds the iframes get before the browser moves on
)

func init() {
	registerDiscovery(func(p *Provider, _ string, doc map[string]any) {
		if _, ok := core.StoreAs[core.FrontchannelStore](p.cfg.Store); ok {
			doc["frontchannel_logout_supported"] = true
			doc["frontchannel_logout_session_supported"] = true
		}
	})
}

type fcFrame struct {
	URL string
	// Isolated: the application shares the identity server's origin, so its
	// frame must not get allow-same-origin (it could then reach this page).
	Isolated bool
}

// frontchannelFrames returns the iframes for the applications of an ended
// session and the sorted set of origins they need. Every URI is validated
// again against the client's current redirect URIs.
func (p *Provider) frontchannelFrames(ctx context.Context, realm string, s core.Session) (frames []fcFrame, origins []string) {
	st, ok := core.StoreAs[core.FrontchannelStore](p.cfg.Store)
	if !ok {
		return nil, nil
	}
	self, _ := idp.WebOrigin(p.base)
	seen := map[string]bool{}
	for _, clientID := range s.Clients {
		if seen[clientID] || len(frames) >= fcMaxFrames {
			continue
		}
		seen[clientID] = true
		cl, err := p.cfg.Store.GetClientByClientID(ctx, realm, clientID)
		if err != nil || !cl.Enabled {
			continue
		}
		raw, err := st.FrontchannelLogoutURI(ctx, realm, cl.ID)
		if err != nil {
			p.cfg.Logger.Error("oidc: front-channel logout uri", "err", err)
			continue
		}
		if raw == "" {
			continue
		}
		origin, err := idp.FrontchannelOrigin(raw, cl.RedirectURIs)
		if err != nil {
			p.cfg.Logger.Warn("oidc: front-channel logout uri refused", "realm", realm, "client", clientID, "reason", err.Error())
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		q := u.Query()
		q.Set("iss", p.issuer(realm))
		q.Set("sid", s.ID)
		u.RawQuery = q.Encode()
		frames = append(frames, fcFrame{URL: u.String(), Isolated: origin == self})
		if !slices.Contains(origins, origin) {
			origins = append(origins, origin)
		}
	}
	slices.Sort(origins)
	return frames, origins
}

var fcLogoutTmpl = template.Must(template.New("fclogout").Parse(withTheme(`<!doctype html>
<html<!--loc-->><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.L.T "Signed out"}}</title>
<!--theme--></head><body><main>
<!--hero:door-->
<h1>{{.L.T "Signed out"}}</h1>
<p class="sub">{{.L.T "You have been signed out. Your applications are being told to sign you out too."}}</p>
{{if .Next}}<p class="sub"><a href="{{.Next}}">{{.L.T "Continue to the application"}}</a></p>{{end}}
{{range .Frames}}{{if .Isolated}}<iframe src="{{.URL}}" sandbox="allow-scripts" referrerpolicy="no-referrer" title="{{$.L.T "Application sign-out"}}" hidden></iframe>{{else}}<iframe src="{{.URL}}" sandbox="allow-scripts allow-same-origin" referrerpolicy="no-referrer" title="{{$.L.T "Application sign-out"}}" hidden></iframe>{{end}}
{{end}}</main></body></html>`)))

type fcPageData struct {
	Nonce  string
	Next   template.URL
	Frames []fcFrame
	L      Loc // ui.go
}

// frontchannelLogout writes the sign-out page for a session this browser just
// ended, when at least one of its applications uses front-channel logout. next
// is the already validated post-logout redirect, or "". It reports whether it
// wrote the response.
func (p *Provider) frontchannelLogout(w http.ResponseWriter, r *http.Request, rl core.Realm, s core.Session, next string) bool {
	frames, origins := p.frontchannelFrames(r.Context(), rl.Name, s)
	if len(frames) == 0 {
		return false
	}
	nonce := randToken(16)
	p.pageHeaders(w, nonce)
	l := p.loc(w)
	// The one page that frames anything: frame-src lists exactly the origins of
	// the frames below. Everything else stays as on every page.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+nonce+"'; frame-src "+
		strings.Join(origins, " ")+"; base-uri 'none'; frame-ancestors 'none'")
	if next != "" {
		// A header, not script: the page needs none.
		w.Header().Set("Refresh", strconv.Itoa(fcRedirectDelay)+"; url="+next)
	}
	w.WriteHeader(http.StatusOK)
	// next passed the post_logout_redirect_uri registration check and
	// safeRedirect (no javascript:, data: ...); template.URL keeps the custom
	// schemes of native apps intact.
	_ = fcLogoutTmpl.Execute(w, fcPageData{Nonce: nonce, Next: template.URL(next), Frames: frames, L: l}) // #nosec G203 -- registered and scheme-checked redirect URI, see above
	return true
}
