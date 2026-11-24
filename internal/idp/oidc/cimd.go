// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/safehttp"
)

// OAuth Client ID Metadata Documents (draft-ietf-oauth-client-id-metadata-
// document): a client_id that is an https URL names a JSON document the
// authorization server fetches. Off by default per realm. The document is
// untrusted input: it only ever yields a PUBLIC, PKCE-only, authorization-code
// client, and such a client always goes through the consent screen (consent.go).
//
// The client is materialised as an ordinary core.Client row (so the token
// endpoint needs no change) and a core.ConsentClient side record that marks it
// as CIMD and holds the cache expiry.

const (
	cimdMaxURL       = 2048
	cimdMaxBody      = 16 << 10
	cimdTimeout      = 4 * time.Second
	cimdMinTTL       = 5 * time.Minute
	cimdDefaultTTL   = time.Hour
	cimdMaxTTL       = 24 * time.Hour
	cimdMaxRedirects = 10
	cimdMaxName      = 100
	cimdIPLimit      = 20 // fetches per IP and window
	cimdRealmLimit   = 120
	cimdWindow       = time.Minute
)

// ErrCIMD is the reason a metadata document or its URL was refused. Messages
// are fixed strings (never document content) and only reach the log.
var ErrCIMD = errors.New("oidc: client metadata document refused")

func cimdErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrCIMD, fmt.Sprintf(format, a...))
}

// cimdState holds the per-Provider fetch client. It lives in a side table so
// Provider needs no new field; tests install their own with setCIMDHTTP.
type cimdState struct {
	once         sync.Once
	http         *safehttp.Client
	allowPrivate bool
}

var cimdStates sync.Map // *Provider -> *cimdState

func (p *Provider) cimd() *cimdState {
	v, _ := cimdStates.LoadOrStore(p, &cimdState{})
	st := v.(*cimdState)
	st.once.Do(func() {
		if st.http != nil {
			return
		}
		ap := p.cfg.Federation != nil && p.cfg.Federation.AllowPrivate()
		st.allowPrivate = ap
		st.http = safehttp.New(safehttp.Options{AllowPrivate: ap, MaxBody: cimdMaxBody, Timeout: cimdTimeout})
	})
	return st
}

// isCIMDClientID reports whether a client_id has the shape of a metadata
// document URL: https (http only to loopback in dev), a host, a real path, no
// userinfo, fragment or dot segments.
func isCIMDClientID(id string, allowPrivate bool) bool {
	return validateCIMDURL(id, allowPrivate) == nil
}

func validateCIMDURL(id string, allowPrivate bool) error {
	if !strings.HasPrefix(id, "https://") && !strings.HasPrefix(id, "http://") {
		return cimdErr("not a URL")
	}
	u, err := safehttp.ValidateURL(id, allowPrivate, "client_id", cimdMaxURL)
	if err != nil {
		return cimdErr("%v", err)
	}
	if len(u.Path) < 2 || !strings.HasPrefix(u.Path, "/") {
		return cimdErr("client_id needs a path component")
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == "." || seg == ".." {
			return cimdErr("dot segments in client_id")
		}
	}
	if strings.Contains(id, "\\") || strings.Contains(u.EscapedPath(), "%2e") || strings.Contains(u.EscapedPath(), "%2E") {
		return cimdErr("ambiguous path in client_id")
	}
	return nil
}

// cimdDoc is the validated subset of a metadata document.
type cimdDoc struct {
	Name         string
	ClientURI    string
	RedirectURIs []string
}

// forbiddenCIMD are members a metadata document must not carry: they are
// registration-response or secret-bearing members.
var forbiddenCIMD = []string{"client_secret", "client_secret_expires_at", "registration_access_token", "registration_client_uri", "client_id_issued_at"}

var cimdURLRE = regexp.MustCompile(`^[\x21-\x7e]+$`)

// parseCIMD validates a fetched document for the client_id URL. Every check
// fails closed; unknown members are ignored.
func parseCIMD(clientID string, body []byte, allowPrivate bool) (cimdDoc, error) {
	var raw map[string]json.RawMessage
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&raw); err != nil || raw == nil || dec.More() {
		return cimdDoc{}, cimdErr("not a single JSON object")
	}
	for _, k := range forbiddenCIMD {
		if _, has := raw[k]; has {
			return cimdDoc{}, cimdErr("document carries %s", k)
		}
	}
	str := func(k string) (string, bool, error) {
		v, has := raw[k]
		if !has {
			return "", false, nil
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return "", true, cimdErr("%s is not a string", k)
		}
		return s, true, nil
	}
	list := func(k string) ([]string, bool, error) {
		v, has := raw[k]
		if !has {
			return nil, false, nil
		}
		var l []string
		if err := json.Unmarshal(v, &l); err != nil {
			return nil, true, cimdErr("%s is not a string array", k)
		}
		return l, true, nil
	}
	id, has, err := str("client_id")
	if err != nil {
		return cimdDoc{}, err
	}
	if !has || id != clientID { // exact string equality, no normalisation
		return cimdDoc{}, cimdErr("client_id does not equal the document URL")
	}
	if m, has, err := str("token_endpoint_auth_method"); err != nil {
		return cimdDoc{}, err
	} else if has && m != "none" {
		return cimdDoc{}, cimdErr("only token_endpoint_auth_method none is allowed")
	}
	if gts, has, err := list("grant_types"); err != nil {
		return cimdDoc{}, err
	} else if has {
		for _, g := range gts {
			if g != "authorization_code" && g != "refresh_token" {
				return cimdDoc{}, cimdErr("grant type %q is not allowed", g)
			}
		}
	}
	if rts, has, err := list("response_types"); err != nil {
		return cimdDoc{}, err
	} else if has && (len(rts) != 1 || rts[0] != "code") {
		return cimdDoc{}, cimdErr("response_types must be [code]")
	}
	uris, has, err := list("redirect_uris")
	if err != nil {
		return cimdDoc{}, err
	}
	if !has || len(uris) == 0 || len(uris) > cimdMaxRedirects {
		return cimdDoc{}, cimdErr("redirect_uris must hold 1-%d entries", cimdMaxRedirects)
	}
	seen := map[string]bool{}
	for _, ru := range uris {
		if !validCIMDRedirect(ru, allowPrivate) {
			return cimdDoc{}, cimdErr("invalid redirect_uri")
		}
		if seen[ru] {
			return cimdDoc{}, cimdErr("duplicate redirect_uri")
		}
		seen[ru] = true
	}
	d := cimdDoc{RedirectURIs: uris}
	name, _, err := str("client_name")
	if err != nil {
		return cimdDoc{}, err
	}
	d.Name = cleanDisplay(name, cimdMaxName)
	if cu, has, err := str("client_uri"); err != nil {
		return cimdDoc{}, err
	} else if has {
		if _, err := safehttp.ValidateURL(cu, allowPrivate, "client_uri", 512); err == nil {
			d.ClientURI = cu // shown as text only; an invalid one is dropped, not fatal
		}
	}
	return d, nil
}

// validCIMDRedirect accepts https, http to a loopback host (native apps, RFC
// 8252) and private-use schemes with a dot (reverse-DNS), nothing else.
func validCIMDRedirect(s string, allowPrivate bool) bool {
	if s == "" || len(s) > 2048 || !cimdURLRE.MatchString(s) || strings.ContainsAny(s, "*#\\") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.User != nil || u.Fragment != "" {
		return false
	}
	switch sch := strings.ToLower(u.Scheme); sch {
	case "https":
		return u.Hostname() != ""
	case "http":
		return safehttp.IsLoopbackHost(u.Hostname())
	case "":
		return false
	default:
		return strings.Contains(sch, ".") && safeRedirect(s)
	}
}

// cleanDisplay trims s to n runes and removes control and bidirectional
// override characters, so a document cannot spoof the consent screen.
func cleanDisplay(s string, n int) string {
	var b strings.Builder
	cnt := 0
	for _, r := range s {
		if unicode.IsControl(r) || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069) || r == 0x200e || r == 0x200f || r == 0xfeff {
			continue
		}
		if cnt++; cnt > n {
			break
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
}

// cacheTTL derives the cache lifetime from Cache-Control, clamped.
func cacheTTL(h http.Header) time.Duration {
	ttl := cimdDefaultTTL
	for _, d := range strings.Split(strings.ToLower(h.Get("Cache-Control")), ",") {
		d = strings.TrimSpace(d)
		switch {
		case d == "no-store" || d == "no-cache":
			return cimdMinTTL
		case strings.HasPrefix(d, "max-age="):
			if n, err := strconv.Atoi(strings.TrimPrefix(d, "max-age=")); err == nil && n >= 0 {
				ttl = time.Duration(n) * time.Second
			}
		}
	}
	return min(max(ttl, cimdMinTTL), cimdMaxTTL)
}

// fetchCIMD GETs the document. No redirects are followed, the destination IP
// is checked at dial time, the body is capped, and only a 200 JSON answer counts.
func (p *Provider) fetchCIMD(ctx context.Context, clientID string) ([]byte, time.Duration, error) {
	st := p.cimd()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientID, nil) // #nosec G704 -- clientID is the CIMD document URL by design; the client refuses non-public destinations at dial time and follows no redirects
	if err != nil {
		return nil, 0, cimdErr("bad request")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "haven-idp-cimd")
	resp, err := st.http.HTTP.Do(req) // #nosec G704 -- see NewRequestWithContext above: dial-time destination guard, no redirects, capped body
	if err != nil {
		if safehttp.IsBlocked(err) {
			return nil, 0, cimdErr("destination not allowed")
		}
		return nil, 0, cimdErr("fetch failed")
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, 0, cimdErr("status %d", resp.StatusCode) // includes refused redirects (3xx)
	}
	if ct := strings.ToLower(resp.Header.Get("Content-Type")); !strings.Contains(ct, "json") {
		return nil, 0, cimdErr("content type is not JSON")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cimdMaxBody+1))
	if err != nil {
		return nil, 0, cimdErr("read failed")
	}
	if len(body) > cimdMaxBody {
		return nil, 0, cimdErr("document too large")
	}
	return body, cacheTTL(resp.Header), nil
}

// cimdFetchAllowed spends one fetch from the per-IP and per-realm budgets.
// Cached documents never reach it. A store error denies.
func (p *Provider) cimdFetchAllowed(ctx context.Context, realm, ip string) bool {
	for _, k := range []struct {
		key string
		max int
	}{{"cimd|" + realm + "|" + ip, cimdIPLimit}, {"cimd-realm|" + realm, cimdRealmLimit}} {
		sum := sha256.Sum256([]byte(k.key))
		ok, err := p.cfg.Store.HitRateLimit(ctx, hex.EncodeToString(sum[:]), p.now(), cimdWindow, k.max)
		if err != nil {
			p.cfg.Logger.Error("oidc: cimd rate limit", "err", err)
			return false
		}
		if !ok {
			return false
		}
	}
	return true
}

func (p *Provider) consentPolicy(ctx context.Context, cs core.ConsentStore, realm string) (core.ConsentPolicy, error) {
	pol, err := cs.GetConsentPolicy(ctx, realm)
	if errors.Is(err, idp.ErrNotFound) {
		return core.ConsentPolicy{Realm: realm}, nil
	}
	return pol, err
}

// authorizeClientFor resolves the client of an /auth request. It layers three
// things over authorizeClient: a kill-switched client is refused, and an https
// client_id resolves through its metadata document when the realm opted in.
func (p *Provider) authorizeClientFor(r *http.Request, realm, clientID string) (core.Client, error) {
	ctx := r.Context()
	cs, on := core.StoreAs[core.ConsentStore](p.cfg.Store)
	if !on {
		return p.authorizeClient(ctx, realm, clientID)
	}
	if _, err := cs.GetConsentBlock(ctx, realm, clientID); err == nil {
		return core.Client{}, idp.ErrNotFound // killed: same answer as unknown
	} else if !errors.Is(err, idp.ErrNotFound) {
		return core.Client{}, err
	}
	allowPrivate := p.cimd().allowPrivate
	if len(clientID) > cimdMaxURL || !isCIMDClientID(clientID, allowPrivate) {
		return p.authorizeClient(ctx, realm, clientID)
	}
	cl, err := p.cfg.Store.GetClientByClientID(ctx, realm, clientID)
	if err != nil && !errors.Is(err, idp.ErrNotFound) {
		return core.Client{}, err
	}
	cc, ccErr := cs.GetConsentClient(ctx, realm, clientID)
	if ccErr != nil && !errors.Is(ccErr, idp.ErrNotFound) {
		return core.Client{}, ccErr
	}
	if err == nil && ccErr != nil {
		return cl, nil // an admin-registered client that happens to be named by a URL
	}
	pol, perr := p.consentPolicy(ctx, cs, realm)
	if perr != nil {
		return core.Client{}, perr
	}
	if !pol.CIMDEnabled {
		return core.Client{}, idp.ErrNotFound
	}
	if err == nil && p.now().Before(cc.ExpiresAt) {
		return cl, nil // cached
	}
	return p.refreshCIMD(r, cs, pol, realm, clientID, cl, err == nil)
}

// refreshCIMD fetches the document and creates or updates the client. If it
// cannot be fetched or validated the client is refused (fail closed), even if
// an older copy exists.
func (p *Provider) refreshCIMD(r *http.Request, cs core.ConsentStore, pol core.ConsentPolicy, realm, clientID string, cl core.Client, exists bool) (core.Client, error) {
	ctx := r.Context()
	u, _ := url.Parse(clientID)
	host := strings.ToLower(u.Hostname())
	if len(pol.CIMDHosts) > 0 && !slices.Contains(pol.CIMDHosts, host) {
		p.cfg.Logger.Info("oidc: cimd host not allowed", "realm", realm, "host", host)
		return core.Client{}, idp.ErrNotFound
	}
	if !p.cimdFetchAllowed(ctx, realm, p.clientIP(r)) {
		p.cfg.Logger.Info("oidc: cimd fetch rate limited", "realm", realm)
		return core.Client{}, idp.ErrNotFound
	}
	body, ttl, err := p.fetchCIMD(ctx, clientID)
	if err == nil {
		var d cimdDoc
		if d, err = parseCIMD(clientID, body, p.cimd().allowPrivate); err == nil {
			return p.storeCIMD(ctx, cs, realm, clientID, d, ttl, cl, exists)
		}
	}
	p.cfg.Logger.Info("oidc: cimd refused", "realm", realm, "host", host, "reason", err.Error())
	return core.Client{}, idp.ErrNotFound
}

func (p *Provider) storeCIMD(ctx context.Context, cs core.ConsentStore, realm, clientID string, d cimdDoc, ttl time.Duration, cl core.Client, exists bool) (core.Client, error) {
	name := d.Name
	if name == "" {
		if u, err := url.Parse(clientID); err == nil {
			name = u.Hostname()
		}
	}
	if exists {
		cl.Name, cl.RedirectURIs = name, slices.Clone(d.RedirectURIs)
		// A disabled row stays disabled: only the kill switch / an admin does that.
		cl.Public, cl.AuthCodeFlow, cl.RequirePKCE, cl.SecretHash = true, true, true, ""
		cl.PasswordFlow, cl.ServiceAccount = false, false
		if err := p.cfg.Store.UpdateClient(ctx, cl); err != nil {
			return core.Client{}, err
		}
	} else {
		cl = core.Client{ID: uuid.NewString(), Realm: realm, ClientID: clientID, Name: name, Enabled: true, Public: true,
			AuthCodeFlow: true, RequirePKCE: true, RedirectURIs: slices.Clone(d.RedirectURIs), CreatedAt: p.now().UTC()}
		if err := p.cfg.Store.CreateClient(ctx, cl); err != nil {
			if !errors.Is(err, idp.ErrConflict) {
				return core.Client{}, err
			}
			// Lost a race with another fetch of the same document: use that row.
			got, gerr := p.cfg.Store.GetClientByClientID(ctx, realm, clientID)
			if gerr != nil {
				return core.Client{}, gerr
			}
			cl = got
		}
	}
	now := p.now()
	err := cs.PutConsentClient(ctx, core.ConsentClient{Realm: realm, ClientID: clientID, Source: core.ConsentClientCIMD,
		Name: name, ClientURI: d.ClientURI, RedirectURIs: d.RedirectURIs,
		Fingerprint: core.ClientFingerprint(clientID, name, d.RedirectURIs), FetchedAt: now, ExpiresAt: now.Add(ttl)})
	if err != nil {
		return core.Client{}, err
	}
	return cl, nil
}
