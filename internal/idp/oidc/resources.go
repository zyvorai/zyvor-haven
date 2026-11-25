// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"unicode"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Resource indicators (RFC 8707) for MCP and other resource servers. See
// docs/mcp-resource-indicators.md.
//
// A client may send `resource` (repeated) on the authorization request, the
// token request (code, refresh, device, client_credentials) and the device
// authorization request. Every value must be a canonical https resource
// identifier on the allow-list of the client (ResourceAllowList), or the
// request fails with invalid_target. The granted set is carried inside the
// authorization code, device code and refresh token strings themselves
// ("<random>~<base64url resources>", plus "~<context>" for the authentication
// context of authn.go): only the sha256 of the whole string is
// stored, so the set cannot be altered without invalidating the token, and no
// schema change is needed. The access token's `aud` becomes
// [client_id, resource...]; the client id stays so userinfo and introspection
// keep working, the resource server checks that ITS identifier is in `aud`.

const (
	maxResources   = 5   // per request / per grant
	maxResourceLen = 256 // bytes of one identifier
	resSep         = "~" // splits the random part from the encoded resources
	// maxTokenLen bounds device codes (random part + 5 encoded resources fit).
	maxTokenLen = 2048
)

// ResourceAllowList names the resource identifiers a client may ask for. A nil
// or empty answer means "no resource may be requested" (fail closed).
// Implementations must return canonical identifiers (see CanonicalResource);
// entries that are not are ignored.
type ResourceAllowList interface {
	AllowedResources(realm, clientID string) []string
}

// ResourcePolicy is the static, file-backed ResourceAllowList. A client that
// has its own entry uses exactly that list (it REPLACES the realm default; an
// empty list means none); other clients use the realm's `resources`.
type ResourcePolicy struct {
	Realms map[string]RealmResources `json:"realms"`
}

// RealmResources is one realm's part of a ResourcePolicy.
type RealmResources struct {
	Resources []string            `json:"resources,omitempty"`
	Clients   map[string][]string `json:"clients,omitempty"`
}

// AllowedResources implements ResourceAllowList. Safe on a nil policy.
func (rp *ResourcePolicy) AllowedResources(realm, clientID string) []string {
	if rp == nil {
		return nil
	}
	rr, ok := rp.Realms[realm]
	if !ok {
		return nil
	}
	if l, ok := rr.Clients[clientID]; ok {
		return l
	}
	return rr.Resources
}

// LoadResourcePolicy reads and validates a policy file. An empty path returns
// (nil, nil): the feature stays off. Unknown fields and invalid or
// non-canonical identifiers are errors, so a typo cannot silently widen or
// drop access. Identifiers are stored in canonical form.
func LoadResourcePolicy(path string) (*ResourcePolicy, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path) // #nosec G304 -- operator-supplied config path
	if err != nil {
		return nil, fmt.Errorf("resources file: %w", err)
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	if err != nil || len(b) > 1<<20 {
		return nil, errors.New("resources file: unreadable or larger than 1 MiB")
	}
	return ParseResourcePolicy(b)
}

// ParseResourcePolicy is LoadResourcePolicy for bytes.
func ParseResourcePolicy(b []byte) (*ResourcePolicy, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var rp ResourcePolicy
	if err := dec.Decode(&rp); err != nil {
		return nil, fmt.Errorf("resources file: %w", err)
	}
	if dec.More() {
		return nil, errors.New("resources file: trailing data")
	}
	canonAll := func(where string, in []string) ([]string, error) {
		var out []string
		for _, s := range in {
			c, err := CanonicalResource(s)
			if err != nil {
				return nil, fmt.Errorf("resources file: %s: %q: %w", where, s, err)
			}
			if !slices.Contains(out, c) {
				out = append(out, c)
			}
		}
		return out, nil
	}
	for rn, rr := range rp.Realms {
		l, err := canonAll("realm "+rn, rr.Resources)
		if err != nil {
			return nil, err
		}
		rr.Resources = l
		for cn, cl := range rr.Clients {
			l, err := canonAll("realm "+rn+" client "+cn, cl)
			if err != nil {
				return nil, err
			}
			rr.Clients[cn] = l
		}
		rp.Realms[rn] = rr
	}
	return &rp, nil
}

// CanonicalResource validates a resource identifier (RFC 8707 section 2, as
// profiled by the MCP authorization spec) and returns its canonical form: an
// absolute https URI with lower-case scheme and host, no default port, no
// userinfo, no query, no fragment, no dot segments. The path is kept as is
// (a trailing slash is significant and is not stripped).
func CanonicalResource(raw string) (string, error) {
	if raw == "" || len(raw) > maxResourceLen {
		return "", errors.New("empty or too long")
	}
	for _, r := range raw {
		if r > unicode.MaxASCII || unicode.IsSpace(r) || unicode.IsControl(r) {
			return "", errors.New("must be printable ASCII without spaces")
		}
	}
	if strings.ContainsAny(raw, "#?") {
		return "", errors.New("fragment and query are not allowed")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" {
		return "", errors.New("not an absolute URI")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return "", errors.New("scheme must be https")
	}
	if u.User != nil || u.Hostname() == "" {
		return "", errors.New("needs a host and no userinfo")
	}
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" && port != "443" {
		host += ":" + port
	}
	path := u.EscapedPath()
	for _, seg := range strings.Split(path, "/") {
		if seg == "." || seg == ".." {
			return "", errors.New("dot segments are not allowed")
		}
	}
	return "https://" + host + path, nil
}

// parseResources canonicalises requested identifiers (deduplicated, in order).
func parseResources(in []string) ([]string, error) {
	if len(in) > maxResources {
		return nil, fmt.Errorf("at most %d resources", maxResources)
	}
	var out []string
	for _, s := range in {
		c, err := CanonicalResource(s)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out, nil
}

// allowedResources is the canonical allow-list of a client (nil = none).
func (p *Provider) allowedResources(realm, clientID string) []string {
	if p.cfg.Resources == nil {
		return nil
	}
	var out []string
	for _, s := range p.cfg.Resources.AllowedResources(realm, clientID) {
		if c, err := CanonicalResource(s); err == nil && !slices.Contains(out, c) {
			out = append(out, c)
		}
	}
	return out
}

// authzResources validates the resource parameters of an authorization or
// device authorization request against the client's allow-list.
func (p *Provider) authzResources(realm, clientID string, in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	req, err := parseResources(in)
	if err != nil {
		return nil, err
	}
	allowed := p.allowedResources(realm, clientID)
	for _, s := range req {
		if !slices.Contains(allowed, s) {
			return nil, errors.New("resource is not allowed for this client")
		}
	}
	return req, nil
}

// encodeResources is the token suffix carrying a granted set ("" for none).
func encodeResources(res []string) string {
	if len(res) == 0 {
		return ""
	}
	return resSep + base64.RawURLEncoding.EncodeToString([]byte(strings.Join(res, "\n")))
}

// decodeResources reads the set back out of a code or refresh token string the
// store already recognised. ok is false for a malformed suffix.
func decodeResources(tok string) (res []string, ok bool) {
	parts := strings.Split(tok, resSep)
	if len(parts) == 1 {
		return nil, true
	}
	// A third segment is the authentication context (authn.go); only then may
	// the resource segment be empty.
	if len(parts) > 3 {
		return nil, false
	}
	enc := parts[1]
	if enc == "" && len(parts) == 3 {
		return nil, true
	}
	b, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return nil, false
	}
	res, err = parseResources(strings.Split(string(b), "\n"))
	if err != nil || len(res) == 0 {
		return nil, false
	}
	return res, true
}

type resCtxKey struct{}

// resGrant is what issue() needs: aud for the access token, granted for the
// refresh token (the full set even when this access token is narrower).
type resGrant struct{ aud, granted []string }

func withResources(r *http.Request, aud, granted []string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), resCtxKey{}, resGrant{aud, granted}))
}

func resourcesOf(ctx context.Context) resGrant {
	g, _ := ctx.Value(resCtxKey{}).(resGrant)
	return g
}

// audClaim is the access token `aud`: the client id alone, or the client id
// followed by the resources.
func audClaim(clientID string, res []string) any {
	if len(res) == 0 {
		return clientID
	}
	return append([]string{clientID}, res...)
}

// resolveResources applies the token request's `resource` values. With
// fromPolicy (client_credentials) they must be on the client's allow-list; no
// resource means a plain token. Otherwise `granted` is what the authorization
// carried: requests may only narrow it (RFC 8707 section 2.2), entries that
// left the allow-list since are dropped, and a grant whose resources are all
// gone fails with invalid_target. aud is the audience for this access token,
// kept the set the (rotated) refresh token carries on.
func (p *Provider) resolveResources(r *http.Request, rl core.Realm, cl core.Client, granted []string, fromPolicy bool) (aud, kept []string, terr *tokenErr) {
	req, err := parseResources(r.PostForm["resource"])
	if err != nil {
		return nil, nil, oerr("invalid_target", "invalid resource: "+err.Error())
	}
	allowed := p.allowedResources(rl.Name, cl.ClientID)
	if fromPolicy {
		for _, s := range req {
			if !slices.Contains(allowed, s) {
				return nil, nil, oerr("invalid_target", "resource is not allowed for this client")
			}
		}
		return req, nil, nil
	}
	src := slices.DeleteFunc(slices.Clone(granted), func(s string) bool { return !slices.Contains(allowed, s) })
	if len(granted) > 0 && len(src) == 0 {
		return nil, nil, oerr("invalid_target", "the granted resources are no longer allowed")
	}
	if len(req) == 0 {
		return src, src, nil
	}
	for _, s := range req {
		if !slices.Contains(src, s) {
			return nil, nil, oerr("invalid_target", "resource exceeds the original grant")
		}
	}
	return req, src, nil
}

func init() {
	// RFC 8414 section 3.1 "path insertion" aliases of the discovery document.
	// MCP clients try these before the OIDC path-appending URL (which keeps
	// working). They are only reachable when the host routes the two
	// /.well-known prefixes to this handler (haven-idp serve does).
	registerFeature(func(p *Provider, mux *http.ServeMux) {
		mux.HandleFunc("GET /.well-known/oauth-authorization-server/realms/{realm}", p.discovery)
		mux.HandleFunc("GET /.well-known/openid-configuration/realms/{realm}", p.discovery)
	})
}
