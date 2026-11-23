// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package kcimport converts a Keycloak realm export into a haven-idp realm
// Spec (config as code), a list of users with their existing password hashes,
// and a Report that names everything that could not be carried over.
//
// The export is read as a token stream: the user list is decoded one user at
// a time, so a very large export is never held in memory as a raw document.
// Nothing secret is copied into the Report or any error: confidential client
// secrets are never read, and password material only ever lands in
// Result.Users.PasswordHash.
package kcimport

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/configcode"
)

// MaxExportBytes is the largest accepted export (streamed).
const MaxExportBytes = 512 << 20

// Options for Convert.
type Options struct {
	// Realm overrides the target realm name; default is the export's realm.
	Realm string
	// TrustEmails marks every imported user's email as verified. Only use it
	// when you trust that the addresses belonged to those users: it asserts
	// ownership the importer cannot check. Off by default.
	TrustEmails bool
}

// Result is the converted export.
type Result struct {
	Spec   *configcode.Spec // realm settings, roles, groups, clients
	Users  []idp.ImportUser // sorted by username; contains password hashes
	Report Report
}

type converter struct {
	w        *collector
	rep      Report
	spec     configcode.Spec
	sourceNm string
	users    []idp.ImportUser
	seenUser map[string]struct{}
	roleSeen map[string]struct{}
	groupSet map[string]struct{}
	notMig   map[string]int
	seenKey  bool
}

// recognized top-level keys; at least one must be present.
var recognized = map[string]bool{
	"realm": true, "users": true, "clients": true, "roles": true, "groups": true,
	"registrationAllowed": true, "identityProviders": true, "authenticationFlows": true,
	"clientScopes": true, "sslRequired": true, "accessTokenLifespan": true,
}

// Convert reads a Keycloak realm export: a realm object, a JSON array holding
// exactly one realm object, or a partial export (users and most other
// sections may be absent). Anything else is rejected.
func Convert(r io.Reader, o Options) (*Result, error) {
	c := &converter{
		w:        newCollector(),
		seenUser: map[string]struct{}{},
		roleSeen: map[string]struct{}{},
		groupSet: map[string]struct{}{},
		notMig:   map[string]int{},
	}
	dec := json.NewDecoder(&capReader{r: r, left: MaxExportBytes})
	t, err := dec.Token()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("invalid Keycloak export: the input is empty")
		}
		return nil, syntaxErr(err)
	}
	d, _ := t.(json.Delim)
	switch d {
	case '{':
		if err := c.object(dec); err != nil {
			return nil, err
		}
	case '[':
		if !dec.More() {
			return nil, errors.New("invalid Keycloak export: the array is empty; expected one realm object")
		}
		if err := expectDelim(dec, '{'); err != nil {
			return nil, errors.New("invalid Keycloak export: the array must contain a realm object")
		}
		if err := c.object(dec); err != nil {
			return nil, err
		}
		if dec.More() {
			return nil, errors.New("invalid Keycloak export: the array holds more than one realm; export one realm at a time")
		}
		if err := expectDelim(dec, ']'); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("invalid Keycloak export: expected a realm object (or an array with one realm)")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("invalid Keycloak export: unexpected data after the realm")
		}
		return nil, syntaxErr(err)
	}
	return c.finish(o)
}

// object parses the realm object; the opening brace is already consumed.
func (c *converter) object(dec *json.Decoder) error {
	st := &c.spec.Settings
	var pol string
	var hasPol bool
	var themes, i18n bool
	setBool := func(dst **bool) error {
		v, err := decodeValue[*bool](dec)
		if err != nil {
			return err
		}
		*dst = v
		return nil
	}
	posInt := func(dst **int) error {
		v, err := decodeValue[*int](dec)
		if err != nil {
			return err
		}
		if v != nil && *v > 0 {
			*dst = v
		}
		return nil
	}
	countArr := func(name string) error {
		v, err := decodeValue[[]json.RawMessage](dec)
		if err != nil {
			return err
		}
		c.notMig[name] += len(v)
		return nil
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return syntaxErr(err)
		}
		key, _ := kt.(string)
		if recognized[key] {
			c.seenKey = true
		}
		switch key {
		case "realm":
			c.sourceNm, err = decodeValue[string](dec)
		case "displayName":
			c.spec.DisplayName, err = decodeValue[string](dec)
		case "enabled":
			err = setBool(&c.spec.Enabled)
		case "registrationAllowed":
			err = setBool(&st.SelfRegistration)
		case "verifyEmail":
			err = setBool(&st.EmailVerificationRequired)
		case "bruteForceProtected":
			err = setBool(&st.BruteForceProtection)
		case "eventsEnabled":
			err = setBool(&st.AuthEvents)
		case "adminEventsEnabled":
			err = setBool(&st.AdminEvents)
		case "revokeRefreshToken":
			err = setBool(&st.RefreshTokenRotation)
		case "sslRequired":
			var s string
			if s, err = decodeValue[string](dec); err == nil {
				switch s {
				case "none", "external", "all":
					st.TransportSecurity = &s
				case "":
				default:
					c.w.add("realm.ssl_required_unknown", "sslRequired", "unknown sslRequired value; transportSecurity left unmanaged")
				}
			}
		case "passwordPolicy":
			pol, err = decodeValue[string](dec)
			hasPol = true
		case "accessTokenLifespan":
			err = posInt(&st.AccessTokenSeconds)
		case "ssoSessionIdleTimeout":
			err = posInt(&st.SessionIdleSeconds)
		case "roles":
			err = c.roles(dec)
		case "groups":
			err = forEach(dec, c.group)
		case "clients":
			err = forEach(dec, c.client)
		case "users":
			err = forEach(dec, c.user)
		case "identityProviders":
			err = countArr("identity_providers")
		case "identityProviderMappers":
			err = countArr("identity_providers")
		case "userFederationProviders", "userFederationMappers":
			err = countArr("user_federation")
		case "components":
			var comp map[string][]struct{}
			if comp, err = decodeValue[map[string][]struct{}](dec); err == nil {
				for k, v := range comp {
					if strings.Contains(k, "UserStorageProvider") {
						c.notMig["user_federation"] += len(v)
					}
				}
			}
		case "authenticationFlows", "authenticatorConfig":
			err = countArr("authentication_flows")
		case "clientScopes":
			err = countArr("client_scopes")
		case "protocolMappers":
			err = countArr("protocol_mappers")
		case "requiredActions":
			err = countArr("required_actions")
		case "eventsListeners", "enabledEventTypes":
			err = countArr("events")
		case "loginTheme", "accountTheme", "adminTheme", "emailTheme":
			var s string
			if s, err = decodeValue[string](dec); s != "" {
				themes = true
			}
		case "internationalizationEnabled":
			var b *bool
			if b, err = decodeValue[*bool](dec); b != nil && *b {
				i18n = true
			}
		default:
			err = skipValue(dec)
		}
		if err != nil {
			return err
		}
	}
	if err := expectDelim(dec, '}'); err != nil {
		return err
	}
	if themes {
		c.notMig["themes"]++
	}
	if i18n {
		c.notMig["internationalization"]++
	}
	if hasPol {
		c.policy(pol)
	}
	return nil
}

// policy keeps only the terms haven-idp enforces.
func (c *converter) policy(pol string) {
	var keep []string
	for _, term := range strings.Split(pol, " and ") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		name, arg := term, ""
		if i := strings.IndexByte(term, '('); i >= 0 && strings.HasSuffix(term, ")") {
			name, arg = term[:i], term[i+1:len(term)-1]
		}
		switch name {
		case "length", "digits", "upperCase", "lowerCase", "specialChars":
			if n := atoiPos(arg); n > 0 {
				keep = append(keep, fmt.Sprintf("%s(%d)", name, n))
				continue
			}
			c.w.add("realm.policy_term_dropped", name, fmt.Sprintf("password policy term %q has an invalid argument and was dropped", safeName(name)))
		default:
			c.w.add("realm.policy_term_dropped", safeName(name), fmt.Sprintf("password policy term %q is not supported by haven-idp and was dropped", safeName(name)))
		}
	}
	if len(keep) > 0 {
		s := strings.Join(keep, " and ")
		c.spec.Settings.PasswordPolicy = &s
	}
}

func atoiPos(s string) int {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 6 {
		return 0
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		n = n*10 + int(r-'0')
	}
	return n
}

// safeName bounds and cleans a name taken from the export before it is shown.
func safeName(s string) string {
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}

type kcRole struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Composite   bool   `json:"composite"`
}

func isBuiltinRole(n string) bool {
	return n == "offline_access" || n == "uma_authorization" || strings.HasPrefix(n, "default-roles-")
}

func (c *converter) roles(dec *json.Decoder) error {
	if err := expectDelim(dec, '{'); err != nil {
		return err
	}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return syntaxErr(err)
		}
		switch kt {
		case "realm":
			err = forEach(dec, c.role)
		case "client":
			var m map[string][]struct{}
			if m, err = decodeValue[map[string][]struct{}](dec); err == nil {
				for _, v := range m {
					c.notMig["client_roles"] += len(v)
				}
			}
		default:
			err = skipValue(dec)
		}
		if err != nil {
			return err
		}
	}
	return expectDelim(dec, '}')
}

func (c *converter) role(r *kcRole) error {
	switch {
	case r.Name == "":
		c.w.add("role.invalid", "", "a realm role without a name was skipped")
	case isBuiltinRole(r.Name):
		c.w.add("role.builtin_skipped", safeName(r.Name), "Keycloak built-in role skipped (haven-idp has its own defaults)")
	case len(r.Name) > 255:
		c.w.add("role.invalid", safeName(r.Name), "role name longer than 255 bytes was skipped")
	default:
		if _, dup := c.roleSeen[r.Name]; dup {
			c.w.add("role.duplicate", safeName(r.Name), "duplicate role skipped")
			return nil
		}
		c.roleSeen[r.Name] = struct{}{}
		c.spec.Roles = append(c.spec.Roles, configcode.Role{Name: r.Name, Description: r.Description})
		if r.Composite {
			c.w.add("role.composite_dropped", safeName(r.Name), "composite role imported without its composition; re-assign the member roles to users or groups")
		}
	}
	return nil
}

type kcGroup struct {
	Name        string         `json:"name"`
	SubGroups   []kcGroup      `json:"subGroups"`
	RealmRoles  []string       `json:"realmRoles"`
	ClientRoles map[string]any `json:"clientRoles"`
	Attributes  map[string]any `json:"attributes"`
}

func countGroups(gs []kcGroup) int {
	n := len(gs)
	for _, g := range gs {
		n += countGroups(g.SubGroups)
	}
	return n
}

func (c *converter) group(g *kcGroup) error {
	if g.Name == "" || len(g.Name) > 255 || strings.Contains(g.Name, "/") {
		c.w.add("group.invalid", safeName(g.Name), "group with a missing, too long or '/' containing name was skipped")
		return nil
	}
	if _, dup := c.groupSet[g.Name]; dup {
		c.w.add("group.duplicate", safeName(g.Name), "duplicate group skipped")
		return nil
	}
	c.groupSet[g.Name] = struct{}{}
	c.spec.Groups = append(c.spec.Groups, configcode.Group{Name: g.Name})
	if n := countGroups(g.SubGroups); n > 0 {
		c.w.add("group.subgroups_dropped", safeName(g.Name), fmt.Sprintf("%d sub-group(s) dropped (nested group paths are unsupported)", n))
	}
	if len(g.RealmRoles) > 0 || len(g.ClientRoles) > 0 {
		c.w.add("group.role_mappings_dropped", safeName(g.Name), "group role mappings are not migrated; assign roles to users directly")
	}
	if len(g.Attributes) > 0 {
		c.w.add("group.attributes_dropped", safeName(g.Name), "group attributes are not migrated")
	}
	return nil
}

type kcClient struct {
	ClientID                  string         `json:"clientId"`
	Name                      string         `json:"name"`
	Enabled                   *bool          `json:"enabled"`
	Protocol                  string         `json:"protocol"`
	PublicClient              bool           `json:"publicClient"`
	BearerOnly                bool           `json:"bearerOnly"`
	StandardFlowEnabled       *bool          `json:"standardFlowEnabled"`
	ImplicitFlowEnabled       bool           `json:"implicitFlowEnabled"`
	DirectAccessGrantsEnabled bool           `json:"directAccessGrantsEnabled"`
	ServiceAccountsEnabled    bool           `json:"serviceAccountsEnabled"`
	AuthorizationServicesOn   bool           `json:"authorizationServicesEnabled"`
	RedirectURIs              []string       `json:"redirectUris"`
	WebOrigins                []string       `json:"webOrigins"`
	Attributes                map[string]any `json:"attributes"`
	ProtocolMappers           []struct{}     `json:"protocolMappers"`
	AuthorizationSettings     *struct{}      `json:"authorizationSettings"`
	DefaultClientScopes       []string       `json:"defaultClientScopes"`
	OptionalClientScopes      []string       `json:"optionalClientScopes"`
}

var builtinClients = map[string]bool{
	"account": true, "account-console": true, "admin-cli": true,
	"broker": true, "realm-management": true, "security-admin-console": true,
}

// uriOK reports whether configcode accepts u as a redirect URI or origin.
func uriOK(u string, origin bool) bool {
	cl := configcode.Client{ClientID: "x"}
	if origin {
		cl.Origins = []string{u}
	} else {
		cl.RedirectURIs = []string{u}
	}
	s := configcode.Spec{APIVersion: configcode.APIVersion, Kind: configcode.KindRealm, Realm: "x", Clients: []configcode.Client{cl}}
	return s.Validate() == nil
}

func (c *converter) client(k *kcClient) error {
	id := k.ClientID
	where := safeName(id)
	c.notMig["protocol_mappers"] += len(k.ProtocolMappers)
	switch {
	case id == "":
		c.w.add("client.invalid", "", "a client without a clientId was skipped")
		return nil
	case len(id) > 255:
		c.w.add("client.invalid", where, "client id longer than 255 bytes was skipped")
		return nil
	case builtinClients[id]:
		c.w.add("client.builtin_skipped", where, "Keycloak built-in client skipped")
		return nil
	case k.Protocol != "" && k.Protocol != "openid-connect":
		if k.Protocol == "saml" {
			c.w.add("client.saml_skipped", where, "SAML client skipped (haven-idp is OIDC only)")
		} else {
			c.w.add("client.protocol_skipped", where, "client with an unsupported protocol skipped")
		}
		return nil
	case k.BearerOnly:
		c.w.add("client.bearer_only_skipped", where, "bearer-only client skipped (resource servers validate tokens; they need no client)")
		return nil
	case k.AuthorizationServicesOn || k.AuthorizationSettings != nil:
		c.notMig["authorization_services"]++
		c.w.add("client.authorization_skipped", where, "client using authorization services skipped (UMA and resource permissions are unsupported)")
		return nil
	}
	for _, e := range c.spec.Clients {
		if e.ClientID == id {
			c.w.add("client.duplicate", where, "duplicate client skipped")
			return nil
		}
	}
	cl := configcode.Client{ClientID: id, Name: k.Name, Public: k.PublicClient, ServiceAccount: k.ServiceAccountsEnabled}
	if k.Enabled != nil && !*k.Enabled {
		f := false
		cl.Enabled = &f
	}
	if cl.Public && cl.ServiceAccount {
		cl.ServiceAccount = false
		c.w.add("client.public_service_account", where, "service accounts are not possible on a public client; the service account was dropped")
	}
	std := k.StandardFlowEnabled == nil || *k.StandardFlowEnabled
	if std != !cl.ServiceAccount {
		cl.AuthCodeFlow = &std
	}
	if k.ImplicitFlowEnabled {
		c.w.add("client.implicit_disabled", where, "implicit flow turned off (unsupported and insecure)")
	}
	if k.DirectAccessGrantsEnabled {
		c.w.add("client.direct_grant_disabled", where, "direct access grants (password grant) turned off (unsupported)")
	}
	if !cl.Public {
		if p, _ := k.Attributes["pkce.code.challenge.method"].(string); p == "S256" {
			t := true
			cl.RequirePKCE = &t
		}
		c.rep.NewSecretClients = append(c.rep.NewSecretClients, id)
		c.w.add("client.new_secret_on_apply", where, "confidential client: a NEW secret is generated when the realm file is applied; the exported secret is not copied. Update the application with the new secret")
	}
	cl.RedirectURIs = c.uris(where, k.RedirectURIs, false)
	cl.Origins = c.uris(where, k.WebOrigins, true)
	if std && len(cl.RedirectURIs) == 0 {
		c.w.add("client.no_redirect_uri", where, "client has no usable redirect URI left; sign-in will fail until you add one")
	}
	c.spec.Clients = append(c.spec.Clients, cl)
	return nil
}

func (c *converter) uris(where string, in []string, origin bool) []string {
	wild, invalid := "client.wildcard_redirect", "client.invalid_redirect"
	what := "redirect URI"
	if origin {
		wild, invalid, what = "client.wildcard_origin", "client.invalid_origin", "web origin"
	}
	set := map[string]struct{}{}
	for _, u := range in {
		switch {
		case strings.Contains(u, "*") || (origin && u == "+"):
			c.w.add(wild, where, fmt.Sprintf("wildcard %s %q dropped (list exact values)", what, safeName(u)))
		case !uriOK(u, origin):
			c.w.add(invalid, where, fmt.Sprintf("%s %q is not acceptable (need absolute https, or http for loopback) and was dropped", what, safeName(u)))
		default:
			set[u] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for u := range set {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

// finish assembles the result.
func (c *converter) finish(o Options) (*Result, error) {
	if !c.seenKey {
		return nil, errors.New("invalid Keycloak export: not a realm export (no realm, users, clients, roles or groups found)")
	}
	name := c.sourceNm
	if o.Realm != "" {
		name = o.Realm
	} else if lower := strings.ToLower(name); lower != name {
		c.w.add("realm.name_normalized", "realm", "realm name lower-cased for haven-idp")
		name = lower
	}
	if name == "" {
		return nil, errors.New("the export has no realm name; pass --realm")
	}
	c.spec.APIVersion, c.spec.Kind, c.spec.Realm = configcode.APIVersion, configcode.KindRealm, name
	if len(c.spec.DisplayName) > 255 {
		c.spec.DisplayName = ""
	}
	c.emailVerification(o)
	sort.Slice(c.spec.Roles, func(i, j int) bool { return c.spec.Roles[i].Name < c.spec.Roles[j].Name })
	sort.Slice(c.spec.Groups, func(i, j int) bool { return c.spec.Groups[i].Name < c.spec.Groups[j].Name })
	sort.Slice(c.spec.Clients, func(i, j int) bool { return c.spec.Clients[i].ClientID < c.spec.Clients[j].ClientID })
	sort.Strings(c.rep.NewSecretClients)
	sort.Slice(c.users, func(i, j int) bool { return c.users[i].Username < c.users[j].Username })
	if err := c.spec.Validate(); err != nil {
		return nil, fmt.Errorf("converted realm is not valid (use --realm to choose a valid name): %w", err)
	}
	c.rep.SourceRealm = c.sourceNm
	c.rep.TargetRealm = name
	c.rep.Mapped.Roles = len(c.spec.Roles)
	c.rep.Mapped.Groups = len(c.spec.Groups)
	c.rep.Mapped.Clients = len(c.spec.Clients)
	c.rep.Mapped.Users = len(c.users)
	for k, n := range c.notMig {
		if n > 0 {
			if c.rep.NotMigrated == nil {
				c.rep.NotMigrated = map[string]int{}
			}
			c.rep.NotMigrated[k] = n
			c.w.add("notmigrated."+k, "", fmt.Sprintf("not migrated: %s (%d in the export)", strings.ReplaceAll(k, "_", " "), n))
		}
	}
	c.w.finish(&c.rep)
	spec := c.spec
	return &Result{Spec: &spec, Users: c.users, Report: c.rep}, nil
}

// emailVerification deals with unverified emails. Keycloak lets such a user sign
// in and then verify by mail (a required action); haven-idp has no email flow
// yet, so a realm that requires verified email would lock them out for good.
// It runs after the whole document is read, so JSON key order does not matter.
func (c *converter) emailVerification(o Options) {
	if o.TrustEmails {
		n := 0
		for i := range c.users {
			if !c.users[i].EmailVerified && c.users[i].Email != "" {
				c.users[i].EmailVerified = true
				n++
			}
		}
		if n > 0 {
			c.w.add("user.emails_marked_verified", "realm", fmt.Sprintf("%d unverified email(s) marked verified (--trust-emails): only correct if you trust those addresses", n))
		}
		return
	}
	req := c.spec.Settings.EmailVerificationRequired
	if req == nil || !*req {
		return
	}
	for _, u := range c.users {
		// Only users who could otherwise sign in: enabled, with a password.
		if u.Enabled && u.PasswordHash != "" && !u.EmailVerified {
			c.w.add("user.email_unverified_blocked", u.Username,
				"email is not verified and the realm requires verified email: this user CANNOT sign in (haven-idp has no email-verification flow yet). Verify them out of band, import with --trust-emails, or set emailVerificationRequired: false")
		}
	}
}
