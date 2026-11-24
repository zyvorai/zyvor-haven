// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package kcimport

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/upstream"
)

// kcIdP is the part of a Keycloak identity provider the converter reads.
// Config values are decoded as raw JSON so a non-string value never fails the
// whole import. clientSecret is never read.
type kcIdP struct {
	Alias       string                     `json:"alias"`
	DisplayName string                     `json:"displayName"`
	ProviderID  string                     `json:"providerId"`
	Enabled     *bool                      `json:"enabled"`
	TrustEmail  bool                       `json:"trustEmail"`
	Config      map[string]json.RawMessage `json:"config"`
}

var badAliasChars = regexp.MustCompile(`[^a-z0-9-]+`)

func cfgString(m map[string]json.RawMessage, k string) string {
	raw, ok := m[k]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return strings.TrimSpace(s)
	}
	return ""
}

// identityProvider converts one Keycloak identity provider to the Admin API
// shape (without the client secret, which Keycloak masks in exports), or
// reports why it cannot be converted. OIDC, Google and Microsoft providers
// convert; GitHub and every other type, and SAML, do not.
func (c *converter) identityProvider(k *kcIdP) error {
	where := safeName(k.Alias)
	cfg := map[string]string{}
	typ := ""
	switch k.ProviderID {
	case "oidc", "keycloak-oidc":
		typ = upstream.TypeOIDC
		iss := cfgString(k.Config, "issuer")
		disco := cfgString(k.Config, "metadataDescriptorUrl")
		if iss == "" && disco == "" {
			c.dropIdP(where, "has no issuer or discovery URL (Keycloak stores endpoints one by one; haven-idp needs the issuer)")
			return nil
		}
		if iss != "" {
			cfg[upstream.KeyIssuer] = iss
		}
		if strings.HasSuffix(disco, "/.well-known/openid-configuration") {
			cfg[upstream.KeyDiscovery] = disco
		}
		if iss == "" && cfg[upstream.KeyDiscovery] == "" {
			c.dropIdP(where, "has no usable issuer or discovery URL")
			return nil
		}
	case "google":
		typ = upstream.TypeGoogle
		if hd := cfgString(k.Config, "hostedDomain"); hd != "" {
			cfg[upstream.KeyHostedDomain] = hd
		}
	case "microsoft":
		typ = upstream.TypeMicrosoft
	default:
		c.dropIdP(where, fmt.Sprintf("type %q is not supported (haven-idp brokers OIDC, Google and Microsoft only; GitHub and SAML are not available)", safeName(k.ProviderID)))
		return nil
	}
	cfg[upstream.KeyClientID] = cfgString(k.Config, "clientId")
	if sc := cfgString(k.Config, "defaultScope"); sc != "" {
		cfg[upstream.KeyScopes] = sc
	}

	alias := strings.Trim(badAliasChars.ReplaceAllString(strings.ToLower(k.Alias), "-"), "-")
	if len(alias) > 32 {
		alias = strings.TrimRight(alias[:32], "-")
	}
	if alias == "" {
		c.dropIdP(where, "has no usable alias")
		return nil
	}
	if alias != k.Alias {
		c.w.add("identity_provider.alias_changed", where, fmt.Sprintf("alias %q becomes %q (aliases are [a-z0-9-]{1,32})", safeName(k.Alias), alias))
	}
	if _, _, err := upstream.ParseConfig(typ, cfg, false); err != nil {
		c.dropIdP(where, "cannot be converted: "+err.Error())
		return nil
	}
	name := k.DisplayName
	if name == "" {
		name = k.Alias
	}
	c.idps = append(c.idps, idp.IdentityProvider{
		Alias: alias, DisplayName: safeName(name), ProviderID: typ,
		Enabled: false, // no secret yet: enable it after setting config.clientSecret
		// Trusting the upstream email is a security decision; the export's flag is kept.
		TrustEmail: k.TrustEmail, Config: cfg,
	})
	c.w.add("identity_provider.secret_required", alias, "converted but DISABLED: the client secret is masked in Keycloak exports and was not migrated. Create it with POST /admin/v1/realms/{realm}/identity-providers (body in identity-providers.json), set config.clientSecret and enabled:true"+
		"; check linkExistingByEmail/autoCreateUsers (not carried over: both default to false)")
	if k.TrustEmail {
		c.w.add("identity_provider.trust_email", alias, "trustEmail is carried over: the upstream's email_verified claim will mark local emails verified")
	}
	return nil
}

func (c *converter) dropIdP(where, why string) {
	c.notMig["identity_providers"]++
	c.w.add("identity_provider.dropped", where, "identity provider not migrated: "+why)
}
