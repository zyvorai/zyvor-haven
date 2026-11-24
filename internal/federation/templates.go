// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package federation

import (
	"errors"
	"fmt"
	"strings"

	"github.com/zyvorai/haven/internal/idmodel"
)

type Field struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Secret      bool   `json:"secret,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Placeholder string `json:"placeholder,omitempty"`
}

type ProviderTemplate struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	ProviderID  string  `json:"providerId"`
	Protocol    string  `json:"protocol"`
	Fields      []Field `json:"fields"`
}

type ConnectionRequest struct {
	Realm       string            `json:"realm"`
	Template    string            `json:"template"`
	Alias       string            `json:"alias"`
	DisplayName string            `json:"displayName,omitempty"`
	Enabled     *bool             `json:"enabled,omitempty"`
	TrustEmail  *bool             `json:"trustEmail,omitempty"`
	Values      map[string]string `json:"values"`
}

func Catalog() []ProviderTemplate {
	return []ProviderTemplate{
		{
			ID: "entra", Name: "Microsoft Entra ID", ProviderID: "oidc", Protocol: "oidc",
			Description: "Enterprise workforce federation through Microsoft Entra ID.",
			Fields: []Field{
				{Name: "tenantId", Label: "Tenant ID", Required: true, Placeholder: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"},
				{Name: "clientId", Label: "Client ID", Required: true},
				{Name: "clientSecret", Label: "Client secret", Required: true, Secret: true},
			},
		},
		{
			ID: "google", Name: "Google Workspace", ProviderID: "google", Protocol: "oidc",
			Description: "Google identity federation for Workspace and Cloud Identity users.",
			Fields: []Field{
				{Name: "clientId", Label: "Client ID", Required: true},
				{Name: "clientSecret", Label: "Client secret", Required: true, Secret: true},
				{Name: "defaultScope", Label: "Scopes", Placeholder: "openid profile email"},
			},
		},
		{
			ID: "github", Name: "GitHub", ProviderID: "github", Protocol: "oidc",
			Description: "GitHub sign-in for developer and engineering environments.",
			Fields: []Field{
				{Name: "clientId", Label: "Client ID", Required: true},
				{Name: "clientSecret", Label: "Client secret", Required: true, Secret: true},
			},
		},
		{
			ID: "oidc", Name: "Generic OpenID Connect", ProviderID: "oidc", Protocol: "oidc",
			Description: "Connect any standards-compliant OpenID Connect provider.",
			Fields: []Field{
				{Name: "issuer", Label: "Issuer URL", Required: true, Placeholder: "https://id.example.com"},
				{Name: "authorizationUrl", Label: "Authorization URL", Required: true},
				{Name: "tokenUrl", Label: "Token URL", Required: true},
				{Name: "jwksUrl", Label: "JWKS URL", Required: true},
				{Name: "userInfoUrl", Label: "UserInfo URL"},
				{Name: "clientId", Label: "Client ID", Required: true},
				{Name: "clientSecret", Label: "Client secret", Required: true, Secret: true},
				{Name: "defaultScope", Label: "Scopes", Placeholder: "openid profile email"},
			},
		},
		{
			ID: "saml", Name: "SAML 2.0", ProviderID: "saml", Protocol: "saml",
			Description: "Enterprise SAML federation for existing identity infrastructure.",
			Fields: []Field{
				{Name: "singleSignOnServiceUrl", Label: "SSO service URL", Required: true},
				{Name: "singleLogoutServiceUrl", Label: "Single logout URL"},
				{Name: "entityId", Label: "Entity ID", Required: true},
				{Name: "signingCertificate", Label: "Signing certificate", Secret: true},
			},
		},
	}
}

func FindTemplate(id string) (ProviderTemplate, bool) {
	for _, t := range Catalog() {
		if t.ID == id {
			return t, true
		}
	}
	return ProviderTemplate{}, false
}

func Validate(req ConnectionRequest) error {
	if strings.TrimSpace(req.Realm) == "" {
		return errors.New("realm is required")
	}
	if strings.TrimSpace(req.Alias) == "" {
		return errors.New("alias is required")
	}
	t, ok := FindTemplate(req.Template)
	if !ok {
		return fmt.Errorf("unknown federation template %q", req.Template)
	}
	for _, field := range t.Fields {
		if field.Required && strings.TrimSpace(req.Values[field.Name]) == "" {
			return fmt.Errorf("%s is required", field.Label)
		}
	}
	return nil
}

// Neutral config keys used in idmodel.FederationProvider.Config. Wire
// spellings live only in provider.go.
const (
	KeyIssuer           = "issuer"
	KeyAuthorizationURL = "authorization_url"
	KeyTokenURL         = "token_url"
	KeyJWKSURL          = "jwks_url"
	KeyUserInfoURL      = "userinfo_url"
	KeyClientID         = "client_id"
	KeyClientSecret     = "client_secret"
	KeyScopes           = "scopes"
	KeySSOURL           = "sso_url"
	KeySLOURL           = "slo_url"
	KeyEntityID         = "entity_id"
	KeySigningCert      = "signing_certificate"

	// Signing/binding options, "true" when enabled.
	KeyUseJWKS                 = "use_jwks"
	KeyValidateSignature       = "validate_signature"
	KeySignAuthnRequests       = "sign_authn_requests"
	KeyPostBindingResponse     = "post_binding_response"
	KeyPostBindingAuthnRequest = "post_binding_authn_request"
)

// BuildProvider validates the request and produces a backend-neutral
// federation provider. Field names the template does not know pass through
// unchanged.
func BuildProvider(req ConnectionRequest) (idmodel.FederationProvider, error) {
	if err := Validate(req); err != nil {
		return idmodel.FederationProvider{}, err
	}
	t, _ := FindTemplate(req.Template)
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	trustEmail := true
	if req.TrustEmail != nil {
		trustEmail = *req.TrustEmail
	}

	cfg := make(map[string]string)
	for k, v := range req.Values {
		if strings.TrimSpace(v) != "" {
			cfg[neutralKey(k)] = strings.TrimSpace(v)
		}
	}

	const defaultScopes = "openid profile email"
	switch req.Template {
	case "entra":
		tenant := cfg["tenantId"]
		cfg[KeyIssuer] = "https://login.microsoftonline.com/" + tenant + "/v2.0"
		cfg[KeyAuthorizationURL] = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/authorize"
		cfg[KeyTokenURL] = "https://login.microsoftonline.com/" + tenant + "/oauth2/v2.0/token"
		cfg[KeyJWKSURL] = "https://login.microsoftonline.com/" + tenant + "/discovery/v2.0/keys"
		cfg[KeyScopes] = defaultScopes
		cfg[KeyUseJWKS] = "true"
		delete(cfg, "tenantId")
	case "google":
		if cfg[KeyScopes] == "" {
			cfg[KeyScopes] = defaultScopes
		}
	case "github":
		// The built-in GitHub broker only needs client credentials.
	case "oidc":
		if cfg[KeyScopes] == "" {
			cfg[KeyScopes] = defaultScopes
		}
		cfg[KeyUseJWKS] = "true"
	case "saml":
		cfg[KeyValidateSignature] = "true"
		cfg[KeySignAuthnRequests] = "true"
		cfg[KeyPostBindingResponse] = "true"
		cfg[KeyPostBindingAuthnRequest] = "true"
	}

	display := strings.TrimSpace(req.DisplayName)
	if display == "" {
		display = t.Name
	}
	return idmodel.FederationProvider{
		Alias:       req.Alias,
		DisplayName: display,
		Kind:        t.ProviderID,
		Enabled:     enabled,
		TrustEmail:  trustEmail,
		StoreToken:  false,
		Config:      cfg,
	}, nil
}

// neutralKey maps a template form field name to its neutral config key.
func neutralKey(field string) string {
	if k, ok := fieldToNeutral[field]; ok {
		return k
	}
	return field
}

var fieldToNeutral = map[string]string{
	"issuer":                 KeyIssuer,
	"authorizationUrl":       KeyAuthorizationURL,
	"tokenUrl":               KeyTokenURL,
	"jwksUrl":                KeyJWKSURL,
	"userInfoUrl":            KeyUserInfoURL,
	"clientId":               KeyClientID,
	"clientSecret":           KeyClientSecret,
	"defaultScope":           KeyScopes,
	"singleSignOnServiceUrl": KeySSOURL,
	"singleLogoutServiceUrl": KeySLOURL,
	"entityId":               KeyEntityID,
	"signingCertificate":     KeySigningCert,
}
