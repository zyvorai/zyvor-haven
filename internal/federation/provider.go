// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package federation

import (
	"github.com/zyvorai/haven/internal/idmodel"
	"github.com/zyvorai/haven/internal/idp"
)

// neutralToWireKey maps neutral config keys to the identity-provider config
// keys of the Admin API. Keys not listed pass through unchanged.
var neutralToWireKey = map[string]string{
	KeyIssuer:                  "issuer",
	KeyAuthorizationURL:        "authorizationUrl",
	KeyTokenURL:                "tokenUrl",
	KeyJWKSURL:                 "jwksUrl",
	KeyUserInfoURL:             "userInfoUrl",
	KeyClientID:                "clientId",
	KeyClientSecret:            "clientSecret",
	KeyScopes:                  "defaultScope",
	KeySSOURL:                  "singleSignOnServiceUrl",
	KeySLOURL:                  "singleLogoutServiceUrl",
	KeyEntityID:                "entityId",
	KeySigningCert:             "signingCertificate",
	KeyUseJWKS:                 "useJwksUrl",
	KeyValidateSignature:       "validateSignature",
	KeySignAuthnRequests:       "wantAuthnRequestsSigned",
	KeyPostBindingResponse:     "postBindingResponse",
	KeyPostBindingAuthnRequest: "postBindingAuthnRequest",
}

// ToIdentityProvider renders a neutral federation provider as the Admin API's
// identity-provider representation. Kind is used as the providerId.
func ToIdentityProvider(p idmodel.FederationProvider) idp.IdentityProvider {
	cfg := make(map[string]string, len(p.Config))
	for k, v := range p.Config {
		if kk, ok := neutralToWireKey[k]; ok {
			k = kk
		}
		cfg[k] = v
	}
	return idp.IdentityProvider{
		Alias:       p.Alias,
		DisplayName: p.DisplayName,
		ProviderID:  p.Kind,
		Enabled:     p.Enabled,
		TrustEmail:  p.TrustEmail,
		StoreToken:  p.StoreToken,
		Config:      cfg,
	}
}

// BuildIdentityProvider validates req and renders it as an identity-provider representation.
func BuildIdentityProvider(req ConnectionRequest) (idp.IdentityProvider, error) {
	p, err := BuildProvider(req)
	if err != nil {
		return idp.IdentityProvider{}, err
	}
	return ToIdentityProvider(p), nil
}
