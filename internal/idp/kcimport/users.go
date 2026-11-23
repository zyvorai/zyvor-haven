// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package kcimport

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/password"
)

const maxFieldBytes = 512

type kcCred struct {
	Type           string `json:"type"`
	SecretData     string `json:"secretData"`
	CredentialData string `json:"credentialData"`
	// legacy (Keycloak < 8) format
	HashedSaltedValue string `json:"hashedSaltedValue"`
	Salt              string `json:"salt"`
	HashIterations    int    `json:"hashIterations"`
	Algorithm         string `json:"algorithm"`
}

type kcUser struct {
	Username               string                     `json:"username"`
	Email                  string                     `json:"email"`
	FirstName              string                     `json:"firstName"`
	LastName               string                     `json:"lastName"`
	Enabled                bool                       `json:"enabled"`
	EmailVerified          bool                       `json:"emailVerified"`
	ServiceAccountClientID string                     `json:"serviceAccountClientId"`
	RequiredActions        []string                   `json:"requiredActions"`
	Credentials            []kcCred                   `json:"credentials"`
	RealmRoles             []string                   `json:"realmRoles"`
	ClientRoles            map[string]json.RawMessage `json:"clientRoles"`
	Groups                 []string                   `json:"groups"`
	Attributes             map[string]json.RawMessage `json:"attributes"`
	FederatedIdentities    []struct{}                 `json:"federatedIdentities"`
	FederationLink         string                     `json:"federationLink"`
	Totp                   bool                       `json:"totp"`
}

var algoNameRE = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

func (c *converter) user(k *kcUser) error {
	un := k.Username
	where := safeName(un)
	if k.ServiceAccountClientID != "" {
		c.w.add("user.service_account_skipped", where, "service-account user skipped (haven-idp creates it with the client)")
		return nil
	}
	if un == "" || len(un) > maxFieldBytes || len(k.Email) > maxFieldBytes || len(k.FirstName) > maxFieldBytes || len(k.LastName) > maxFieldBytes {
		c.w.add("user.invalid", where, "user with a missing or oversized username/email/name was skipped")
		return nil
	}
	if _, dup := c.seenUser[un]; dup {
		c.w.add("user.duplicate", where, "duplicate username skipped")
		return nil
	}
	c.seenUser[un] = struct{}{}
	u := idp.ImportUser{Username: un, Email: k.Email, FirstName: k.FirstName, LastName: k.LastName, Enabled: k.Enabled, EmailVerified: k.EmailVerified}

	for _, a := range k.RequiredActions {
		if a == "UPDATE_PASSWORD" || a == "VERIFY_EMAIL" {
			u.RequiredActions = append(u.RequiredActions, a)
		} else {
			c.w.add("user.required_action_dropped", where, fmt.Sprintf("required action %q dropped", safeName(a)))
		}
	}
	for _, r := range k.RealmRoles {
		if isBuiltinRole(r) {
			c.w.add("user.builtin_role_dropped", where, "Keycloak built-in role assignment dropped")
			continue
		}
		u.Roles = append(u.Roles, r)
	}
	for _, g := range k.Groups {
		if strings.HasPrefix(g, "/") && !strings.Contains(g[1:], "/") && len(g) > 1 {
			u.Groups = append(u.Groups, g)
		} else {
			c.w.add("user.nested_group_dropped", where, fmt.Sprintf("membership of nested or malformed group %q dropped", safeName(g)))
		}
	}
	if len(k.ClientRoles) > 0 {
		c.w.add("user.client_roles_dropped", where, "client role assignments are not migrated")
	}
	c.credentials(&u, k, where)
	if len(k.Attributes) > 0 {
		c.w.add("user.attributes_dropped", where, "custom user attributes are not migrated")
	}
	if len(k.FederatedIdentities) > 0 {
		c.w.add("user.federated_identity_dropped", where, "federated (brokered) identity links are not migrated")
	}
	if k.FederationLink != "" {
		c.w.add("user.federation_link_dropped", where, "user federation link (LDAP/AD) is not migrated")
	}
	c.users = append(c.users, u)
	if u.PasswordHash != "" {
		c.rep.Mapped.UsersWithPassword++
	} else {
		c.rep.Mapped.UsersWithoutPassword++
	}
	return nil
}

func (c *converter) credentials(u *idp.ImportUser, k *kcUser, where string) {
	var otp, webauthn, other bool
	otp = k.Totp
	pwSeen := false
	for i := range k.Credentials {
		cr := &k.Credentials[i]
		switch cr.Type {
		case "password":
			if pwSeen {
				continue // only the first (current) password is used
			}
			pwSeen = true
			enc, ok := c.passwordHash(cr, where)
			if ok {
				u.PasswordHash = enc
			}
		case "otp", "totp", "hotp":
			otp = true
		case "webauthn", "webauthn-passwordless":
			webauthn = true
		default:
			other = true
		}
	}
	if !pwSeen {
		c.w.add("user.no_password", where, "user has no password credential; they must use the password reset flow")
	}
	if otp {
		c.w.add("user.otp_not_migrated", where, "OTP (authenticator app) credential not migrated; the user must re-enroll")
	}
	if webauthn {
		c.w.add("user.webauthn_not_migrated", where, "WebAuthn/passkey credential not migrated; the user must re-enroll")
	}
	if other {
		c.w.add("user.credential_not_migrated", where, "credential of an unsupported type not migrated")
	}
}

type secretData struct {
	Value string              `json:"value"`
	Salt  string              `json:"salt"`
	Extra map[string][]string `json:"additionalParameters"`
}

type credData struct {
	HashIterations int                 `json:"hashIterations"`
	Algorithm      string              `json:"algorithm"`
	Extra          map[string][]string `json:"additionalParameters"`
}

// passwordHash converts one Keycloak password credential. On failure it adds a
// warning (never including the hash or the underlying error text) and returns
// ok=false so the user imports without a password.
func (c *converter) passwordHash(cr *kcCred, where string) (string, bool) {
	var kc password.KeycloakCredential
	if cr.SecretData != "" || cr.CredentialData != "" {
		var sd secretData
		var cd credData
		if json.Unmarshal([]byte(cr.SecretData), &sd) != nil || json.Unmarshal([]byte(cr.CredentialData), &cd) != nil {
			c.w.add("user.password_unreadable", where, "password credential could not be read; the user must reset their password")
			return "", false
		}
		kc = password.KeycloakCredential{Algorithm: cd.Algorithm, Iterations: cd.HashIterations, Salt: sd.Salt, Value: sd.Value, Extra: cd.Extra}
		if len(kc.Extra) == 0 {
			kc.Extra = sd.Extra
		}
	} else {
		kc = password.KeycloakCredential{Algorithm: cr.Algorithm, Iterations: cr.HashIterations, Salt: cr.Salt, Value: cr.HashedSaltedValue}
		if kc.Algorithm == "" {
			kc.Algorithm = "pbkdf2"
		}
	}
	enc, err := password.FromKeycloak(kc)
	if err == nil {
		err = password.ValidateEncoded(enc)
	}
	if err != nil {
		alg := "unknown"
		if algoNameRE.MatchString(kc.Algorithm) {
			alg = kc.Algorithm
		}
		c.w.add("user.password_unsupported", where, fmt.Sprintf("password hash with algorithm %q cannot be converted; the user must reset their password", alg))
		return "", false
	}
	return enc, true
}
