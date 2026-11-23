# Migrate from Keycloak to haven-idp

Keycloak support stays for the migration period and is deprecated; it will be removed in a later
release. Existing planes are never switched silently: a plane with a Keycloak CR keeps
`engine: keycloak` until you change it. Plan this as a parallel run, not an in-place upgrade.

## What is and is not migrated

haven-idp is not a Keycloak clone. Be clear about the gap before you start.

| Migrates (as config) | Does NOT migrate |
|---|---|
| Realm settings Haven manages (see [config-as-code.md](config-as-code.md)) | **Users' password hashes**: users must set a new password (reset flow) |
| OIDC clients (public/confidential, redirect URIs, origins, PKCE) | Identity brokering and user federation (external IdPs, LDAP/AD) |
| Realm roles and groups | SAML clients and IdPs |
| Realm password policy, token lifetimes | Fine-grained authorization services (UMA, resource permissions) |
|  | Custom Keycloak SPIs, themes, flows and required-action providers |
|  | Existing sessions, offline tokens and refresh tokens (everyone signs in again) |
|  | Client secrets (new ones are generated; update every relying app) |

If you depend on anything in the right-hand column, do not cut over yet. haven-idp does not import
Keycloak password hashes, and the config tool leaves users out of scope, so budget for a forced
password reset and a user-provisioning step you script yourself.

## 1. Take a recovery point

Before touching anything:

```bash
# Haven Time Machine snapshot (console: Time Machine), or Keycloak's own export:
kubectl -n identity exec platform-0 -- /opt/keycloak/bin/kcadm.sh \
  config credentials --server http://localhost:8080 --realm master --user admin
kubectl -n identity exec platform-0 -- /opt/keycloak/bin/kcadm.sh \
  create realms/<realm>/partial-export -s exportClients=true -s exportGroupsAndRoles=true -o > <realm>.json
```

Pod names and flags vary by Keycloak version; adapt as needed. Also take a CNPG backup
(`haven backup --now`). Keep both until the migration is closed out. The export contains
configuration only; it is sensitive, so store it like a secret.

## 2. Convert to a config file

The config-as-code tool manages realms through haven-idp's admin API. There is no automatic
Keycloak-to-haven-idp converter that is verified end to end, so translate by hand (or script) from the
partial export into the `Realm` file format, then let the tool check you:

```yaml
apiVersion: haven.zyvor.dev/v1
kind: Realm
realm: platform
settings: {passwordPolicy: "length(12) and digits(1)", bruteForceProtection: true}
roles: [{name: admin}]
groups: [{name: platform-admins}]
clients:
  - clientId: grafana
    public: false
    redirectUris: ["https://grafana.example.com/login/generic_oauth"]
```

```bash
haven-idp validate -f realm.yaml
```

Copy each client's `redirectUris`, `webOrigins`, `publicClient` and `standardFlowEnabled`. Review
every client the export marks as SAML, `serviceAccountsEnabled`, or using `authorizationServicesEnabled`:
those need a decision, not a copy. Once the new server is running, `haven-idp export <realm>`
dumps what haven-idp actually holds, which is the file to commit.

## 3. Stand up haven-idp next to Keycloak

Use a different hostname so both run at once, for example `auth-new.example.com`. Either create a
second IdentityPlane (`spec.engine: native`, another name and namespace) or deploy the Helm/overlay objects
in a scratch namespace. Do not change `engine` on the existing plane.

```bash
kubectl apply -f plane-native.yaml
bash cli/haven doctor platform2 -n identity-new     # IdentityProviderReady=True, issuer printed
HAVEN_IDP_URL=... HAVEN_IDP_ADMIN_REALM=platform HAVEN_IDP_ADMIN_CLIENT_SECRET=... \
  haven-idp plan -f realm.yaml && haven-idp apply -f realm.yaml --secrets-file ./new-client-secrets.env
```

Apply writes generated client secrets once, to the 0600 file you name; it never overwrites an
existing file. Move them into your secret manager and delete the file.

## 4. Parallel run and cut-over

1. **Test users first.** Create a few users in haven-idp; sign in from a staging copy of each app
   against the new issuer (`https://<new host>/realms/<realm>`). Issuer, JWKS and token claims differ
   from Keycloak's: check audiences, `groups`/role claims and any app that hard-codes Keycloak paths
   (`/auth/realms/...`).
2. **Migrate relying apps one at a time:** switch issuer URL, client ID and the new secret. Keep Keycloak
   serving the rest.
3. **Users:** announce the password reset, or run the reset flow from the console. Provision accounts
   yourself (your own script or the console); the config tool does not manage users.
4. **Console:** set `identity.backend=native` (Helm) only after realms and clients exist in
   haven-idp. Until then the console keeps showing Keycloak.
5. **Freeze and cut over:** lower DNS TTLs, stop admin changes in Keycloak, run the final
   `plan --check` (exit 0 means no drift), then point the old hostname at haven-idp or update every
   app. Hold Keycloak read-only for at least one rollback window (suggest 14 days).
6. **Decommission:** delete the Keycloak CR and its database, remove `INSTALL_KEYCLOAK_OPERATOR`
   from your tooling, and drop the keycloak RBAC rules from your chart values when you can.

## Rollback

While Keycloak is still running and untouched, rollback is a configuration change: point apps and DNS
back at the Keycloak issuer. Users who set a new password in haven-idp must use their old Keycloak
password again. Nothing in haven-idp writes to Keycloak. After you delete Keycloak, rollback means
restoring from the section 1 recovery point (Time Machine or CNPG backup), so do not delete it early.

## Checklist

- [ ] Recovery point and CNPG backup taken
- [ ] Every SAML, federation, UMA and custom-SPI use identified and decided
- [ ] `realm.yaml` passes `validate` and `plan --check`
- [ ] Each relying app tested against the new issuer
- [ ] Password-reset communication sent
- [ ] Rollback window agreed before Keycloak is removed
