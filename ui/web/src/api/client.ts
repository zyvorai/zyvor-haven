// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

const BASE = '/api/v1';
const TOKEN_KEY = 'haven-session-token';

export class APIError extends Error {
  status: number;
  keycloak?: unknown;
  constructor(message: string, status: number, keycloak?: unknown) {
    super(message);
    this.status = status;
    this.keycloak = keycloak;
  }
}

export function getToken() {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string | null) {
  if (token) sessionStorage.setItem(TOKEN_KEY, token);
  else sessionStorage.removeItem(TOKEN_KEY);
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(init?.headers as Record<string, string> | undefined),
  };
  const token = getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers,
  });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  if (!res.ok) {
    let body: { error?: string; keycloak?: unknown } = {};
    try {
      body = text ? JSON.parse(text) : {};
    } catch {
      /* ignore */
    }
    throw new APIError(body.error ?? text ?? res.statusText, res.status, body.keycloak);
  }
  return text ? JSON.parse(text) : (undefined as T);
}

export interface KeycloakStatus {
  connected: boolean;
  version?: string;
  realmCount: number;
  keycloakUrl: string;
}

export interface Realm {
  id?: string;
  realm: string;
  displayName?: string;
  enabled: boolean;
}

export interface Client {
  id?: string;
  clientId: string;
  name?: string;
  description?: string;
  enabled: boolean;
  publicClient: boolean;
  bearerOnly?: boolean;
  protocol?: string;
  redirectUris?: string[];
  webOrigins?: string[];
  standardFlowEnabled?: boolean;
  implicitFlowEnabled?: boolean;
  directAccessGrantsEnabled?: boolean;
  serviceAccountsEnabled?: boolean;
  attributes?: Record<string, string>;
  secret?: string;
  realm?: string;
}

export interface ClientSecret {
  type: string;
  value: string;
}

export interface User {
  id?: string;
  username: string;
  email?: string;
  firstName?: string;
  lastName?: string;
  enabled: boolean;
  emailVerified?: boolean;
}

export interface Role {
  id?: string;
  name: string;
  description?: string;
}

export interface Group {
  id?: string;
  name: string;
  path?: string;
}

export interface IdentityProvider {
  alias: string;
  displayName?: string;
  providerId: string;
  enabled: boolean;
}

export interface AdminEvent {
  time: number;
  operationType?: string;
  resourceType?: string;
  resourcePath?: string;
  error?: string;
}

export interface PlaneCard {
  label: string;
  value: string;
  meta: string;
  ok: boolean;
  live: boolean;
  configured?: boolean;
}

export interface PlaneCondition {
  type: string;
  status: string;
  reason?: string;
  message?: string;
}

export interface PlaneStatus {
  available: boolean;
  plane: string;
  namespace: string;
  phase?: string;
  phaseCard: PlaneCard;
  postgres: PlaneCard;
  backup: PlaneCard;
  certificate: PlaneCard;
  conditions?: PlaneCondition[];
  lastSync?: string;
  message?: string;
}

export interface PlaneCapabilities {
  inCluster: boolean;
  canCreatePlane: boolean;
  plane: string;
  namespace: string;
  message?: string;
}

export interface PlaneCreateResult {
  name: string;
  namespace: string;
  profile: string;
  hostname: string;
  realm?: string;
}

export type SecuritySeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface SecurityFinding {
  ruleId: string;
  severity: SecuritySeverity;
  realm: string;
  clientId?: string;
  title: string;
  evidence?: string;
  remediation: string;
}

export interface SecurityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface SecurityRealmReport {
  realm: string;
  score: number;
  fingerprint: string;
  clientCount: number;
  counts: SecurityCounts;
  findings: SecurityFinding[];
}

export interface SecurityPostureReport {
  score: number;
  grade: string;
  fingerprint: string;
  baseline?: string;
  drifted?: boolean;
  realmCount: number;
  clientCount: number;
  counts: SecurityCounts;
  findings: SecurityFinding[];
  realms: SecurityRealmReport[];
}

export interface SnapshotSummary {
  id: string;
  realm: string;
  createdAt: string;
  reason?: string;
  fingerprint: string;
  clients: number;
  users: number;
  roles: number;
  groups: number;
  providers: number;
}

export interface RealmSnapshot {
  schemaVersion: number;
  id: string;
  realm: string;
  createdAt: string;
  reason?: string;
  fingerprint: string;
  realmConfig: Realm;
  clients: Client[];
  users: User[];
  roles: Role[];
  groups: Group[];
  identityProviders: IdentityProvider[];
}

export interface ChangeSet {
  added: string[];
  removed: string[];
}

export interface SnapshotDiff {
  snapshotId: string;
  realm: string;
  snapshotFingerprint: string;
  liveFingerprint: string;
  drifted: boolean;
  clients: ChangeSet;
  users: ChangeSet;
  roles: ChangeSet;
  groups: ChangeSet;
  providers: ChangeSet;
  access: ChangeSet;
  nativeConfigChanged: boolean;
}

export interface RestoreResult {
  targetRealm: string;
  clients: number;
  users: number;
  roles: number;
  groups: number;
  providers: number;
  warnings?: string[];
}

export interface CredentialInventoryItem {
  realm: string;
  clientId: string;
  clientUuid: string;
  enabled: boolean;
  serviceAccount: boolean;
  lastRotatedAt?: string;
  ageDays?: number;
  rotationDue: boolean;
  overlapAvailable: boolean;
  rotationTracked: boolean;
}

export interface FederationField {
  name: string;
  label: string;
  secret?: boolean;
  required?: boolean;
  placeholder?: string;
}

export interface FederationTemplate {
  id: string;
  name: string;
  description: string;
  providerId: string;
  protocol: string;
  fields: FederationField[];
}

function postureQuery(opts?: { realm?: string; baseline?: string; includeMaster?: boolean }) {
  const q = new URLSearchParams();
  if (opts?.realm) q.set('realm', opts.realm);
  if (opts?.baseline) q.set('baseline', opts.baseline);
  if (opts?.includeMaster) q.set('includeMaster', '1');
  const encoded = q.toString();
  return encoded ? `?${encoded}` : '';
}

export const api = {
  health: () => request<{ status: string }>('/health'),
  authProviders: () =>
    request<{
      local: { enabled: boolean; default_username?: string };
      lab: { operator_login: boolean; hint?: string };
      oidc?: { enabled: boolean; login_url?: string };
      saml?: { enabled: boolean };
      hasLocalCreds?: boolean;
    }>('/auth/providers'),
  authLogin: (username: string, password: string) =>
    request<{
      token: string;
      user: string;
      role: string;
      auth: string;
      expiresAt: string;
    }>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  authSession: () =>
    request<{ user: string; role: string; auth: string; mode?: string }>(
      '/auth/session',
    ),
  authLogout: () =>
    request<void>('/auth/logout', { method: 'POST' }),
  changeConsolePassword: (currentPassword: string, newPassword: string) =>
    request<{ ok: boolean; user: string; note?: string }>('/auth/password', {
      method: 'POST',
      body: JSON.stringify({ currentPassword, newPassword }),
    }),
  changeKeycloakAdminPassword: (currentPassword: string, newPassword: string) =>
    request<{ ok: boolean; user: string; note?: string }>(
      '/keycloak/admin-password',
      {
        method: 'POST',
        body: JSON.stringify({ currentPassword, newPassword }),
      },
    ),
  planeStatus: () => request<PlaneStatus>('/plane/status'),
  planeCapabilities: () => request<PlaneCapabilities>('/plane/capabilities'),
  createPlane: (body: {
    name?: string;
    namespace?: string;
    profile: string;
    hostname: string;
    exposeClass?: string;
    adminEmail?: string;
    firstRealm?: string;
    audience?: string;
  }) =>
    request<PlaneCreateResult>('/planes', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  keycloakStatus: () => request<KeycloakStatus>('/keycloak/status'),
  securityPosture: (opts?: { realm?: string; baseline?: string; includeMaster?: boolean }) =>
    request<SecurityPostureReport>(`/security/posture${postureQuery(opts)}`),
  securityPostureSarif: (opts?: { realm?: string; baseline?: string; includeMaster?: boolean }) =>
    request<unknown>(`/security/posture/sarif${postureQuery(opts)}`),
  listSnapshots: (realm?: string) =>
    request<SnapshotSummary[]>(`/time-machine/snapshots${realm ? `?realm=${encodeURIComponent(realm)}` : ''}`),
  createSnapshot: (realm: string, reason?: string) =>
    request<RealmSnapshot>('/time-machine/snapshots', {
      method: 'POST',
      body: JSON.stringify({ realm, reason }),
    }),
  getSnapshot: (id: string) =>
    request<RealmSnapshot>(`/time-machine/snapshots/${encodeURIComponent(id)}`),
  diffSnapshot: (id: string) =>
    request<SnapshotDiff>(`/time-machine/snapshots/${encodeURIComponent(id)}/diff`),
  restoreSnapshot: (id: string, targetRealm: string) =>
    request<RestoreResult>(`/time-machine/snapshots/${encodeURIComponent(id)}/restore`, {
      method: 'POST', body: JSON.stringify({ targetRealm }),
    }),
  deleteSnapshot: (id: string) =>
    request<void>(`/time-machine/snapshots/${encodeURIComponent(id)}`, { method: 'DELETE' }),
  listCredentials: () =>
    request<{ rotationDays: number; items: CredentialInventoryItem[] }>('/credentials'),
  rotateCredential: (realm: string, clientUuid: string) =>
    request<{ realm: string; clientId: string; clientUuid: string; secret: string; overlapAvailable: boolean; note: string }>(
      `/credentials/${encodeURIComponent(realm)}/${encodeURIComponent(clientUuid)}/rotate`, { method: 'POST' }),
  retireCredential: (realm: string, clientUuid: string) =>
    request<{ ok: boolean; overlapAvailable: boolean }>(
      `/credentials/${encodeURIComponent(realm)}/${encodeURIComponent(clientUuid)}/retire`, { method: 'POST' }),
  federationCatalog: () => request<FederationTemplate[]>('/federation/catalog'),
  listFederationConnections: (realm: string) =>
    request<IdentityProvider[]>(`/federation/connections?realm=${encodeURIComponent(realm)}`),
  createFederationConnection: (body: { realm: string; template: string; alias: string; displayName?: string; enabled?: boolean; trustEmail?: boolean; values: Record<string,string> }) =>
    request<IdentityProvider>('/federation/connections', { method: 'POST', body: JSON.stringify(body) }),
  deleteFederationConnection: (realm: string, alias: string) =>
    request<void>(`/federation/connections/${encodeURIComponent(realm)}/${encodeURIComponent(alias)}`, { method: 'DELETE' }),
  keycloakConfig: () =>
    request<{ keycloakUrl: string; adminUser: string }>('/keycloak/config'),
  connectKeycloak: (body: {
    keycloakUrl: string;
    adminUser: string;
    password: string;
    consoleUrl?: string;
  }) =>
    request<KeycloakStatus>('/keycloak/connect', {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  listRealms: () => request<Realm[]>('/realms'),
  getRealm: (realm: string) => request<Realm>(`/realms/${encodeURIComponent(realm)}`),
  createRealm: (body: Realm) =>
    request<void>('/realms', { method: 'POST', body: JSON.stringify(body) }),
  updateRealm: (realm: string, body: Realm) =>
    request<void>(`/realms/${encodeURIComponent(realm)}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    }),
  deleteRealm: (realm: string) =>
    request<void>(`/realms/${encodeURIComponent(realm)}`, { method: 'DELETE' }),
  listAllClients: () => request<Client[]>('/clients'),
  listClients: (realm: string) =>
    request<Client[]>(`/realms/${encodeURIComponent(realm)}/clients`),
  createClient: (realm: string, body: Client) =>
    request<void>(`/realms/${encodeURIComponent(realm)}/clients`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  deleteClient: (realm: string, id: string) =>
    request<void>(`/realms/${encodeURIComponent(realm)}/clients/${id}`, {
      method: 'DELETE',
    }),
  getClientSecret: (realm: string, id: string) =>
    request<ClientSecret>(
      `/realms/${encodeURIComponent(realm)}/clients/${id}/secret`,
    ),
  regenerateClientSecret: (realm: string, id: string) =>
    request<ClientSecret>(
      `/realms/${encodeURIComponent(realm)}/clients/${id}/secret`,
      { method: 'POST' },
    ),
  listUsers: (realm: string, search?: string) => {
    const q = search ? `?search=${encodeURIComponent(search)}` : '';
    return request<User[]>(`/realms/${encodeURIComponent(realm)}/users${q}`);
  },
  createUser: (realm: string, body: User) =>
    request<void>(`/realms/${encodeURIComponent(realm)}/users`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  updateUser: (realm: string, id: string, body: User) =>
    request<void>(`/realms/${encodeURIComponent(realm)}/users/${id}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    }),
  deleteUser: (realm: string, id: string) =>
    request<void>(`/realms/${encodeURIComponent(realm)}/users/${id}`, {
      method: 'DELETE',
    }),
  resetPassword: (
    realm: string,
    id: string,
    value: string,
    temporary = true,
  ) =>
    request<void>(`/realms/${encodeURIComponent(realm)}/users/${id}/password`, {
      method: 'PUT',
      body: JSON.stringify({ type: 'password', value, temporary }),
    }),
  listRoles: (realm: string) =>
    request<Role[]>(`/realms/${encodeURIComponent(realm)}/roles`),
  createRole: (realm: string, body: Role) =>
    request<void>(`/realms/${encodeURIComponent(realm)}/roles`, {
      method: 'POST',
      body: JSON.stringify(body),
    }),
  listGroups: (realm: string) =>
    request<Group[]>(`/realms/${encodeURIComponent(realm)}/groups`),
  listIdentityProviders: (realm: string) =>
    request<IdentityProvider[]>(
      `/realms/${encodeURIComponent(realm)}/identity-providers`,
    ),
  listEvents: (realm: string) =>
    request<AdminEvent[]>(`/realms/${encodeURIComponent(realm)}/events`),
};
