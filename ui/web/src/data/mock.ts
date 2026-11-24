// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

export const planeStatus = {
  phase: { label: 'Phase', value: 'Ready', meta: 'All systems nominal', ok: true },
  identity: { label: 'Identity server', value: '3/3', meta: 'All instances ready', ok: true },
  postgres: { label: 'Postgres primary', value: 'healthy', meta: '2 replicas streaming', ok: true },
  backup: { label: 'Last Backup', value: '2h ago', meta: 'snapshot-20260827-0200', ok: true },
  cert: { label: 'Certificate', value: '84 days', meta: 'expires 2026-11-20', ok: true },
};

export const reconcileSteps = [
  { id: 'observatory', label: 'Observatory', sub: 'watchers synced' },
  { id: 'ingress', label: 'Ingress', sub: 'rules reconciled' },
  { id: 'certs', label: 'Certificates', sub: 'secrets valid' },
  { id: 'identity', label: 'Identity server', sub: 'realms synced' },
  { id: 'postgres', label: 'Postgres', sub: 'clusters healthy' },
  { id: 'vault', label: 'Vault', sub: 'leases rotated' },
  { id: 'gateway', label: 'API Gateway', sub: 'routes active' },
];

export const sidebarNav = [
  { path: '/deck', label: 'Command Deck', icon: 'deck' },
  { path: '/deploy', label: 'Deploy wizard', icon: 'deploy' },
  { path: '/planes', label: 'Planes', icon: 'planes' },
  { path: '/realms', label: 'Realm Studio', icon: 'realms' },
  { path: '/clients', label: 'Clients', icon: 'clients' },
  { path: '/federation', label: 'Federation', icon: 'federation' },
  { path: '/credentials', label: 'Credentials', icon: 'credentials' },
  { path: '/security', label: 'Guard', icon: 'guard' },
  { path: '/access-review', label: 'Access Review', icon: 'access' },
  { path: '/time-machine', label: 'Time Machine', icon: 'timemachine' },
  { path: '/atlas', label: 'Atlas', icon: 'atlas' },
  { path: '/settings', label: 'Settings', icon: 'settings' },
] as const;

export const commandPaletteItems = [
  'Deploy a new identity plane',
  'Open plane "platform"',
  'Mint OIDC client for Grafana',
  'Invite tenant admin',
];

export const problems = [
  {
    title: 'Database is bring-your-own',
    desc: 'Identity servers need a database, and most operators leave Postgres to you. Teams wire Bitnami charts, random StatefulSets, or forgotten RDS URLs.',
  },
  {
    title: 'Secrets are tribal knowledge',
    desc: 'Bootstrap admin passwords live in Slack threads. JDBC credentials are kubectl one-offs nobody rotates.',
  },
  {
    title: 'Day-2 is two UIs',
    desc: 'kubectl plus a separate identity admin console, no backup story, no realm GitOps. Haven is one plane you operate.',
  },
];
