// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

export type PaletteAction = 'navigate' | 'shell';

export type PaletteCommand = {
  id: string;
  label: string;
  keywords?: string[];
  action: PaletteAction;
  path?: string;
  hint?: string;
};

export const paletteCommands: PaletteCommand[] = [
  {
    id: 'deploy',
    label: 'Deploy a new identity plane',
    keywords: ['wizard', 'create', 'plane'],
    action: 'navigate',
    path: '/deploy',
  },
  {
    id: 'open-plane',
    label: 'Open plane "platform"',
    keywords: ['deck', 'overview', 'health', 'planes'],
    action: 'navigate',
    path: '/planes',
  },
  {
    id: 'atlas',
    label: 'Open Atlas topology',
    keywords: ['topology', 'map', 'postgres', 'identity server'],
    action: 'navigate',
    path: '/atlas',
  },
  {
    id: 'realms',
    label: 'Open Realm Studio',
    keywords: ['realms', 'tenants'],
    action: 'navigate',
    path: '/realms',
  },
  {
    id: 'clients',
    label: 'Mint OIDC client for Grafana',
    keywords: ['client', 'oidc', 'grafana', 'app'],
    action: 'navigate',
    path: '/clients?catalog=grafana',
  },
  {
    id: 'invite',
    label: 'Invite tenant admin',
    keywords: ['user', 'admin', 'invite'],
    action: 'navigate',
    path: '/realms/platform?tab=users',
  },
  {
    id: 'settings',
    label: 'Identity server connection settings',
    keywords: ['identity server', 'connect', 'credentials'],
    action: 'navigate',
    path: '/settings?focus=identity-server',
  },
];
