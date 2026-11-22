// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import type { Client } from '../api/client';

export type PlatformClientTemplate = {
  id: string;
  name: string;
  description: string;
  publicClient: boolean;
  redirectUris?: string[];
  webOrigins?: string[];
  standardFlowEnabled?: boolean;
  directAccessGrantsEnabled?: boolean;
  bindHint?: string;
};

export const platformCatalog: PlatformClientTemplate[] = [
  {
    id: 'kubernetes',
    name: 'Kubernetes API',
    description: 'OIDC for kube-apiserver (confidential). Configure --oidc-issuer-url after mint.',
    publicClient: false,
    standardFlowEnabled: true,
    directAccessGrantsEnabled: false,
    bindHint: 'Set apiserver --oidc-client-id=kubernetes and issuer to this realm.',
  },
  {
    id: 'grafana',
    name: 'Grafana',
    description: 'Confidential OIDC client for Grafana SSO.',
    publicClient: false,
    redirectUris: ['https://grafana.example.internal/*', 'http://grafana.example.internal/*'],
    webOrigins: ['+'],
    standardFlowEnabled: true,
    directAccessGrantsEnabled: false,
  },
  {
    id: 'argocd',
    name: 'Argo CD',
    description: 'Confidential OIDC client for Argo CD Dex / built-in OIDC.',
    publicClient: false,
    redirectUris: [
      'https://argocd.example.internal/auth/callback',
      'http://argocd.example.internal/auth/callback',
    ],
    webOrigins: ['+'],
    standardFlowEnabled: true,
    directAccessGrantsEnabled: false,
  },
];

export function toCreateBody(t: PlatformClientTemplate): Client {
  return {
    clientId: t.id,
    name: t.name,
    description: t.description,
    enabled: true,
    publicClient: t.publicClient,
    protocol: 'openid-connect',
    standardFlowEnabled: t.standardFlowEnabled ?? true,
    directAccessGrantsEnabled: t.directAccessGrantsEnabled ?? false,
    redirectUris: t.redirectUris,
    webOrigins: t.webOrigins,
  };
}
