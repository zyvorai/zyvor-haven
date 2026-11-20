// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

export type HavenConfig = {
  keycloakUrl?: string;
  keycloakAdminUrl?: string;
  keycloakNamespace?: string;
};

let cached: HavenConfig | null = null;

export async function loadConfig(): Promise<HavenConfig> {
  if (cached) return cached;
  try {
    const res = await fetch('/config.json', { cache: 'no-store' });
    if (res.ok) {
      cached = (await res.json()) as HavenConfig;
      return cached;
    }
  } catch {
    /* demo / offline */
  }
  cached = {};
  return cached;
}
