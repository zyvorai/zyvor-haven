// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { StatusCard } from '../components/StatusCard';
import { ReconcileTimeline } from '../components/ReconcileTimeline';
import { api, type KeycloakStatus, type PlaneStatus } from '../api/client';
import {
  type NavIconId,
  navIcons,
} from '../components/NavIcons';

const quickActions: {
  path: string;
  icon: NavIconId;
  label: string;
  desc: string;
}[] = [
  { path: '/realms', icon: 'realms', label: 'Realm Studio', desc: 'Manage tenants & realms' },
  { path: '/clients', icon: 'clients', label: 'Clients', desc: 'OIDC apps across realms' },
  { path: '/deploy', icon: 'deploy', label: 'Deploy wizard', desc: 'Spin up identity plane' },
  { path: '/settings?focus=keycloak', icon: 'settings', label: 'Settings', desc: 'Keycloak connection' },
];

const cardIcons: Record<string, string> = {
  Keycloak: '🔐',
  Phase: '◆',
  'Postgres primary': '🗄',
  'Last Backup': '↑',
  Certificate: '✓',
};

export function CommandDeck() {
  const [kc, setKc] = useState<KeycloakStatus | null>(null);
  const [kcErr, setKcErr] = useState('');
  const [plane, setPlane] = useState<PlaneStatus | null>(null);

  useEffect(() => {
    api.keycloakStatus().then(setKc).catch((e) => setKcErr(e.message));
    api.planeStatus().then(setPlane).catch(() => setPlane(null));
    const id = window.setInterval(() => {
      api.planeStatus().then(setPlane).catch(() => {});
    }, 30000);
    return () => window.clearInterval(id);
  }, []);

  const kcCard = kc
    ? {
        label: 'Keycloak',
        value: kc.connected ? kc.version ?? 'connected' : 'offline',
        meta: kc.connected
          ? `${kc.realmCount} realm${kc.realmCount === 1 ? '' : 's'} · live`
          : kcErr || 'unreachable',
        ok: kc.connected,
        variant: 'live' as const,
      }
    : {
        label: 'Keycloak',
        value: '…',
        meta: 'checking',
        ok: true,
        variant: 'live' as const,
      };

  const liveCards = plane
    ? [
        {
          label: plane.phaseCard.label,
          value: plane.phaseCard.value,
          meta: plane.phaseCard.meta,
          ok: plane.phaseCard.ok,
          variant: 'live' as const,
        },
        {
          label: plane.postgres.label,
          value: plane.postgres.value,
          meta: plane.postgres.meta,
          ok: plane.postgres.ok,
          variant: plane.postgres.live ? ('live' as const) : ('mock' as const),
        },
        {
          label: plane.backup.label,
          value: plane.backup.value,
          meta: plane.backup.meta,
          ok: plane.backup.ok,
          variant: plane.backup.live ? ('live' as const) : ('mock' as const),
        },
        {
          label: plane.certificate.label,
          value: plane.certificate.value,
          meta: plane.certificate.meta,
          ok: plane.certificate.ok,
          variant: plane.certificate.live ? ('live' as const) : ('mock' as const),
        },
      ]
    : [];

  const cards = [kcCard, ...liveCards];

  return (
    <ConsoleLayout>
      <div className="console-content">
        <div className="console-content-inner">
          <div className="deck-hero">
            <p className="deck-eyebrow">Command Deck</p>
            <h1 className="deck-title">Platform at a glance</h1>
            <p className="deck-subtitle">
              Live identity plane health, Keycloak status, and reconcile progress —
              operate entirely from Haven.
            </p>
          </div>

          {kc?.connected ? (
            <div className="keycloak-featured">
              <div>
                <div className="keycloak-featured-label">
                  <span className="keycloak-live-dot" aria-hidden />
                  Connected Keycloak
                </div>
                <code className="keycloak-url-chip">{kc.keycloakUrl}</code>
                <div className="keycloak-meta">
                  {kc.realmCount} realm{kc.realmCount === 1 ? '' : 's'} · v{kc.version}
                  {plane?.phase ? ` · plane ${plane.phase}` : ''}
                </div>
              </div>
              <div className="keycloak-featured-actions">
                <Link to="/realms" className="btn btn-primary deck-btn">
                  Open Realm Studio
                </Link>
                <Link to="/clients" className="btn btn-ghost deck-btn">
                  View clients
                </Link>
              </div>
            </div>
          ) : (
            <div className="keycloak-featured keycloak-featured--offline">
              <div>
                <div className="keycloak-featured-label">Keycloak offline</div>
                <p className="keycloak-meta" style={{ marginTop: 0 }}>
                  {kcErr || 'Not connected — configure in Settings'}
                </p>
              </div>
              <Link to="/settings?focus=keycloak" className="btn btn-primary deck-btn">
                Connect Keycloak
              </Link>
            </div>
          )}

          <div className="deck-quick-actions">
            {quickActions.map((a) => {
              const Icon = navIcons[a.icon];
              return (
                <Link key={a.path} to={a.path} className="deck-action-card">
                  <span className="deck-action-icon" aria-hidden>
                    <Icon size={20} />
                  </span>
                  <span className="deck-action-label">{a.label}</span>
                  <span className="deck-action-desc">{a.desc}</span>
                </Link>
              );
            })}
          </div>

          <div className="deck-bento">
            {cards.map((c) => (
              <StatusCard
                key={c.label}
                label={c.label}
                value={c.value}
                meta={c.meta}
                ok={c.ok}
                icon={cardIcons[c.label]}
                variant={c.variant}
              />
            ))}
          </div>

          <ReconcileTimeline conditions={plane?.conditions} phase={plane?.phase} />
        </div>
      </div>
    </ConsoleLayout>
  );
}
