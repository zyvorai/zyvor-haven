// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useEffect, useState, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { StatusCard } from '../components/StatusCard';
import { ReconcileTimeline } from '../components/ReconcileTimeline';
import { api, type IdentityServerStatus, type PlaneStatus } from '../api/client';
import {
  type NavIconId,
  navIcons,
  IconRealms,
  IconPulse,
  IconDatabase,
  IconBackup,
  IconCertificate,
} from '../components/NavIcons';
import { RingGauge, type Tone } from '../components/graphics/Charts';
import { Art, SkeletonBlock } from '../components/graphics/Art';

const quickActions: {
  path: string;
  icon: NavIconId;
  label: string;
  desc: string;
}[] = [
  { path: '/realms', icon: 'realms', label: 'Realm Studio', desc: 'Manage tenants & realms' },
  { path: '/clients', icon: 'clients', label: 'Clients', desc: 'OIDC apps across realms' },
  { path: '/deploy', icon: 'deploy', label: 'Deploy wizard', desc: 'Spin up identity plane' },
  { path: '/settings?focus=identity-server', icon: 'settings', label: 'Settings', desc: 'Identity server connection' },
];

const cardIcons: Record<string, ReactNode> = {
  'Identity server': <IconRealms size={20} />,
  Phase: <IconPulse size={20} />,
  'Postgres primary': <IconDatabase size={20} />,
  'Last Backup': <IconBackup size={20} />,
  Certificate: <IconCertificate size={20} />,
};

export function CommandDeck() {
  const [server, setServer] = useState<IdentityServerStatus | null>(null);
  const [serverErr, setServerErr] = useState('');
  const [plane, setPlane] = useState<PlaneStatus | null>(null);
  const [planeLoaded, setPlaneLoaded] = useState(false);

  useEffect(() => {
    api.identityServerStatus().then(setServer).catch((e) => setServerErr(e.message));
    api
      .planeStatus()
      .then(setPlane)
      .catch(() => setPlane(null))
      .finally(() => setPlaneLoaded(true));
    const id = window.setInterval(() => {
      api.planeStatus().then(setPlane).catch(() => {});
    }, 30000);
    return () => window.clearInterval(id);
  }, []);

  const serverCard = server
    ? {
        label: 'Identity server',
        value: server.connected ? server.version ?? 'connected' : 'offline',
        meta: server.connected
          ? `${server.realmCount} realm${server.realmCount === 1 ? '' : 's'} · live`
          : serverErr || 'unreachable',
        ok: server.connected,
        variant: 'live' as const,
      }
    : serverErr
      ? {
          label: 'Identity server',
          value: 'offline',
          meta: serverErr,
          ok: false,
          variant: 'live' as const,
        }
      : {
          label: 'Identity server',
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

  const cards = [serverCard, ...liveCards];
  const checked = server || serverErr ? cards : [];
  const healthy = checked.filter((c) => c.ok).length;
  const ringTone: Tone = checked.length === 0 ? 'muted' : healthy === checked.length ? 'ok' : healthy >= checked.length - 1 ? 'warn' : 'err';
  const phaseLabel = plane?.phase ?? plane?.phaseCard?.value ?? (server ? (server.connected ? 'Connected' : 'Offline') : '…');

  return (
    <ConsoleLayout>
      <div className="console-content">
        <div className="console-content-inner">
          <div className="deck-hero">
            <div className="deck-hero-copy">
              <p className="deck-eyebrow">Command Deck</p>
              <h1 className="deck-title">Platform at a glance</h1>
              <p className="deck-subtitle">
                Live identity plane health, identity server status, and reconcile progress —
                operate entirely from Haven.
              </p>
            </div>
            <div className="deck-hero-health card-glass">
              <RingGauge
                value={healthy}
                max={Math.max(checked.length, 1)}
                tone={ringTone}
                pulse={checked.length > 0 && healthy === checked.length}
                center={phaseLabel}
                caption={checked.length ? `${healthy} of ${checked.length} healthy` : 'checking'}
                label={
                  checked.length
                    ? `Plane health: ${healthy} of ${checked.length} checks healthy, phase ${phaseLabel}`
                    : 'Plane health: checking'
                }
              />
              <ul className="deck-checks" aria-label="Health checks">
                {checked.length === 0 && <li className="deck-check deck-check--idle">Waiting for status…</li>}
                {checked.map((c) => (
                  <li key={c.label} className={`deck-check ${c.ok ? 'is-ok' : 'is-warn'}`}>
                    <span className="deck-check-dot" aria-hidden />
                    <span className="deck-check-name">{c.label}</span>
                    <span className="deck-check-val">{c.ok ? 'Healthy' : 'Attention'}</span>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {server?.connected ? (
            <div className="identity-featured">
              <div>
                <div className="identity-featured-label">
                  <span className="identity-live-dot" aria-hidden />
                  Identity server
                </div>
                <code className="identity-url-chip">{server.identityServerUrl}</code>
                <div className="identity-meta">
                  {server.realmCount} realm{server.realmCount === 1 ? '' : 's'} · v{server.version}
                  {plane?.phase ? ` · plane ${plane.phase}` : ''}
                </div>
              </div>
              <div className="identity-featured-actions">
                <Link to="/realms" className="btn btn-primary deck-btn">
                  Open Realm Studio
                </Link>
                <Link to="/clients" className="btn btn-ghost deck-btn">
                  View clients
                </Link>
              </div>
            </div>
          ) : server || serverErr ? (
            <div className="identity-featured identity-featured--offline">
              <div className="identity-offline-art" aria-hidden>
                <Art name="offline" size={120} />
              </div>
              <div className="identity-offline-copy">
                <div className="identity-featured-label">Identity server offline</div>
                <p className="identity-meta" style={{ marginTop: 0 }}>
                  {serverErr || 'Not connected — configure in Settings'}
                </p>
              </div>
              <Link to="/settings?focus=identity-server" className="btn btn-primary deck-btn">
                Connect identity server
              </Link>
            </div>
          ) : (
            <div className="identity-featured identity-featured--loading">
              <SkeletonBlock label="Checking identity server connection" rows={1} />
            </div>
          )}

          <div className="deck-quick-actions">
            {quickActions.map((a) => {
              const Icon = navIcons[a.icon];
              return (
                <Link key={a.path} to={a.path} className="deck-action-card">
                  <span className="deck-action-icon" aria-hidden>
                    <Icon size={22} />
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
            {(server || serverErr) && !planeLoaded && [0, 1, 2, 3].map((i) => <SkeletonBlock key={i} card label="Loading plane status" rows={1} />)}
          </div>

          <ReconcileTimeline conditions={plane?.conditions} phase={plane?.phase} />
        </div>
      </div>
    </ConsoleLayout>
  );
}
