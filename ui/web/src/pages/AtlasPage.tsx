// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { ConsolePageHeader } from '../components/ConsolePageHeader';
import { api, type KeycloakStatus, type PlaneStatus } from '../api/client';

type NodeState = 'ok' | 'warn' | 'off';

function nodeClass(s: NodeState) {
  return `atlas-node atlas-node--${s}`;
}

/** Animated connector between topology tiers. Dash flow is paused when the target is down. */
function Flow({ state, split }: { state: NodeState; split?: boolean }) {
  return (
    <svg className={`atlas-flow atlas-flow--${state}`} viewBox="0 0 320 44" width="320" height="44" aria-hidden focusable="false" fill="none">
      {split ? (
        <>
          <path d="M160 0v10c0 8-60 8-60 18v16" />
          <path d="M160 0v10c0 8 60 8 60 18v16" />
        </>
      ) : (
        <path d="M160 0v44" />
      )}
    </svg>
  );
}

export function AtlasPage() {
  const [kc, setKc] = useState<KeycloakStatus | null>(null);
  const [plane, setPlane] = useState<PlaneStatus | null>(null);

  useEffect(() => {
    api.keycloakStatus().then(setKc).catch(() => setKc(null));
    api.planeStatus().then(setPlane).catch(() => setPlane(null));
  }, []);

  const consoleState: NodeState = 'ok';
  const kcState: NodeState = kc?.connected ? 'ok' : 'warn';
  const pgState: NodeState =
    plane?.postgres?.ok || plane?.postgres?.value === 'external' ? 'ok' : 'warn';
  const ingressState: NodeState = kc?.connected ? 'ok' : 'off';

  return (
    <ConsoleLayout>
      <div className="console-content">
        <div className="console-content-inner">
          <ConsolePageHeader
            eyebrow="Topology"
            title="Atlas"
            subtitle="How traffic reaches identity — Console → Ingress → Keycloak → Postgres."
            actions={
              <Link to="/planes" className="btn btn-ghost">
                All planes
              </Link>
            }
          />

          <div className="atlas-canvas">
            <div className="atlas-row">
              <div className={nodeClass(consoleState)}>
                <div className="atlas-node-kicker">Control</div>
                <div className="atlas-node-title">Haven Console</div>
                <div className="atlas-node-meta">:30742 · operator UI</div>
              </div>
            </div>
            <div className="atlas-arrow">
              <Flow state={ingressState} />
              <span>↓ Admin API / OIDC</span>
            </div>
            <div className="atlas-row">
              <div className={nodeClass(ingressState)}>
                <div className="atlas-node-kicker">Edge</div>
                <div className="atlas-node-title">Ingress / NodePort</div>
                <div className="atlas-node-meta">
                  {kc?.keycloakUrl ? new URL(kc.keycloakUrl).host : 'Keycloak host'}
                </div>
              </div>
            </div>
            <div className="atlas-arrow">
              <Flow state={kcState} split />
              <span>↓ Issuer</span>
            </div>
            <div className="atlas-row atlas-row--split">
              <div className={nodeClass(kcState)}>
                <div className="atlas-node-kicker">Identity</div>
                <div className="atlas-node-title">Keycloak</div>
                <div className="atlas-node-meta">
                  {kc?.connected
                    ? `v${kc.version} · ${kc.realmCount} realms`
                    : 'Offline — connect in Settings'}
                </div>
              </div>
              <div className={nodeClass(pgState)}>
                <div className="atlas-node-kicker">Data</div>
                <div className="atlas-node-title">Postgres</div>
                <div className="atlas-node-meta">
                  {plane?.postgres?.value ?? '—'} · {plane?.postgres?.meta ?? ''}
                </div>
              </div>
            </div>

            <div className="atlas-legend">
              <span className="atlas-legend-ok">Live</span>
              <span className="atlas-legend-warn">Degraded</span>
              <span className="atlas-legend-off">Unavailable</span>
            </div>
          </div>

          <div className="atlas-links">
            <Link to="/deck">Command Deck</Link>
            <Link to="/realms">Realm Studio</Link>
            <Link to="/clients">Clients</Link>
            <Link to="/settings?focus=keycloak">Settings</Link>
          </div>
        </div>
      </div>
    </ConsoleLayout>
  );
}
