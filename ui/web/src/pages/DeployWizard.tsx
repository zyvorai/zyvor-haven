// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { api, type PlaneCapabilities } from '../api/client';

type Audience = 'platform' | 'application' | 'both';
type Durability = 'dev' | 'staging' | 'production';

export function DeployWizard() {
  const nav = useNavigate();
  const [audience, setAudience] = useState<Audience>('platform');
  const [durability, setDurability] = useState<Durability>('production');
  const [hostname, setHostname] = useState('auth.cloud.internal');
  const [routing, setRouting] = useState('gateway');
  const [adminEmail, setAdminEmail] = useState('admin@cloud.internal');
  const [realm, setRealm] = useState('platform');
  const [toast, setToast] = useState('');
  const [busy, setBusy] = useState(false);
  const [caps, setCaps] = useState<PlaneCapabilities | null>(null);

  useEffect(() => {
    api.planeCapabilities().then(setCaps).catch(() =>
      setCaps({ inCluster: false, canCreatePlane: false, plane: 'platform', namespace: 'identity' }),
    );
  }, []);

  const canCreatePlane = !!caps?.canCreatePlane;
  const kcInstances = durability === 'dev' ? 1 : durability === 'staging' ? 2 : 3;
  const pgInstances = kcInstances;

  const summary = canCreatePlane
    ? durability === 'production'
      ? 'Creates an IdentityPlane CR — controller provisions HA Postgres + haven-idp when operators are installed.'
      : durability === 'staging'
        ? 'Creates an IdentityPlane CR with staging profile (2 instances, NetworkPolicy).'
        : 'Creates an IdentityPlane CR with the dev profile (single instances).'
    : 'Console cannot create IdentityPlanes — this run bootstraps a realm + haven-console client only. Apply a sample CR or grant create RBAC for full plane deploy.';

  const handleDeploy = async () => {
    setBusy(true);
    setToast('');
    try {
      if (canCreatePlane) {
        const created = await api.createPlane({
          profile: durability,
          hostname,
          exposeClass: routing,
          adminEmail,
          firstRealm: realm,
          audience,
        });
        setToast(`IdentityPlane ${created.namespace}/${created.name} created`);
        setTimeout(() => nav('/deck'), 1200);
        return;
      }

      await api.createRealm({
        realm,
        displayName: realm,
        enabled: true,
      });
      await api.createClient(realm, {
        clientId: 'haven-console',
        name: 'Haven Console',
        enabled: true,
        publicClient: true,
        protocol: 'openid-connect',
        standardFlowEnabled: true,
        redirectUris: [
          `https://${hostname}/*`,
          `http://${hostname}/*`,
          'http://*/*',
          'https://*/*',
        ],
        webOrigins: ['+'],
      });
      if (adminEmail) {
        const username = adminEmail.split('@')[0] || 'admin';
        await api.createUser(realm, {
          username,
          email: adminEmail,
          enabled: true,
          emailVerified: true,
        });
      }
      setToast(
        `Realm "${realm}" bootstrapped — plane CR needs cluster write RBAC or kubectl apply of the sample IdentityPlane`,
      );
      setTimeout(() => nav(`/realms/${encodeURIComponent(realm)}`), 1500);
    } catch (e) {
      setToast(e instanceof Error ? e.message : 'Deploy failed');
    } finally {
      setBusy(false);
    }
  };

  const title = canCreatePlane ? 'Deploy identity plane' : 'Bootstrap first realm';
  const cta = canCreatePlane
    ? busy
      ? 'Creating plane…'
      : 'Create IdentityPlane →'
    : busy
      ? 'Bootstrapping…'
      : 'Bootstrap realm →';

  return (
    <ConsoleLayout>
        <div className="wizard-layout">
          <div className="wizard-steps">
            <div className="deck-hero" style={{ marginBottom: 'var(--zy-s6)' }}>
              <p className="deck-eyebrow">Product Wizards</p>
              <h1 className="deck-title" style={{ fontSize: '1.75rem' }}>{title}</h1>
              {caps && !canCreatePlane && (
                <p className="deck-subtitle" style={{ marginTop: 8 }}>
                  {caps.message || 'Realm bootstrap mode — IdentityPlane create unavailable.'}
                </p>
              )}
            </div>
            <div className="wizard-step active done">
              <div className="wizard-step-num">1</div>
              <div>
                <div className="wizard-step-title">Who is this for?</div>
                <div className="wizard-options">
                  {(
                    [
                      ['platform', 'Platform SSO', 'Kubernetes, Grafana, Argo, Zeus OS'],
                      ['application', 'Application tenants', 'B2B realms for workloads'],
                      ['both', 'Both', 'Platform SSO plus tenant realms'],
                    ] as const
                  ).map(([id, titleOpt, desc]) => (
                    <div
                      key={id}
                      className={`wizard-option ${audience === id ? 'selected' : ''}`}
                      onClick={() => setAudience(id)}
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => e.key === 'Enter' && setAudience(id)}
                    >
                      <div className="wizard-option-title">{titleOpt}</div>
                      <div className="wizard-option-desc">{desc}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className={`wizard-step active done${canCreatePlane ? '' : ' wizard-step-muted'}`}>
              <div className="wizard-step-num">2</div>
              <div>
                <div className="wizard-step-title">
                  How durable?{!canCreatePlane ? ' (informational)' : ''}
                </div>
                <div className="wizard-options">
                  {(
                    [
                      ['dev', 'Dev 1+1', '1 Postgres, 1 identity server, disposable'],
                      ['staging', 'Staging 2+2', '2 instances, daily backup'],
                      ['production', 'Production 3+3', '3 pods across 3 nodes, PITR'],
                    ] as const
                  ).map(([id, titleOpt, desc]) => (
                    <div
                      key={id}
                      className={`wizard-option ${durability === id ? 'selected' : ''}`}
                      onClick={() => setDurability(id)}
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => e.key === 'Enter' && setDurability(id)}
                    >
                      <div className="wizard-option-title">{titleOpt}</div>
                      <div className="wizard-option-desc">{desc}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className={`wizard-step active done${canCreatePlane ? '' : ' wizard-step-muted'}`}>
              <div className="wizard-step-num">3</div>
              <div>
                <div className="wizard-step-title">
                  How do people reach it?{!canCreatePlane ? ' (informational)' : ''}
                </div>
                <div className="wizard-field">
                  <label htmlFor="hostname">Hostname</label>
                  <input
                    id="hostname"
                    value={hostname}
                    onChange={(e) => setHostname(e.target.value)}
                  />
                </div>
                <div className="wizard-field">
                  <label htmlFor="routing">Routing type</label>
                  <select
                    id="routing"
                    value={routing}
                    onChange={(e) => setRouting(e.target.value)}
                    disabled={!canCreatePlane}
                  >
                    <option value="gateway">Gateway API</option>
                    <option value="ingress">Ingress</option>
                    <option value="none">None (cluster-internal)</option>
                  </select>
                </div>
              </div>
            </div>

            <div className="wizard-step active">
              <div className="wizard-step-num">4</div>
              <div>
                <div className="wizard-step-title">Who signs in first?</div>
                <div className="wizard-field">
                  <label htmlFor="email">Admin email</label>
                  <input
                    id="email"
                    type="email"
                    value={adminEmail}
                    onChange={(e) => setAdminEmail(e.target.value)}
                  />
                </div>
                <div className="wizard-field">
                  <label htmlFor="realm">First realm</label>
                  <input
                    id="realm"
                    value={realm}
                    onChange={(e) => setRealm(e.target.value)}
                  />
                </div>
              </div>
            </div>
          </div>

          <aside className="wizard-preview">
            <div className="wizard-preview-title">Live preview</div>
            <div className="preview-stack">
              <div className="preview-node">
                <div className="preview-node-title">
                  Gateway ({routing === 'gateway' ? 'Gateway API' : routing === 'ingress' ? 'Ingress' : 'internal'})
                </div>
              </div>
              <div className="preview-arrow">↓</div>
              <div className="preview-node">
                <div className="preview-node-title">
                  Identity server ({kcInstances} pod{kcInstances > 1 ? 's' : ''})
                </div>
                <div className="preview-pods">
                  {Array.from({ length: kcInstances }).map((_, i) => (
                    <div key={i} className="preview-pod">
                      pod
                    </div>
                  ))}
                </div>
              </div>
              <div className="preview-arrow">↓</div>
              <div className="preview-node">
                <div className="preview-node-title">
                  CloudNativePG ({pgInstances} instance
                  {pgInstances > 1 ? 's' : ''})
                </div>
                <div className="preview-pods">
                  {Array.from({ length: pgInstances }).map((_, i) => (
                    <div key={i} className="preview-pod">
                      db
                    </div>
                  ))}
                </div>
              </div>
            </div>
            <div className="preview-summary">{summary}</div>
            <div
              style={{
                marginTop: 16,
                fontSize: 12,
                color: 'var(--zy-muted)',
                fontFamily: 'var(--zy-mono)',
              }}
            >
              {hostname} · realm/{realm} · {audience}
              {caps ? ` · ${canCreatePlane ? 'plane create' : 'realm bootstrap'}` : ''}
            </div>
          </aside>
        </div>

        <footer className="wizard-footer">
          <button type="button" className="btn btn-ghost" style={{ padding: '8px 20px' }} onClick={() => nav(-1)}>
            Back
          </button>
          <div className="wizard-progress">
            <div className="wizard-progress-fill" style={{ width: '100%' }} />
          </div>
          <button
            type="button"
            className="btn btn-primary"
            style={{ padding: '8px 24px' }}
            onClick={handleDeploy}
            disabled={busy || !realm || !hostname}
          >
            {cta}
          </button>
        </footer>

      {toast && (
        <div className="toast" role="status">
          {toast}
        </div>
      )}
    </ConsoleLayout>
  );
}
