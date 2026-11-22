// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { ConsolePageHeader } from '../components/ConsolePageHeader';
import { PasswordDialog } from '../components/PasswordDialog';
import { useTheme, type ThemeMode } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';
import { api, type KeycloakStatus } from '../api/client';

function labKeycloakURL(): string {
  if (typeof window === 'undefined') return 'http://localhost:30180';
  const { protocol, hostname } = window.location;
  return `${protocol}//${hostname}:30180`;
}

export function SettingsPage() {
  const { mode, setMode } = useTheme();
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [adminUrl, setAdminUrl] = useState('');
  const [keycloakUrl, setKeycloakUrl] = useState('');
  const [adminUser, setAdminUser] = useState('admin');
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState<KeycloakStatus | null>(null);
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [pwMode, setPwMode] = useState<'console' | 'keycloak' | null>(null);

  const labURL = useMemo(() => labKeycloakURL(), []);
  const focusKeycloak = searchParams.get('focus') === 'keycloak';

  useEffect(() => {
    api.keycloakConfig().then((c) => {
      const url = c.keycloakUrl || labURL;
      setKeycloakUrl(url);
      setAdminUser(c.adminUser || 'admin');
      if (url) setAdminUrl(`${url.replace(/\/$/, '')}/admin`);
    });
    api.keycloakStatus().then(setStatus).catch(() => setStatus(null));
  }, [labURL]);

  useEffect(() => {
    if (!focusKeycloak) return;
    const el = document.getElementById('settings-keycloak');
    el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [focusKeycloak]);

  const applyLabDefaults = () => {
    setKeycloakUrl(labURL);
    setAdminUser('admin');
    setPassword('');
    setMsg(`Lab defaults filled — URL ${labURL}. Enter the admin password (often changeme), then Test & connect.`);
    setErr('');
    const next = new URLSearchParams(searchParams);
    next.set('focus', 'keycloak');
    setSearchParams(next, { replace: true });
  };

  const connect = async () => {
    setBusy(true);
    setErr('');
    setMsg('');
    try {
      const st = await api.connectKeycloak({
        keycloakUrl: keycloakUrl.replace(/\/$/, ''),
        adminUser,
        password,
        consoleUrl: typeof window !== 'undefined' ? window.location.origin : undefined,
      });
      setStatus(st);
      setAdminUrl(`${keycloakUrl.replace(/\/$/, '')}/admin`);
      setPassword('');
      setMsg(`Connected — Keycloak ${st.version ?? ''} · ${st.realmCount} realm(s)`);
      if (focusKeycloak) {
        const next = new URLSearchParams(searchParams);
        next.delete('focus');
        setSearchParams(next, { replace: true });
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Connection failed');
      setStatus(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <ConsoleLayout>
        <div className="console-content">
          <div className="console-content-inner">
            <ConsolePageHeader
              eyebrow="Configuration"
              title="Settings"
              subtitle="Connect Haven to Keycloak from the UI — no SSH required for day-2 reconnect."
            />

          <section className="card settings-card">
            <h2>Appearance</h2>
            <p className="settings-desc">Choose light, dark, or match your system preference.</p>
            <div className="theme-segmented" role="group" aria-label="Theme">
              {(['light', 'dark', 'system'] as ThemeMode[]).map((m) => (
                <button
                  key={m}
                  type="button"
                  className={`theme-segment ${mode === m ? 'active' : ''}`}
                  onClick={() => setMode(m)}
                >
                  {m.charAt(0).toUpperCase() + m.slice(1)}
                </button>
              ))}
            </div>
          </section>

          <section className="card settings-card">
            <h2>Passwords</h2>
            <p className="settings-desc">
              Change Haven console sign-in or the Keycloak master admin password.
              Realm users: open Realm Studio → Users → Set password.
            </p>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setPwMode('console')}
                disabled={user?.auth === 'lab'}
                title={user?.auth === 'lab' ? 'Lab demo account cannot change password' : undefined}
              >
                Change console password
              </button>
              <button
                type="button"
                className="btn btn-ghost"
                onClick={() => setPwMode('keycloak')}
                disabled={!status?.connected}
              >
                Change Keycloak admin password
              </button>
            </div>
            {user?.auth === 'lab' && (
              <p style={{ marginTop: 12, fontSize: 13, color: 'var(--zy-muted)' }}>
                Signed in as lab demo — sign in as Keycloak admin to change console password, or use
                Keycloak admin password below.
              </p>
            )}
          </section>

          <section
            id="settings-keycloak"
            className={`card settings-card${focusKeycloak ? ' settings-card-focus' : ''}`}
          >
            <h2>Keycloak connection</h2>
            <p className="settings-desc">
              Point Haven at any reachable Keycloak Admin API. Credentials stay on the Haven server —
              the browser never stores your admin password.
            </p>

            {!status?.connected && (
              <div className="settings-offline-hint" role="status">
                <strong>Keycloak offline</strong>
                <p>
                  Realm Studio and Clients need a live Admin API. For this host, lab Keycloak is usually
                  on port <code>30180</code>. Fill lab defaults, enter the admin password, then connect.
                </p>
                <button type="button" className="btn btn-ghost" onClick={applyLabDefaults}>
                  Use lab defaults ({labURL})
                </button>
              </div>
            )}

            {status?.connected && (
              <div className="settings-online-hint" role="status">
                Connected to {status.keycloakUrl} · v{status.version} · {status.realmCount} realms
              </div>
            )}

            <div className="wizard-field">
              <label htmlFor="kc-url">Keycloak URL</label>
              <input
                id="kc-url"
                value={keycloakUrl}
                onChange={(e) => setKeycloakUrl(e.target.value)}
                placeholder={labURL}
                autoFocus={focusKeycloak}
              />
              <span className="settings-field-hint">
                Examples: <code>{labURL}</code> · <code>http://keycloak.identity.svc:8080</code>
              </span>
            </div>
            <div className="wizard-field">
              <label htmlFor="kc-user">Admin username</label>
              <input
                id="kc-user"
                value={adminUser}
                onChange={(e) => setAdminUser(e.target.value)}
                placeholder="admin"
              />
            </div>
            <div className="wizard-field">
              <label htmlFor="kc-pass">Admin password</label>
              <input
                id="kc-pass"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={status?.connected ? '••••••••' : 'Required to connect'}
              />
            </div>

            <div className="settings-actions">
              <button
                type="button"
                className="btn btn-primary"
                disabled={busy || !keycloakUrl || !password}
                onClick={connect}
              >
                {busy ? 'Connecting…' : 'Test & connect'}
              </button>
              <button type="button" className="btn btn-ghost" onClick={applyLabDefaults}>
                Fill lab defaults
              </button>
            </div>

            {err && <p className="settings-err">{err}</p>}
            {msg && <p className="settings-ok">{msg}</p>}
          </section>

          <section className="card settings-card">
            <h2>Advanced</h2>
            <p className="settings-desc">
              Use the Keycloak SPI console only for low-level provider configuration and debugging.
            </p>
            {adminUrl ? (
              <a
                href={adminUrl}
                target="_blank"
                rel="noreferrer"
                className="btn btn-ghost"
                style={{ fontSize: 13 }}
              >
                Open Keycloak SPI console ↗
              </a>
            ) : (
              <span style={{ color: 'var(--zy-muted)', fontSize: 13 }}>
                Connect Keycloak above to enable
              </span>
            )}
          </section>
          </div>
        </div>

      <PasswordDialog
        open={pwMode === 'console'}
        title="Change console password"
        subtitle={`Updates Haven sign-in for ${user?.name ?? 'this account'} (until pod restart unless persisted in secret).`}
        requireCurrent
        confirmLabel="Update console password"
        onCancel={() => setPwMode(null)}
        onSubmit={async ({ currentPassword, newPassword }) => {
          const res = await api.changeConsolePassword(currentPassword!, newPassword);
          setPwMode(null);
          setMsg(res.note ?? 'Console password updated.');
        }}
      />

      <PasswordDialog
        open={pwMode === 'keycloak'}
        title="Change Keycloak admin password"
        subtitle={`Resets master-realm password for ${adminUser} and reconnects Haven.`}
        requireCurrent
        confirmLabel="Update Keycloak admin"
        onCancel={() => setPwMode(null)}
        onSubmit={async ({ currentPassword, newPassword }) => {
          const res = await api.changeKeycloakAdminPassword(currentPassword!, newPassword);
          setPwMode(null);
          setMsg(res.note ?? 'Keycloak admin password updated.');
        }}
      />
    </ConsoleLayout>
  );
}
