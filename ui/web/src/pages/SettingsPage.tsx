// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { ConsolePageHeader } from '../components/ConsolePageHeader';
import { PasswordDialog } from '../components/PasswordDialog';
import { useTheme, type ThemeMode } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';
import { api, type IdentityServerStatus } from '../api/client';

// Lab identity server default URL.
function labIdentityServerURL(): string {
  if (typeof window === 'undefined') return 'http://localhost:30180';
  const { protocol, hostname } = window.location;
  return `${protocol}//${hostname}:30180`;
}

export function SettingsPage() {
  const { mode, setMode } = useTheme();
  const { user } = useAuth();
  const [searchParams, setSearchParams] = useSearchParams();
  const [adminUrl, setAdminUrl] = useState('');
  const [identityServerUrl, setIdentityServerUrl] = useState('');
  const [adminUser, setAdminUser] = useState('admin');
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState<IdentityServerStatus | null>(null);
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);
  const [pwMode, setPwMode] = useState<'console' | 'identity-server' | null>(null);

  const labURL = useMemo(() => labIdentityServerURL(), []);
  const focusIdentityServer = searchParams.get('focus') === 'identity-server';

  useEffect(() => {
    api.identityServerConfig().then((c) => {
      const url = c.identityServerUrl || labURL;
      setIdentityServerUrl(url);
      setAdminUser(c.adminUser || 'admin');
      if (url) setAdminUrl(`${url.replace(/\/$/, '')}/admin`);
    });
    api.identityServerStatus().then(setStatus).catch(() => setStatus(null));
  }, [labURL]);

  useEffect(() => {
    if (!focusIdentityServer) return;
    const el = document.getElementById('settings-identity-server');
    el?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [focusIdentityServer]);

  const applyLabDefaults = () => {
    setIdentityServerUrl(labURL);
    setAdminUser('admin');
    setPassword('');
    setMsg(`Lab defaults filled — URL ${labURL}. Enter the admin password (often changeme), then Test & connect.`);
    setErr('');
    const next = new URLSearchParams(searchParams);
    next.set('focus', 'identity-server');
    setSearchParams(next, { replace: true });
  };

  const connect = async () => {
    setBusy(true);
    setErr('');
    setMsg('');
    try {
      const st = await api.connectIdentityServer({
        identityServerUrl: identityServerUrl.replace(/\/$/, ''),
        adminUser,
        password,
        consoleUrl: typeof window !== 'undefined' ? window.location.origin : undefined,
      });
      setStatus(st);
      setAdminUrl(`${identityServerUrl.replace(/\/$/, '')}/admin`);
      setPassword('');
      setMsg(`Connected — identity server ${st.version ?? ''} · ${st.realmCount} realm(s)`);
      if (focusIdentityServer) {
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
              subtitle="Connect Haven to your identity server from the UI — no SSH required for day-2 reconnect."
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
              Change Haven console sign-in or the identity server admin password.
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
                onClick={() => setPwMode('identity-server')}
                disabled={!status?.connected}
              >
                Change identity server admin password
              </button>
            </div>
            {user?.auth === 'lab' && (
              <p style={{ marginTop: 12, fontSize: 13, color: 'var(--zy-muted)' }}>
                Signed in as lab demo — sign in as an identity server admin to change the console password, or use
                the identity server admin password below.
              </p>
            )}
          </section>

          <section
            id="settings-identity-server"
            className={`card settings-card${focusIdentityServer ? ' settings-card-focus' : ''}`}
          >
            <h2>Identity server connection</h2>
            <p className="settings-desc">
              Point Haven at any reachable identity server admin API. Credentials stay on the Haven server —
              the browser never stores your admin password.
            </p>

            {!status?.connected && (
              <div className="settings-offline-hint" role="status">
                <strong>Identity server offline</strong>
                <p>
                  Realm Studio and Clients need a live admin API. For this host, the lab identity server is usually
                  on port <code>30180</code>. Fill lab defaults, enter the admin password, then connect.
                </p>
                <button type="button" className="btn btn-ghost" onClick={applyLabDefaults}>
                  Use lab defaults ({labURL})
                </button>
              </div>
            )}

            {status?.connected && (
              <div className="settings-online-hint" role="status">
                Connected to {status.identityServerUrl} · v{status.version} · {status.realmCount} realms
              </div>
            )}

            <div className="wizard-field">
              <label htmlFor="server-url">Identity server URL</label>
              <input
                id="server-url"
                value={identityServerUrl}
                onChange={(e) => setIdentityServerUrl(e.target.value)}
                placeholder={labURL}
                autoFocus={focusIdentityServer}
              />
              <span className="settings-field-hint">
                Examples: <code>{labURL}</code> · <code>http://haven-idp.identity.svc:8080</code>
              </span>
            </div>
            <div className="wizard-field">
              <label htmlFor="server-user">Admin username</label>
              <input
                id="server-user"
                value={adminUser}
                onChange={(e) => setAdminUser(e.target.value)}
                placeholder="admin"
              />
            </div>
            <div className="wizard-field">
              <label htmlFor="server-pass">Admin password</label>
              <input
                id="server-pass"
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
                disabled={busy || !identityServerUrl || !password}
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
              Use the identity server admin console only for low-level configuration and debugging.
            </p>
            {adminUrl ? (
              <a
                href={adminUrl}
                target="_blank"
                rel="noreferrer"
                className="btn btn-ghost"
                style={{ fontSize: 13 }}
              >
                Open identity server admin console ↗
              </a>
            ) : (
              <span style={{ color: 'var(--zy-muted)', fontSize: 13 }}>
                Connect the identity server above to enable
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
        open={pwMode === 'identity-server'}
        title="Change identity server admin password"
        subtitle={`Resets admin password for ${adminUser} and reconnects Haven.`}
        requireCurrent
        confirmLabel="Update identity server admin"
        onCancel={() => setPwMode(null)}
        onSubmit={async ({ currentPassword, newPassword }) => {
          const res = await api.changeIdentityServerAdminPassword(currentPassword!, newPassword);
          setPwMode(null);
          setMsg(res.note ?? 'Identity server admin password updated.');
        }}
      />
    </ConsoleLayout>
  );
}
