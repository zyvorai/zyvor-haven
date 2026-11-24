// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useEffect, useMemo, useState, type FormEvent } from 'react';
import { Link, Navigate, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ZyvorLogo } from '../components/ZyvorLogo';
import { Art, Mesh } from '../components/graphics/Art';

const STATS = [
  { label: 'Realms', sub: 'tenant boundaries' },
  { label: 'OIDC', sub: 'platform clients' },
  { label: 'Planes', sub: 'live health' },
];

function readLoginDest() {
  if (typeof window === 'undefined') {
    return { host: '', origin: '', port: '', protocol: '' };
  }
  const { hostname, origin, port, protocol } = window.location;
  return {
    host: hostname || 'localhost',
    origin: origin || '',
    port: port || (protocol === 'https:' ? '443' : protocol === 'http:' ? '80' : ''),
    protocol: protocol.replace(':', '') || 'https',
  };
}

export function LoginPage() {
  const { user, ready, signIn, defaultUsername, labHint, oidcLoginUrl } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const from = (location.state as { from?: string } | null)?.from || '/deck';
  const loginDest = useMemo(() => readLoginDest(), []);

  const [username, setUsername] = useState(defaultUsername);
  const [password, setPassword] = useState('');
  const [pending, setPending] = useState(false);
  const [err, setErr] = useState('');

  useEffect(() => {
    setUsername((u) => u || defaultUsername);
  }, [defaultUsername]);

  useEffect(() => {
    document.title = `Sign in · Haven · ${loginDest.host || 'cluster'}`;
    return () => {
      document.title = 'Haven';
    };
  }, [loginDest.host]);

  if (ready && user) {
    return <Navigate to={from} replace />;
  }

  const onSubmit = async (e: FormEvent) => {
    e.preventDefault();
    if (pending || !username || !password) return;
    setPending(true);
    setErr('');
    const ok = await signIn(username, password);
    setPending(false);
    if (ok) navigate(from, { replace: true });
    else setErr('Sign in failed — check username and password.');
  };

  return (
    <div className="login-page">
      <div className="login-backdrop" aria-hidden>
        <Mesh />
      </div>

      <div className="login-shell">
        <div className="login-brand-panel">
          <div className="login-brand-row">
            <ZyvorLogo className="login-logo" />
          </div>
          <h1 className="login-headline">
            Haven.
            <br />
            <span className="login-headline-accent">Identity for the private cloud.</span>
          </h1>
          <p className="login-lede">
            {loginDest.host
              ? `Operate your identity server, realms, and OIDC on ${loginDest.host} — plane health, Atlas topology, and day-2 identity in one place.`
              : 'Operate your identity server, realms, and OIDC clients from one console — plane health, Atlas topology, and day-2 identity in one place.'}
          </p>

          <div className="login-dest" aria-label="This machine">
            <p className="login-dest-kicker">This machine</p>
            <p className="login-dest-host">{loginDest.host || 'localhost'}</p>
            <ul className="login-dest-facts">
              <li>
                <span>Product</span>
                <strong>Haven</strong>
              </li>
              <li>
                <span>Host</span>
                <strong className="login-mono">{loginDest.host || '—'}</strong>
              </li>
              <li>
                <span>Origin</span>
                <strong className="login-mono" title={loginDest.origin}>
                  {loginDest.origin || '—'}
                </strong>
              </li>
              <li>
                <span>Protocol</span>
                <strong className="login-mono">
                  {loginDest.protocol || '—'}
                  {loginDest.port ? ` · ${loginDest.port}` : ''}
                </strong>
              </li>
            </ul>
          </div>

          <div className="login-art" aria-hidden>
            <Art name="shield" size={260} />
          </div>

          <div className="login-stats">
            {STATS.map((s) => (
              <div key={s.label} className="login-stat">
                <div className="login-stat-label">{s.label}</div>
                <div className="login-stat-sub">{s.sub}</div>
              </div>
            ))}
          </div>
        </div>

        <div className="login-card">
          <div className="login-card-mobile-brand">
            <ZyvorLogo className="login-logo-sm" />
            <span>zyvor · Haven</span>
          </div>
          <p className="login-sign-in-context">
            Signing in to <strong>Haven</strong>
            {loginDest.host ? (
              <>
                {' '}
                on <span className="login-apple-host">{loginDest.host}</span>
              </>
            ) : null}
          </p>
          <p className="login-eyebrow">Haven Console</p>
          <h2 className="login-card-title">Sign in to continue</h2>
          <p className="login-card-sub">
            Use single sign-on, console credentials, or an identity server admin account.
          </p>

          {labHint && (
            <div className="login-lab-banner" role="status">
              <span className="login-lab-banner-label">Lab / test</span>
              <span>
                Operator login enabled — use <strong className="login-mono">{labHint}</strong> or
                fill below.
              </span>
            </div>
          )}

          <div className="login-dest login-dest-mobile" aria-label="This machine">
            <p className="login-dest-kicker">This machine</p>
            <ul className="login-dest-facts">
              <li>
                <span>Host</span>
                <strong className="login-mono">{loginDest.host || '—'}</strong>
              </li>
              <li>
                <span>Origin</span>
                <strong className="login-mono" title={loginDest.origin}>
                  {loginDest.origin || '—'}
                </strong>
              </li>
              <li>
                <span>Protocol</span>
                <strong className="login-mono">
                  {loginDest.protocol || '—'}
                  {loginDest.port ? ` · ${loginDest.port}` : ''}
                </strong>
              </li>
            </ul>
          </div>

          {oidcLoginUrl && (
            <div className="login-sso">
              <a className="btn btn-ghost login-sso-btn" href={oidcLoginUrl}>
                Sign in with single sign-on
              </a>
              <div className="login-sso-divider">
                <span>or use a password</span>
              </div>
            </div>
          )}

          <form className="login-form" onSubmit={onSubmit}>
            <label className="login-field">
              <span>Username</span>
              <input
                autoFocus={!oidcLoginUrl}
                autoComplete="username"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
              />
            </label>
            <label className="login-field">
              <span>Password</span>
              <input
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
              />
            </label>
            {err && <p className="login-error">{err}</p>}
            <button
              type="submit"
              className="btn btn-primary login-submit"
              disabled={pending || !username || !password}
            >
              {pending ? 'Signing in…' : 'Sign in'}
            </button>
            {labHint && (
              <button
                type="button"
                className="login-demo"
                onClick={() => {
                  setUsername('demo');
                  setPassword('demo');
                }}
              >
                Lab mode — fill {labHint}
              </button>
            )}
          </form>

          <div className="login-secure">
            Sessions are scoped to this browser and expire automatically.
          </div>
        </div>
      </div>

      <div className="login-footer">
        Haven by Zyvor · <Link to="/">Overview</Link>
        {loginDest.host ? (
          <>
            {' '}
            · <span className="login-mono" title={loginDest.origin}>{loginDest.host}</span>
          </>
        ) : null}
      </div>
    </div>
  );
}
