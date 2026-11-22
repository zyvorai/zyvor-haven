// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import { api, getToken, setToken } from '../api/client';

export type AuthUser = {
  name: string;
  role: string;
  auth: string;
  initials: string;
};

type AuthContextValue = {
  user: AuthUser | null;
  ready: boolean;
  defaultUsername: string;
  labHint: string | null;
  oidcLoginUrl: string | null;
  signIn: (username: string, password: string) => Promise<boolean>;
  signOut: () => Promise<void>;
};

const AuthContext = createContext<AuthContextValue | null>(null);

function initials(name: string) {
  return (
    name
      .split(/[\s.@_-]+/)
      .filter(Boolean)
      .slice(0, 2)
      .map((p) => p[0]?.toUpperCase())
      .join('') || '?'
  );
}

function consumeHavenTokenFromURL() {
  if (typeof window === 'undefined') return;
  const params = new URLSearchParams(window.location.search);
  const tok = params.get('haven_token');
  if (!tok) return;
  setToken(tok);
  params.delete('haven_token');
  params.delete('sso');
  const next = `${window.location.pathname}${params.toString() ? `?${params}` : ''}${window.location.hash}`;
  window.history.replaceState({}, '', next || window.location.pathname);
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<AuthUser | null>(null);
  const [ready, setReady] = useState(false);
  const [defaultUsername, setDefaultUsername] = useState('admin');
  const [labHint, setLabHint] = useState<string | null>(null);
  const [oidcLoginUrl, setOidcLoginUrl] = useState<string | null>(null);

  const loadSession = useCallback(async () => {
    if (!getToken()) {
      setUser(null);
      return false;
    }
    try {
      const s = await api.authSession();
      setUser({
        name: s.user,
        role: s.role,
        auth: s.auth,
        initials: initials(s.user),
      });
      return true;
    } catch {
      setToken(null);
      setUser(null);
      return false;
    }
  }, []);

  useEffect(() => {
    (async () => {
      consumeHavenTokenFromURL();
      try {
        const p = await api.authProviders();
        if (p.local?.default_username) setDefaultUsername(p.local.default_username);
        setLabHint(p.lab?.operator_login ? p.lab.hint ?? 'demo / demo' : null);
        setOidcLoginUrl(p.oidc?.enabled && p.oidc.login_url ? p.oidc.login_url : null);
      } catch {
        /* ignore */
      }
      await loadSession();
      setReady(true);
    })();
  }, [loadSession]);

  const signIn = useCallback(
    async (username: string, password: string) => {
      try {
        const res = await api.authLogin(username, password);
        setToken(res.token);
        setUser({
          name: res.user,
          role: res.role,
          auth: res.auth,
          initials: initials(res.user),
        });
        return true;
      } catch {
        setToken(null);
        setUser(null);
        return false;
      }
    },
    [],
  );

  const signOut = useCallback(async () => {
    try {
      await api.authLogout();
    } catch {
      /* ignore */
    }
    setToken(null);
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({ user, ready, defaultUsername, labHint, oidcLoginUrl, signIn, signOut }),
    [user, ready, defaultUsername, labHint, oidcLoginUrl, signIn, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
