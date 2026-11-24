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

export type ThemeMode = 'light' | 'dark' | 'system';

type ThemeContextValue = {
  mode: ThemeMode;
  resolved: 'light' | 'dark';
  setMode: (mode: ThemeMode) => void;
  toggle: () => void;
};

const STORAGE_KEY = 'haven-theme';

const ThemeContext = createContext<ThemeContextValue | null>(null);

function systemDark() {
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function resolve(mode: ThemeMode): 'light' | 'dark' {
  if (mode === 'system') return systemDark() ? 'dark' : 'light';
  return mode;
}

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(() => {
    const saved = localStorage.getItem(STORAGE_KEY) as ThemeMode | null;
    return saved ?? 'system';
  });

  const [sysTick, setSysTick] = useState(0);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const resolved = useMemo(() => resolve(mode), [mode, sysTick]);

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', resolved);
    localStorage.setItem(STORAGE_KEY, mode);
  }, [mode, resolved]);

  useEffect(() => {
    if (mode !== 'system') return;
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const onChange = () => {
      document.documentElement.setAttribute('data-theme', resolve('system'));
      setSysTick((n) => n + 1);
    };
    mq.addEventListener('change', onChange);
    return () => mq.removeEventListener('change', onChange);
  }, [mode]);

  const setMode = useCallback((m: ThemeMode) => setModeState(m), []);

  const toggle = useCallback(() => {
    setModeState((prev) => {
      const current = resolve(prev);
      return current === 'dark' ? 'light' : 'dark';
    });
  }, []);

  const value = useMemo(
    () => ({ mode, resolved, setMode, toggle }),
    [mode, resolved, setMode, toggle],
  );

  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error('useTheme must be used within ThemeProvider');
  return ctx;
}
