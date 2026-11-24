// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useEffect, useState, type ReactNode } from 'react';
import { useNavigate } from 'react-router-dom';
import { Sidebar } from './Sidebar';
import { ConsoleMobileNav } from './ConsoleMobileNav';
import { ConsoleTopbar } from './ConsoleTopbar';
import { CommandPalette, useCommandPalette } from './CommandPalette';
import { useTheme } from '../context/ThemeContext';
import { useAuth } from '../context/AuthContext';
import { IconMoon, IconSun } from './NavIcons';

type Props = {
  children: ReactNode;
  realm?: string;
  trailing?: ReactNode;
  hideTopbar?: boolean;
};

export function ConsoleLayout({ children, realm, trailing, hideTopbar }: Props) {
  const { open, setOpen } = useCommandPalette();
  const { toggle, resolved } = useTheme();
  const { user, signOut } = useAuth();
  const navigate = useNavigate();
  const [toast, setToast] = useState('');

  useEffect(() => {
    if (!toast) return;
    const t = window.setTimeout(() => setToast(''), 2800);
    return () => window.clearTimeout(t);
  }, [toast]);

  return (
    <div className="console-layout">
      <ConsoleMobileNav />
      <Sidebar />
      <div className="console-main">
        {!hideTopbar && (
          <ConsoleTopbar
            realm={realm}
            onOpenPalette={() => setOpen(true)}
            trailing={
              <>
                {trailing}
                {user && (
                  <div className="console-user">
                    <span className="console-user-chip" title={`${user.name} · ${user.role}`}>
                      {user.initials}
                    </span>
                    <button
                      type="button"
                      className="console-signout"
                      onClick={async () => {
                        await signOut();
                        navigate('/login');
                      }}
                    >
                      Sign out
                    </button>
                  </div>
                )}
                <button
                  type="button"
                  className="theme-toggle-btn"
                  onClick={toggle}
                  aria-label={resolved === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
                  title={resolved === 'dark' ? 'Light mode' : 'Dark mode'}
                >
                  {resolved === 'dark' ? <IconSun size={18} /> : <IconMoon size={18} />}
                </button>
              </>
            }
          />
        )}
        {children}
      </div>
      <CommandPalette
        open={open}
        onClose={() => setOpen(false)}
        onNavigate={(path) => navigate(path)}
        onShell={(hint) => setToast(hint ?? 'Coming soon')}
      />
      {toast && (
        <div className="console-toast" role="status">
          {toast}
        </div>
      )}
    </div>
  );
}
