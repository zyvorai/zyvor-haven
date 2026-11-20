// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { Link, useLocation } from 'react-router-dom';
import { useTheme } from '../context/ThemeContext';
import { ZyvorLogo } from './ZyvorLogo';

export function NavBar() {
  const { pathname } = useLocation();
  const { toggle, resolved } = useTheme();
  const isConsole = pathname.startsWith('/deck') || pathname.startsWith('/deploy');

  return (
    <nav className="gnav">
      <div className="gnav-inner">
        <Link to="/" className="gnav-brand">
          <ZyvorLogo className="gnav-logo" />
          <div className="gnav-product">
            <span className="gnav-product-name">Haven</span>
            <span className="gnav-product-sub">Identity plane</span>
          </div>
        </Link>
        <div className="gnav-links">
          <Link to="/" className={pathname === '/' ? 'active' : ''}>
            Overview
          </Link>
          <Link to="/deck" className={isConsole ? 'active' : ''}>
            Console
          </Link>
          <a
            href="https://github.com/zyvorai/haven"
            target="_blank"
            rel="noreferrer"
          >
            GitHub
          </a>
        </div>
        <div className="gnav-actions">
          <button
            type="button"
            className="theme-toggle-btn"
            onClick={toggle}
            aria-label={resolved === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {resolved === 'dark' ? '☀' : '☾'}
          </button>
          <Link to="/login" className="gnav-cta">
            Sign in
          </Link>
        </div>
      </div>
    </nav>
  );
}
