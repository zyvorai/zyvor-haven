// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { Link, useLocation } from 'react-router-dom';
import { ZyvorLogo } from './ZyvorLogo';

const mobileLinks = [
  { path: '/deck', label: 'Deck' },
  { path: '/planes', label: 'Planes' },
  { path: '/atlas', label: 'Atlas' },
  { path: '/realms', label: 'Realms' },
  { path: '/settings', label: 'Settings' },
];

export function ConsoleMobileNav() {
  const { pathname } = useLocation();

  return (
    <nav className="console-mobile-nav" aria-label="Console navigation">
      <div className="console-mobile-brand">
        <a href="https://zyvor.dev" target="_blank" rel="noreferrer">
          <ZyvorLogo />
        </a>
        <span className="console-mobile-brand-name">Haven</span>
      </div>
      <div className="console-mobile-pills">
        {mobileLinks.map((item) => (
          <Link
            key={item.path}
            to={item.path}
            className={`console-mobile-pill ${
              pathname === item.path || pathname.startsWith(item.path + '/')
                ? 'active'
                : ''
            }`}
          >
            {item.label}
          </Link>
        ))}
      </div>
    </nav>
  );
}
