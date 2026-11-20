// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { Link } from 'react-router-dom';
import { ZyvorLogo } from './ZyvorLogo';

export function Footer() {
  return (
    <footer className="site-footer">
      <div className="wrap footer-inner">
        <div className="footer-brand">
          <a href="https://zyvor.dev" target="_blank" rel="noreferrer">
            <ZyvorLogo className="footer-logo" />
          </a>
          <div>
            <div className="footer-meta">Haven by Zyvor</div>
            <div className="footer-meta">Zyvor Production License</div>
          </div>
        </div>
        <div className="footer-links">
          <a
            href="https://github.com/zyvorai/haven"
            target="_blank"
            rel="noreferrer"
          >
            GitHub
          </a>
          <Link to="/deck">Console</Link>
          <Link to="/realms">Realm Studio</Link>
        </div>
      </div>
    </footer>
  );
}
