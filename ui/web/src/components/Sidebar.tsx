// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { Link, useLocation } from 'react-router-dom';
import { useEffect, useState } from 'react';
import { sidebarNav } from '../data/mock';
import { api, type IdentityServerStatus, type PlaneStatus } from '../api/client';
import { ZyvorLogo } from './ZyvorLogo';
import {
  IconChevronLeft,
  IconChevronRight,
  navIcons,
} from './NavIcons';

const STORAGE_KEY = 'haven-sidebar-collapsed';

function readCollapsed(): boolean {
  try {
    return localStorage.getItem(STORAGE_KEY) === '1';
  } catch {
    return false;
  }
}

export function Sidebar() {
  const { pathname } = useLocation();
  const [server, setServer] = useState<IdentityServerStatus | null>(null);
  const [plane, setPlane] = useState<PlaneStatus | null>(null);
  const [collapsed, setCollapsed] = useState(readCollapsed);

  useEffect(() => {
    api.identityServerStatus().then(setServer).catch(() => setServer(null));
    api.planeStatus().then(setPlane).catch(() => setPlane(null));
  }, [pathname]);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, collapsed ? '1' : '0');
    } catch {
      /* ignore */
    }
  }, [collapsed]);

  const statusLabel = server?.connected
    ? `Connected · v${server.version ?? '—'}`
    : 'Identity server offline';
  const statusDetail =
    server?.connected
      ? `${server.realmCount} realm${server.realmCount === 1 ? '' : 's'}${plane?.phase ? ` · ${plane.phase}` : ''}`
      : '';

  return (
    <aside className={`sidebar${collapsed ? ' is-collapsed' : ''}`} aria-label="Console navigation">
      <div className="sidebar-brand">
        <div className="sidebar-brand-row">
          <a href="https://zyvor.dev" target="_blank" rel="noreferrer" title="Zyvor">
            <ZyvorLogo className="sidebar-logo" />
          </a>
          <button
            type="button"
            className="sidebar-collapse-btn"
            onClick={() => setCollapsed((c) => !c)}
            aria-expanded={!collapsed}
            aria-controls="haven-sidebar-nav"
            title={collapsed ? 'Expand menu' : 'Collapse menu'}
            aria-label={collapsed ? 'Expand menu' : 'Collapse menu'}
          >
            {collapsed ? <IconChevronRight /> : <IconChevronLeft />}
          </button>
        </div>
        <div className="sidebar-brand-text">
          <div className="sidebar-product">Haven</div>
          <div className="sidebar-sub">Identity console</div>
        </div>
      </div>
      <nav id="haven-sidebar-nav" className="sidebar-nav">
        {sidebarNav.map((item) => {
          const active =
            pathname === item.path || pathname.startsWith(`${item.path}/`);
          const Icon = navIcons[item.icon];
          return (
            <Link
              key={item.label}
              to={item.path}
              className={`sidebar-link ${active ? 'active' : ''}`}
              title={item.label}
              aria-label={item.label}
            >
              <span className="sidebar-link-icon" aria-hidden>
                <Icon />
              </span>
              <span className="sidebar-link-label">{item.label}</span>
            </Link>
          );
        })}
      </nav>
      <div
        className="sidebar-status"
        title={statusDetail ? `${statusLabel} · ${statusDetail}` : statusLabel}
      >
        <span
          className="sidebar-status-dot"
          style={{ background: server?.connected ? 'var(--zy-ok)' : 'var(--zy-warn)' }}
        />
        <div className="sidebar-status-text">
          <span
            className="sidebar-status-label"
            style={{ color: server?.connected ? 'var(--zy-ok)' : 'var(--zy-warn)' }}
          >
            {statusLabel}
          </span>
          {server?.connected && statusDetail && (
            <div className="sidebar-uptime">{statusDetail}</div>
          )}
        </div>
      </div>
    </aside>
  );
}
