// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { Link, useParams } from 'react-router-dom';

const tabs = [
  { id: 'overview', label: 'Overview' },
  { id: 'clients', label: 'Clients' },
  { id: 'users', label: 'Users' },
  { id: 'roles', label: 'Roles' },
  { id: 'idps', label: 'IdPs' },
  { id: 'events', label: 'Events' },
] as const;

export type RealmTab = (typeof tabs)[number]['id'];

interface RealmTabsProps {
  active: RealmTab;
}

export function RealmTabs({ active }: RealmTabsProps) {
  const { realm = '' } = useParams();
  return (
    <nav className="realm-tabs">
      {tabs.map((t) => (
        <Link
          key={t.id}
          to={`/realms/${encodeURIComponent(realm)}?tab=${t.id}`}
          className={`realm-tab ${active === t.id ? 'active' : ''}`}
        >
          {t.label}
        </Link>
      ))}
    </nav>
  );
}
