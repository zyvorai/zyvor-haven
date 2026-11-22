// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import type { ReactNode } from 'react';

type Props = {
  eyebrow?: string;
  title: string;
  subtitle?: string;
  actions?: ReactNode;
};

export function ConsolePageHeader({ eyebrow, title, subtitle, actions }: Props) {
  return (
    <div className="console-page-header">
      <div>
        {eyebrow && <p className="console-eyebrow">{eyebrow}</p>}
        <h1 className="console-page-title">{title}</h1>
        {subtitle && <p className="console-page-subtitle">{subtitle}</p>}
      </div>
      {actions && <div className="console-page-header-actions">{actions}</div>}
    </div>
  );
}
