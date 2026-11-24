// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import type { ReactNode } from 'react';
import { Art, type ArtName } from './graphics/Art';

type Props = {
  eyebrow?: string;
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  art?: ArtName;
};

export function ConsolePageHeader({ eyebrow, title, subtitle, actions, art }: Props) {
  return (
    <div className={`console-page-header${art ? ' console-page-header--art' : ''}`}>
      <div className="console-page-header-copy">
        {eyebrow && <p className="console-eyebrow">{eyebrow}</p>}
        <h1 className="console-page-title">{title}</h1>
        {subtitle && <p className="console-page-subtitle">{subtitle}</p>}
      </div>
      {actions && <div className="console-page-header-actions">{actions}</div>}
      {art && (
        <div className="console-page-header-art" aria-hidden>
          <Art name={art} size={188} />
        </div>
      )}
    </div>
  );
}
