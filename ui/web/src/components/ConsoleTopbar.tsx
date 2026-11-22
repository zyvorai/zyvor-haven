// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import type { ReactNode } from 'react';

type Props = {
  realm?: string;
  onOpenPalette?: () => void;
  trailing?: ReactNode;
};

export function ConsoleTopbar({ realm = 'platform', onOpenPalette, trailing }: Props) {
  return (
    <header className="console-topbar">
      <div className="console-topbar-realm">
        <span className="console-topbar-realm-dot" aria-hidden />
        <span>{realm}</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        {trailing}
        {onOpenPalette && (
          <button type="button" className="console-palette-btn" onClick={onOpenPalette}>
            Command Palette
            <kbd>⌘K</kbd>
          </button>
        )}
      </div>
    </header>
  );
}
