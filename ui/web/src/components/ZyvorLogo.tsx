// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useTheme } from '../context/ThemeContext';

/** Zyvor mark that swaps to a light wordmark in dark theme. */
export function ZyvorLogo({ className = '', alt = 'Zyvor' }: { className?: string; alt?: string }) {
  const { resolved } = useTheme();
  const src = resolved === 'dark' ? '/zyvor-logo-dark.png' : '/zyvor-logo.png';
  return <img src={src} alt={alt} className={className} />;
}
