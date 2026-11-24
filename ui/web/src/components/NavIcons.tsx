// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import type { ReactNode, SVGProps } from 'react';

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function Icon({ size = 18, children, ...rest }: IconProps & { children: ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden
      {...rest}
    >
      {children}
    </svg>
  );
}

/** Gradient accent fill (defined once by GraphicDefs) — dual-tone, themes with the page. */
function Soft({ d, ...rest }: { d?: string } & SVGProps<SVGPathElement>) {
  return <path d={d} fill="url(#hv-accent)" fillOpacity="0.28" stroke="none" {...rest} />;
}

export function IconDeck(props: IconProps) {
  return (
    <Icon {...props}>
      <Soft d="M4 4h7v9H4z" />
      <rect x="4" y="4" width="7" height="9" rx="1.75" />
      <rect x="13" y="4" width="7" height="5" rx="1.75" />
      <Soft d="M13 12h7v8h-7z" />
      <rect x="13" y="12" width="7" height="8" rx="1.75" />
      <rect x="4" y="16" width="7" height="4" rx="1.75" />
    </Icon>
  );
}

export function IconDeploy(props: IconProps) {
  return (
    <Icon {...props}>
      <Soft d="M12 3.5 7.2 14.2h3.1V20h3.4v-5.8h3.1L12 3.5Z" />
      <path d="M12 3.5 7.2 14.2h3.1V20h3.4v-5.8h3.1L12 3.5Z" />
      <path d="M5.5 20.5h13" />
    </Icon>
  );
}

export function IconPlanes(props: IconProps) {
  return (
    <Icon {...props}>
      <Soft d="M6.5 7.5h11A1.5 1.5 0 0 1 19 9v9.5H6.5V7.5Z" />
      <path d="M8 6.5h8.5A1.5 1.5 0 0 1 18 8v.5" />
      <rect x="5" y="8" width="14" height="11" rx="2" />
      <path d="M5 12h14" />
      <circle cx="8" cy="10.2" r="0.7" fill="currentColor" stroke="none" />
      <circle cx="10.2" cy="10.2" r="0.7" fill="currentColor" fillOpacity="0.45" stroke="none" />
    </Icon>
  );
}

export function IconRealms(props: IconProps) {
  return (
    <Icon {...props}>
      <Soft d="M12 3.2 19.2 7.2v9.6L12 20.8 4.8 16.8V7.2L12 3.2Z" />
      <path d="M12 3.2 19.2 7.2v9.6L12 20.8 4.8 16.8V7.2L12 3.2Z" />
      <circle cx="12" cy="12" r="2.6" />
      <path d="M12 9.4V7.6" />
    </Icon>
  );
}

export function IconClients(props: IconProps) {
  return (
    <Icon {...props}>
      <Soft d="M4 5.5h11A1.5 1.5 0 0 1 16.5 7v8.5H4V5.5Z" />
      <rect x="3.5" y="5" width="12.5" height="11.5" rx="2" />
      <path d="M7 20h5.5" />
      <path d="M9.75 16.5V20" />
      <circle cx="18.2" cy="14.2" r="3.1" />
      <path d="M18.2 12.4v3.6" />
      <path d="M16.4 14.2h3.6" />
    </Icon>
  );
}

export function IconGuard(props: IconProps) {
  return (
    <Icon {...props}>
      <Soft d="M12 3.2 19 6v5.5c0 4.5-2.7 7.7-7 9.3-4.3-1.6-7-4.8-7-9.3V6l7-2.8Z" />
      <path d="M12 3.2 19 6v5.5c0 4.5-2.7 7.7-7 9.3-4.3-1.6-7-4.8-7-9.3V6l7-2.8Z" />
      <path d="m8.8 12 2.1 2.1 4.5-4.7" />
    </Icon>
  );
}

export function IconFederation(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="7" cy="8" r="3" />
      <circle cx="17" cy="8" r="3" />
      <circle cx="12" cy="17" r="3" />
      <Soft d="M12 14a3 3 0 1 0 0 6 3 3 0 0 0 0-6Z" />
      <path d="m9.5 9.8 1.1 4.2M14.5 9.8 13.4 14M9.8 17h4.4" />
    </Icon>
  );
}

export function IconCredentials(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="8" cy="12" r="4.2" />
      <path d="M12.2 12H21M17 12v3M19.5 12v2" />
      <Soft d="M4 8h8v8H4z" />
    </Icon>
  );
}

export function IconTimeMachine(props: IconProps) {
  return (
    <Icon {...props}>
      <Soft d="M12 4a8 8 0 1 0 0 16 8 8 0 0 0 0-16Z" />
      <circle cx="12" cy="12" r="8" />
      <path d="M12 7v5l3 2M6.2 5.8 3.8 6.2l.4-2.4" />
      <path d="M4.2 6.2A9.5 9.5 0 0 1 12 2.5" />
    </Icon>
  );
}

export function IconAtlas(props: IconProps) {
  return (
    <Icon {...props}>
      <Soft d="M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18Z" />
      <circle cx="12" cy="12" r="9" />
      <path d="M3.2 12h17.6" />
      <path d="M12 3a13.5 13.5 0 0 1 0 18" />
      <path d="M12 3a13.5 13.5 0 0 0 0 18" />
      <circle cx="12" cy="12" r="1.35" fill="currentColor" stroke="none" />
    </Icon>
  );
}

export function IconSettings(props: IconProps) {
  return (
    <Icon {...props}>
      <Soft d="M12 8.2a3.8 3.8 0 1 0 0 7.6 3.8 3.8 0 0 0 0-7.6Z" />
      <circle cx="12" cy="12" r="3.1" />
      <path d="M12 3.2v2.1" />
      <path d="M12 18.7v2.1" />
      <path d="m5.05 5.05 1.5 1.5" />
      <path d="m17.45 17.45 1.5 1.5" />
      <path d="M3.2 12h2.1" />
      <path d="M18.7 12h2.1" />
      <path d="m5.05 18.95 1.5-1.5" />
      <path d="m17.45 6.55 1.5-1.5" />
    </Icon>
  );
}

export function IconChevronLeft(props: IconProps) {
  return (
    <Icon size={14} {...props}>
      <path d="m14.5 18-6-6 6-6" />
    </Icon>
  );
}

export function IconChevronRight(props: IconProps) {
  return (
    <Icon size={14} {...props}>
      <path d="m9.5 18 6-6-6-6" />
    </Icon>
  );
}


export function IconAccess(props: IconProps) {
  return (
    <Icon {...props}>
      <Soft d="M3.5 19.5c0-3.6 2.7-5.5 6-5.5s6 1.9 6 5.5H3.5Z" />
      <circle cx="9.5" cy="8" r="3.5" />
      <path d="M3.5 19.5c0-3.6 2.7-5.5 6-5.5s6 1.9 6 5.5" />
      <path d="m16.5 9.5 1.8 1.8 3.2-3.6" />
    </Icon>
  );
}

export function IconSun(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="4" />
      <path d="M12 2.8v2M12 19.2v2M4.4 4.4l1.4 1.4M18.2 18.2l1.4 1.4M2.8 12h2M19.2 12h2M4.4 19.6l1.4-1.4M18.2 5.8l1.4-1.4" />
    </Icon>
  );
}

export function IconMoon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M20 14.5A8.5 8.5 0 0 1 9.5 4a8.5 8.5 0 1 0 10.5 10.5Z" />
    </Icon>
  );
}

export function IconSearch(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="11" cy="11" r="6.5" />
      <path d="m16 16 4.5 4.5" />
    </Icon>
  );
}

export function IconPulse(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M3 12h4l2.5-6 4 12 2.5-6H21" />
    </Icon>
  );
}

export function IconDatabase(props: IconProps) {
  return (
    <Icon {...props}>
      <Soft d="M5 6c0 1.7 3.1 3 7 3s7-1.3 7-3-3.1-3-7-3-7 1.3-7 3Z" />
      <ellipse cx="12" cy="6" rx="7" ry="3" />
      <path d="M5 6v6c0 1.7 3.1 3 7 3s7-1.3 7-3V6M5 12v6c0 1.7 3.1 3 7 3s7-1.3 7-3v-6" />
    </Icon>
  );
}

export function IconBackup(props: IconProps) {
  return (
    <Icon {...props}>
      <Soft d="M12 3.5a8.5 8.5 0 1 0 0 17 8.5 8.5 0 0 0 0-17Z" />
      <path d="M12 16.5v-8M8.5 12 12 8.5l3.5 3.5" />
      <circle cx="12" cy="12" r="8.5" />
    </Icon>
  );
}

export function IconCertificate(props: IconProps) {
  return (
    <Icon {...props}>
      <Soft d="M5 3.5h14v11H5z" />
      <rect x="4" y="3.5" width="16" height="12" rx="2.5" />
      <path d="m9 9.5 2 2 4-4M8.5 15.5 7.5 21l4.5-2.2 4.5 2.2-1-5.5" />
    </Icon>
  );
}

export function IconAlert(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 4 3 19.5h18L12 4Z" />
      <path d="M12 10v4.5M12 17.2v.1" />
    </Icon>
  );
}

export const navIcons = {
  deck: IconDeck,
  deploy: IconDeploy,
  planes: IconPlanes,
  realms: IconRealms,
  clients: IconClients,
  guard: IconGuard,
  federation: IconFederation,
  credentials: IconCredentials,
  access: IconAccess,
  timemachine: IconTimeMachine,
  atlas: IconAtlas,
  settings: IconSettings,
} as const;

export type NavIconId = keyof typeof navIcons;
