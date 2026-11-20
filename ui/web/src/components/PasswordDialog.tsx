// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useState } from 'react';

type Props = {
  open: boolean;
  title: string;
  subtitle?: string;
  confirmLabel?: string;
  requireCurrent?: boolean;
  temporaryToggle?: boolean;
  onCancel: () => void;
  onSubmit: (opts: {
    currentPassword?: string;
    newPassword: string;
    temporary: boolean;
  }) => Promise<void>;
};

export function PasswordDialog({
  open,
  title,
  subtitle,
  confirmLabel = 'Update password',
  requireCurrent = false,
  temporaryToggle = false,
  onCancel,
  onSubmit,
}: Props) {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [temporary, setTemporary] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  if (!open) return null;

  const canSubmit =
    newPassword.length >= 8 &&
    newPassword === confirm &&
    (!requireCurrent || currentPassword.length > 0) &&
    !busy;

  const handle = async () => {
    if (!canSubmit) return;
    setBusy(true);
    setErr('');
    try {
      await onSubmit({
        currentPassword: requireCurrent ? currentPassword : undefined,
        newPassword,
        temporary,
      });
      setCurrentPassword('');
      setNewPassword('');
      setConfirm('');
      setTemporary(false);
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Update failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.55)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 120,
        padding: 16,
      }}
      onClick={onCancel}
    >
      <div
        className="card"
        style={{ padding: 24, width: '100%', maxWidth: 420 }}
        onClick={(e) => e.stopPropagation()}
      >
        <h3 style={{ margin: '0 0 8px' }}>{title}</h3>
        {subtitle && (
          <p style={{ margin: '0 0 16px', fontSize: 13, color: 'var(--zy-muted)' }}>{subtitle}</p>
        )}
        {requireCurrent && (
          <div className="wizard-field">
            <label htmlFor="pw-current">Current password</label>
            <input
              id="pw-current"
              type="password"
              autoComplete="current-password"
              value={currentPassword}
              onChange={(e) => setCurrentPassword(e.target.value)}
            />
          </div>
        )}
        <div className="wizard-field">
          <label htmlFor="pw-new">New password</label>
          <input
            id="pw-new"
            type="password"
            autoComplete="new-password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
          />
        </div>
        <div className="wizard-field">
          <label htmlFor="pw-confirm">Confirm new password</label>
          <input
            id="pw-confirm"
            type="password"
            autoComplete="new-password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </div>
        {temporaryToggle && (
          <label
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              fontSize: 13,
              marginBottom: 12,
              color: 'var(--zy-slate)',
            }}
          >
            <input
              type="checkbox"
              checked={temporary}
              onChange={(e) => setTemporary(e.target.checked)}
            />
            Temporary — user must change on next login
          </label>
        )}
        {newPassword && newPassword.length < 8 && (
          <p style={{ color: 'var(--zy-warn)', fontSize: 13 }}>At least 8 characters.</p>
        )}
        {confirm && newPassword !== confirm && (
          <p style={{ color: 'var(--zy-danger)', fontSize: 13 }}>Passwords do not match.</p>
        )}
        {err && <p style={{ color: 'var(--zy-danger)', fontSize: 13 }}>{err}</p>}
        <div style={{ display: 'flex', gap: 12, marginTop: 8, justifyContent: 'flex-end' }}>
          <button type="button" className="btn btn-ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button type="button" className="btn btn-primary" disabled={!canSubmit} onClick={handle}>
            {busy ? 'Saving…' : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
