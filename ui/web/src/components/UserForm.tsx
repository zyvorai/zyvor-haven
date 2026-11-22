// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useState } from 'react';
import type { User } from '../api/client';

interface UserFormProps {
  onSubmit: (user: User, password?: string) => Promise<void>;
  onCancel: () => void;
}

export function UserForm({ onSubmit, onCancel }: UserFormProps) {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const handle = async () => {
    setBusy(true);
    setErr('');
    try {
      await onSubmit(
        {
          username,
          email,
          enabled: true,
          emailVerified: true,
        },
        password || undefined,
      );
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card" style={{ padding: 20, maxWidth: 420 }}>
      <h3 style={{ margin: '0 0 16px' }}>Invite user</h3>
      <div className="wizard-field">
        <label htmlFor="uname">Username</label>
        <input id="uname" value={username} onChange={(e) => setUsername(e.target.value)} />
      </div>
      <div className="wizard-field">
        <label htmlFor="uemail">Email</label>
        <input id="uemail" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
      </div>
      <div className="wizard-field">
        <label htmlFor="upw">Temporary password (optional)</label>
        <input id="upw" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      </div>
      {err && <p style={{ color: 'var(--zy-danger)', fontSize: 13 }}>{err}</p>}
      <div style={{ display: 'flex', gap: 12, marginTop: 8 }}>
        <button type="button" className="btn btn-ghost" onClick={onCancel}>Cancel</button>
        <button type="button" className="btn btn-primary" disabled={busy || !username} onClick={handle}>
          {busy ? 'Creating…' : 'Create'}
        </button>
      </div>
    </div>
  );
}
