// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useState } from 'react';
import type { Client } from '../api/client';

interface ClientFormProps {
  initial?: Partial<Client>;
  onSubmit: (client: Client) => Promise<void>;
  onCancel: () => void;
}

export function ClientForm({ initial, onSubmit, onCancel }: ClientFormProps) {
  const [clientId, setClientId] = useState(initial?.clientId ?? '');
  const [name, setName] = useState(initial?.name ?? '');
  const [publicClient, setPublicClient] = useState(initial?.publicClient ?? true);
  const [redirectUris, setRedirectUris] = useState(
    (initial?.redirectUris ?? ['http://localhost/*']).join('\n'),
  );
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');

  const handle = async () => {
    setBusy(true);
    setErr('');
    try {
      await onSubmit({
        clientId,
        name: name || clientId,
        enabled: true,
        publicClient,
        protocol: 'openid-connect',
        standardFlowEnabled: true,
        directAccessGrantsEnabled: false,
        redirectUris: redirectUris.split('\n').map((s) => s.trim()).filter(Boolean),
        webOrigins: publicClient ? ['+'] : [],
      });
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card" style={{ padding: 20, maxWidth: 480 }}>
      <h3 style={{ margin: '0 0 16px' }}>{initial ? 'Edit client' : 'Mint OIDC client'}</h3>
      <div className="wizard-field">
        <label htmlFor="cid">Client ID</label>
        <input id="cid" value={clientId} onChange={(e) => setClientId(e.target.value)} disabled={!!initial?.clientId} />
      </div>
      <div className="wizard-field">
        <label htmlFor="cname">Name</label>
        <input id="cname" value={name} onChange={(e) => setName(e.target.value)} />
      </div>
      <label style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, fontSize: 14 }}>
        <input type="checkbox" checked={publicClient} onChange={(e) => setPublicClient(e.target.checked)} />
        Public client (browser / SPA)
      </label>
      <div className="wizard-field">
        <label htmlFor="uris">Redirect URIs (one per line)</label>
        <textarea
          id="uris"
          rows={3}
          value={redirectUris}
          onChange={(e) => setRedirectUris(e.target.value)}
          style={{ width: '100%', fontFamily: 'var(--zy-mono)', fontSize: 13 }}
        />
      </div>
      {err && <p style={{ color: 'var(--zy-danger)', fontSize: 13 }}>{err}</p>}
      <div style={{ display: 'flex', gap: 12, marginTop: 8 }}>
        <button type="button" className="btn btn-ghost" onClick={onCancel}>Cancel</button>
        <button type="button" className="btn btn-primary" disabled={busy || !clientId} onClick={handle}>
          {busy ? 'Saving…' : 'Save'}
        </button>
      </div>
    </div>
  );
}
