// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useCallback, useEffect, useMemo, useState } from 'react';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { ConsolePageHeader } from '../components/ConsolePageHeader';
import { api, type CredentialInventoryItem } from '../api/client';

export function CredentialCenterPage() {
  const [items, setItems] = useState<CredentialInventoryItem[]>([]);
  const [rotationDays, setRotationDays] = useState(90);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [secret, setSecret] = useState<{ clientId: string; value: string; overlap: boolean; note: string } | null>(null);

  const load = useCallback(async () => {
    try { const r = await api.listCredentials(); setItems(r.items); setRotationDays(r.rotationDays); }
    catch (e) { setMessage(e instanceof Error ? e.message : 'Failed to load credentials'); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const due = useMemo(() => items.filter((i) => i.rotationDue).length, [items]);
  const overlap = useMemo(() => items.filter((i) => i.overlapAvailable).length, [items]);

  const rotate = async (item: CredentialInventoryItem) => {
    setBusy(item.clientUuid); setSecret(null); setMessage('');
    try {
      const r = await api.rotateCredential(item.realm, item.clientUuid);
      setSecret({ clientId: item.clientId, value: r.secret, overlap: r.overlapAvailable, note: r.note });
      await load();
    } catch (e) { setMessage(e instanceof Error ? e.message : 'Rotation failed'); }
    finally { setBusy(''); }
  };

  const retire = async (item: CredentialInventoryItem) => {
    setBusy(`retire:${item.clientUuid}`); setMessage('');
    try { await api.retireCredential(item.realm, item.clientUuid); setMessage(`Previous secret retired for ${item.clientId}.`); await load(); }
    catch (e) { setMessage(e instanceof Error ? e.message : 'Retire failed'); }
    finally { setBusy(''); }
  };

  return (
    <ConsoleLayout>
      <div className="console-content"><div className="console-content-inner">
        <ConsolePageHeader eyebrow="Secure" title="Credential Center" subtitle="Rotate confidential OIDC client secrets, track age, and use Keycloak's overlap window when available." />

        <div className="ops-stat-grid">
          <div className="ops-stat"><span>Confidential clients</span><strong>{items.length}</strong></div>
          <div className="ops-stat"><span>Rotation policy</span><strong>{rotationDays}d</strong></div>
          <div className="ops-stat"><span>Due</span><strong>{due}</strong></div>
          <div className="ops-stat"><span>Overlap active</span><strong>{overlap}</strong></div>
        </div>

        {secret && <section className="ops-secret" role="status"><div><div className="ops-kicker">Copy once</div><h3>{secret.clientId}</h3><p>{secret.note}</p></div><div className="ops-secret-value"><code>{secret.value}</code><button className="btn btn-ghost" onClick={() => void navigator.clipboard.writeText(secret.value)}>Copy</button></div></section>}
        {message && <div className="ops-message" role="status">{message}</div>}

        <section className="ops-panel">
          <div className="ops-panel-head"><div><div className="ops-kicker">Inventory</div><h3>Client credentials</h3></div><button className="btn btn-ghost" onClick={() => void load()}>Refresh</button></div>
          <div className="ops-table-wrap"><table className="ops-table"><thead><tr><th>Client</th><th>Realm</th><th>Age</th><th>State</th><th></th></tr></thead><tbody>
            {items.map((item) => <tr key={`${item.realm}:${item.clientUuid}`}><td><strong>{item.clientId}</strong>{item.serviceAccount && <small>service account</small>}</td><td>{item.realm}</td><td>{item.ageDays == null ? 'Untracked' : `${item.ageDays}d`}</td><td>{item.overlapAvailable ? <span className="ops-pill warn">Overlap</span> : item.rotationDue ? <span className="ops-pill warn">Due</span> : <span className="ops-pill ok">Ready</span>}</td><td className="ops-row-actions"><button className="btn btn-primary" disabled={!!busy} onClick={() => void rotate(item)}>{busy === item.clientUuid ? 'Rotating…' : 'Rotate'}</button>{item.overlapAvailable && <button className="btn btn-ghost" disabled={!!busy} onClick={() => void retire(item)}>{busy === `retire:${item.clientUuid}` ? 'Retiring…' : 'Retire previous'}</button>}</td></tr>)}
            {!items.length && <tr><td colSpan={5}><div className="ops-empty">No confidential clients were found.</div></td></tr>}
          </tbody></table></div>
        </section>
      </div></div>
    </ConsoleLayout>
  );
}
