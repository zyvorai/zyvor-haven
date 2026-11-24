// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useCallback, useEffect, useMemo, useState } from 'react';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { ConsolePageHeader } from '../components/ConsolePageHeader';
import { EmptyState, SkeletonBlock } from '../components/graphics/Art';
import { BarList, Donut } from '../components/graphics/Charts';
import { api, type CredentialInventoryItem } from '../api/client';

export function CredentialCenterPage() {
  const [items, setItems] = useState<CredentialInventoryItem[]>([]);
  const [rotationDays, setRotationDays] = useState(90);
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [loaded, setLoaded] = useState(false);
  const [secret, setSecret] = useState<{ clientId: string; value: string; overlap: boolean; note: string } | null>(null);

  const load = useCallback(async () => {
    try { const r = await api.listCredentials(); setItems(r.items); setRotationDays(r.rotationDays); }
    catch (e) { setMessage(e instanceof Error ? e.message : 'Failed to load credentials'); }
    finally { setLoaded(true); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const due = useMemo(() => items.filter((i) => i.rotationDue).length, [items]);
  const overlap = useMemo(() => items.filter((i) => i.overlapAvailable).length, [items]);
  const aged = useMemo(() => items.filter((i) => i.ageDays != null), [items]);
  const ready = Math.max(0, items.length - due - overlap);

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
        <ConsolePageHeader art="key" eyebrow="Secure" title="Credential Center" subtitle="Rotate confidential OIDC client secrets, track age, and use the identity server's overlap window when available." />

        <div className="ops-stat-grid">
          <div className="ops-stat"><span>Confidential clients</span><strong>{items.length}</strong></div>
          <div className="ops-stat"><span>Rotation policy</span><strong>{rotationDays}d</strong></div>
          <div className="ops-stat"><span>Due</span><strong>{due}</strong></div>
          <div className="ops-stat"><span>Overlap active</span><strong>{overlap}</strong></div>
        </div>

        {items.length > 0 && (
          <section className="ops-panel ops-chart-panel">
            <div className="ops-panel-head"><div><div className="ops-kicker">Rotation health</div><h3>Secret age against policy</h3></div></div>
            <div className="ops-chart-row">
              <Donut
                label="Credential states"
                center={`${items.length}`}
                parts={[
                  { label: 'due', value: due, tone: 'err' },
                  { label: 'overlap', value: overlap, tone: 'warn' },
                  { label: 'ready', value: ready, tone: 'ok' },
                ]}
              />
              <ul className="chart-legend" aria-hidden>
                <li><i style={{ background: 'var(--zy-chart-4)' }} />Due {due}</li>
                <li><i style={{ background: 'var(--zy-chart-3)' }} />Overlap {overlap}</li>
                <li><i style={{ background: 'var(--zy-chart-2)' }} />Ready {ready}</li>
              </ul>
              <div className="ops-chart-main">
                {aged.length > 0 ? (
                  <BarList
                    label="Secret age in days"
                    unit="d"
                    max={Math.max(rotationDays * 1.25, ...aged.map((i) => i.ageDays ?? 0))}
                    marker={{ at: rotationDays, text: `${rotationDays}d policy` }}
                    data={aged.map((i) => ({ label: i.clientId, value: i.ageDays ?? 0, tone: i.rotationDue ? 'err' : i.overlapAvailable ? 'warn' : 'ok' }))}
                  />
                ) : (
                  <p className="ops-note">No rotation history is tracked yet.</p>
                )}
              </div>
            </div>
          </section>
        )}

        {secret && <section className="ops-secret" role="status"><div><div className="ops-kicker">Copy once</div><h3>{secret.clientId}</h3><p>{secret.note}</p></div><div className="ops-secret-value"><code>{secret.value}</code><button className="btn btn-ghost" onClick={() => void navigator.clipboard.writeText(secret.value)}>Copy</button></div></section>}
        {message && <div className="ops-message" role="status">{message}</div>}

        <section className="ops-panel">
          <div className="ops-panel-head"><div><div className="ops-kicker">Inventory</div><h3>Client credentials</h3></div><button className="btn btn-ghost" onClick={() => void load()}>Refresh</button></div>
          <div className="ops-table-wrap"><table className="ops-table"><thead><tr><th>Client</th><th>Realm</th><th>Age</th><th>State</th><th></th></tr></thead><tbody>
            {!loaded && <tr><td colSpan={5}><SkeletonBlock label="Loading credentials" rows={2} /></td></tr>}
            {items.map((item) => <tr key={`${item.realm}:${item.clientUuid}`}><td><strong>{item.clientId}</strong>{item.serviceAccount && <small>service account</small>}</td><td>{item.realm}</td><td>{item.ageDays == null ? 'Untracked' : `${item.ageDays}d`}</td><td>{item.overlapAvailable ? <span className="ops-pill warn">Overlap</span> : item.rotationDue ? <span className="ops-pill warn">Due</span> : <span className="ops-pill ok">Ready</span>}</td><td className="ops-row-actions"><button className="btn btn-primary" disabled={!!busy} onClick={() => void rotate(item)}>{busy === item.clientUuid ? 'Rotating…' : 'Rotate'}</button>{item.overlapAvailable && <button className="btn btn-ghost" disabled={!!busy} onClick={() => void retire(item)}>{busy === `retire:${item.clientUuid}` ? 'Retiring…' : 'Retire previous'}</button>}</td></tr>)}
            {loaded && !items.length && <tr><td colSpan={5}><EmptyState compact art="key" title="No confidential clients" body="No confidential clients were found." /></td></tr>}
          </tbody></table></div>
        </section>
      </div></div>
    </ConsoleLayout>
  );
}
