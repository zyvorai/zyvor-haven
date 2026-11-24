// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useCallback, useEffect, useMemo, useState, type ChangeEvent } from 'react';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { ConsolePageHeader } from '../components/ConsolePageHeader';
import { Art, EmptyState, SkeletonBlock } from '../components/graphics/Art';
import { Sparkline } from '../components/graphics/Charts';
import { SnapshotRail } from '../components/graphics/SnapshotRail';
import { api, type Realm, type SnapshotDiff, type SnapshotSummary } from '../api/client';

function changeCount(diff?: SnapshotDiff | null) {
  if (!diff) return 0;
  return [diff.clients, diff.users, diff.roles, diff.groups, diff.providers, diff.access]
    .reduce((n, c) => n + c.added.length + c.removed.length, diff.nativeConfigChanged ? 1 : 0);
}

export function TimeMachinePage() {
  const [realms, setRealms] = useState<Realm[]>([]);
  const [realm, setRealm] = useState('platform');
  const [items, setItems] = useState<SnapshotSummary[]>([]);
  const [selected, setSelected] = useState<SnapshotSummary | null>(null);
  const [diff, setDiff] = useState<SnapshotDiff | null>(null);
  const [reason, setReason] = useState('manual recovery point');
  const [targetRealm, setTargetRealm] = useState('');
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');
  const [loaded, setLoaded] = useState(false);

  const load = useCallback(async () => {
    try {
      const rs = await api.listRealms();
      setRealms(rs.filter((r) => r.realm !== 'master'));
      const active = rs.some((r) => r.realm === realm) ? realm : (rs.find((r) => r.realm !== 'master')?.realm ?? realm);
      if (active !== realm) setRealm(active);
      setItems(await api.listSnapshots(active));
    } catch (e) {
      setMessage(e instanceof Error ? e.message : 'Failed to load Time Machine');
    } finally {
      setLoaded(true);
    }
  }, [realm]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { setSelected(null); setDiff(null); setTargetRealm(`${realm}-recovery`); }, [realm]);

  const create = async () => {
    setBusy('create'); setMessage('');
    try {
      const snap = await api.createSnapshot(realm, reason);
      setMessage(`Recovery point ${snap.id} created.`);
      await load();
    } catch (e) { setMessage(e instanceof Error ? e.message : 'Snapshot failed'); }
    finally { setBusy(''); }
  };

  const inspect = async (item: SnapshotSummary) => {
    setSelected(item); setBusy(item.id); setMessage('');
    try { setDiff(await api.diffSnapshot(item.id)); }
    catch (e) { setMessage(e instanceof Error ? e.message : 'Diff failed'); }
    finally { setBusy(''); }
  };

  const restore = async () => {
    if (!selected || !targetRealm.trim()) return;
    setBusy('restore'); setMessage('');
    try {
      const result = await api.restoreSnapshot(selected.id, targetRealm.trim());
      setMessage(`Restored into ${result.targetRealm}: ${result.clients} clients, ${result.users} users, ${result.roles} roles.`);
    } catch (e) { setMessage(e instanceof Error ? e.message : 'Restore failed'); }
    finally { setBusy(''); }
  };

  const counts = useMemo(() => changeCount(diff), [diff]);
  const chrono = useMemo(() => [...items].sort((a, b) => +new Date(a.createdAt) - +new Date(b.createdAt)), [items]);

  return (
    <ConsoleLayout>
      <div className="console-content"><div className="console-content-inner">
        <ConsolePageHeader art="clock" eyebrow="Recover" title="Time Machine" subtitle="Immutable realm recovery points, drift-aware diffs, and safe restore into an isolated realm." />

        <section className="ops-hero ops-hero--tm">
          <div className="ops-hero-main">
            <div className="ops-kicker">Recovery posture</div>
            <h2>{items.length ? `${items.length} recovery point${items.length === 1 ? '' : 's'}` : 'No recovery points yet'}</h2>
            <p>Snapshots exclude client secrets by design. Credential Center owns secret rotation separately.</p>
            {chrono.length > 0 ? (
              <>
                <SnapshotRail items={chrono} selectedId={selected?.id} />
                {chrono.length > 1 && (
                  <Sparkline
                    values={chrono.map((c) => c.users)}
                    label={`Users per recovery point, from ${chrono[0].users} to ${chrono[chrono.length - 1].users}`}
                    from={`${chrono[0].users} users`}
                    to={`${chrono[chrono.length - 1].users} users`}
                    tone="violet"
                  />
                )}
              </>
            ) : (
              <div className="ops-hero-art"><Art name="clock" size={170} /></div>
            )}
          </div>
          <div className="ops-actions">
            <label>Realm<select value={realm} onChange={(e: ChangeEvent<HTMLSelectElement>) => setRealm(e.target.value)}>{realms.map((r) => <option key={r.realm}>{r.realm}</option>)}</select></label>
            <label>Reason<input value={reason} onChange={(e: ChangeEvent<HTMLInputElement>) => setReason(e.target.value)} /></label>
            <button className="btn btn-primary" onClick={() => void create()} disabled={!!busy}>{busy === 'create' ? 'Creating…' : 'Create recovery point'}</button>
          </div>
        </section>

        {message && <div className="ops-message" role="status">{message}</div>}

        <div className="ops-split">
          <section className="ops-panel">
            <div className="ops-panel-head"><div><div className="ops-kicker">History</div><h3>{realm}</h3></div></div>
            <div className="ops-list">
              {items.map((item) => (
                <button key={item.id} className={`ops-list-row${selected?.id === item.id ? ' active' : ''}`} onClick={() => void inspect(item)}>
                  <span><strong>{new Date(item.createdAt).toLocaleString()}</strong><small>{item.reason || 'recovery point'}</small></span>
                  <span className="ops-meta">{item.clients} apps · {item.users} users</span>
                </button>
              ))}
              {!loaded && <SkeletonBlock label="Loading recovery points" rows={2} />}
              {loaded && !items.length && <EmptyState compact art="clock" title="Nothing to restore yet" body="Create the first recovery point before your next production change." />}
            </div>
          </section>

          <section className="ops-panel">
            <div className="ops-panel-head"><div><div className="ops-kicker">Compare</div><h3>{selected ? 'Snapshot vs live' : 'Select a snapshot'}</h3></div>{diff && <span className={`ops-pill ${diff.drifted ? 'warn' : 'ok'}`}>{diff.drifted ? `${counts} changes` : 'No drift'}</span>}</div>
            {diff ? (
              <>
                <div className="ops-fingerprint"><span>Snapshot</span><code>{diff.snapshotFingerprint.slice(0, 18)}…</code><span>Live</span><code>{diff.liveFingerprint.slice(0, 18)}…</code></div>
                <div className="ops-diff-grid">
                  {(['clients','users','roles','groups','providers','access'] as const).map((k) => <div key={k} className="ops-diff-card"><strong>{k}</strong><span>+{diff[k].added.length}</span><span>−{diff[k].removed.length}</span></div>)}
                </div>
                {diff.nativeConfigChanged && <div className="ops-message">Advanced client/group/role configuration changed in the native export.</div>}
                <div className="ops-restore-box">
                  <strong>Safe restore</strong><p>Haven never overwrites the source realm. It creates an isolated recovery realm for validation first.</p>
                  <div className="ops-inline"><input value={targetRealm} onChange={(e: ChangeEvent<HTMLInputElement>) => setTargetRealm(e.target.value)} placeholder="platform-recovery" /><button className="btn btn-primary" onClick={() => void restore()} disabled={busy === 'restore'}>{busy === 'restore' ? 'Restoring…' : 'Restore to new realm'}</button></div>
                </div>
              </>
            ) : <EmptyState compact art="clock" title="Compare with live" body="Select a recovery point to see drift and restore options." />}
          </section>
        </div>
      </div></div>
    </ConsoleLayout>
  );
}
