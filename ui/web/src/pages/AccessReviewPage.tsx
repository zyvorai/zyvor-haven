// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useCallback, useEffect, useState } from 'react';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { ConsolePageHeader } from '../components/ConsolePageHeader';
import { api, type AccessReviewReport, type AccessReviewCampaignView } from '../api/client';

const riskClass = (risk: string) => (risk === 'high' ? 'warn' : risk === 'medium' ? 'warn' : 'ok');

export function AccessReviewPage() {
  const [realms, setRealms] = useState<string[]>([]);
  const [realm, setRealm] = useState('');
  const [report, setReport] = useState<AccessReviewReport | null>(null);
  const [campaign, setCampaign] = useState<AccessReviewCampaignView | null>(null);
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');

  useEffect(() => {
    api.listRealms().then((r) => { const names = r.map((x) => x.realm); setRealms(names); if (names.length) setRealm(names[0]); })
      .catch((e) => setMessage(e instanceof Error ? e.message : 'Failed to load realms'));
  }, []);

  const run = useCallback(async (label: string, fn: () => Promise<void>) => {
    setBusy(label); setMessage('');
    try { await fn(); } catch (e) { setMessage(e instanceof Error ? e.message : 'Request failed'); } finally { setBusy(''); }
  }, []);

  const analyse = () => run('analyse', async () => { setReport(await api.accessReviewReport(realm)); setCampaign(null); });
  const start = () => run('start', async () => { setCampaign(await api.createAccessReviewCampaign(realm)); });
  const decide = (username: string, action: string) => run(`${username}:${action}`, async () => {
    if (!campaign) return;
    setCampaign(await api.decideAccessReview(campaign.campaign.id, username, action, notes[username] ?? ''));
  });
  const close = () => run('close', async () => { if (campaign) setCampaign(await api.closeAccessReview(campaign.campaign.id)); });

  const open = campaign?.campaign.status === 'open';

  return (
    <ConsoleLayout>
      <div className="console-content"><div className="console-content-inner">
        <ConsolePageHeader eyebrow="Govern" title="Access Review" subtitle="Find privileged and stale accounts, then record who certified or revoked each one. Haven records decisions; it never changes Keycloak access." />

        <section className="ops-panel">
          <div className="ops-panel-head"><div><div className="ops-kicker">Scope</div><h3>Realm</h3></div>
            <div className="ops-row-actions">
              <select value={realm} onChange={(e) => setRealm(e.target.value)} aria-label="Realm">{realms.map((r) => <option key={r}>{r}</option>)}</select>
              <button className="btn btn-ghost" disabled={!realm || !!busy} onClick={() => void analyse()}>{busy === 'analyse' ? 'Analysing…' : 'Analyse'}</button>
              <button className="btn btn-primary" disabled={!realm || !!busy} onClick={() => void start()}>{busy === 'start' ? 'Starting…' : 'Start campaign'}</button>
            </div></div>
        </section>

        {message && <div className="ops-message" role="status">{message}</div>}

        {report && !campaign && <>
          <div className="ops-stat-grid">
            <div className="ops-stat"><span>With access</span><strong>{report.summary.withAccess}</strong></div>
            <div className="ops-stat"><span>Privileged</span><strong>{report.summary.privileged}</strong></div>
            <div className="ops-stat"><span>Stale (disabled)</span><strong>{report.summary.staleAccess}</strong></div>
            <div className="ops-stat"><span>High risk</span><strong>{report.summary.highRisk}</strong></div>
          </div>
          {report.breakGlass.warnings?.map((w) => <div className="ops-message" role="status" key={w}>Break-glass: {w}</div>)}
          <section className="ops-panel"><div className="ops-table-wrap"><table className="ops-table"><thead><tr><th>User</th><th>Risk</th><th>Flags</th><th>Roles and groups</th></tr></thead><tbody>
            {report.items.map((it) => <tr key={it.username}><td><strong>{it.username}</strong>{!it.enabled && <small>disabled</small>}</td><td><span className={`ops-pill ${riskClass(it.risk)}`}>{it.risk}</span></td><td>{(it.flags ?? []).join(', ')}</td><td>{[...(it.realmRoles ?? []), ...(it.groups ?? [])].join(', ')}</td></tr>)}
            {!report.items.length && <tr><td colSpan={4}><div className="ops-empty">No accounts hold access in this realm.</div></td></tr>}
          </tbody></table></div></section>
        </>}

        {campaign && <section className="ops-panel">
          <div className="ops-panel-head"><div><div className="ops-kicker">Campaign {campaign.campaign.id} · {campaign.campaign.status}</div>
            <h3>{campaign.progress.Certified} certified, {campaign.progress.Revoked} to revoke, {campaign.progress.Pending + campaign.progress.Deferred} open</h3></div>
            {open && <button className="btn btn-primary" disabled={!!busy} onClick={() => void close()}>Close campaign</button>}</div>
          <div className="ops-table-wrap"><table className="ops-table"><thead><tr><th>User</th><th>Risk</th><th>Decision</th><th>Note</th><th></th></tr></thead><tbody>
            {campaign.campaign.items.map((it) => <tr key={it.username}>
              <td><strong>{it.username}</strong><small>{(it.flags ?? []).join(', ')}</small></td>
              <td><span className={`ops-pill ${riskClass(it.risk)}`}>{it.risk}</span></td>
              <td>{it.decision ? `${it.decision.action} by ${it.decision.reviewer}` : 'pending'}</td>
              <td>{open ? <input maxLength={500} value={notes[it.username] ?? ''} onChange={(e) => setNotes({ ...notes, [it.username]: e.target.value })} aria-label={`Note for ${it.username}`} /> : it.decision?.note}</td>
              <td className="ops-row-actions">{open && <>
                <button className="btn btn-ghost" disabled={!!busy} onClick={() => void decide(it.username, 'certify')}>Certify</button>
                <button className="btn btn-ghost" disabled={!!busy} onClick={() => void decide(it.username, 'revoke')}>Revoke</button>
                <button className="btn btn-ghost" disabled={!!busy} onClick={() => void decide(it.username, 'defer')}>Defer</button></>}</td>
            </tr>)}
          </tbody></table></div>
          {!!campaign.revokeWorkItems.length && <p className="ops-note">Revocation work items for an administrator: {campaign.revokeWorkItems.join(', ')}</p>}
        </section>}
      </div></div>
    </ConsoleLayout>
  );
}
