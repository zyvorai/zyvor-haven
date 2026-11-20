// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useCallback, useEffect, useMemo, useState, type ChangeEvent } from 'react';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { ConsolePageHeader } from '../components/ConsolePageHeader';
import { api, type FederationTemplate, type IdentityProvider, type Realm } from '../api/client';

export function FederationHubPage() {
  const [catalog, setCatalog] = useState<FederationTemplate[]>([]);
  const [realms, setRealms] = useState<Realm[]>([]);
  const [realm, setRealm] = useState('platform');
  const [connections, setConnections] = useState<IdentityProvider[]>([]);
  const [selected, setSelected] = useState<FederationTemplate | null>(null);
  const [alias, setAlias] = useState('');
  const [values, setValues] = useState<Record<string,string>>({});
  const [busy, setBusy] = useState('');
  const [message, setMessage] = useState('');

  const loadConnections = useCallback(async (r: string) => {
    if (!r) return;
    try { setConnections(await api.listFederationConnections(r)); }
    catch (e) { setMessage(e instanceof Error ? e.message : 'Failed to load federation'); }
  }, []);

  useEffect(() => {
    void Promise.all([api.federationCatalog(), api.listRealms()]).then(([c, rs]) => {
      setCatalog(c); const filtered = rs.filter((r) => r.realm !== 'master'); setRealms(filtered);
      const active = filtered.some((r) => r.realm === realm) ? realm : (filtered[0]?.realm ?? realm); setRealm(active); void loadConnections(active);
    }).catch((e) => setMessage(e instanceof Error ? e.message : 'Failed to load federation'));
  }, []); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { void loadConnections(realm); }, [realm, loadConnections]);

  const connectedAliases = useMemo(() => new Set(connections.map((c) => c.alias)), [connections]);

  const choose = (t: FederationTemplate) => { setSelected(t); setAlias(t.id); setValues({}); setMessage(''); };
  const connect = async () => {
    if (!selected) return;
    setBusy('connect'); setMessage('');
    try {
      await api.createFederationConnection({ realm, template: selected.id, alias, displayName: selected.name, values });
      setMessage(`${selected.name} connected to ${realm}.`); setSelected(null); await loadConnections(realm);
    } catch (e) { setMessage(e instanceof Error ? e.message : 'Connection failed'); }
    finally { setBusy(''); }
  };
  const remove = async (idp: IdentityProvider) => {
    setBusy(idp.alias); setMessage('');
    try { await api.deleteFederationConnection(realm, idp.alias); setMessage(`${idp.alias} removed.`); await loadConnections(realm); }
    catch (e) { setMessage(e instanceof Error ? e.message : 'Delete failed'); }
    finally { setBusy(''); }
  };

  return (
    <ConsoleLayout>
      <div className="console-content"><div className="console-content-inner">
        <ConsolePageHeader eyebrow="Operate" title="Federation Hub" subtitle="Connect enterprise identity providers without dropping operators into raw Keycloak configuration." actions={<label className="ops-realm-select">Realm<select value={realm} onChange={(e: ChangeEvent<HTMLSelectElement>) => setRealm(e.target.value)}>{realms.map((r) => <option key={r.realm}>{r.realm}</option>)}</select></label>} />

        <section className="ops-provider-grid">
          {catalog.map((t) => <button key={t.id} className={`ops-provider-card${selected?.id === t.id ? ' active' : ''}`} onClick={() => choose(t)}><span className="ops-provider-mark">{t.name.slice(0,2).toUpperCase()}</span><strong>{t.name}</strong><p>{t.description}</p>{connectedAliases.has(t.id) && <span className="ops-pill ok">Connected</span>}</button>)}
        </section>

        {selected && <section className="ops-panel ops-form-panel"><div className="ops-panel-head"><div><div className="ops-kicker">New connection</div><h3>{selected.name}</h3></div><button className="btn btn-ghost" onClick={() => setSelected(null)}>Close</button></div>
          <div className="ops-form-grid"><label>Alias<input value={alias} onChange={(e: ChangeEvent<HTMLInputElement>) => setAlias(e.target.value)} /></label>{selected.fields.map((f) => <label key={f.name}>{f.label}{f.required && ' *'}<input type={f.secret ? 'password' : 'text'} placeholder={f.placeholder} value={values[f.name] ?? ''} onChange={(e: ChangeEvent<HTMLInputElement>) => setValues((v) => ({...v, [f.name]: e.target.value}))} /></label>)}</div>
          <div className="ops-form-actions"><p>Haven enables trust-email by default and applies secure SAML/OIDC defaults where the provider supports them.</p><button className="btn btn-primary" disabled={busy === 'connect'} onClick={() => void connect()}>{busy === 'connect' ? 'Connecting…' : 'Connect provider'}</button></div>
        </section>}

        {message && <div className="ops-message" role="status">{message}</div>}

        <section className="ops-panel"><div className="ops-panel-head"><div><div className="ops-kicker">Live</div><h3>Connected providers</h3></div></div><div className="ops-table-wrap"><table className="ops-table"><thead><tr><th>Provider</th><th>Type</th><th>Status</th><th></th></tr></thead><tbody>{connections.map((idp) => <tr key={idp.alias}><td><strong>{idp.displayName || idp.alias}</strong><small>{idp.alias}</small></td><td>{idp.providerId}</td><td><span className={`ops-pill ${idp.enabled ? 'ok' : 'warn'}`}>{idp.enabled ? 'Enabled' : 'Disabled'}</span></td><td className="ops-row-actions"><button className="btn btn-ghost" disabled={!!busy} onClick={() => void remove(idp)}>{busy === idp.alias ? 'Removing…' : 'Remove'}</button></td></tr>)}{!connections.length && <tr><td colSpan={4}><div className="ops-empty">No external identity providers connected to this realm.</div></td></tr>}</tbody></table></div></section>
      </div></div>
    </ConsoleLayout>
  );
}
