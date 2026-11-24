// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { ConsolePageHeader } from '../components/ConsolePageHeader';
import { Art, SkeletonBlock } from '../components/graphics/Art';
import { DataTable } from '../components/DataTable';
import { api, type Client, type Realm } from '../api/client';
import { platformCatalog, toCreateBody } from '../data/platformClients';

export function ClientsPage() {
  const [searchParams, setSearchParams] = useSearchParams();
  const catalogFocus = searchParams.get('catalog');

  const [clients, setClients] = useState<Client[]>([]);
  const [realms, setRealms] = useState<Realm[]>([]);
  const [realm, setRealm] = useState('platform');
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');
  const [toast, setToast] = useState('');
  const [busyId, setBusyId] = useState<string | null>(null);
  const [secretOnce, setSecretOnce] = useState<{ clientId: string; secret: string } | null>(null);

  const reload = useCallback(async () => {
    setErr('');
    try {
      const [all, rs] = await Promise.all([api.listAllClients(), api.listRealms()]);
      setClients(all);
      setRealms(rs);
      if (rs.length && !rs.some((r) => r.realm === realm)) {
        setRealm(rs[0].realm);
      }
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Failed to load clients');
    } finally {
      setLoading(false);
    }
  }, [realm]);

  useEffect(() => {
    void reload();
  }, [reload]);

  const inRealm = useMemo(
    () => clients.filter((c) => c.realm === realm),
    [clients, realm],
  );

  const mint = async (clientId: string) => {
    const tmpl = platformCatalog.find((t) => t.id === clientId);
    if (!tmpl) return;
    setBusyId(clientId);
    setToast('');
    setSecretOnce(null);
    try {
      await api.createClient(realm, toCreateBody(tmpl));
      await reload();
      const created = (await api.listClients(realm)).find((c) => c.clientId === clientId);
      if (created?.id && !tmpl.publicClient) {
        const sec = await api.getClientSecret(realm, created.id);
        if (sec.value) setSecretOnce({ clientId, secret: sec.value });
      }
      setToast(`Minted ${clientId} in realm ${realm}`);
      if (catalogFocus === clientId) {
        const next = new URLSearchParams(searchParams);
        next.delete('catalog');
        setSearchParams(next, { replace: true });
      }
    } catch (e) {
      setToast(e instanceof Error ? e.message : 'Mint failed');
    } finally {
      setBusyId(null);
    }
  };

  useEffect(() => {
    if (!catalogFocus || loading) return;
    const el = document.getElementById(`catalog-${catalogFocus}`);
    el?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }, [catalogFocus, loading]);

  return (
    <ConsoleLayout>
        <div className="console-content">
          <div className="console-content-inner">
            <ConsolePageHeader
              art="apps"
              eyebrow="Identity"
              title="Clients"
              subtitle="Platform catalog one-click mint, plus OIDC clients across realms."
            />

            <section className="catalog-panel" aria-label="Platform catalog">
              <div className="catalog-panel-head">
                <div>
                  <p className="deck-eyebrow" style={{ margin: 0 }}>Platform catalog</p>
                  <h2 className="catalog-title">Mint SSO clients</h2>
                </div>
                <label className="catalog-realm">
                  Realm
                  <select value={realm} onChange={(e) => setRealm(e.target.value)} disabled={!realms.length}>
                    {(realms.length ? realms : [{ realm: 'platform' }]).map((r) => (
                      <option key={r.realm} value={r.realm}>
                        {r.realm}
                      </option>
                    ))}
                  </select>
                </label>
              </div>
              <div className="catalog-grid">
                {platformCatalog.map((t) => {
                  const minted = inRealm.some((c) => c.clientId === t.id);
                  const highlight = catalogFocus === t.id;
                  return (
                    <div
                      key={t.id}
                      id={`catalog-${t.id}`}
                      className={`catalog-card${highlight ? ' catalog-card-focus' : ''}`}
                    >
                      <div className="catalog-card-title">{t.name}</div>
                      <code className="catalog-card-id">{t.id}</code>
                      <p className="catalog-card-desc">{t.description}</p>
                      {t.bindHint && <p className="catalog-card-hint">{t.bindHint}</p>}
                      {minted ? (
                        <Link
                          className="btn btn-ghost"
                          to={`/realms/${encodeURIComponent(realm)}?tab=clients`}
                          style={{ marginTop: 12 }}
                        >
                          Minted — open realm
                        </Link>
                      ) : (
                        <button
                          type="button"
                          className="btn btn-primary"
                          style={{ marginTop: 12 }}
                          disabled={!!busyId || !realms.length}
                          onClick={() => void mint(t.id)}
                        >
                          {busyId === t.id ? 'Minting…' : 'Mint'}
                        </button>
                      )}
                    </div>
                  );
                })}
              </div>
              {secretOnce && (
                <div className="catalog-secret" role="status">
                  Client secret for <strong>{secretOnce.clientId}</strong> (copy once):{' '}
                  <code>{secretOnce.secret}</code>
                </div>
              )}
            </section>

          {err && (
            <div className="inline-error" role="alert">
              <Art name="offline" size={84} />
              <p>{err}</p>
            </div>
          )}
          {loading ? (
            <SkeletonBlock card label="Loading clients…" rows={3} />
          ) : (
            <DataTable
              rows={clients.filter((c) => !c.clientId.startsWith('account') && c.clientId !== 'broker' && c.clientId !== 'realm-management')}
              keyField={(c) => `${c.realm}-${c.id ?? c.clientId}`}
              empty="No clients yet"
              columns={[
                {
                  key: 'clientId',
                  label: 'Client ID',
                  render: (c) =>
                    c.realm ? (
                      <Link
                        to={`/realms/${encodeURIComponent(c.realm)}?tab=clients`}
                        style={{ color: 'var(--zy-500)' }}
                      >
                        {c.clientId}
                      </Link>
                    ) : (
                      c.clientId
                    ),
                },
                { key: 'realm', label: 'Realm' },
                { key: 'name', label: 'Name' },
                {
                  key: 'type',
                  label: 'Type',
                  render: (c) => (c.publicClient ? 'Public' : 'Confidential'),
                },
                {
                  key: 'enabled',
                  label: 'Status',
                  render: (c) => (
                    <span style={{ color: c.enabled ? 'var(--zy-ok)' : 'var(--zy-muted)' }}>
                      {c.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  ),
                },
              ]}
            />
          )}
          </div>
        </div>
      {toast && (
        <div className="toast" role="status">
          {toast}
        </div>
      )}
    </ConsoleLayout>
  );
}
