// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { ConsolePageHeader } from '../components/ConsolePageHeader';
import { Art, SkeletonBlock } from '../components/graphics/Art';
import { DataTable } from '../components/DataTable';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { api, type Realm } from '../api/client';

export function RealmsPage() {
  const nav = useNavigate();
  const [realms, setRealms] = useState<Realm[]>([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [newRealm, setNewRealm] = useState('');
  const [deleteTarget, setDeleteTarget] = useState<Realm | null>(null);

  const load = () => {
    setLoading(true);
    api
      .listRealms()
      .then((r) => setRealms(r.filter((x) => x.realm !== 'master')))
      .catch((e) => setErr(e.message))
      .finally(() => setLoading(false));
  };

  useEffect(load, []);

  const create = async () => {
    await api.createRealm({
      realm: newRealm,
      displayName: newRealm,
      enabled: true,
    });
    setShowCreate(false);
    setNewRealm('');
    load();
    nav(`/realms/${encodeURIComponent(newRealm)}`);
  };

  const remove = async () => {
    if (!deleteTarget) return;
    await api.deleteRealm(deleteTarget.realm);
    setDeleteTarget(null);
    load();
  };

  return (
    <ConsoleLayout>
        <div className="console-content">
          <div className="console-content-inner">
            <ConsolePageHeader
              art="realm"
              eyebrow="Identity"
              title="Realm Studio"
              subtitle="Create and manage realms as tenant boundaries."
              actions={
                <button type="button" className="btn btn-primary" onClick={() => setShowCreate(true)}>
                  + Create realm
                </button>
              }
            />
          {err && (
            <div className="settings-offline-hint settings-offline-hint--art" role="alert">
              <Art name="offline" size={110} />
              <div>
              <strong>Identity server unreachable</strong>
              <p>{err}</p>
              <Link to="/settings?focus=identity-server" className="btn btn-primary">
                Configure in Settings
              </Link>
              </div>
            </div>
          )}
          {loading ? (
            <SkeletonBlock card label="Loading realms…" rows={3} />
          ) : err ? null : (
            <DataTable
              rows={realms}
              empty="No realms yet"
              emptyArt="realm"
              keyField={(r) => r.realm}
              onRowClick={(r) => nav(`/realms/${encodeURIComponent(r.realm)}`)}
              columns={[
                { key: 'realm', label: 'Realm', render: (r) => (
                  <Link to={`/realms/${encodeURIComponent(r.realm)}`} style={{ color: 'var(--zy-500)' }}>
                    {r.realm}
                  </Link>
                )},
                { key: 'displayName', label: 'Display name' },
                {
                  key: 'enabled',
                  label: 'Status',
                  render: (r) => (
                    <span style={{ color: r.enabled ? 'var(--zy-ok)' : 'var(--zy-muted)' }}>
                      {r.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  ),
                },
                {
                  key: 'actions',
                  label: '',
                  render: (r) => (
                    <button
                      type="button"
                      className="btn btn-ghost"
                      style={{ fontSize: 12, padding: '4px 8px' }}
                      onClick={(e) => {
                        e.stopPropagation();
                        setDeleteTarget(r);
                      }}
                    >
                      Delete
                    </button>
                  ),
                },
              ]}
            />
          )}
          </div>
        </div>

      {showCreate && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.6)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 100,
          }}
          onClick={() => setShowCreate(false)}
        >
          <div className="card" style={{ padding: 24, width: 360 }} onClick={(e) => e.stopPropagation()}>
            <h3 style={{ marginTop: 0 }}>Create realm</h3>
            <div className="wizard-field">
              <label htmlFor="nr">Realm name</label>
              <input id="nr" value={newRealm} onChange={(e) => setNewRealm(e.target.value)} placeholder="platform" />
            </div>
            <div style={{ display: 'flex', gap: 12, marginTop: 16 }}>
              <button type="button" className="btn btn-ghost" onClick={() => setShowCreate(false)}>Cancel</button>
              <button type="button" className="btn btn-primary" disabled={!newRealm} onClick={create}>Create</button>
            </div>
          </div>
        </div>
      )}

      <ConfirmDialog
        open={!!deleteTarget}
        title="Delete realm"
        message={`Permanently delete realm "${deleteTarget?.realm}"? All users and clients will be removed.`}
        confirmLabel="Delete realm"
        danger
        onConfirm={remove}
        onCancel={() => setDeleteTarget(null)}
      />
    </ConsoleLayout>
  );
}
