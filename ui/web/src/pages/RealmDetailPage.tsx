// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useCallback, useEffect, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { RealmTabs, type RealmTab } from '../components/RealmTabs';
import { DataTable } from '../components/DataTable';
import { ClientForm } from '../components/ClientForm';
import { UserForm } from '../components/UserForm';
import { ConfirmDialog } from '../components/ConfirmDialog';
import { PasswordDialog } from '../components/PasswordDialog';
import {
  api,
  type AdminEvent,
  type Client,
  type IdentityProvider,
  type Realm,
  type Role,
  type User,
} from '../api/client';

export function RealmDetailPage() {
  const { realm = '' } = useParams();
  const [search] = useSearchParams();
  const tab = (search.get('tab') as RealmTab) || 'overview';
  const [detail, setDetail] = useState<Realm | null>(null);
  const [clients, setClients] = useState<Client[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [idps, setIdps] = useState<IdentityProvider[]>([]);
  const [events, setEvents] = useState<AdminEvent[]>([]);
  const [err, setErr] = useState('');
  const [showClientForm, setShowClientForm] = useState(false);
  const [showUserForm, setShowUserForm] = useState(false);
  const [secret, setSecret] = useState<{ clientId: string; value: string } | null>(null);
  const [regenClient, setRegenClient] = useState<Client | null>(null);
  const [pwUser, setPwUser] = useState<User | null>(null);
  const [pwToast, setPwToast] = useState('');

  const load = useCallback(async () => {
    setErr('');
    try {
      setDetail(await api.getRealm(realm));
      if (tab === 'clients') setClients(await api.listClients(realm));
      if (tab === 'users') setUsers(await api.listUsers(realm));
      if (tab === 'roles') setRoles(await api.listRoles(realm));
      if (tab === 'idps') setIdps(await api.listIdentityProviders(realm));
      if (tab === 'events') setEvents(await api.listEvents(realm));
    } catch (e) {
      setErr(e instanceof Error ? e.message : 'Load failed');
    }
  }, [realm, tab]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (!pwToast) return;
    const timer = window.setTimeout(() => setPwToast(''), 2800);
    return () => window.clearTimeout(timer);
  }, [pwToast]);

  const showSecret = async (c: Client) => {
    if (!c.id || c.publicClient) return;
    const sec = await api.getClientSecret(realm, c.id);
    setSecret({ clientId: c.clientId, value: sec.value });
  };

  const doRegen = async () => {
    if (!regenClient?.id) return;
    const sec = await api.regenerateClientSecret(realm, regenClient.id);
    setRegenClient(null);
    setSecret({ clientId: regenClient.clientId, value: sec.value });
    load();
  };

  return (
    <ConsoleLayout realm={realm}>
        <div className="console-content">
          <div className="console-content-inner">
            <div style={{ marginBottom: 'var(--zy-s4)' }}>
              <Link to="/realms" className="console-eyebrow" style={{ textDecoration: 'none' }}>
                ← Realms
              </Link>
              <h1 className="console-page-title">{realm}</h1>
            </div>
          <RealmTabs active={tab} />
          {err && <p style={{ color: 'var(--zy-danger)' }}>{err}</p>}
          {pwToast && <p style={{ color: 'var(--zy-ok)' }}>{pwToast}</p>}

          {tab === 'overview' && detail && (
            <div className="card" style={{ padding: 20 }}>
              <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: '140px 1fr', gap: 12, fontSize: 14 }}>
                <dt style={{ color: 'var(--zy-muted)' }}>Display name</dt>
                <dd style={{ margin: 0 }}>{detail.displayName || detail.realm}</dd>
                <dt style={{ color: 'var(--zy-muted)' }}>Enabled</dt>
                <dd style={{ margin: 0, color: detail.enabled ? 'var(--zy-ok)' : 'var(--zy-muted)' }}>
                  {detail.enabled ? 'Yes' : 'No'}
                </dd>
                <dt style={{ color: 'var(--zy-muted)' }}>Realm ID</dt>
                <dd style={{ margin: 0, fontFamily: 'var(--zy-mono)', fontSize: 12 }}>{detail.id}</dd>
              </dl>
            </div>
          )}

          {tab === 'clients' && (
            <>
              <div style={{ marginBottom: 16 }}>
                <button type="button" className="btn btn-primary" onClick={() => setShowClientForm(true)}>
                  + Mint client
                </button>
              </div>
              {showClientForm && (
                <div style={{ marginBottom: 20 }}>
                  <ClientForm
                    onCancel={() => setShowClientForm(false)}
                    onSubmit={async (c) => {
                      await api.createClient(realm, c);
                      setShowClientForm(false);
                      load();
                    }}
                  />
                </div>
              )}
              <DataTable
                rows={clients.filter((c) => !c.clientId.startsWith('account') && c.clientId !== 'broker')}
                keyField={(c) => c.id ?? c.clientId}
                columns={[
                  { key: 'clientId', label: 'Client ID' },
                  { key: 'name', label: 'Name' },
                  {
                    key: 'type',
                    label: 'Type',
                    render: (c) => (c.publicClient ? 'Public' : 'Confidential'),
                  },
                  {
                    key: 'actions',
                    label: '',
                    render: (c) => (
                      <span style={{ display: 'flex', gap: 8 }}>
                        {!c.publicClient && c.id && (
                          <>
                            <button type="button" className="btn btn-ghost" style={{ fontSize: 12 }} onClick={() => showSecret(c)}>
                              Secret
                            </button>
                            <button type="button" className="btn btn-ghost" style={{ fontSize: 12 }} onClick={() => setRegenClient(c)}>
                              Rotate
                            </button>
                          </>
                        )}
                      </span>
                    ),
                  },
                ]}
              />
            </>
          )}

          {tab === 'users' && (
            <>
              <div style={{ marginBottom: 16 }}>
                <button type="button" className="btn btn-primary" onClick={() => setShowUserForm(true)}>
                  + Invite user
                </button>
              </div>
              {showUserForm && (
                <div style={{ marginBottom: 20 }}>
                  <UserForm
                    onCancel={() => setShowUserForm(false)}
                    onSubmit={async (u, pw) => {
                      await api.createUser(realm, u);
                      setShowUserForm(false);
                      load();
                      if (pw && u.username) {
                        const list = await api.listUsers(realm, u.username);
                        const created = list.find((x) => x.username === u.username);
                        if (created?.id) await api.resetPassword(realm, created.id, pw, true);
                      }
                    }}
                  />
                </div>
              )}
              <DataTable
                rows={users}
                keyField={(u) => u.id ?? u.username}
                columns={[
                  { key: 'username', label: 'Username' },
                  { key: 'email', label: 'Email' },
                  {
                    key: 'enabled',
                    label: 'Status',
                    render: (u) => (
                      <span style={{ color: u.enabled ? 'var(--zy-ok)' : 'var(--zy-muted)' }}>
                        {u.enabled ? 'Active' : 'Disabled'}
                      </span>
                    ),
                  },
                  {
                    key: 'actions',
                    label: '',
                    render: (u) =>
                      u.id ? (
                        <button
                          type="button"
                          className="btn btn-ghost"
                          style={{ fontSize: 12 }}
                          onClick={() => setPwUser(u)}
                        >
                          Set password
                        </button>
                      ) : null,
                  },
                ]}
              />
            </>
          )}

          {tab === 'roles' && (
            <DataTable
              rows={roles}
              keyField={(r) => r.id ?? r.name}
              columns={[
                { key: 'name', label: 'Role' },
                { key: 'description', label: 'Description' },
              ]}
            />
          )}

          {tab === 'idps' && (
            <DataTable
              rows={idps}
              keyField={(i) => i.alias}
              empty="No identity providers configured"
              columns={[
                { key: 'alias', label: 'Alias' },
                { key: 'providerId', label: 'Provider' },
                {
                  key: 'enabled',
                  label: 'Status',
                  render: (i) => (i.enabled ? 'Enabled' : 'Disabled'),
                },
              ]}
            />
          )}

          {tab === 'events' && (
            <DataTable
              rows={events}
              keyField={(e) => `${e.time}-${e.resourcePath ?? ''}`}
              empty="No admin events"
              columns={[
                {
                  key: 'time',
                  label: 'Time',
                  render: (e) => new Date(e.time).toLocaleString(),
                },
                { key: 'operationType', label: 'Operation' },
                { key: 'resourceType', label: 'Resource' },
                { key: 'resourcePath', label: 'Path' },
              ]}
            />
          )}
          </div>
        </div>

      {secret && (
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
          onClick={() => setSecret(null)}
        >
          <div className="card" style={{ padding: 24, maxWidth: 480 }} onClick={(e) => e.stopPropagation()}>
            <h3 style={{ marginTop: 0 }}>Client secret — {secret.clientId}</h3>
            <p style={{ fontSize: 13, color: 'var(--zy-muted)' }}>Copy now. This value may not be shown again.</p>
            <code
              style={{
                display: 'block',
                padding: 12,
                background: 'var(--zy-surface-2)',
                borderRadius: 8,
                fontFamily: 'var(--zy-mono)',
                fontSize: 13,
                wordBreak: 'break-all',
              }}
            >
              {secret.value}
            </code>
            <button
              type="button"
              className="btn btn-primary"
              style={{ marginTop: 16 }}
              onClick={() => navigator.clipboard.writeText(secret.value)}
            >
              Copy
            </button>
          </div>
        </div>
      )}

      <ConfirmDialog
        open={!!regenClient}
        title="Regenerate client secret"
        message={`Generate a new secret for "${regenClient?.clientId}"? The old secret will stop working immediately.`}
        confirmLabel="Regenerate"
        danger
        onConfirm={doRegen}
        onCancel={() => setRegenClient(null)}
      />

      <PasswordDialog
        open={!!pwUser}
        title={`Set password — ${pwUser?.username ?? ''}`}
        subtitle="Updates this user's Keycloak credentials in the current realm."
        confirmLabel="Set password"
        temporaryToggle
        onCancel={() => setPwUser(null)}
        onSubmit={async ({ newPassword, temporary }) => {
          if (!pwUser?.id) return;
          await api.resetPassword(realm, pwUser.id, newPassword, temporary);
          setPwUser(null);
          setPwToast(`Password updated for ${pwUser.username}`);
        }}
      />
    </ConsoleLayout>
  );
}
