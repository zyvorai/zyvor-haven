// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { useCallback, useEffect, useMemo, useState, type ChangeEvent } from 'react';
import { api, type SecurityFinding, type SecurityPostureReport } from '../api/client';
import { ConsoleLayout } from '../components/ConsoleLayout';
import { ConsolePageHeader } from '../components/ConsolePageHeader';
import { BarList, ScoreDial, StackBar, scoreBand, type Tone } from '../components/graphics/Charts';
import { Art, SkeletonBlock } from '../components/graphics/Art';

const sevTone: Record<string, Tone> = { critical: 'err', high: 'err', medium: 'warn', low: 'blue', info: 'muted' };

const BASELINE_KEY = 'haven-guard-baseline';

function severityRank(value: SecurityFinding['severity']) {
  return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[value];
}

function saveFile(name: string, value: unknown) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/sarif+json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

export function SecurityPosturePage() {
  const [report, setReport] = useState<SecurityPostureReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [realm, setRealm] = useState('');
  const [baseline, setBaseline] = useState(() => localStorage.getItem(BASELINE_KEY) ?? '');
  const [exporting, setExporting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setReport(await api.securityPosture({ realm, baseline }));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load posture');
    } finally {
      setLoading(false);
    }
  }, [realm, baseline]);

  useEffect(() => {
    void load();
  }, [load]);

  const findings = useMemo(
    () => [...(report?.findings ?? [])].sort((a, b) => severityRank(a.severity) - severityRank(b.severity)),
    [report],
  );

  async function exportSarif() {
    setExporting(true);
    try {
      const sarif = await api.securityPostureSarif({ realm, baseline });
      saveFile('haven-guard.sarif', sarif);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to export SARIF');
    } finally {
      setExporting(false);
    }
  }

  function markBaseline() {
    if (!report?.fingerprint) return;
    localStorage.setItem(BASELINE_KEY, report.fingerprint);
    setBaseline(report.fingerprint);
  }

  function clearBaseline() {
    localStorage.removeItem(BASELINE_KEY);
    setBaseline('');
  }

  return (
    <ConsoleLayout>
      <main className="console-page guard-page">
        <ConsolePageHeader
          eyebrow="Haven Guard"
          title="Identity posture"
          subtitle="Continuously audit OIDC clients, detect configuration drift, and export findings to CI."
          actions={
            <div className="guard-actions">
              <button type="button" className="secondary-btn" onClick={() => void load()} disabled={loading}>
                {loading ? 'Scanning…' : 'Rescan'}
              </button>
              <button type="button" className="primary-btn" onClick={() => void exportSarif()} disabled={exporting || !report}>
                {exporting ? 'Exporting…' : 'Export SARIF'}
              </button>
            </div>
          }
        />

        <section className="guard-filterbar" aria-label="Posture filters">
          <label>
            <span>Realm</span>
            <input
              value={realm}
              onChange={(e: ChangeEvent<HTMLInputElement>) => setRealm(e.target.value.trim())}
              placeholder="All realms (master excluded)"
            />
          </label>
          <div className="guard-baseline">
            <span>Drift baseline</span>
            <strong>{baseline ? 'Pinned' : 'Not set'}</strong>
            {baseline ? (
              <button type="button" className="text-btn" onClick={clearBaseline}>Clear</button>
            ) : (
              <button type="button" className="text-btn" onClick={markBaseline} disabled={!report}>Pin current</button>
            )}
          </div>
        </section>

        {error && (
          <div className="guard-error" role="alert">
            <Art name="offline" size={72} />
            <div>
              <strong>Guard could not complete the scan</strong>
              <span>{error}</span>
            </div>
            <button type="button" className="secondary-btn" onClick={() => void load()}>Try again</button>
          </div>
        )}

        {loading && !report && (
          <section className="guard-summary-grid" aria-busy="true">
            <SkeletonBlock card label="Scanning identity posture" rows={3} />
            <SkeletonBlock card label="Loading severity counts" rows={3} />
            <SkeletonBlock card label="Loading fingerprint" rows={3} />
          </section>
        )}

        {report && (
          <>
            <section className="guard-summary-grid">
              <article className="guard-score-card">
                <ScoreDial score={report.score} grade={report.grade} />
                <div>
                  <p className="guard-kicker">Security grade</p>
                  <h2>{report.grade}</h2>
                  <p>{report.realmCount} realms · {report.clientCount} application clients</p>
                  <p className={`guard-band guard-band--${scoreBand(report.score).name.replace(' ', '-')}`}>{scoreBand(report.score).name}</p>
                </div>
              </article>

              <article className="guard-count-card">
                <p className="guard-kicker">Findings by severity</p>
                <StackBar
                  label="Findings by severity"
                  parts={(['critical', 'high', 'medium', 'low'] as const).map((k) => ({ label: k, value: report.counts[k], tone: sevTone[k] }))}
                />
                <div><span className="sev-dot critical" />Critical<strong>{report.counts.critical}</strong></div>
                <div><span className="sev-dot high" />High<strong>{report.counts.high}</strong></div>
                <div><span className="sev-dot medium" />Medium<strong>{report.counts.medium}</strong></div>
                <div><span className="sev-dot low" />Low<strong>{report.counts.low}</strong></div>
              </article>

              <article className="guard-drift-card">
                <p className="guard-kicker">Configuration fingerprint</p>
                <code title={report.fingerprint}>{report.fingerprint.slice(0, 22)}…</code>
                <div className={`guard-drift-state ${baseline ? (report.drifted ? 'drifted' : 'clean') : 'neutral'}`}>
                  {baseline ? (report.drifted ? 'Drift detected' : 'Matches baseline') : 'Pin this state to detect drift'}
                </div>
                <button type="button" className="text-btn" onClick={markBaseline}>Use as baseline</button>
              </article>
            </section>

            <section className="guard-section">
              <div className="guard-section-head">
                <div>
                  <p className="guard-kicker">Findings</p>
                  <h2>{findings.length ? `${findings.length} items need attention` : 'No risky OIDC settings detected'}</h2>
                </div>
              </div>

              <div className="guard-findings">
                {findings.map((finding, index) => (
                  <article className="guard-finding" key={`${finding.ruleId}-${finding.realm}-${finding.clientId ?? ''}-${index}`}>
                    <div className="guard-finding-top">
                      <span className={`guard-severity ${finding.severity}`}>{finding.severity}</span>
                      <code>{finding.ruleId}</code>
                      <span className="guard-scope">{finding.realm}{finding.clientId ? ` / ${finding.clientId}` : ''}</span>
                    </div>
                    <h3>{finding.title}</h3>
                    {finding.evidence && <p className="guard-evidence">{finding.evidence}</p>}
                    <p className="guard-remediation">{finding.remediation}</p>
                  </article>
                ))}
                {!findings.length && (
                  <div className="guard-empty">
                    <Art name="shield" size={150} />
                    <strong>Guard is clean.</strong>
                    <span>Authorization Code + PKCE, exact redirects, and trusted origins are in good shape.</span>
                  </div>
                )}
              </div>
            </section>

            <section className="guard-section">
              <div className="guard-section-head">
                <div>
                  <p className="guard-kicker">Realm inventory</p>
                  <h2>Score by tenant</h2>
                </div>
              </div>
              {report.realms.length > 0 && (
                <BarList
                  label="Score by tenant"
                  max={100}
                  data={report.realms.map((item) => ({ label: item.realm, value: item.score, tone: item.score >= 85 ? 'ok' : item.score >= 70 ? 'teal' : item.score >= 50 ? 'warn' : 'err' }))}
                />
              )}
              <div className="guard-realm-grid">
                {report.realms.map((item) => (
                  <article key={item.realm} className="guard-realm-card">
                    <div>
                      <strong>{item.realm}</strong>
                      <span>{item.clientCount} app clients</span>
                    </div>
                    <div className="guard-realm-score">{item.score}</div>
                  </article>
                ))}
              </div>
            </section>
          </>
        )}
      </main>
    </ConsoleLayout>
  );
}
