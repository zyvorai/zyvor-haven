// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { Link } from 'react-router-dom';
import { Footer } from '../components/Footer';
import { NavBar } from '../components/NavBar';
import { problems } from '../data/mock';

export function Landing() {
  return (
    <>
      <NavBar />
      <main>
        <section className="hero fade-in">
          <div className="wrap-narrow">
            <p className="hero-eyebrow">Private cloud identity</p>
            <h1 className="hero-title">Identity for the private cloud.</h1>
            <p className="hero-sub">
              Haven turns an identity server and PostgreSQL into one product. Declare an
              IdentityPlane — get HA Postgres, the haven-idp identity server,
              certs, ingress, and your first realm.
            </p>
            <div className="btn-row" style={{ justifyContent: 'center' }}>
              <Link to="/login" className="btn btn-primary">
                Sign in
              </Link>
              <Link to="/deck" className="btn btn-ghost">
                Open Command Deck
              </Link>
            </div>
          </div>
        </section>

        <section className="section section-alt">
          <div className="wrap">
            <p className="section-eyebrow">Why Haven</p>
            <h2 className="section-title">The gap most identity operators leave open</h2>
            <div className="card-grid">
              {problems.map((p) => (
                <article key={p.title} className="card">
                  <h3 className="card-title">{p.title}</h3>
                  <p className="card-desc">{p.desc}</p>
                </article>
              ))}
            </div>
          </div>
        </section>

        <section className="section">
          <div className="wrap">
            <p className="section-eyebrow">Architecture</p>
            <h2 className="section-title">One object. Two runtimes.</h2>
            <p className="section-sub">
              IdentityPlane composes CloudNativePG, haven-idp, and
              cert-manager — Haven owns the plane, not a fork of upstream.
            </p>
            <div className="arch-flow">
              <div className="arch-node accent">IdentityPlane CR</div>
              <div className="arch-arrow">↓</div>
              <div className="arch-row">
                <div className="arch-node">CloudNativePG</div>
                <div className="arch-node">haven-idp</div>
                <div className="arch-node">Certs + Ingress</div>
              </div>
            </div>
          </div>
        </section>

        <section className="section section-alt" id="quick-start">
          <div className="wrap">
            <p className="section-eyebrow">Quick start</p>
            <h2 className="section-title">Running in three commands</h2>
            <div className="steps">
              <div className="step">
                <div className="step-num">1</div>
                <div>
                  <h3 className="step-title">Install operators (once per cluster)</h3>
                  <p className="step-desc">
                    CloudNativePG and cert-manager.
                  </p>
                  <pre className="code-block">
                    <span className="cmd">$</span> ./deploy/operators/install.sh
                  </pre>
                </div>
              </div>
              <div className="step">
                <div className="step-num">2</div>
                <div>
                  <h3 className="step-title">Deploy Postgres + identity server</h3>
                  <p className="step-desc">
                    The v0 compose path — same manifests the v1 controller will render.
                  </p>
                  <pre className="code-block">
                    <span className="cmd">$</span> make dev{'\n'}
                    <span className="cmd">$</span> make wait && make doctor
                  </pre>
                </div>
              </div>
              <div className="step">
                <div className="step-num">3</div>
                <div>
                  <h3 className="step-title">Sign in</h3>
                  <p className="step-desc">
                    Print the command that reads the generated admin password, then sign in to the console.
                  </p>
                  <pre className="code-block">
                    <span className="cmd">$</span> make admin
                  </pre>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="section">
          <div className="wrap">
            <p className="section-eyebrow">Console</p>
            <h2 className="section-title">Command Deck</h2>
            <p className="section-sub">
              Plane health, database lag, backup age, and a live reconcile timeline —
              private-cloud ops, not an admin form.
            </p>
            <div
              className="card"
              style={{
                padding: 0,
                overflow: 'hidden',
                marginBottom: 'var(--zy-s6)',
              }}
            >
              <img
                src="/wireframes/command-deck.jpg"
                alt="Haven Command Deck wireframe"
                style={{ width: '100%', opacity: 0.92 }}
                onError={(e) => {
                  (e.target as HTMLImageElement).style.display = 'none';
                }}
              />
            </div>
            <Link to="/deck" className="btn btn-primary">
              Open Command Deck
            </Link>
          </div>
        </section>
      </main>
      <Footer />
    </>
  );
}
