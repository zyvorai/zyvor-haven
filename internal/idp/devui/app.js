/* Haven OIDC playground UI. Depends on lib.js (window.HavenDev). */
(function () {
  'use strict';
  const L = window.HavenDev;
  const SS = window.sessionStorage;
  const $ = (id) => document.getElementById(id);

  const S = { cfg: null, disc: null, jwks: null, timeline: [], tokens: null, scope: '', oldRefresh: null };

  // ---- persistence -------------------------------------------------------
  const save = (k, v) => SS.setItem('hd.' + k, JSON.stringify(v));
  const load = (k) => { try { return JSON.parse(SS.getItem('hd.' + k)); } catch (e) { return null; } };
  const persist = () => { save('timeline', S.timeline); save('tokens', S.tokens); save('scope', S.scope); save('oldRefresh', S.oldRefresh); save('fromRefresh', !!S.fromRefresh); };

  // ---- small DOM helpers (textContent only, never innerHTML) -------------
  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
    for (const kid of kids) e.append(kid);
    return e;
  }
  const pretty = (s) => { try { return JSON.stringify(JSON.parse(s), null, 2); } catch (e) { return s; } };
  const redirectUri = () => location.origin + '/dev/';
  const baseFail = () => ({ clientId: S.cfg.client_id, redirectUri: redirectUri() });

  // ---- HTTP with timeline ------------------------------------------------
  async function http(label, method, url, { headers = {}, form = null } = {}) {
    const reqBody = form ? new URLSearchParams(form).toString() : '';
    if (form) headers = Object.assign({ 'Content-Type': 'application/x-www-form-urlencoded' }, headers);
    const x = { label, method, url, reqHeaders: headers, reqBody, status: 0, resHeaders: {}, resBody: '' };
    try {
      const res = await fetch(url, { method, headers, body: form ? reqBody : undefined, credentials: 'omit', cache: 'no-store' });
      x.status = res.status;
      res.headers.forEach((v, k) => { x.resHeaders[k] = v; });
      x.resBody = await res.text();
    } catch (e) {
      x.resBody = 'network error: ' + e.message;
    }
    S.timeline.push(x);
    persist();
    renderTimeline();
    return x;
  }
  const json = (x) => { try { return JSON.parse(x.resBody); } catch (e) { return null; } };

  // ---- rendering ---------------------------------------------------------
  function renderTimeline() {
    const ol = $('timeline');
    ol.replaceChildren();
    $('timeline-empty').hidden = S.timeline.length > 0;
    S.timeline.forEach((x, i) => {
      const cls = x.status >= 200 && x.status < 400 ? 'pass' : 'fail';
      const copy = el('button', { type: 'button' }, 'Copy as curl');
      copy.addEventListener('click', async () => {
        try { await navigator.clipboard.writeText(L.toCurl(x)); copy.textContent = 'Copied'; }
        catch (e) { copy.textContent = 'Copy failed'; }
      });
      const hdrs = (h) => Object.entries(h).map(([k, v]) => k + ': ' + v).join('\n');
      ol.append(el('li', {},
        el('div', {}, el('strong', {}, (i + 1) + '. ' + x.label + ' '), el('code', {}, x.method + ' ' + x.url), ' ',
          el('span', { class: cls }, String(x.status || 'ERR')), ' ', copy),
        el('details', {}, el('summary', {}, 'Request'), el('pre', {}, hdrs(x.reqHeaders) + (x.reqBody ? '\n\n' + x.reqBody : ''))),
        el('details', { open: '' }, el('summary', {}, 'Response'), el('pre', {}, hdrs(x.resHeaders) + '\n\n' + pretty(x.resBody)))));
    });
  }

  function renderDiag(items) {
    $('diag-section').hidden = items.length === 0;
    $('diag').replaceChildren(...items.map((t) => el('div', { class: 'diag-item' }, t)));
  }

  function renderChecks(rows) {
    $('checks-section').hidden = rows.length === 0;
    $('checks').tBodies[0].replaceChildren(...rows.map((r) => el('tr', {},
      el('td', { class: r.pass ? 'pass' : 'fail' }, r.pass ? 'PASS' : 'FAIL'), el('td', {}, r.label), el('td', {}, r.hint))));
  }

  function tokenCard(name, token, sig) {
    const card = el('div', { class: 'tok' }, el('h3', {}, name));
    const d = L.decodeJwt(token);
    if (!d) {
      card.append(el('p', { class: 'muted' }, 'Opaque token (not a JWT), shown as-is.'), el('pre', {}, token));
      return card;
    }
    card.append(
      el('p', {}, 'Signature: ', el('span', { class: sig && sig.ok ? 'pass' : 'fail' }, sig && sig.ok ? 'VERIFIED' : 'NOT VERIFIED'), ' ' + (sig ? sig.reason : '')),
      el('details', { open: '' }, el('summary', {}, 'Header'), el('pre', {}, JSON.stringify(d.header, null, 2))),
      el('details', { open: '' }, el('summary', {}, 'Payload'), el('pre', {}, JSON.stringify(d.payload, null, 2))),
      el('details', {}, el('summary', {}, 'Raw'), el('pre', {}, token)));
    return card;
  }

  async function inspect() {
    const t = S.tokens;
    $('tokens-section').hidden = !t;
    if (!t) { renderChecks([]); return; }
    const sigs = {};
    if (t.access_token) sigs.access = await L.verifyJwt(t.access_token, S.jwks);
    if (t.id_token) sigs.id = await L.verifyJwt(t.id_token, S.jwks);
    const cards = [];
    if (t.access_token) cards.push(tokenCard('access_token', t.access_token, sigs.access));
    if (t.id_token) cards.push(tokenCard('id_token', t.id_token, sigs.id));
    if (t.refresh_token) cards.push(tokenCard('refresh_token', t.refresh_token, null));
    $('tokens').replaceChildren(...cards);
    renderChecks(await L.runChecks({
      issuer: S.cfg.issuer, clientId: S.cfg.client_id, accessToken: t.access_token, idToken: t.id_token,
      nonce: load('nonce'), fromRefresh: !!S.fromRefresh, requestedScope: S.scope, jwks: S.jwks, now: Math.floor(Date.now() / 1000), sigs }));
  }

  function updateButtons() {
    const t = S.tokens;
    $('btn-userinfo').disabled = !(t && t.access_token);
    $('btn-refresh').disabled = !(t && t.refresh_token);
    $('btn-replay').disabled = !S.oldRefresh;
    $('btn-signout').disabled = !(t && t.id_token && S.disc && S.disc.end_session_endpoint);
  }

  // ---- flows -------------------------------------------------------------
  async function discover() {
    const x = await http('Discovery', 'GET', S.cfg.issuer.replace(/\/$/, '') + '/.well-known/openid-configuration');
    S.disc = json(x);
    if (!S.disc || !S.disc.authorization_endpoint) throw new Error('Discovery failed. Is the issuer ' + S.cfg.issuer + ' reachable from this origin?');
    S.jwks = json(await http('JWKS', 'GET', S.disc.jwks_uri));
  }

  const selectedScope = () =>
    Array.from(document.querySelectorAll('input[name=scope]:checked')).map((c) => c.value).join(' ');

  async function signIn() {
    S.timeline = []; S.tokens = null; S.oldRefresh = null; S.fromRefresh = false;
    await discover();
    const verifier = L.randomB64url(32);
    const state = L.randomB64url(16);
    const nonce = L.randomB64url(16);
    S.scope = selectedScope();
    save('verifier', verifier); save('state', state); save('nonce', nonce);
    persist();
    const q = new URLSearchParams({
      response_type: 'code', client_id: S.cfg.client_id, redirect_uri: redirectUri(), scope: S.scope,
      state, nonce, code_challenge: await L.pkceChallenge(verifier), code_challenge_method: 'S256' });
    location.assign(S.disc.authorization_endpoint + '?' + q.toString());
  }

  async function handleCallback(p) {
    history.replaceState(null, '', location.pathname);
    const f = Object.assign(baseFail(), { error: p.get('error') || '', description: p.get('error_description') || '' });
    await discover();
    S.timeline.push({ label: 'Authorization response', method: 'GET', url: location.origin + location.pathname + '?' + p.toString(),
      reqHeaders: {}, reqBody: '', status: p.get('error') ? 400 : 302, resHeaders: {}, resBody: JSON.stringify(Object.fromEntries(p), null, 2) });
    renderTimeline();
    const want = load('state');
    if (!want || p.get('state') !== want) f.stateMismatch = true;
    const iss = p.get('iss');
    if (iss !== null ? iss !== S.disc.issuer : S.disc.authorization_response_iss_parameter_supported) f.issMismatch = true;
    if (f.error || f.stateMismatch || f.issMismatch || !p.get('code')) { renderDiag(L.diagnose(f)); persist(); return; }
    const x = await http('Token (authorization_code)', 'POST', S.disc.token_endpoint, { form: {
      grant_type: 'authorization_code', client_id: S.cfg.client_id, code: p.get('code'),
      code_verifier: load('verifier'), redirect_uri: redirectUri() } });
    await takeTokens(x, f, false);
  }

  async function takeTokens(x, f, isRefresh) {
    const b = json(x) || {};
    if (x.status !== 200) {
      renderDiag(L.diagnose(Object.assign(f, { error: b.error, description: b.error_description, body: x.resBody, status: x.status })));
      return;
    }
    if (isRefresh) S.oldRefresh = S.tokens && S.tokens.refresh_token;
    S.tokens = b;
    S.fromRefresh = !!isRefresh; // a refreshed id_token carries no nonce (OIDC Core 12.2)
    const issues = [];
    if (!b.refresh_token) issues.push({ noRefreshToken: true });
    if (!b.id_token) issues.push({ noIdToken: true });
    renderDiag(issues.flatMap((i) => L.diagnose(Object.assign({}, f, i))));
    persist();
    await inspect();
    updateButtons();
  }

  async function callUserinfo() {
    const ep = S.disc.userinfo_endpoint;
    await http('Userinfo (access_token)', 'GET', ep, { headers: { Authorization: 'Bearer ' + S.tokens.access_token } });
    if (S.tokens.id_token) await http('Userinfo (id_token, expected to be rejected)', 'GET', ep, { headers: { Authorization: 'Bearer ' + S.tokens.id_token } });
  }

  async function refresh() {
    const x = await http('Token (refresh_token)', 'POST', S.disc.token_endpoint, { form: {
      grant_type: 'refresh_token', client_id: S.cfg.client_id, refresh_token: S.tokens.refresh_token } });
    await takeTokens(x, baseFail(), true);
  }

  async function replayOld() {
    const x = await http('Token (replay OLD refresh_token, expected invalid_grant)', 'POST', S.disc.token_endpoint, { form: {
      grant_type: 'refresh_token', client_id: S.cfg.client_id, refresh_token: S.oldRefresh } });
    const b = json(x) || {};
    renderDiag(L.diagnose(Object.assign(baseFail(), { error: b.error, description: b.error_description, body: x.resBody, status: x.status })));
    S.oldRefresh = null; persist(); updateButtons();
  }

  function signOut() {
    const q = new URLSearchParams({ id_token_hint: S.tokens.id_token, post_logout_redirect_uri: redirectUri(), client_id: S.cfg.client_id });
    S.tokens = null; S.oldRefresh = null; persist();
    location.assign(S.disc.end_session_endpoint + '?' + q.toString());
  }

  function clearAll() {
    SS.clear();
    S.timeline = []; S.tokens = null; S.oldRefresh = null;
    renderTimeline(); renderDiag([]); renderChecks([]);
    $('tokens-section').hidden = true;
    updateButtons();
  }

  // ---- boot --------------------------------------------------------------
  const guard = (fn) => async () => {
    try { await fn(); } catch (e) { renderDiag([String(e.message || e)]); }
  };

  async function init() {
    S.cfg = await (await fetch('config.json', { cache: 'no-store' })).json();
    $('issuer').textContent = S.cfg.issuer;
    $('client').textContent = S.cfg.client_id;
    $('redirect').textContent = redirectUri();
    S.timeline = load('timeline') || [];
    S.tokens = load('tokens');
    S.scope = load('scope') || '';
    S.oldRefresh = load('oldRefresh');
    S.fromRefresh = !!load('fromRefresh');
    $('btn-signin').addEventListener('click', guard(signIn));
    $('btn-userinfo').addEventListener('click', guard(callUserinfo));
    $('btn-refresh').addEventListener('click', guard(refresh));
    $('btn-replay').addEventListener('click', guard(replayOld));
    $('btn-signout').addEventListener('click', guard(signOut));
    $('btn-clear').addEventListener('click', clearAll);
    renderTimeline();
    const p = new URLSearchParams(location.search);
    if ((p.has('code') || p.has('error')) && (p.get('state') || '').startsWith('wz.')) {
      // A "Test login" run from the add-an-app wizard: hand the response to the
      // opener (same origin only) and leave the playground's own state alone.
      history.replaceState(null, '', location.pathname);
      if (window.opener) {
        window.opener.postMessage({ type: 'haven-wz', search: '?' + p.toString() }, location.origin);
        window.close();
      } else {
        renderDiag(['This is a Test login callback but no wizard window opened it. Start Test login again from the Add an app section.']);
      }
      return;
    }
    if (p.has('code') || p.has('error')) {
      await guard(() => handleCallback(p))();
    } else if (S.tokens) {
      await guard(async () => { await discover(); await inspect(); })();
    }
    updateButtons();
    $('btn-signin').focus();
  }

  window.HavenDevApp = { init };
  init().catch((e) => renderDiag(['Could not load config.json: ' + e.message]));
})();
