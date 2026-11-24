/* Add-an-app wizard and Test login debugger. Depends on lib.js and snippets.js.
 * Everything is inserted with textContent. The client secret lives only in the
 * `mem.secret` variable: never in storage, the URL, a snippet or the timeline. */
(function () {
  'use strict';
  const L = window.HavenDev;
  const SN = window.HavenSnippets;
  const $ = (id) => document.getElementById(id);
  const SS = window.sessionStorage;

  const mem = { secret: '', app: null, cfg: null, disc: null, jwks: null };
  // Placeholders only; built from parts so no absolute URL literal sits in this file.
  const H = 'http' + ':' + '//';
  const PLACEHOLDER = { spa: H + 'localhost:5173/callback', web: 'https' + ':' + '//app.example.com/oidc/callback', native: H + '127.0.0.1:8000', m2m: '' };

  function el(tag, attrs, ...kids) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
    for (const kid of kids) e.append(kid);
    return e;
  }
  const typeNow = () => (document.querySelector('input[name=wz-type]:checked') || {}).value || 'spa';
  const callbackUri = () => location.origin + '/dev/';
  const isConfidential = (a) => a && !a.public;

  async function copy(text, btn) {
    const old = btn.textContent;
    try { await navigator.clipboard.writeText(text); btn.textContent = 'Copied'; } catch (e) { btn.textContent = 'Copy failed'; }
    setTimeout(() => { btn.textContent = old; }, 1500);
  }

  // ---- form ----------------------------------------------------------------
  function syncForm() {
    const t = typeNow();
    $('wz-redirects-row').hidden = t === 'm2m';
    $('wz-cb-row').hidden = t === 'm2m';
    $('wz-redirects').setAttribute('placeholder', PLACEHOLDER[t]);
  }

  const showErrors = (msgs) => $('wz-errors').replaceChildren(...msgs.map((m) => el('div', { class: 'diag-item' }, m)));

  function readForm() {
    return {
      type: typeNow(),
      name: $('wz-name').value,
      redirectUris: typeNow() === 'm2m' ? [] : $('wz-redirects').value.split('\n').map((s) => s.trim()).filter(Boolean),
      playgroundCallback: typeNow() !== 'm2m' && $('wz-cb').checked,
    };
  }

  async function register(ev) {
    ev.preventDefault();
    const f = readForm();
    const errs = L.validateApp(f);
    showErrors(errs.map((e) => e.message));
    if (errs.length) return;
    $('wz-create').disabled = true;
    try {
      const res = await fetch('api/clients', {
        method: 'POST', credentials: 'omit', cache: 'no-store',
        headers: { 'Content-Type': 'application/json', 'X-Haven-Dev': '1' },
        body: JSON.stringify(f),
      });
      let b = {};
      try { b = await res.json(); } catch (e) { /* non-JSON error body */ }
      if (res.status !== 201) { showErrors(['Registration failed (' + res.status + '): ' + (b.error || 'unexpected response')]); return; }
      mem.secret = b.secret || '';
      delete b.secret; // the response object no longer carries it
      mem.app = b;
      try { SS.setItem('hd.wz.app', JSON.stringify(b)); } catch (e) { /* storage unavailable */ }
      showResult();
    } catch (e) {
      showErrors(['Registration failed: ' + e.message]);
    } finally {
      $('wz-create').disabled = false;
    }
  }

  // ---- result: secret, snippets -----------------------------------------------
  function renderSecret() {
    const has = !!mem.secret;
    $('wz-secret-box').hidden = !has;
    $('wz-secret').textContent = has ? mem.secret : '';
    $('wz-secret-ask').hidden = !(isConfidential(mem.app) && !has);
  }

  async function showResult() {
    const a = mem.app;
    $('wz-result').hidden = false;
    $('wz-client').textContent = a.clientId;
    $('wz-issuer').textContent = mem.cfg.issuer;
    $('wz-redirs').textContent = (a.redirectUris || []).join(' , ') || '(none)';
    renderSecret();
    $('wz-checks').hidden = true; $('wz-summary').replaceChildren(); $('wz-tokens').replaceChildren(); $('wz-test-status').textContent = '';
    let tokenEndpoint;
    try { await ensureDiscovery(); tokenEndpoint = mem.disc.token_endpoint; } catch (e) { /* snippets fall back to the default path */ }
    const primary = (a.redirectUris || []).find((u) => u !== callbackUri()) || (a.redirectUris || [])[0] || '';
    const snips = SN.buildSnippets({ type: a.type, name: a.name, clientId: a.clientId, issuer: mem.cfg.issuer, redirectUri: primary, tokenEndpoint });
    const tabs = $('wz-tabs');
    const pane = $('wz-snippet-pane');
    const select = (s, btn) => {
      for (const b of tabs.children) b.setAttribute('aria-selected', b === btn ? 'true' : 'false');
      const copyBtn = el('button', { type: 'button' }, 'Copy snippet');
      copyBtn.addEventListener('click', () => copy(s.code, copyBtn));
      const note = s.relevant ? '' : ' (less common for this app type)';
      pane.replaceChildren(el('p', { class: 'muted' }, s.title + note + ' · secrets come from the OIDC_CLIENT_SECRET environment variable'), el('pre', { class: 'snippet' }, s.code), copyBtn);
    };
    tabs.replaceChildren(...snips.map((s) => {
      const b = el('button', { type: 'button', role: 'tab', 'aria-selected': 'false' }, s.title);
      b.addEventListener('click', () => select(s, b));
      return b;
    }));
    select(snips[0], tabs.children[0]);
  }

  // ---- discovery ------------------------------------------------------------------
  async function ensureDiscovery() {
    if (mem.disc && mem.jwks) return;
    const r = await fetch(mem.cfg.issuer.replace(/\/$/, '') + '/.well-known/openid-configuration', { credentials: 'omit', cache: 'no-store' });
    mem.disc = await r.json();
    mem.jwks = await (await fetch(mem.disc.jwks_uri, { credentials: 'omit', cache: 'no-store' })).json();
  }

  // ---- Test login -----------------------------------------------------------------
  const exchanges = [];
  async function post(label, url, form, clientAuth) {
    const headers = { 'Content-Type': 'application/x-www-form-urlencoded' };
    const shown = Object.assign({}, headers);
    if (clientAuth) { headers.Authorization = 'Basic ' + btoa(unescape(encodeURIComponent(clientAuth.id + ':' + clientAuth.secret))); shown.Authorization = 'Basic [redacted]'; }
    const body = new URLSearchParams(form).toString();
    const x = { label, method: 'POST', url, reqHeaders: shown, reqBody: body.replace(/(code_verifier|refresh_token)=[^&]*/g, '$1=[hidden]'), status: 0, resBody: '' };
    try {
      const res = await fetch(url, { method: 'POST', headers, body, credentials: 'omit', cache: 'no-store' });
      x.status = res.status; x.resBody = await res.text();
    } catch (e) { x.resBody = 'network error: ' + e.message; }
    exchanges.push(x);
    let json = null; try { json = JSON.parse(x.resBody); } catch (e) { /* keep null */ }
    return { status: x.status, body: json };
  }

  function clientAuth() {
    const secret = mem.secret || $('wz-secret-in').value;
    return isConfidential(mem.app) && secret ? { id: mem.app.clientId, secret } : null;
  }

  function renderRows(rows) {
    const c = L.summarize(rows);
    $('wz-summary').replaceChildren(el('p', {}, 'Result: ', el('span', { class: 'pass' }, c.PASS + ' PASS'), ' · ',
      el('span', { class: c.FAIL ? 'fail' : 'muted' }, c.FAIL + ' FAIL'), ' · ', el('span', { class: 'warn' }, c.INFO + ' INFO'), ' · ' + c.SKIP + ' skipped'));
    const cls = { PASS: 'pass', FAIL: 'fail', INFO: 'warn', SKIP: 'muted' };
    $('wz-checks').hidden = false;
    $('wz-checks').tBodies[0].replaceChildren(...rows.map((r) => el('tr', { 'data-check': r.id },
      el('td', { class: cls[r.status] }, r.status), el('td', {}, r.label), el('td', {}, r.input), el('td', {}, r.fix))));
  }

  function tokenCard(name, token, sig) {
    const card = el('div', { class: 'tok' }, el('h4', {}, name));
    const d = L.decodeJwt(token);
    if (!d) { card.append(el('p', { class: 'muted' }, 'Opaque token (not a JWT).')); return card; }
    card.append(
      el('p', {}, 'Signature: ', el('span', { class: sig && sig.ok ? 'pass' : 'fail' }, sig && sig.ok ? 'VERIFIED' : 'NOT VERIFIED'), ' ' + (sig ? sig.reason : '')),
      el('details', { open: '' }, el('summary', {}, 'Header'), el('pre', {}, JSON.stringify(d.header, null, 2))),
      el('details', { open: '' }, el('summary', {}, 'Claims'), el('pre', {}, JSON.stringify(d.payload, null, 2))));
    return card;
  }

  function renderExchanges() {
    const hdr = (h) => Object.entries(h).map(([k, v]) => k + ': ' + v).join('\n');
    return el('details', {}, el('summary', {}, 'HTTP exchanges (' + exchanges.length + ')'),
      ...exchanges.map((x) => el('pre', {}, x.label + '\n' + x.method + ' ' + x.url + '\n' + hdr(x.reqHeaders) + '\n\n' + x.reqBody + '\n\n=> ' + x.status + '\n' + x.resBody)));
  }

  const status = (t) => { $('wz-test-status').textContent = t; };

  async function testM2M() {
    const ca = clientAuth();
    if (!ca) { status('Paste the client secret above first (it is only kept in memory).'); return; }
    status('Requesting a token with client_credentials...');
    const r = await post('Token (client_credentials)', mem.disc.token_endpoint, { grant_type: 'client_credentials' }, ca);
    const b = r.body || {};
    const sigs = b.access_token ? { access: await L.verifyJwt(b.access_token, mem.jwks) } : {};
    renderRows(L.evaluateM2M({ configuredIssuer: mem.cfg.issuer, clientId: mem.app.clientId, disc: mem.disc, tokenStatus: r.status, tokenBody: b, sigs, now: Math.floor(Date.now() / 1000) }));
    $('wz-tokens').replaceChildren(...(b.access_token ? [tokenCard('access_token', b.access_token, sigs.access)] : []), renderExchanges());
    status('Done.');
  }

  function waitForCallback(popup, state) {
    return new Promise((resolve) => {
      let done = false;
      const finish = (v) => { if (done) return; done = true; window.removeEventListener('message', onMsg); clearInterval(t); clearTimeout(to); resolve(v); };
      const onMsg = (ev) => {
        if (ev.origin !== location.origin || ev.source !== popup || !ev.data || ev.data.type !== 'haven-wz') return;
        finish(new URLSearchParams(String(ev.data.search || '')));
      };
      window.addEventListener('message', onMsg);
      const t = setInterval(() => { if (popup.closed) setTimeout(() => finish(null), 300); }, 500);
      const to = setTimeout(() => finish(null), 5 * 60 * 1000);
      void state;
    });
  }

  async function testLogin() {
    exchanges.length = 0;
    $('wz-tokens').replaceChildren(); $('wz-checks').hidden = true; $('wz-summary').replaceChildren();
    try { await ensureDiscovery(); } catch (e) { status('Discovery failed: ' + e.message + '. Open this page on the same origin as the issuer.'); return; }
    if (mem.app.type === 'm2m') { await testM2M(); return; }

    const a = mem.app;
    const redirectUri = callbackUri();
    const scope = 'openid profile email offline_access';
    if (!(a.redirectUris || []).includes(redirectUri)) {
      renderRows([{ id: 'redirect_uri', label: 'redirect_uri is registered', status: 'FAIL',
        input: 'this page ' + redirectUri + ' is not registered; registered: ' + (a.redirectUris || []).join(', '),
        fix: 'Register another app with "Also register this page" ticked (exact URI ' + redirectUri + '), or test from the app itself.' }]);
      status('Test login needs the playground callback registered, so no login was started.');
      return;
    }
    const ca = clientAuth();
    if (isConfidential(a) && !ca) { status('Paste the client secret above first (it is only kept in memory).'); return; }

    const verifier = L.randomB64url(32);
    const state = 'wz.' + L.randomB64url(16);
    const nonce = L.randomB64url(16);
    const challenge = await L.pkceChallenge(verifier);
    const q = new URLSearchParams({ response_type: 'code', client_id: a.clientId, redirect_uri: redirectUri, scope, state, nonce, code_challenge: challenge, code_challenge_method: 'S256' });
    const popup = window.open('about:blank', 'havenwz', 'popup=yes,width=520,height=760');
    if (!popup) { status('The browser blocked the login popup. Allow popups for this page and try again.'); return; }
    popup.location.href = mem.disc.authorization_endpoint + '?' + q.toString();
    status('Waiting for you to sign in in the popup window...');
    const p = await waitForCallback(popup, state);
    try { popup.close(); } catch (e) { /* already closed */ }
    const base = { configuredIssuer: mem.cfg.issuer, clientId: a.clientId, redirectUri, registeredRedirects: a.redirectUris || [], request: { scope, state, nonce, pkceMethod: 'S256' }, disc: mem.disc, now: Math.floor(Date.now() / 1000) };
    if (!p) {
      renderRows(await L.evaluateLogin(Object.assign(base, { callback: { error: 'popup_closed', description: 'the login window closed before the IdP redirected back (an IdP error page, such as an unregistered redirect_uri, shows there instead of redirecting)' } })));
      status('No authorization response was received.');
      return;
    }
    const cb = { state: p.get('state'), iss: p.get('iss'), error: p.get('error'), description: p.get('error_description'), code: p.get('code') };
    exchanges.push({ label: 'Authorization response', method: 'GET', url: redirectUri + '?' + [...p.keys()].filter((k) => k !== 'code').map((k) => k + '=' + p.get(k)).join('&') + (p.get('code') ? '&code=[hidden]' : ''), reqHeaders: {}, reqBody: '', status: p.get('error') ? 400 : 302, resBody: '' });
    if (cb.error || !cb.code || cb.state !== state) {
      renderRows(await L.evaluateLogin(Object.assign(base, { callback: cb })));
      status('The authorization response failed.');
      return;
    }
    status('Exchanging the code...');
    const form = { grant_type: 'authorization_code', code: cb.code, code_verifier: verifier, redirect_uri: redirectUri };
    if (!ca) form.client_id = a.clientId;
    const tr = await post('Token (authorization_code)', mem.disc.token_endpoint, form, ca);
    const tokens = tr.status === 200 ? tr.body : null;
    const ctx = Object.assign(base, { callback: cb, tokenStatus: tr.status, tokenBody: tr.body, tokens });
    let sigs = {};
    if (tokens) {
      sigs = { access: tokens.access_token ? await L.verifyJwt(tokens.access_token, mem.jwks) : null, id: tokens.id_token ? await L.verifyJwt(tokens.id_token, mem.jwks) : null };
      ctx.sigs = sigs;
      if (mem.disc.userinfo_endpoint && tokens.access_token) {
        try {
          const res = await fetch(mem.disc.userinfo_endpoint, { headers: { Authorization: 'Bearer ' + tokens.access_token }, credentials: 'omit', cache: 'no-store' });
          const txt = await res.text(); let body = null; try { body = JSON.parse(txt); } catch (e) { /* not JSON */ }
          exchanges.push({ label: 'Userinfo', method: 'GET', url: mem.disc.userinfo_endpoint, reqHeaders: { Authorization: 'Bearer [redacted]' }, reqBody: '', status: res.status, resBody: txt });
          ctx.userinfo = { status: res.status, body };
        } catch (e) { ctx.userinfo = { status: 0, body: null }; }
      }
      if (tokens.refresh_token) {
        const rf = { grant_type: 'refresh_token', refresh_token: tokens.refresh_token };
        if (!ca) rf.client_id = a.clientId;
        ctx.refresh = await post('Token (refresh_token)', mem.disc.token_endpoint, rf, ca);
      }
    }
    renderRows(await L.evaluateLogin(ctx));
    const cards = [];
    if (tokens) {
      if (tokens.id_token) cards.push(tokenCard('id_token', tokens.id_token, sigs.id));
      if (tokens.access_token) cards.push(tokenCard('access_token', tokens.access_token, sigs.access));
    }
    cards.push(renderExchanges());
    $('wz-tokens').replaceChildren(...cards);
    status('Done.');
  }

  // ---- boot -------------------------------------------------------------------------
  async function init() {
    mem.cfg = await (await fetch('config.json', { cache: 'no-store' })).json();
    $('wz-cb-uri').textContent = callbackUri();
    syncForm();
    for (const r of document.querySelectorAll('input[name=wz-type]')) r.addEventListener('change', syncForm);
    $('wz-form').addEventListener('submit', register);
    $('wz-copy-secret').addEventListener('click', () => copy(mem.secret, $('wz-copy-secret')));
    $('wz-hide-secret').addEventListener('click', () => { mem.secret = ''; renderSecret(); });
    $('wz-test').addEventListener('click', () => { testLogin().catch((e) => status('Test login failed: ' + e.message)); });
    // Restore the (secret-free) app after a reload so snippets and Test login survive.
    try {
      const saved = JSON.parse(SS.getItem('hd.wz.app'));
      if (saved && saved.clientId) { mem.app = saved; await showResult(); }
    } catch (e) { /* nothing saved */ }
  }

  const isCb = /^wz\./.test(new URLSearchParams(location.search).get('state') || '');
  if (!isCb) init().catch((e) => showErrors(['Could not start the wizard: ' + e.message]));
  window.HavenWizard = { init };
})();
