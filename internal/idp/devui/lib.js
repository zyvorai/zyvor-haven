/* Pure helpers for the Haven OIDC playground. No DOM access here. */
(function (root) {
  'use strict';

  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const cr = () => root.crypto || globalThis.crypto;

  function b64urlEncode(bytes) {
    let s = '';
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function b64urlDecode(str) {
    if (typeof str !== 'string' || /[^A-Za-z0-9_-]/.test(str)) throw new Error('invalid base64url');
    const pad = '='.repeat((4 - (str.length % 4)) % 4);
    const bin = atob(str.replace(/-/g, '+').replace(/_/g, '/') + pad);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function randomB64url(n) {
    const a = new Uint8Array(n);
    cr().getRandomValues(a);
    return b64urlEncode(a);
  }

  async function sha256(bytes) {
    return new Uint8Array(await cr().subtle.digest('SHA-256', bytes));
  }

  async function pkceChallenge(verifier) {
    return b64urlEncode(await sha256(enc.encode(verifier)));
  }

  /** Decode a compact JWS without verifying. Returns null when not a JWT. */
  function decodeJwt(token) {
    if (typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    try {
      return {
        header: JSON.parse(dec.decode(b64urlDecode(parts[0]))),
        payload: JSON.parse(dec.decode(b64urlDecode(parts[1]))),
        signingInput: parts[0] + '.' + parts[1],
        signature: parts[2],
      };
    } catch (e) {
      return null;
    }
  }

  /** at_hash: base64url of the left half of SHA-256(access_token). */
  async function atHash(accessToken) {
    const h = await sha256(enc.encode(accessToken));
    return b64urlEncode(h.slice(0, h.length / 2));
  }

  /**
   * Verify an ES256 JWT against a JWKS using WebCrypto.
   * Returns {ok, reason}. Rejects any alg other than ES256 (including none).
   */
  async function verifyJwt(token, jwks) {
    const d = decodeJwt(token);
    if (!d) return { ok: false, reason: 'not a JWT' };
    if (d.header.alg !== 'ES256') return { ok: false, reason: 'alg is ' + JSON.stringify(d.header.alg) + ', only ES256 is accepted' };
    if (!d.header.kid) return { ok: false, reason: 'no kid in header' };
    const key = ((jwks && jwks.keys) || []).find((k) => k.kid === d.header.kid);
    if (!key) return { ok: false, reason: 'kid ' + d.header.kid + ' not found in JWKS' };
    if (key.kty !== 'EC' || key.crv !== 'P-256') return { ok: false, reason: 'JWKS key is not EC P-256' };
    let sig;
    try { sig = b64urlDecode(d.signature); } catch (e) { return { ok: false, reason: 'bad signature encoding' }; }
    if (sig.length !== 64) return { ok: false, reason: 'signature is not raw r||s (64 bytes)' };
    try {
      const pub = await cr().subtle.importKey(
        'jwk', { kty: 'EC', crv: 'P-256', x: key.x, y: key.y, ext: true },
        { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
      const ok = await cr().subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pub, sig, enc.encode(d.signingInput));
      return ok ? { ok: true, reason: 'signature valid' } : { ok: false, reason: 'signature does not match' };
    } catch (e) {
      return { ok: false, reason: 'verify error: ' + e.message };
    }
  }

  const row = (id, label, pass, hint) => ({ id, label, pass, hint });
  const sameSet = (a, b) => a.length === b.length && a.every((x) => b.includes(x));

  /**
   * Run PASS/FAIL checks.
   * ctx: {issuer, clientId, accessToken, idToken, nonce, requestedScope,
   *       jwks, now (seconds), sigs: {access, id} (verifyJwt results)}
   */
  async function runChecks(ctx) {
    const rows = [];
    const access = decodeJwt(ctx.accessToken);
    const idt = decodeJwt(ctx.idToken);
    const toks = [['access', access], ['id', idt]].filter((t) => t[1]);
    for (const [name, t] of toks) {
      const alg = t.header.alg;
      rows.push(row(name + '.alg', name + ' token alg is ES256', alg === 'ES256',
        alg === 'ES256' ? 'Signed with ES256.' : 'Got alg=' + JSON.stringify(alg) + '. Reject it: only ES256 is expected (never accept "none").'));
      const kid = t.header.kid;
      const inJwks = !!kid && ((ctx.jwks && ctx.jwks.keys) || []).some((k) => k.kid === kid);
      rows.push(row(name + '.kid', name + ' token kid is in JWKS', inJwks,
        inJwks ? 'kid ' + kid + ' found.' : 'kid ' + JSON.stringify(kid) + ' is missing from the JWKS; the key may have rotated, reload the page.'));
      const s = ctx.sigs && ctx.sigs[name];
      rows.push(row(name + '.sig', name + ' token signature verifies', !!(s && s.ok), s ? s.reason : 'not verified'));
      const p = t.payload;
      rows.push(row(name + '.iss', name + ' token iss equals issuer', p.iss === ctx.issuer,
        p.iss === ctx.issuer ? 'iss matches.' : 'iss is ' + JSON.stringify(p.iss) + ' but the issuer is ' + ctx.issuer + '. Check the base URL / proxy headers.'));
      const aud = [].concat(p.aud === undefined ? [] : p.aud);
      const audOk = name === 'id' ? aud.includes(ctx.clientId) : aud.includes(ctx.clientId) || p.azp === ctx.clientId;
      rows.push(row(name + '.aud', name + ' token aud contains client id', audOk,
        audOk ? 'aud=' + JSON.stringify(p.aud) + '.' : 'aud ' + JSON.stringify(p.aud) + (name === 'access' ? ' / azp ' + JSON.stringify(p.azp) : '') + ' does not include ' + ctx.clientId + '.'));
      const skew = typeof p.iat === 'number' ? Math.round(p.iat - ctx.now) : null;
      const expOk = typeof p.exp === 'number' && p.exp > ctx.now;
      rows.push(row(name + '.exp', name + ' token exp in future', expOk,
        expOk ? 'Expires in ' + Math.round(p.exp - ctx.now) + 's.' : 'Token is expired or has no exp. Refresh or sign in again.'));
      const iatOk = skew !== null && Math.abs(skew) <= 60;
      rows.push(row(name + '.iat', name + ' token iat is sane', iatOk,
        skew === null ? 'No iat claim.' : 'iat minus browser clock = ' + skew + 's' + (iatOk ? '.' : ' (more than 60s: clock skew between this machine and the IdP).')));
    }
    if (access) {
      const t = access.payload.typ;
      rows.push(row('access.typ', 'access token typ is Bearer', t === 'Bearer', t === 'Bearer' ? 'typ=Bearer.' : 'typ is ' + JSON.stringify(t) + ', expected "Bearer".'));
      if (ctx.requestedScope) {
        const want = ctx.requestedScope.split(/\s+/).filter(Boolean);
        const got = String(access.payload.scope || '').split(/\s+/).filter(Boolean);
        const ok = sameSet(want, got);
        rows.push(row('access.scope', 'scope claim matches requested scope', ok,
          ok ? 'scope=' + got.join(' ') : 'requested [' + want.join(' ') + '] but token has [' + got.join(' ') + '].'));
      }
    }
    if (idt) {
      const t = idt.payload.typ;
      rows.push(row('id.typ', 'id_token typ is ID', t === 'ID', t === 'ID' ? 'typ=ID.' : 'typ is ' + JSON.stringify(t) + ', expected "ID".'));
      if (ctx.fromRefresh && idt.payload.nonce === undefined) {
        // OIDC Core 12.2: an id_token from a refresh response need not carry the
        // original nonce, so absence is correct here (a present nonce is still checked below).
        rows.push(row('id.nonce', 'nonce not applicable to a refreshed token', true, 'Refresh responses carry no nonce (OIDC Core 12.2); the nonce was verified at sign-in.'));
      } else {
        const nOk = !!ctx.nonce && idt.payload.nonce === ctx.nonce;
        rows.push(row('id.nonce', 'nonce matches', nOk, nOk ? 'nonce echoed.' : 'id_token nonce ' + JSON.stringify(idt.payload.nonce) + ' differs from the one sent. Possible replay, or sessionStorage was cleared.'));
      }
      if (ctx.accessToken) {
        const want = await atHash(ctx.accessToken);
        const ok = idt.payload.at_hash === want;
        rows.push(row('id.at_hash', 'at_hash matches access token', ok, ok ? 'at_hash matches.' : 'expected ' + want + ', got ' + JSON.stringify(idt.payload.at_hash) + '.'));
      }
    }
    return rows;
  }

  /** Map a failure to plain-language advice. Returns an array of strings. */
  function diagnose(f) {
    const out = [];
    const err = f.error || '';
    const desc = f.description || '';
    const text = (err + ' ' + desc + ' ' + (f.body || '')).toLowerCase();
    if (f.stateMismatch) out.push('State mismatch: the state returned does not match the one stored for this tab. Start again with "Sign in" in this same tab; do not open the callback URL in another browser or tab.');
    if (f.issMismatch) out.push('The iss response parameter does not match the configured issuer. Either the IdP base URL / reverse proxy is wrong, or this is a mix-up attack. Fix the IdP base URL.');
    if (/invalid redirect|redirect_uri/.test(text)) out.push('Invalid redirect URI: register exactly ' + f.redirectUri + ' as a redirect URI on client ' + f.clientId + ' (exact match, including the trailing slash).');
    if (err === 'invalid_grant') out.push('invalid_grant: the code or refresh token was already used (a used refresh token has been rotated: use the newest one), expired (codes live 60s), or the redirect_uri / code_verifier differs from the authorize request. Sign in again.');
    if (err === 'invalid_request') out.push('invalid_request: a required parameter is missing or malformed. Common causes: no state, code_challenge_method other than S256, or missing code_challenge (PKCE is mandatory).');
    if (err === 'invalid_client' || /invalid client/.test(text)) out.push('Invalid client: client ' + f.clientId + ' does not exist, is disabled, or does not have the authorization code flow enabled in this realm.');
    if (err === 'invalid_scope') out.push('invalid_scope: one of the requested scopes is not allowed for this client.');
    if (f.noRefreshToken) out.push('No refresh token was issued: tick the offline_access scope, and make sure the client may use the refresh_token grant.');
    if (f.noIdToken) out.push('No id_token was returned: the openid scope must be requested.');
    if (err === 'login_required') out.push('login_required: prompt=none was used or no session exists. Sign in interactively.');
    if (err === 'access_denied') out.push('access_denied: the user or policy denied the request.');
    if (!out.length && (err || f.status >= 400)) out.push('Unrecognised failure' + (err ? ' (' + err + ')' : '') + '. Check the Timeline below for the raw response and the IdP logs.');
    return out;
  }

  const shq = (s) => "'" + String(s).replace(/'/g, "'\\''") + "'";

  function toCurl(x) {
    const parts = ['curl', '-i', '-X', x.method, shq(x.url)];
    for (const [k, v] of Object.entries(x.reqHeaders || {})) parts.push('-H', shq(k + ': ' + v));
    if (x.reqBody) parts.push('--data', shq(x.reqBody));
    return parts.join(' ');
  }

  // ---- add-an-app: input validation (twin of ValidateRedirect in wizard.go) ----

  const LOOPBACK = ['localhost', '127.0.0.1', '[::1]'];

  /** Returns null when the redirect URI is acceptable, else a short reason. */
  function validateRedirect(raw) {
    if (typeof raw !== 'string' || raw === '' || raw.length > 2048) return 'redirect URI must be 1 to 2048 characters';
    if (/[\u0000-\u0020\u007f-\u009f\u2028\u2029]/.test(raw)) return 'redirect URI must not contain spaces or control characters';
    if (raw.includes('*')) return 'wildcards are not allowed in redirect URIs';
    if (raw.includes('#')) return 'redirect URIs must not contain a fragment';
    const m = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?]*)([/?].*)?$/.exec(raw);
    if (!m) return 'redirect URI must be an absolute http(s) URL';
    const scheme = m[1].toLowerCase();
    const auth = m[2];
    if (auth.includes('@')) return 'redirect URIs must not contain credentials';
    const hp = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.-]+)(?::([0-9]*))?$/.exec(auth);
    if (!hp) return 'redirect URI has an invalid host';
    const host = hp[1].toLowerCase();
    if (hp[2] !== undefined && hp[2] !== '' && (Number(hp[2]) > 65535 || Number(hp[2]) === 0)) return 'redirect URI has an invalid port';
    if (scheme === 'https') return null;
    if (scheme === 'http') return LOOPBACK.includes(host) ? null : 'http is only allowed for localhost, 127.0.0.1 and [::1]; use https';
    return 'redirect URI scheme must be https (or http for loopback)';
  }

  const APP_TYPES = ['spa', 'web', 'native', 'm2m'];

  /** Validate the wizard form. Returns an array of {field, message}; empty means valid. */
  function validateApp(app) {
    const errs = [];
    if (!APP_TYPES.includes(app.type)) errs.push({ field: 'type', message: 'choose an app type' });
    const name = typeof app.name === 'string' ? app.name : '';
    if (!name.trim() || name.length > 100 || /[\u0000-\u001f\u007f-\u009f]/.test(name)) errs.push({ field: 'name', message: 'name must be 1 to 100 printable characters' });
    const uris = app.redirectUris || [];
    if (app.type === 'm2m') {
      if (uris.length) errs.push({ field: 'redirectUris', message: 'machine-to-machine apps have no redirect URIs' });
    } else {
      if (!uris.length) errs.push({ field: 'redirectUris', message: 'at least one redirect URI is required' });
      if (uris.length > 10) errs.push({ field: 'redirectUris', message: 'at most 10 redirect URIs' });
      const seen = new Set();
      for (const u of uris) {
        const e = validateRedirect(u);
        if (e) errs.push({ field: 'redirectUris', message: e + ': ' + String(u).slice(0, 80) });
        else if (app.type === 'native' && !/^http:/i.test(u)) errs.push({ field: 'redirectUris', message: 'native apps use a loopback redirect (http on 127.0.0.1, localhost or [::1]): ' + u.slice(0, 80) });
        if (seen.has(u)) errs.push({ field: 'redirectUris', message: 'duplicate redirect URI: ' + String(u).slice(0, 80) });
        seen.add(u);
      }
    }
    return errs;
  }

  // ---- Test login: evaluate a finished authorization-code run -------------

  const chk = (id, label, status, input, fix) => ({ id, label, status, input: input || '', fix: fix || '' });
  const audList = (p) => [].concat(p.aud === undefined ? [] : p.aud);
  const q = (v) => JSON.stringify(v === undefined ? null : v);

  /**
   * Evaluate a Test login run. Every row is {id, label, status, input, fix} with
   * status PASS, FAIL, INFO (informational, never a failure) or SKIP.
   * ctx: {configuredIssuer, clientId, redirectUri, registeredRedirects, request:{scope,state,nonce,
   *   pkceMethod}, callback:{state,iss,error,description,code}, disc, tokenStatus, tokens, tokenBody,
   *   sigs:{access,id}, userinfo:{status,body}|null, refresh:{status,body}|null, now}
   */
  async function evaluateLogin(ctx) {
    const rows = [];
    const cb = ctx.callback || {};
    const rq = ctx.request || {};
    const disc = ctx.disc || {};
    const regs = ctx.registeredRedirects || [];

    const regOk = regs.includes(ctx.redirectUri);
    const redirectRejected = /redirect/i.test((cb.error || '') + ' ' + (cb.description || ''));
    const regPass = regOk && !redirectRejected;
    rows.push(chk('redirect_uri', 'redirect_uri is registered', regPass ? 'PASS' : 'FAIL',
      'redirect_uri sent: ' + ctx.redirectUri + '; registered: ' + (regs.length ? regs.join(', ') : '(none known)'),
      regPass ? '' : 'Register exactly ' + ctx.redirectUri + ' as a redirect URI on client ' + ctx.clientId + ' (exact match, including the trailing slash and port).'));

    const methods = disc.code_challenge_methods_supported;
    const s256 = rq.pkceMethod === 'S256' && (!methods || methods.includes('S256'));
    rows.push(chk('pkce', 'PKCE is used (S256)', s256 ? 'PASS' : 'FAIL',
      'code_challenge_method sent: ' + q(rq.pkceMethod) + '; IdP supports: ' + q(methods),
      s256 ? '' : 'Send code_challenge and code_challenge_method=S256 on the authorize request and code_verifier on the token request. The IdP must list S256 in code_challenge_methods_supported.'));

    if (cb.error) {
      rows.push(chk('authorize', 'authorization response is a code', 'FAIL', 'error=' + cb.error + (cb.description ? ' (' + cb.description + ')' : ''),
        diagnose({ error: cb.error, description: cb.description, clientId: ctx.clientId, redirectUri: ctx.redirectUri }).join(' ') || 'See the Timeline for the raw response.'));
      return rows;
    }
    const stOk = !!rq.state && cb.state === rq.state;
    rows.push(chk('state', 'state matches', stOk ? 'PASS' : 'FAIL', 'sent ' + q(rq.state) + ', returned ' + q(cb.state),
      stOk ? '' : 'The state returned differs from the one stored for this run. Do not open the callback URL in another tab; run Test login again. If it persists the IdP is not echoing state.'));
    if (!stOk) return rows;

    if (ctx.tokenStatus !== 200) {
      const b = ctx.tokenBody || {};
      rows.push(chk('token', 'token endpoint returned tokens', 'FAIL', 'HTTP ' + ctx.tokenStatus + ' ' + q(b.error) + (b.error_description ? ' ' + b.error_description : ''),
        diagnose({ error: b.error, description: b.error_description, status: ctx.tokenStatus, body: JSON.stringify(b), clientId: ctx.clientId, redirectUri: ctx.redirectUri }).join(' ') || 'See the Timeline.'));
      return rows;
    }
    const t = ctx.tokens || {};
    const idt = decodeJwt(t.id_token);
    const acc = decodeJwt(t.access_token);
    if (!idt) rows.push(chk('id_token', 'an id_token was returned', 'FAIL', t.id_token ? 'id_token is not a JWT' : 'no id_token in the token response', 'Request the openid scope.'));

    // iss
    const issBad = [];
    if (disc.issuer !== ctx.configuredIssuer) issBad.push('discovery issuer ' + q(disc.issuer) + ' differs from the configured issuer ' + q(ctx.configuredIssuer));
    if (cb.iss && cb.iss !== disc.issuer) issBad.push('callback iss ' + q(cb.iss) + ' differs from discovery issuer');
    for (const [n, x] of [['id_token', idt], ['access_token', acc]]) if (x && x.payload.iss !== disc.issuer) issBad.push(n + ' iss ' + q(x.payload.iss) + ' differs from discovery issuer ' + q(disc.issuer));
    rows.push(chk('iss', 'iss matches discovery issuer', issBad.length ? 'FAIL' : 'PASS', issBad.join('; ') || 'issuer ' + disc.issuer,
      issBad.length ? 'Your app must use the issuer exactly as discovery reports it. Fix the IdP base URL / proxy Host headers so they agree, and set the app issuer to the discovery value.' : ''));

    // aud
    if (idt) {
      const ok = audList(idt.payload).includes(ctx.clientId);
      rows.push(chk('aud', 'id_token aud contains the client id', ok ? 'PASS' : 'FAIL', 'aud=' + q(idt.payload.aud) + ', client id=' + q(ctx.clientId),
        ok ? '' : 'Your app verifies aud against its own client id. The id_token was issued for a different client: check the client id configured in the app.'));
    }
    if (acc) {
      const ok = audList(acc.payload).includes(ctx.clientId) || acc.payload.azp === ctx.clientId;
      rows.push(chk('aud.access', 'access_token aud or azp names the client', ok ? 'PASS' : 'FAIL', 'aud=' + q(acc.payload.aud) + ', azp=' + q(acc.payload.azp),
        ok ? '' : 'The access token was not issued to this client. Check the client id.'));
    }

    // exp / iat
    const timeBad = [];
    for (const [n, x] of [['id_token', idt], ['access_token', acc]]) {
      if (!x) continue;
      const p = x.payload;
      if (typeof p.exp !== 'number' || p.exp <= ctx.now) timeBad.push(n + ' exp ' + q(p.exp) + ' is not in the future (now ' + ctx.now + ')');
      if (typeof p.iat !== 'number') timeBad.push(n + ' has no iat');
      else {
        const skew = Math.round(p.iat - ctx.now);
        if (Math.abs(skew) > 60) timeBad.push(n + ' iat differs from this browser clock by ' + skew + 's');
        if (typeof p.exp === 'number' && p.exp <= p.iat) timeBad.push(n + ' exp is not after iat');
      }
    }
    const life = idt && typeof idt.payload.exp === 'number' && typeof idt.payload.iat === 'number' ? 'id_token lifetime ' + Math.round(idt.payload.exp - idt.payload.iat) + 's' : '';
    rows.push(chk('time', 'exp and iat are sane', timeBad.length ? 'FAIL' : 'PASS', timeBad.join('; ') || life,
      timeBad.length ? 'Clock skew: sync this machine and the IdP host with NTP. Apps should allow a leeway of about 60s when checking exp, nbf and iat. A token that is already expired means the app is reusing an old token.' : ''));

    // nonce
    if (idt) {
      const ok = !!rq.nonce && idt.payload.nonce === rq.nonce;
      rows.push(chk('nonce', 'nonce matches', ok ? 'PASS' : 'FAIL', 'sent ' + q(rq.nonce) + ', id_token nonce ' + q(idt.payload.nonce),
        ok ? '' : 'Send a fresh random nonce on every authorize request, keep it with the session and compare it with the id_token nonce claim. A missing nonce means the app did not send one or the IdP dropped it.'));
    }

    // at_hash
    if (idt && t.access_token) {
      const want = await atHash(t.access_token);
      const got = idt.payload.at_hash;
      if (got === undefined) rows.push(chk('at_hash', 'at_hash validates', 'INFO', 'id_token has no at_hash', 'at_hash is optional in the code flow; apps that check it should treat absence as acceptable.'));
      else rows.push(chk('at_hash', 'at_hash validates', got === want ? 'PASS' : 'FAIL', 'expected ' + want + ', got ' + q(got),
        got === want ? '' : 'at_hash is base64url of the left half of SHA-256(access_token). The id_token and access_token come from different token responses (for example a refreshed access token mixed with an old id_token).'));
    }

    // signature
    for (const [n, x, k] of [['id_token', idt, 'id'], ['access_token', acc, 'access']]) {
      if (!x) continue;
      const sg = (ctx.sigs || {})[k];
      rows.push(chk('sig.' + k, n + ' signature verifies against JWKS', sg && sg.ok ? 'PASS' : 'FAIL',
        'alg=' + q(x.header.alg) + ', kid=' + q(x.header.kid) + (sg ? ': ' + sg.reason : ''),
        sg && sg.ok ? '' : 'Fetch the JWKS from discovery jwks_uri (refetch once when the kid is unknown: keys rotate), accept only ES256 and verify with the key whose kid matches. Never accept alg none.'));
    }
    if (!acc && t.access_token) rows.push(chk('sig.access', 'access_token signature', 'INFO', 'access token is opaque (not a JWT)', 'Validate opaque tokens by introspection.'));

    // sid / auth_time (informational: SSO sessions land separately)
    if (idt) {
      const have = ['sid', 'auth_time'].filter((c) => idt.payload[c] !== undefined);
      const miss = ['sid', 'auth_time'].filter((c) => idt.payload[c] === undefined);
      rows.push(chk('sid', 'sid and auth_time are present', miss.length ? 'INFO' : 'PASS',
        'present: ' + (have.join(', ') || 'none') + (miss.length ? '; absent: ' + miss.join(', ') : ''),
        miss.length ? 'Informational. sid (session id) and auth_time are issued once SSO sessions are enabled; apps needing back-channel logout or max_age checks need them.' : ''));
    }

    // userinfo
    if (ctx.userinfo) {
      const u = ctx.userinfo;
      const sub = idt && idt.payload.sub;
      const ok = u.status === 200 && !!u.body && !!sub && u.body.sub === sub;
      rows.push(chk('userinfo', 'userinfo sub matches the id_token sub', ok ? 'PASS' : 'FAIL',
        'userinfo HTTP ' + u.status + ', sub ' + q(u.body && u.body.sub) + ', id_token sub ' + q(sub),
        ok ? '' : u.status !== 200 ? 'The userinfo call failed: send the access_token as "Authorization: Bearer", with the openid scope granted.' : 'userinfo sub must equal the id_token sub (OIDC Core 5.3.2). Do not trust userinfo for another subject.'));
    } else {
      rows.push(chk('userinfo', 'userinfo sub matches the id_token sub', 'SKIP', 'userinfo was not called', ''));
    }

    // refresh
    const wantRefresh = String(rq.scope || '').split(/\s+/).includes('offline_access');
    if (!wantRefresh) rows.push(chk('refresh', 'refresh works', 'INFO', 'offline_access was not requested', 'Request offline_access to receive a refresh token.'));
    else if (!t.refresh_token) rows.push(chk('refresh', 'refresh works', 'FAIL', 'offline_access requested but no refresh_token returned',
      'Allow the refresh_token grant for this client, and keep offline_access in the requested scope.'));
    else if (!ctx.refresh) rows.push(chk('refresh', 'refresh works', 'SKIP', 'refresh was not attempted', ''));
    else {
      const r = ctx.refresh;
      const ok = r.status === 200 && !!(r.body && r.body.access_token);
      rows.push(chk('refresh', 'refresh works', ok ? 'PASS' : 'FAIL', 'HTTP ' + r.status + (r.body && r.body.error ? ' ' + r.body.error : ''),
        ok ? '' : diagnose({ error: r.body && r.body.error, description: r.body && r.body.error_description, status: r.status, clientId: ctx.clientId }).join(' ') || 'Check the Timeline.'));
    }
    return rows;
  }

  /**
   * Evaluate a machine-to-machine (client_credentials) run.
   * ctx: {configuredIssuer, clientId, disc, tokenStatus, tokenBody, sigs:{access}, now}
   */
  function evaluateM2M(ctx) {
    const rows = [];
    const b = ctx.tokenBody || {};
    if (ctx.tokenStatus !== 200) {
      rows.push(chk('token', 'token endpoint returned a token', 'FAIL', 'HTTP ' + ctx.tokenStatus + ' ' + q(b.error),
        b.error === 'invalid_client' ? 'Client authentication failed: the client id or secret is wrong. Secrets are shown once; regenerate it in the admin API if lost.'
          : b.error === 'unauthorized_client' ? 'This client may not use client_credentials: it must be a confidential client with service accounts enabled.'
            : 'See the Timeline for the raw response.'));
      return rows;
    }
    rows.push(chk('token', 'token endpoint returned a token', 'PASS', 'token_type=' + q(b.token_type) + ', expires_in=' + q(b.expires_in), ''));
    const acc = decodeJwt(b.access_token);
    if (!acc) { rows.push(chk('jwt', 'access_token is a JWT', 'INFO', 'opaque token', 'Validate opaque tokens by introspection.')); return rows; }
    const p = acc.payload;
    const issOk = p.iss === (ctx.disc || {}).issuer && p.iss === ctx.configuredIssuer;
    rows.push(chk('iss', 'iss matches discovery issuer', issOk ? 'PASS' : 'FAIL', 'token iss ' + q(p.iss) + ', discovery ' + q((ctx.disc || {}).issuer) + ', configured ' + q(ctx.configuredIssuer),
      issOk ? '' : 'The resource server must use the issuer exactly as discovery reports it.'));
    const sg = (ctx.sigs || {}).access;
    rows.push(chk('sig', 'signature verifies against JWKS', sg && sg.ok ? 'PASS' : 'FAIL', 'alg=' + q(acc.header.alg) + ', kid=' + q(acc.header.kid) + (sg ? ': ' + sg.reason : ''),
      sg && sg.ok ? '' : 'Verify with the JWKS key matching kid, accept only ES256.'));
    const forClient = p.client_id === ctx.clientId || p.azp === ctx.clientId || audList(p).includes(ctx.clientId) || p.sub === 'service-account-' + ctx.clientId;
    rows.push(chk('client', 'token belongs to this client', forClient ? 'PASS' : 'FAIL', 'sub=' + q(p.sub) + ', client_id=' + q(p.client_id) + ', azp=' + q(p.azp),
      forClient ? '' : 'The token was issued to a different client: check the client id.'));
    const skew = typeof p.iat === 'number' ? Math.round(p.iat - ctx.now) : null;
    const timeOk = typeof p.exp === 'number' && p.exp > ctx.now && skew !== null && Math.abs(skew) <= 60;
    rows.push(chk('time', 'exp and iat are sane', timeOk ? 'PASS' : 'FAIL', 'exp ' + q(p.exp) + ', iat ' + q(p.iat) + ', browser clock ' + ctx.now,
      timeOk ? '' : 'Clock skew or an expired token: sync clocks with NTP and allow about 60s of leeway.'));
    rows.push(chk('no_refresh', 'no refresh token (expected)', b.refresh_token ? 'INFO' : 'PASS', b.refresh_token ? 'a refresh_token was issued' : 'none issued',
      b.refresh_token ? 'Machine clients should request a new token instead of holding refresh tokens.' : ''));
    return rows;
  }

  /** Reduce a row list to counts, for the summary line. */
  function summarize(rows) {
    const c = { PASS: 0, FAIL: 0, INFO: 0, SKIP: 0 };
    for (const r of rows) c[r.status] = (c[r.status] || 0) + 1;
    return c;
  }

  const api = { b64urlEncode, b64urlDecode, randomB64url, sha256, pkceChallenge, decodeJwt, atHash, verifyJwt, runChecks, diagnose, toCurl,
    validateRedirect, validateApp, evaluateLogin, evaluateM2M, summarize };
  root.HavenDev = Object.assign(root.HavenDev || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
