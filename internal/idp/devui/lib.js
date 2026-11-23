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
      const nOk = !!ctx.nonce && idt.payload.nonce === ctx.nonce;
      rows.push(row('id.nonce', 'nonce matches', nOk, nOk ? 'nonce echoed.' : 'id_token nonce ' + JSON.stringify(idt.payload.nonce) + ' differs from the one sent. Possible replay, or sessionStorage was cleared.'));
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

  const api = { b64urlEncode, b64urlDecode, randomB64url, sha256, pkceChallenge, decodeJwt, atHash, verifyJwt, runChecks, diagnose, toCurl };
  root.HavenDev = Object.assign(root.HavenDev || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
