'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const L = require('./lib.js');

const b64u = (b) => Buffer.from(b).toString('base64url');
const mk = (kp, kid, header, payload) => {
  const h = b64u(JSON.stringify({ alg: 'ES256', kid, typ: 'JWT', ...header }));
  const p = b64u(JSON.stringify(payload));
  const sig = crypto.sign('sha256', Buffer.from(h + '.' + p), { key: kp.privateKey, dsaEncoding: 'ieee-p1363' });
  return h + '.' + p + '.' + b64u(sig);
};
const jwks = (kp, kid) => ({ keys: [{ kid, ...kp.publicKey.export({ format: 'jwk' }) }] });
const kp = () => crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });

test('base64url roundtrip', () => {
  const bytes = new Uint8Array([0, 251, 255, 62, 63, 1]);
  const s = L.b64urlEncode(bytes);
  assert.ok(!/[+/=]/.test(s));
  assert.deepEqual(Array.from(L.b64urlDecode(s)), Array.from(bytes));
  assert.throws(() => L.b64urlDecode('a+b'));
  assert.equal(L.randomB64url(32).length, 43);
});

test('PKCE S256 RFC 7636 vector', async () => {
  assert.equal(await L.pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});

test('decodeJwt', () => {
  const d = L.decodeJwt(mk(kp(), 'k1', {}, { sub: 'u' }));
  assert.equal(d.header.alg, 'ES256');
  assert.equal(d.payload.sub, 'u');
  assert.equal(L.decodeJwt('opaque-token'), null);
  assert.equal(L.decodeJwt('a.b.c'), null);
});

test('at_hash', async () => {
  const at = 'access-token-value';
  const want = crypto.createHash('sha256').update(at).digest().subarray(0, 16).toString('base64url');
  assert.equal(await L.atHash(at), want);
});

test('ES256 verify', async () => {
  const k = kp(), other = kp();
  const tok = mk(k, 'k1', {}, { sub: 'u' });
  assert.equal((await L.verifyJwt(tok, jwks(k, 'k1'))).ok, true);
  assert.equal((await L.verifyJwt(tok, jwks(other, 'k1'))).ok, false);
  assert.match((await L.verifyJwt(tok, jwks(k, 'zzz'))).reason, /not found/);
  const parts = tok.split('.');
  const tampered = parts[0] + '.' + b64u(JSON.stringify({ sub: 'admin' })) + '.' + parts[2];
  assert.equal((await L.verifyJwt(tampered, jwks(k, 'k1'))).ok, false);
  const none = b64u(JSON.stringify({ alg: 'none', kid: 'k1' })) + '.' + parts[1] + '.';
  assert.match((await L.verifyJwt(none, jwks(k, 'k1'))).reason, /only ES256/);
  assert.equal((await L.verifyJwt(mk(k, 'k1', { alg: 'HS256' }, {}), jwks(k, 'k1'))).ok, false);
});

test('runChecks pass and fail', async () => {
  const k = kp();
  const now = 1_700_000_000, iss = 'http://i/realms/r', cid = 'pg';
  const access = mk(k, 'k1', {}, { iss, sub: 'u', aud: 'account', azp: cid, exp: now + 300, iat: now, jti: 'j', scope: 'openid profile', typ: 'Bearer' });
  const idt = mk(k, 'k1', {}, { iss, sub: 'u', aud: cid, exp: now + 300, iat: now, typ: 'ID', nonce: 'n1', at_hash: await L.atHash(access) });
  const J = jwks(k, 'k1');
  const sigs = { access: await L.verifyJwt(access, J), id: await L.verifyJwt(idt, J) };
  const base = { issuer: iss, clientId: cid, accessToken: access, idToken: idt, nonce: 'n1', requestedScope: 'openid profile', jwks: J, now, sigs };
  let rows = await L.runChecks(base);
  assert.ok(rows.length >= 15);
  assert.deepEqual(rows.filter((r) => !r.pass), []);
  rows = await L.runChecks({ ...base, nonce: 'other', issuer: 'http://evil', requestedScope: 'openid email', now: now + 1000 });
  const failed = new Set(rows.filter((r) => !r.pass).map((r) => r.id));
  for (const id of ['id.nonce', 'access.iss', 'id.iss', 'access.scope', 'access.exp', 'id.exp']) assert.ok(failed.has(id), id);
  const bad = mk(k, 'k1', {}, { iss, aud: cid, exp: now + 5, iat: now, typ: 'Bearer', nonce: 'n1', at_hash: 'bad' });
  rows = await L.runChecks({ ...base, idToken: bad });
  const f2 = new Set(rows.filter((r) => !r.pass).map((r) => r.id));
  assert.ok(f2.has('id.typ') && f2.has('id.at_hash'));
});

test('diagnose and toCurl', () => {
  assert.match(L.diagnose({ error: 'invalid_grant' })[0], /rotated/);
  assert.match(L.diagnose({ stateMismatch: true })[0], /State mismatch/);
  assert.match(L.diagnose({ body: 'Invalid redirect URI.', redirectUri: 'http://h/dev/', clientId: 'pg', status: 400 })[0], /http:\/\/h\/dev\//);
  assert.match(L.diagnose({ noRefreshToken: true })[0], /offline_access/);
  assert.deepEqual(L.diagnose({ status: 200 }), []);
  const c = L.toCurl({ method: 'POST', url: 'http://h/t', reqHeaders: { A: "it's" }, reqBody: 'a=1' });
  assert.equal(c, "curl -i -X POST 'http://h/t' -H 'A: it'\\''s' --data 'a=1'");
});
