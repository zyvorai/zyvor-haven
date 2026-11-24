'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const L = require('./lib.js');
const vectors = require('./testdata/redirects.json');

const b64u = (b) => Buffer.from(b).toString('base64url');
const kp = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const J = { keys: [{ kid: 'k1', ...kp.publicKey.export({ format: 'jwk' }) }] };
const mk = (payload, header) => {
  const h = b64u(JSON.stringify({ alg: 'ES256', kid: 'k1', typ: 'JWT', ...header }));
  const p = b64u(JSON.stringify(payload));
  const sig = crypto.sign('sha256', Buffer.from(h + '.' + p), { key: kp.privateKey, dsaEncoding: 'ieee-p1363' });
  return h + '.' + p + '.' + b64u(sig);
};

test('validateRedirect agrees with the shared vectors', () => {
  for (const u of vectors.ok) assert.equal(L.validateRedirect(u), null, 'should accept ' + JSON.stringify(u));
  for (const u of vectors.bad) assert.notEqual(L.validateRedirect(u), null, 'should reject ' + JSON.stringify(u));
});

test('validateApp', () => {
  const ok = { type: 'web', name: 'Billing', redirectUris: ['https://b.example.com/cb'] };
  assert.deepEqual(L.validateApp(ok), []);
  assert.equal(L.validateApp({ ...ok, type: 'nope' })[0].field, 'type');
  assert.equal(L.validateApp({ ...ok, name: '  ' })[0].field, 'name');
  assert.equal(L.validateApp({ ...ok, name: 'a\nb' })[0].field, 'name');
  assert.equal(L.validateApp({ ...ok, name: 'x'.repeat(101) })[0].field, 'name');
  assert.ok(L.validateApp({ ...ok, redirectUris: [] }).length);
  assert.ok(L.validateApp({ ...ok, redirectUris: ['http://evil.example.com/cb'] }).length);
  assert.ok(L.validateApp({ ...ok, redirectUris: ['https://a/cb', 'https://a/cb'] }).some((e) => /duplicate/.test(e.message)));
  assert.ok(L.validateApp({ ...ok, redirectUris: Array.from({ length: 11 }, (_, i) => 'https://a/' + i) }).length);
  // native: loopback http only
  assert.ok(L.validateApp({ ...ok, type: 'native' }).length);
  assert.deepEqual(L.validateApp({ ...ok, type: 'native', redirectUris: ['http://127.0.0.1:8000'] }), []);
  // m2m: no redirects
  assert.deepEqual(L.validateApp({ type: 'm2m', name: 'job', redirectUris: [] }), []);
  assert.ok(L.validateApp({ type: 'm2m', name: 'job', redirectUris: ['https://a/cb'] }).length);
});

// ---- evaluateLogin ----------------------------------------------------------
const now = 1_800_000_000;
const iss = 'https://idp.example.com/realms/demo';
const cid = 'app-1';
const ru = 'https://app.example.com/cb';

async function good(over = {}) {
  const access = mk({ iss, sub: 'u1', aud: 'account', azp: cid, exp: now + 300, iat: now, typ: 'Bearer', scope: 'openid' });
  const id = mk({ iss, sub: 'u1', aud: cid, exp: now + 300, iat: now, typ: 'ID', nonce: 'N', at_hash: await L.atHash(access) });
  const ctx = {
    configuredIssuer: iss, clientId: cid, redirectUri: ru, registeredRedirects: [ru],
    request: { scope: 'openid profile offline_access', state: 'S', nonce: 'N', pkceMethod: 'S256' },
    callback: { state: 'S', iss, code: 'c' },
    disc: { issuer: iss, code_challenge_methods_supported: ['S256'] },
    tokenStatus: 200, tokens: { access_token: access, id_token: id, refresh_token: 'r' },
    sigs: { access: await L.verifyJwt(access, J), id: await L.verifyJwt(id, J) },
    userinfo: { status: 200, body: { sub: 'u1' } }, refresh: { status: 200, body: { access_token: 'x' } }, now,
  };
  return Object.assign(ctx, over);
}
const byId = (rows, id) => rows.find((r) => r.id === id);

test('evaluateLogin: all good', async () => {
  const rows = await L.evaluateLogin(await good());
  for (const r of rows) assert.ok(['PASS', 'INFO'].includes(r.status), r.id + ' ' + r.status + ' ' + r.input);
  assert.equal(byId(rows, 'sid').status, 'INFO', 'absent sid/auth_time is INFO, never FAIL');
  assert.equal(byId(rows, 'redirect_uri').status, 'PASS');
  assert.equal(byId(rows, 'sig.id').status, 'PASS');
  assert.equal(byId(rows, 'at_hash').status, 'PASS');
  assert.equal(L.summarize(rows).FAIL, 0);
});

test('evaluateLogin: sid and auth_time present is PASS', async () => {
  const c = await good();
  const access = c.tokens.access_token;
  const id = mk({ iss, sub: 'u1', aud: cid, exp: now + 300, iat: now, typ: 'ID', nonce: 'N', at_hash: await L.atHash(access), sid: 's', auth_time: now });
  c.tokens.id_token = id; c.sigs.id = await L.verifyJwt(id, J);
  assert.equal(byId(await L.evaluateLogin(c), 'sid').status, 'PASS');
});

test('evaluateLogin: each failure names the wrong input and gives a fix', async () => {
  const fails = {
    state: [{ callback: { state: 'EVIL', iss, code: 'c' } }, /EVIL/],
    redirect_uri: [{ registeredRedirects: ['https://other/cb'] }, /https:\/\/other\/cb/],
    pkce: [{ request: { scope: 'openid', state: 'S', nonce: 'N', pkceMethod: 'plain' } }, /plain/],
    iss: [{ disc: { issuer: 'https://evil/realms/demo', code_challenge_methods_supported: ['S256'] } }, /evil/],
    aud: [{ clientId: 'someone-else', registeredRedirects: [ru] }, /someone-else/],
    nonce: [{ request: { scope: 'openid', state: 'S', nonce: 'WRONG', pkceMethod: 'S256' } }, /WRONG/],
    userinfo: [{ userinfo: { status: 200, body: { sub: 'u2' } } }, /u2/],
    refresh: [{ refresh: { status: 400, body: { error: 'invalid_grant' } } }, /invalid_grant/],
  };
  for (const [id, [over, re]] of Object.entries(fails)) {
    const rows = await L.evaluateLogin(await good(over));
    const r = byId(rows, id);
    assert.equal(r.status, 'FAIL', id + ' should FAIL, got ' + r.status);
    assert.match(r.input, re, id + ' input');
    assert.ok(r.fix.length > 20, id + ' needs a fix text');
  }
});

test('evaluateLogin: expired, skewed and tampered tokens', async () => {
  const c = await good();
  const exp = mk({ iss, sub: 'u1', aud: cid, exp: now - 5, iat: now - 400, typ: 'ID', nonce: 'N' });
  c.tokens.id_token = exp; c.sigs.id = await L.verifyJwt(exp, J);
  let rows = await L.evaluateLogin(c);
  assert.equal(byId(rows, 'time').status, 'FAIL');
  assert.match(byId(rows, 'time').fix, /Clock skew/);

  const c2 = await good();
  const parts = c2.tokens.id_token.split('.');
  const forged = parts[0] + '.' + b64u(JSON.stringify({ iss, sub: 'admin', aud: cid, exp: now + 9, iat: now, nonce: 'N' })) + '.' + parts[2];
  c2.tokens.id_token = forged; c2.sigs.id = await L.verifyJwt(forged, J);
  rows = await L.evaluateLogin(c2);
  assert.equal(byId(rows, 'sig.id').status, 'FAIL');
  assert.match(byId(rows, 'sig.id').input, /does not match/);

  const c3 = await good();
  const none = b64u(JSON.stringify({ alg: 'none' })) + '.' + c3.tokens.id_token.split('.')[1] + '.';
  c3.tokens.id_token = none; c3.sigs.id = await L.verifyJwt(none, J);
  assert.equal(byId(await L.evaluateLogin(c3), 'sig.id').status, 'FAIL');
});

test('evaluateLogin: at_hash mismatch fails, absent is INFO', async () => {
  const c = await good();
  const id = mk({ iss, sub: 'u1', aud: cid, exp: now + 300, iat: now, typ: 'ID', nonce: 'N', at_hash: 'AAAA' });
  c.tokens.id_token = id; c.sigs.id = await L.verifyJwt(id, J);
  assert.equal(byId(await L.evaluateLogin(c), 'at_hash').status, 'FAIL');
  const id2 = mk({ iss, sub: 'u1', aud: cid, exp: now + 300, iat: now, typ: 'ID', nonce: 'N' });
  c.tokens.id_token = id2; c.sigs.id = await L.verifyJwt(id2, J);
  assert.equal(byId(await L.evaluateLogin(c), 'at_hash').status, 'INFO');
});

test('evaluateLogin: refresh states', async () => {
  const c = await good();
  delete c.tokens.refresh_token;
  assert.equal(byId(await L.evaluateLogin(c), 'refresh').status, 'FAIL'); // offline_access asked, none issued
  const c2 = await good({ request: { scope: 'openid', state: 'S', nonce: 'N', pkceMethod: 'S256' } });
  assert.equal(byId(await L.evaluateLogin(c2), 'refresh').status, 'INFO');
});

test('evaluateLogin: authorize error and token error stop early with a fix', async () => {
  let rows = await L.evaluateLogin(await good({ callback: { error: 'access_denied', description: 'nope', state: 'S' } }));
  assert.equal(byId(rows, 'authorize').status, 'FAIL');
  assert.match(byId(rows, 'authorize').fix, /denied/);
  rows = await L.evaluateLogin(await good({ callback: { error: 'invalid_request', description: 'Invalid redirect_uri' } }));
  assert.equal(byId(rows, 'redirect_uri').status, 'FAIL');
  rows = await L.evaluateLogin(await good({ tokenStatus: 400, tokenBody: { error: 'invalid_grant' }, tokens: null }));
  assert.equal(byId(rows, 'token').status, 'FAIL');
  assert.match(byId(rows, 'token').fix, /invalid_grant/);
});

test('evaluateM2M', async () => {
  const access = mk({ iss, sub: 'service-account-' + cid, client_id: cid, exp: now + 300, iat: now, typ: 'Bearer' });
  const ctx = { configuredIssuer: iss, clientId: cid, disc: { issuer: iss }, tokenStatus: 200, tokenBody: { access_token: access, token_type: 'Bearer', expires_in: 300 }, sigs: { access: await L.verifyJwt(access, J) }, now };
  const rows = L.evaluateM2M(ctx);
  assert.equal(L.summarize(rows).FAIL, 0);
  assert.equal(byId(L.evaluateM2M({ ...ctx, tokenStatus: 401, tokenBody: { error: 'invalid_client' } }), 'token').status, 'FAIL');
  assert.equal(byId(L.evaluateM2M({ ...ctx, clientId: 'other' }), 'client').status, 'FAIL');
});
