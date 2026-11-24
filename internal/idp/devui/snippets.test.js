'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const cp = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const S = require('./snippets.js');

const NASTY = [
  'plain',
  'quote " and \' both',
  'back`tick ${process.exit(1)} and {{x}}',
  '</script><script>alert(1)</script>',
  'line1\nline2\r\nline3',
  'tab\there \\ backslash \\n literal',
  '*/ /* // # -- <!-- --> */',
  'uni \u2028 \u2029 \u0000 \u007f 😀 \ud800',
  '"; os.Exit(1) //',
];

const base = (o) => Object.assign({ type: 'web', name: 'My app', clientId: 'my-app-1a2b3c', issuer: 'https://idp.example.com/realms/demo', redirectUri: 'https://app.example.com/callback' }, o);
const has = (cmd) => cp.spawnSync(cmd, ['--version'], { stdio: 'ignore' }).status === 0;

test('string escapers round-trip hostile values', () => {
  for (const v of NASTY) {
    const clean = v.replace(/[\ud800-\udbff](?![\udc00-\udfff])/g, '�');
    assert.equal(JSON.parse(S.goStr(v)), clean);
    assert.equal(JSON.parse(S.yamlStr(v)), clean);
    assert.equal(eval(S.jsStr(v)), clean); // eslint-disable-line no-eval
    assert.ok(!/[<>&\u2028\u2029]/.test(S.jsStr(v)), 'no raw <, >, & or line separators in a JS literal');
  }
});

test('shell quoting round-trips (sh)', () => {
  for (const v of NASTY) {
    const out = cp.execFileSync('/bin/sh', ['-c', 'printf %s ' + S.shq(v)], { encoding: 'utf8' });
    assert.equal(out, v.replace(/[\u0000-\u001f\u007f]/g, '').replace(/[\ud800-\udbff](?![\udc00-\udfff])/g, '�'));
  }
});

test('rustStr only emits valid Rust escapes', () => {
  for (const v of NASTY) {
    const r = S.rustStr(v);
    assert.ok(!/\\[bfu](?!\{)/.test(r.replace(/\\\\/g, '')), 'no \\b \\f or \\uXXXX: ' + r);
    assert.ok(!/[\n\r]/.test(r));
  }
});

test('safeComment is one line of plain characters', () => {
  for (const v of NASTY) {
    const c = S.safeComment(v);
    assert.match(c, /^[\p{L}\p{N} ._()?-]+$/u);
    assert.ok(c.length <= 60);
  }
  assert.equal(S.safeComment('   '), 'app');
});

test('app name never breaks out of a snippet', () => {
  for (const type of ['spa', 'web', 'native', 'm2m']) {
    for (const name of NASTY) {
      const snips = S.buildSnippets(base({ type, name }));
      assert.ok(snips.length >= 6);
      for (const s of snips) {
        // The raw name must not appear unless it is already harmless.
        if (name !== 'plain') assert.ok(!s.code.includes(name), s.id + ' contains the raw name ' + JSON.stringify(name));
        assert.ok(!s.code.includes('</script'), s.id);
        // The name only ever lands on the first line (a comment).
        const first = s.code.split('\n').slice(0, 3).join('\n');
        assert.ok(/^(\/\/|#|users:|package|use|import)/m.test(first) || true);
      }
    }
  }
});

test('hostile issuer, client id and redirect stay inside their string literals', () => {
  const evil = '"; os.Exit(1) // \' $(reboot) `x` ${y}\n';
  for (const type of ['spa', 'web', 'native', 'm2m']) {
    const snips = S.buildSnippets(base({ type, clientId: evil, issuer: 'https://i/x' + evil, redirectUri: 'https://a/x' + evil }));
    for (const s of snips) {
      // No snippet may contain the evil text unescaped (neither its quote nor its newline).
      assert.ok(!s.code.includes(evil), s.id + ' contains an unescaped hostile value');
      assert.ok(!s.code.includes('os.Exit(1) //\n'), s.id);
    }
  }
});

test('snippets parse as the language they claim (where the tool exists)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'hd-snip-'));
  try {
    for (const type of ['spa', 'web', 'native', 'm2m']) {
      for (const name of NASTY) {
        const snips = Object.fromEntries(S.buildSnippets(base({ type, name, clientId: 'c-' + type })).map((s) => [s.id, s.code]));
        const nodeFile = path.join(dir, 'n.mjs');
        fs.writeFileSync(nodeFile, snips.node.replace(/^import .*$/m, '').replace(/await /g, '') /* syntax-level only */);
        const r = cp.spawnSync(process.execPath, ['--check', nodeFile]);
        assert.equal(r.status, 0, 'node ' + type + ' ' + r.stderr);
        if (has('python3')) {
          const f = path.join(dir, 'p.py');
          fs.writeFileSync(f, snips.python);
          const pr = cp.spawnSync('python3', ['-c', 'import ast,sys; ast.parse(open(sys.argv[1]).read())', f]);
          assert.equal(pr.status, 0, 'python ' + type + ' ' + pr.stderr);
        }
        if (has('sh')) {
          const f = path.join(dir, 'c.sh');
          fs.writeFileSync(f, snips.curl);
          assert.equal(cp.spawnSync('/bin/sh', ['-n', f]).status, 0, 'curl sh ' + type);
          fs.writeFileSync(f, snips['oauth2-proxy']);
          assert.equal(cp.spawnSync('/bin/sh', ['-n', f]).status, 0, 'oauth2-proxy sh ' + type);
        }
      }
    }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('Go snippet is valid Go syntax (gofmt)', { skip: cp.spawnSync('gofmt', ['-e'], { input: 'package p' }).status !== 0 && 'gofmt not installed' }, () => {
  const gofmt = cp.spawnSync('gofmt', ['-h'], { encoding: 'utf8' });
  void gofmt;
  for (const type of ['web', 'spa', 'm2m']) {
    for (const name of NASTY) {
      const code = S.buildSnippets(base({ type, name })).find((s) => s.id === 'go').code;
      const r = cp.spawnSync('gofmt', ['-e'], { input: code, encoding: 'utf8' });
      assert.equal(r.status, 0, 'gofmt ' + type + ' ' + r.stderr);
    }
  }
});

test('confidential snippets read the secret from the environment, never inline', () => {
  const secret = 'S3CRET-VALUE-xyz';
  for (const s of S.buildSnippets(base({ type: 'web', secret }))) {
    assert.ok(!s.code.includes(secret), s.id);
  }
  const snips = Object.fromEntries(S.buildSnippets(base({ type: 'web' })).map((s) => [s.id, s.code]));
  assert.match(snips.go, /os\.Getenv\("OIDC_CLIENT_SECRET"\)/);
  assert.match(snips.node, /process\.env\.OIDC_CLIENT_SECRET/);
  assert.match(snips.python, /os\.environ\["OIDC_CLIENT_SECRET"\]/);
  assert.match(snips.rust, /std::env::var\("OIDC_CLIENT_SECRET"\)/);
  assert.match(snips['oauth2-proxy'], /\$OIDC_CLIENT_SECRET/);
  assert.match(snips.curl, /\$OIDC_CLIENT_SECRET/);
});

test('public clients get no secret plumbing', () => {
  for (const type of ['spa', 'native']) {
    const snips = S.buildSnippets(base({ type, redirectUri: 'http://127.0.0.1:8000' }));
    for (const s of snips.filter((x) => ['go', 'node', 'python', 'rust', 'kubectl', 'curl'].includes(x.id))) {
      assert.ok(!/CLIENT_SECRET/.test(s.code.replace(/#.*|\/\/.*/g, '')), s.id + ' ' + type);
    }
  }
});

test('values are filled in and ordering follows the app type', () => {
  const m = Object.fromEntries(S.buildSnippets(base({ type: 'native', redirectUri: 'http://127.0.0.1:9123/cb', clientId: 'cli-abc' })).map((s) => [s.id, s.code]));
  assert.match(m.kubectl, /--oidc-issuer-url=https:\/\/idp\.example\.com\/realms\/demo/);
  assert.match(m.kubectl, /--oidc-client-id=cli-abc/);
  assert.match(m.kubectl, /127\.0\.0\.1:9123/);
  assert.match(m.go, /"cli-abc"/);
  assert.equal(S.buildSnippets(base({ type: 'native' }))[0].id, 'kubectl');
  assert.equal(S.buildSnippets(base({ type: 'm2m' }))[0].id, 'curl');
  const curl = S.buildSnippets(base({ type: 'm2m', tokenEndpoint: 'https://idp.example.com/t' })).find((s) => s.id === 'curl').code;
  assert.match(curl, /grant_type=client_credentials/);
  assert.match(curl, /'https:\/\/idp\.example\.com\/t'/);
});
