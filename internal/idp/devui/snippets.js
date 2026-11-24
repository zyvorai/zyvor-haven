/* Copy-paste integration snippets for the add-an-app wizard. Pure string
 * templates: no DOM, no network. Every value that is interpolated goes through
 * an escaper for the target language, and the app name is only ever used in a
 * sanitised single-line comment. The client secret is never placed in a
 * snippet: confidential clients read it from the OIDC_CLIENT_SECRET variable. */
(function (root) {
  'use strict';

  const lone = (s) => String(s).replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, '�');

  /** JSON string literal; valid as a JS, Go, Python or YAML double-quoted string. */
  function jsonStr(s) {
    return JSON.stringify(lone(s)).replace(/[\u2028\u2029<>&]/g, (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
  }
  const jsStr = jsonStr;
  const goStr = jsonStr;
  const pyStr = jsonStr;
  const yamlStr = jsonStr;

  /** Rust string literal: Rust has no \b, \f or \uXXXX, only \u{...}. */
  function rustStr(s) {
    let o = '"';
    for (const ch of lone(s)) {
      const c = ch.codePointAt(0);
      if (ch === '\\') o += '\\\\';
      else if (ch === '"') o += '\\"';
      else if (ch === '\n') o += '\\n';
      else if (ch === '\r') o += '\\r';
      else if (ch === '\t') o += '\\t';
      else if (c < 0x20 || c === 0x7f || c === 0x2028 || c === 0x2029) o += '\\u{' + c.toString(16) + '}';
      else o += ch;
    }
    return o + '"';
  }

  /** POSIX shell single-quoted word. Control characters (newlines) are dropped. */
  function shq(s) {
    return "'" + lone(s).replace(/[\u0000-\u001f\u007f]/g, '').replace(/'/g, "'\\''") + "'";
  }

  /** A name made safe for use inside a one-line comment in any of the languages. */
  function safeComment(s) {
    const t = lone(s).replace(/[^\p{L}\p{N} ._()-]/gu, '?').replace(/\s+/g, ' ').trim();
    return t.slice(0, 60) || 'app';
  }

  /** One-line text for use inside a comment. */
  const ol = (s) => lone(s).replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, '');
  const isLoopbackHttp =(u) => /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/|$)/i.test(u);
  const portOf = (u) => { const m = /^http:\/\/(?:\[::1\]|[^/:]+)(?::(\d+))?/i.exec(u); return m && m[1] ? m[1] : '8000'; };
  const trim = (s) => String(s).replace(/\/+$/, '');

  /**
   * app: {type: spa|web|native|m2m, name, clientId, issuer, redirectUri, tokenEndpoint?}
   * Returns [{id, title, lang, relevant, code}] with the most relevant first.
   */
  function buildSnippets(app) {
    const conf = app.type === 'web' || app.type === 'm2m';
    const m2m = app.type === 'm2m';
    const issuer = trim(app.issuer);
    const cid = app.clientId;
    const ru = app.redirectUri || '';
    const tokenEp = app.tokenEndpoint || issuer + '/protocol/openid-connect/token';
    const nm = safeComment(app.name);
    const L = (...lines) => lines.join('\n') + '\n';
    const out = [];
    const add = (id, title, lang, relevant, code) => out.push({ id, title, lang, relevant, code });

    // ---- Go -------------------------------------------------------------
    if (m2m) {
      add('go', 'Go (golang.org/x/oauth2)', 'go', true, L(
        '// ' + nm + ': machine-to-machine. go get golang.org/x/oauth2',
        'package main', '',
        'import (', '\t"context"', '\t"fmt"', '\t"os"', '',
        '\t"golang.org/x/oauth2/clientcredentials"', ')', '',
        'func main() {',
        '\tcfg := clientcredentials.Config{',
        '\t\tClientID:     ' + goStr(cid) + ',',
        '\t\tClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),',
        '\t\tTokenURL:     ' + goStr(tokenEp) + ',',
        '\t}',
        '\ttok, err := cfg.Token(context.Background())',
        '\tif err != nil {', '\t\tpanic(err)', '\t}',
        '\tfmt.Println(tok.TokenType, tok.Expiry)', '}'));
    } else {
      add('go', 'Go (coreos/go-oidc + oauth2)', 'go', true, L(
        '// ' + nm + '. go get github.com/coreos/go-oidc/v3/oidc golang.org/x/oauth2',
        'package main', '',
        'import (', '\t"context"', '\t"net/http"', '\t"os"', '',
        '\t"github.com/coreos/go-oidc/v3/oidc"', '\t"golang.org/x/oauth2"', ')', '',
        'func main() {',
        '\tctx := context.Background()',
        '\tprovider, err := oidc.NewProvider(ctx, ' + goStr(issuer) + ')',
        '\tif err != nil {', '\t\tpanic(err)', '\t}',
        '\tcfg := oauth2.Config{',
        '\t\tClientID:    ' + goStr(cid) + ',',
        conf ? '\t\tClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),' : '\t\t// public client: no secret, PKCE protects the code',
        '\t\tEndpoint:    provider.Endpoint(),',
        '\t\tRedirectURL: ' + goStr(ru) + ',',
        '\t\tScopes:      []string{oidc.ScopeOpenID, "profile", "email"},',
        '\t}',
        '\tverifier := provider.Verifier(&oidc.Config{ClientID: ' + goStr(cid) + '})',
        '',
        '\thttp.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {',
        '\t\t// Store state, nonce and pv in the user session (not shown).',
        '\t\tstate, nonce, pv := randomString(), randomString(), oauth2.GenerateVerifier()',
        '\t\turl := cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(pv), oauth2.SetAuthURLParam("nonce", nonce))',
        '\t\thttp.Redirect(w, r, url, http.StatusFound)',
        '\t})',
        '\thttp.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {',
        '\t\t// Compare r.URL.Query().Get("state") with the stored state first.',
        '\t\ttok, err := cfg.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(storedVerifier))',
        '\t\tif err != nil {', '\t\t\thttp.Error(w, "exchange failed", http.StatusBadGateway)', '\t\t\treturn', '\t\t}',
        '\t\traw, _ := tok.Extra("id_token").(string)',
        '\t\tidt, err := verifier.Verify(r.Context(), raw) // checks signature, iss, aud, exp',
        '\t\tif err != nil || idt.Nonce != storedNonce {', '\t\t\thttp.Error(w, "bad id_token", http.StatusUnauthorized)', '\t\t\treturn', '\t\t}',
        '\t\t// idt.Claims(&claims) now holds the verified user.',
        '\t})',
        '\t_ = http.ListenAndServe(":3000", nil)', '}'));
    }

    // ---- Node -----------------------------------------------------------
    {
      const insecure = /^http:/i.test(issuer);
      const disc = 'await client.discovery(new URL(' + jsStr(issuer) + '), ' + jsStr(cid) + ', ' +
        (conf ? 'process.env.OIDC_CLIENT_SECRET' : 'undefined') +
        (insecure ? ', undefined, { execute: [client.allowInsecureRequests] }' : '') + ')';
      if (m2m) {
        add('node', 'Node (openid-client)', 'js', true, L(
          '// ' + nm + ': machine-to-machine. npm install openid-client',
          "import * as client from 'openid-client';", '',
          'const config = ' + disc + ';',
          'const tokens = await client.clientCredentialsGrant(config);',
          'console.log(tokens.token_type, tokens.expires_in);'));
      } else {
        add('node', 'Node (openid-client)', 'js', true, L(
          '// ' + nm + '. npm install openid-client (v6)',
          "import * as client from 'openid-client';", '',
          'const config = ' + disc + ';',
          'const redirectUri = ' + jsStr(ru) + ';', '',
          '// /login: keep codeVerifier, state and nonce in the session.',
          'const codeVerifier = client.randomPKCECodeVerifier();',
          'const state = client.randomState();',
          'const nonce = client.randomNonce();',
          'const url = client.buildAuthorizationUrl(config, {',
          "  redirect_uri: redirectUri, scope: 'openid profile email',",
          "  code_challenge: await client.calculatePKCECodeChallenge(codeVerifier), code_challenge_method: 'S256',",
          '  state, nonce,', '});',
          '// redirect the browser to url.href', '',
          '// /callback: currentUrl is the full callback URL the app received.',
          'const tokens = await client.authorizationCodeGrant(config, currentUrl, {',
          '  pkceCodeVerifier: codeVerifier, expectedState: state, expectedNonce: nonce,', '});',
          'const claims = tokens.claims(); // verified: signature, iss, aud, exp, nonce',
          'console.log(claims.sub);'));
      }
    }

    // ---- Python ---------------------------------------------------------
    if (m2m) {
      add('python', 'Python (authlib)', 'python', true, L(
        '# ' + nm + ': machine-to-machine. pip install authlib requests',
        'import os', 'from authlib.integrations.requests_client import OAuth2Session', '',
        'client = OAuth2Session(' + pyStr(cid) + ', os.environ["OIDC_CLIENT_SECRET"])',
        'token = client.fetch_token(' + pyStr(tokenEp) + ', grant_type="client_credentials")',
        'print(token["token_type"], token["expires_in"])'));
    } else {
      add('python', 'Python (authlib)', 'python', true, L(
        '# ' + nm + '. pip install authlib requests',
        'import os', 'import requests',
        'from authlib.integrations.requests_client import OAuth2Session',
        'from authlib.jose import JsonWebKey, jwt',
        'from authlib.common.security import generate_token', '',
        'ISSUER = ' + pyStr(issuer),
        'meta = requests.get(ISSUER + "/.well-known/openid-configuration", timeout=10).json()',
        'assert meta["issuer"] == ISSUER  # use the issuer exactly as discovery reports it', '',
        'client = OAuth2Session(',
        '    ' + pyStr(cid) + ',',
        conf ? '    os.environ["OIDC_CLIENT_SECRET"],' : '    None,  # public client',
        '    scope="openid profile email",',
        '    redirect_uri=' + pyStr(ru) + ',',
        '    code_challenge_method="S256",', ')', '',
        '# /login: keep verifier, state and nonce in the session.',
        'verifier, nonce = generate_token(48), generate_token(16)',
        'url, state = client.create_authorization_url(meta["authorization_endpoint"], code_verifier=verifier, nonce=nonce)', '',
        '# /callback: authorization_response is the full callback URL; check state first.',
        'token = client.fetch_token(meta["token_endpoint"], authorization_response=authorization_response, code_verifier=verifier)',
        'jwks = JsonWebKey.import_key_set(requests.get(meta["jwks_uri"], timeout=10).json())',
        'claims = jwt.decode(token["id_token"], jwks, claims_options={',
        '    "iss": {"essential": True, "value": ISSUER},',
        '    "aud": {"essential": True, "value": ' + pyStr(cid) + '},', '})',
        'claims.validate()  # exp, iat',
        'assert claims["nonce"] == nonce'));
    }

    // ---- Rust -----------------------------------------------------------
    if (m2m) {
      add('rust', 'Rust (oauth2 crate)', 'rust', false, L(
        '// ' + nm + ': machine-to-machine. Cargo: oauth2 = "5", tokio = { version = "1", features = ["full"] }',
        'use oauth2::{basic::BasicClient, reqwest, AuthUrl, ClientId, ClientSecret, TokenResponse, TokenUrl};', '',
        '#[tokio::main]', 'async fn main() -> Result<(), Box<dyn std::error::Error>> {',
        '    let http = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none()).build()?;',
        '    let client = BasicClient::new(ClientId::new(' + rustStr(cid) + '.to_string()))',
        '        .set_client_secret(ClientSecret::new(std::env::var("OIDC_CLIENT_SECRET")?))',
        '        .set_auth_uri(AuthUrl::new(' + rustStr(issuer + '/protocol/openid-connect/auth') + '.to_string())?)',
        '        .set_token_uri(TokenUrl::new(' + rustStr(tokenEp) + '.to_string())?);',
        '    let tok = client.exchange_client_credentials().request_async(&http).await?;',
        '    println!("{:?}", tok.expires_in());', '    Ok(())', '}'));
    } else {
      add('rust', 'Rust (openidconnect crate)', 'rust', true, L(
        '// ' + nm + '. Cargo: openidconnect = "4", tokio = { version = "1", features = ["full"] }',
        'use openidconnect::core::{CoreClient, CoreProviderMetadata, CoreResponseType};',
        'use openidconnect::{reqwest, AuthenticationFlow, AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce,',
        '    OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl, Scope, TokenResponse};', '',
        '#[tokio::main]', 'async fn main() -> Result<(), Box<dyn std::error::Error>> {',
        '    let http = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none()).build()?;',
        '    let meta = CoreProviderMetadata::discover_async(IssuerUrl::new(' + rustStr(issuer) + '.to_string())?, &http).await?;',
        '    let client = CoreClient::from_provider_metadata(',
        '        meta,',
        '        ClientId::new(' + rustStr(cid) + '.to_string()),',
        conf ? '        Some(ClientSecret::new(std::env::var("OIDC_CLIENT_SECRET")?)),' : '        None, // public client',
        '    )',
        '    .set_redirect_uri(RedirectUrl::new(' + rustStr(ru) + '.to_string())?);', '',
        '    // /login: keep verifier, csrf and nonce in the session.',
        '    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();',
        '    let (url, csrf, nonce) = client',
        '        .authorize_url(AuthenticationFlow::<CoreResponseType>::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)',
        '        .add_scope(Scope::new("profile".to_string()))',
        '        .add_scope(Scope::new("email".to_string()))',
        '        .set_pkce_challenge(challenge)',
        '        .url();',
        '    println!("open {url}");', '',
        '    // /callback: compare the returned state with csrf, then exchange the code.',
        '    let code = AuthorizationCode::new(String::from("code-from-callback"));',
        '    let tok = client.exchange_code(code)?.set_pkce_verifier(verifier).request_async(&http).await?;',
        '    let id = tok.id_token().ok_or("no id_token")?;',
        '    let claims = id.claims(&client.id_token_verifier(), &nonce)?; // signature, iss, aud, exp, nonce',
        '    println!("{}", claims.subject().as_str());', '    let _ = csrf;', '    Ok(())', '}'));
    }

    // ---- kubectl / kubelogin --------------------------------------------
    {
      const port = isLoopbackHttp(ru) ? portOf(ru) : '8000';
      const note = isLoopbackHttp(ru) ? '' : '# NOTE: kubelogin needs a loopback redirect URI (http://localhost:8000 by default); register one with the "CLI or native" type.\n';
      add('kubectl', 'kubectl + kubelogin (oidc-login)', 'yaml', app.type === 'native', note + L(
        '# ' + nm + '. Install: kubectl krew install oidc-login',
        '# 1. Try the login and see the claims:',
        '#   kubectl oidc-login setup --oidc-issuer-url=' + ol(issuer) + ' --oidc-client-id=' + ol(cid) + ' --listen-address=127.0.0.1:' + port,
        '# 2. API server flags (the issuer must be https for a real cluster):',
        '#   --oidc-issuer-url=' + ol(issuer) + ' --oidc-client-id=' + ol(cid) + ' --oidc-username-claim=sub',
        '# 3. kubeconfig user:',
        'users:',
        '- name: oidc',
        '  user:',
        '    exec:',
        '      apiVersion: client.authentication.k8s.io/v1',
        '      command: kubectl',
        '      interactiveMode: IfAvailable',
        '      args:',
        '      - oidc-login',
        '      - get-token',
        '      - ' + yamlStr('--oidc-issuer-url=' + issuer),
        '      - ' + yamlStr('--oidc-client-id=' + cid),
        '      - ' + yamlStr('--oidc-extra-scope=email'),
        '      - ' + yamlStr('--listen-address=127.0.0.1:' + port),
        '      # PKCE is used automatically when the IdP advertises S256.',
        conf ? '      # A client secret would have to be an argument here: use a public (native) client for kubectl instead.' : '      # public client: no secret'));
    }

    // ---- nginx + oauth2-proxy -------------------------------------------
    {
      add('oauth2-proxy', 'nginx + oauth2-proxy', 'bash', app.type === 'web', L(
        '# ' + nm + '. 1. oauth2-proxy environment (set the secrets from your secret store, not from this page):',
        'export OAUTH2_PROXY_PROVIDER=oidc',
        'export OAUTH2_PROXY_OIDC_ISSUER_URL=' + shq(issuer),
        'export OAUTH2_PROXY_CLIENT_ID=' + shq(cid),
        'export OAUTH2_PROXY_CLIENT_SECRET="$OIDC_CLIENT_SECRET"',
        'export OAUTH2_PROXY_REDIRECT_URL=' + shq(ru) + '   # must end in /oauth2/callback',
        'export OAUTH2_PROXY_CODE_CHALLENGE_METHOD=S256',
        'export OAUTH2_PROXY_COOKIE_SECRET="$(openssl rand -base64 32 | tr -- \'+/\' \'-_\')"',
        'export OAUTH2_PROXY_EMAIL_DOMAINS=' + shq('*'),
        'export OAUTH2_PROXY_HTTP_ADDRESS=' + shq('127.0.0.1:4180'),
        'export OAUTH2_PROXY_UPSTREAMS=static://202',
        'oauth2-proxy',
        '',
        '# 2. nginx.conf (server block):',
        'cat <<\'NGINX\'',
        'location /oauth2/ {',
        '    proxy_pass http://127.0.0.1:4180;',
        '    proxy_set_header Host $host;',
        '    proxy_set_header X-Auth-Request-Redirect $request_uri;',
        '}',
        'location = /oauth2/auth {',
        '    internal;',
        '    proxy_pass http://127.0.0.1:4180;',
        '    proxy_set_header Host $host;',
        '    proxy_pass_request_body off;',
        '    proxy_set_header Content-Length "";',
        '}',
        'location / {',
        '    auth_request /oauth2/auth;',
        '    error_page 401 = /oauth2/sign_in;',
        '    auth_request_set $user $upstream_http_x_auth_request_user;',
        '    proxy_set_header X-User $user;',
        '    proxy_pass http://127.0.0.1:3000;  # your app',
        '}',
        'NGINX'));
    }

    // ---- SPA --------------------------------------------------------------
    add('spa', 'Browser SPA (oidc-client-ts)', 'js', app.type === 'spa', L(
      '// ' + nm + '. npm install oidc-client-ts. Public client: PKCE S256, no secret in the browser.',
      "import { UserManager } from 'oidc-client-ts';", '',
      'export const userManager = new UserManager({',
      '  authority: ' + jsStr(issuer) + ',',
      '  client_id: ' + jsStr(cid) + ',',
      '  redirect_uri: ' + jsStr(ru) + ',',
      "  response_type: 'code', scope: 'openid profile email',", '});',
      '// userManager.signinRedirect(); then on the redirect_uri page: await userManager.signinCallback();'));

    // ---- curl -----------------------------------------------------------
    {
      const c = [
        '# ' + nm + ': OIDC_CLIENT_ID and OIDC_CLIENT_SECRET come from the environment.',
        'export OIDC_CLIENT_ID=' + shq(cid)];
      if (conf) c.push('export OIDC_CLIENT_SECRET=...   # paste once; never commit it');
      if (m2m) {
        c.push('curl -s ' + shq(tokenEp) + ' \\', '  -u "$OIDC_CLIENT_ID:$OIDC_CLIENT_SECRET" \\', '  -d grant_type=client_credentials');
      } else {
        c.push('# After the browser login returns ?code=...&state=..., exchange the code (PKCE verifier from your login step):',
          'curl -s ' + shq(tokenEp) + ' \\',
          conf ? '  -u "$OIDC_CLIENT_ID:$OIDC_CLIENT_SECRET" \\' : '  -d client_id="$OIDC_CLIENT_ID" \\',
          '  -d grant_type=authorization_code \\', '  -d code="$CODE" \\', '  -d code_verifier="$CODE_VERIFIER" \\',
          '  --data-urlencode redirect_uri=' + shq(ru));
      }
      add('curl', m2m ? 'curl (client_credentials)' : 'curl (token endpoint)', 'bash', m2m, L(...c));
    }

    // Most useful first for each kind of app; the rest stay available.
    const order = {
      spa: ['spa', 'curl'],
      web: ['go', 'node', 'python', 'rust', 'oauth2-proxy', 'curl'],
      native: ['kubectl', 'go', 'rust', 'python', 'node', 'curl'],
      m2m: ['curl', 'go', 'node', 'python', 'rust'],
    }[app.type] || [];
    const rank = (s) => { const i = order.indexOf(s.id); return i < 0 ? order.length : i; };
    for (const s of out) s.relevant = order.includes(s.id);
    return out.sort((a, b) => rank(a) - rank(b));
  }

  const api = { buildSnippets, jsonStr, goStr, jsStr, pyStr, rustStr, yamlStr, shq, safeComment };
  root.HavenSnippets = Object.assign(root.HavenSnippets || {}, api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
