// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/haven/internal/idp/core"
)

// ---- certificates ----

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

var certSerial = big.NewInt(1000)

// mkCert issues a certificate signed by parent (nil = self signed), valid
// around now.
func mkCert(t *testing.T, now time.Time, parent *testCert, mut func(*x509.Certificate)) testCert {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certSerial = new(big.Int).Add(certSerial, big.NewInt(1))
	tpl := &x509.Certificate{SerialNumber: certSerial, Subject: pkix.Name{CommonName: "client1", Organization: []string{"Acme"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if mut != nil {
		mut(tpl)
	}
	signer, signerCert := crypto.Signer(k), tpl
	if parent != nil {
		signer, signerCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signerCert, &k.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCert{c, k}
}

func mkCA(t *testing.T, now time.Time, parent *testCert, cn string) testCert {
	return mkCert(t, now, parent, func(c *x509.Certificate) {
		c.Subject = pkix.Name{CommonName: cn}
		c.IsCA, c.BasicConstraintsValid = true, true
		c.KeyUsage, c.ExtKeyUsage = x509.KeyUsageCertSign, nil
	})
}

func (c testCert) pem() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.cert.Raw}))
}

func (c testCert) escaped() string { return url.PathEscape(c.pem()) }

func (c testCert) jwk(kid string) map[string]any {
	j := caKey{kid, c.key}.jwk()
	j["x5c"] = []string{base64.StdEncoding.EncodeToString(c.cert.Raw)}
	return j
}

func certJWKS(certs ...testCert) string {
	var l []any
	for i, c := range certs {
		l = append(l, c.jwk(string(rune('a'+i))))
	}
	return mustJSON(map[string]any{"keys": l})
}

// direct presents certs as the TLS client certificates of the connection.
func direct(certs ...testCert) func(*http.Request) {
	return func(r *http.Request) {
		st := &tls.ConnectionState{}
		for _, c := range certs {
			st.PeerCertificates = append(st.PeerCertificates, c.cert)
		}
		r.TLS = st
	}
}

const certHeader = "X-Client-Cert"

// proxied sends the header from the given TCP peer.
func proxied(peer string, values ...string) func(*http.Request) {
	return func(r *http.Request) {
		r.RemoteAddr = net.JoinHostPort(peer, "5555")
		for _, v := range values {
			r.Header.Add(certHeader, v)
		}
	}
}

var proxyCfg = MTLSConfig{ProxyHeader: certHeader, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}}

type tlsEnv struct {
	*caEnv
	ca, other testCert
	leaf      testCert
}

// newTLSEnv: direct mTLS with one CA, and "svc" configured for tls_client_auth.
func newTLSEnv(t *testing.T) *tlsEnv {
	t.Helper()
	e := &tlsEnv{caEnv: newCAEnv(t, devOpts{})}
	e.ca = mkCA(t, e.now, nil, "Test CA")
	e.other = mkCA(t, e.now, nil, "Other CA")
	e.leaf = mkCert(t, e.now, &e.ca, nil)
	roots := x509.NewCertPool()
	roots.AddCert(e.ca.cert)
	e.h.cfg.MTLS = MTLSConfig{Direct: true, Roots: roots}
	e.configure(t, e.cl, core.ClientAuth{Method: core.AuthMethodTLS, TLSSubjectDN: "CN=client1,O=Acme"})
	return e
}

var svcForm = url.Values{"grant_type": {"client_credentials"}, "client_id": {"svc"}}

// ---- tls_client_auth ----

func TestTLSClientAuthSubjects(t *testing.T) {
	e := newTLSEnv(t)
	uri, _ := url.Parse("spiffe://acme.example/payments")
	leaf := mkCert(t, e.now, &e.ca, func(c *x509.Certificate) {
		c.DNSNames = []string{"client.acme.example"}
		c.URIs = []*url.URL{uri}
		c.IPAddresses = []net.IP{net.ParseIP("192.0.2.7")}
		c.EmailAddresses = []string{"svc@acme.example"}
	})
	for name, x := range map[string]struct {
		cfg core.ClientAuth
		ok  bool
	}{
		"dn":              {core.ClientAuth{TLSSubjectDN: "CN=client1,O=Acme"}, true},
		"dn reordered":    {core.ClientAuth{TLSSubjectDN: "O=Acme,CN=client1"}, false},
		"dn partial":      {core.ClientAuth{TLSSubjectDN: "CN=client1"}, false},
		"dn case":         {core.ClientAuth{TLSSubjectDN: "CN=Client1,O=Acme"}, false},
		"dns":             {core.ClientAuth{TLSSANDNS: "CLIENT.acme.example"}, true},
		"dns parent":      {core.ClientAuth{TLSSANDNS: "acme.example"}, false},
		"uri":             {core.ClientAuth{TLSSANURI: "spiffe://acme.example/payments"}, true},
		"uri prefix":      {core.ClientAuth{TLSSANURI: "spiffe://acme.example/pay"}, false},
		"ip":              {core.ClientAuth{TLSSANIP: "192.0.2.7"}, true},
		"ip other":        {core.ClientAuth{TLSSANIP: "192.0.2.8"}, false},
		"email":           {core.ClientAuth{TLSSANEmail: "svc@acme.example"}, true},
		"email other":     {core.ClientAuth{TLSSANEmail: "x@acme.example"}, false},
		"nothing at all":  {core.ClientAuth{}, false},
		"cn is not a SAN": {core.ClientAuth{TLSSANDNS: "client1"}, false},
	} {
		x.cfg.Method = core.AuthMethodTLS
		e.configure(t, e.cl, x.cfg)
		code, out, _ := e.send(tokenR, svcForm, direct(leaf))
		if (code == 200) != x.ok || (!x.ok && out["error"] != "invalid_client") {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
}

func TestTLSClientAuthRejections(t *testing.T) {
	e := newTLSEnv(t)
	if code, out, _ := e.send(tokenR, svcForm, direct(e.leaf)); code != 200 || out["access_token"] == nil {
		t.Fatalf("control: %d %v", code, out)
	}
	if _, bound := claimsOf(t, mustToken(t, e, svcForm, direct(e.leaf)))["cnf"]; bound {
		t.Fatal("token bound although binding was not asked for")
	}
	expired := mkCert(t, e.now, &e.ca, func(c *x509.Certificate) { c.NotAfter = e.now.Add(-time.Minute) })
	notYet := mkCert(t, e.now, &e.ca, func(c *x509.Certificate) { c.NotBefore = e.now.Add(time.Hour) })
	serverOnly := mkCert(t, e.now, &e.ca, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth} })
	foreign := mkCert(t, e.now, &e.other, nil) // right subject, wrong CA
	selfMade := mkCert(t, e.now, nil, nil)     // right subject, no CA
	inter := mkCA(t, e.now, &e.ca, "Intermediate")
	viaInter := mkCert(t, e.now, &inter, nil)
	for name, mod := range map[string]func(*http.Request){
		"no certificate":       func(*http.Request) {},
		"empty tls state":      direct(),
		"expired":              direct(expired),
		"not yet valid":        direct(notYet),
		"server auth only":     direct(serverOnly),
		"other CA":             direct(foreign),
		"self signed":          direct(selfMade),
		"intermediate missing": direct(viaInter),
		"proxy header ignored": proxied("10.1.2.3", e.leaf.escaped()),
	} {
		code, out, _ := e.send(tokenR, svcForm, mod)
		if code != 401 || out["error"] != "invalid_client" {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	// The intermediate sent by the client completes the chain.
	if code, out, _ := e.send(tokenR, svcForm, direct(viaInter, inter)); code != 200 {
		t.Errorf("with intermediate: %d %v", code, out)
	}
	// A client-sent chain cannot introduce its own trust anchor.
	if code, _, _ := e.send(tokenR, svcForm, direct(foreign, e.other)); code != 401 {
		t.Errorf("client supplied root accepted: %d", code)
	}
	// A secret travelling along is refused even with the right certificate.
	both := url.Values{"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"s3cret"}}
	for name, c := range map[string]func() (int, map[string]any, http.Header){
		"post": func() (int, map[string]any, http.Header) { return e.send(tokenR, both, direct(e.leaf)) },
		"empty secret": func() (int, map[string]any, http.Header) {
			f := url.Values{"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {""}}
			return e.send(tokenR, f, direct(e.leaf))
		},
		"basic": func() (int, map[string]any, http.Header) {
			return e.send(tokenR, svcForm, direct(e.leaf), basicAuth("svc", "s3cret"))
		},
	} {
		if code, out, _ := c(); code != 401 && code != 400 {
			t.Errorf("certificate plus %s: %d %v", name, code, out)
		}
	}
	// Without trust anchors the PKI method is off: never the system roots.
	e.h.cfg.MTLS.Roots = nil
	if code, _, _ := e.send(tokenR, svcForm, direct(e.leaf)); code != 401 {
		t.Errorf("no roots: %d", code)
	}
	// And with mutual TLS off the connection certificate is not looked at.
	e.h.cfg.MTLS = MTLSConfig{}
	if code, _, _ := e.send(tokenR, svcForm, direct(e.leaf)); code != 401 {
		t.Errorf("mtls off: %d", code)
	}
}

func mustToken(t *testing.T, e *tlsEnv, f url.Values, mod ...func(*http.Request)) string {
	t.Helper()
	code, out, _ := e.send(tokenR, f, mod...)
	at, _ := out["access_token"].(string)
	if code != 200 || at == "" {
		t.Fatalf("token: %d %v", code, out)
	}
	return at
}

// ---- self_signed_tls_client_auth ----

func TestSelfSignedTLSClientAuth(t *testing.T) {
	e := newTLSEnv(t)
	mine := mkCert(t, e.now, nil, nil)
	twin := mkCert(t, e.now, nil, nil) // same subject, other key
	e.configure(t, e.cl, core.ClientAuth{Method: core.AuthMethodSelfSignedTLS, JWKS: certJWKS(mine)})
	if code, out, _ := e.send(tokenR, svcForm, direct(mine)); code != 200 {
		t.Fatalf("registered: %d %v", code, out)
	}
	for name, mod := range map[string]func(*http.Request){
		"same subject, other key": direct(twin),
		"a CA-issued certificate": direct(e.leaf),
		"registered cert second":  direct(twin, mine),
		"none":                    func(*http.Request) {},
	} {
		if code, out, _ := e.send(tokenR, svcForm, mod); code != 401 {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	// The bare public key without the certificate is not enough.
	e.configure(t, e.cl, core.ClientAuth{Method: core.AuthMethodSelfSignedTLS, JWKS: jwksOf(caKey{"a", mine.key})})
	if code, _, _ := e.send(tokenR, svcForm, direct(mine)); code != 401 {
		t.Errorf("key without x5c: %d", code)
	}
	old := mkCert(t, e.now, nil, func(c *x509.Certificate) { c.NotAfter = e.now.Add(-time.Second) })
	e.configure(t, e.cl, core.ClientAuth{Method: core.AuthMethodSelfSignedTLS, JWKS: certJWKS(old)})
	if code, _, _ := e.send(tokenR, svcForm, direct(old)); code != 401 {
		t.Errorf("expired registered cert: %d", code)
	}
	// From a jwks_uri, with rotation.
	s := newJWKSSrv(t, certJWKS(mine))
	e.trust(s)
	e.configure(t, e.cl, core.ClientAuth{Method: core.AuthMethodSelfSignedTLS, JWKSURI: s.uri()})
	if code, out, _ := e.send(tokenR, svcForm, direct(mine)); code != 200 {
		t.Fatalf("jwks_uri: %d %v", code, out)
	}
	s.set(func() { s.body = certJWKS(twin) })
	for i := 0; i < 5; i++ {
		e.send(tokenR, svcForm, direct(twin))
	}
	if s.hits.Load() != 1 {
		t.Fatalf("unknown certificates bypass the rate limit: %d fetches", s.hits.Load())
	}
	e.advance(jwksMinGap)
	if code, out, _ := e.send(tokenR, svcForm, direct(twin)); code != 200 {
		t.Fatalf("rotated: %d %v", code, out)
	}
}

// ---- the proxy header ----

func TestMTLSProxyHeader(t *testing.T) {
	e := newTLSEnv(t)
	leaf := e.leaf
	header := proxied("10.1.2.3", leaf.escaped())

	// Not configured: a header is just a header.
	e.h.cfg.MTLS = MTLSConfig{}
	if code, _, _ := e.send(tokenR, svcForm, header); code != 401 {
		t.Fatal("header trusted by default")
	}
	roots := x509.NewCertPool()
	roots.AddCert(e.ca.cert)
	e.h.cfg.MTLS = MTLSConfig{Direct: true, Roots: roots}
	if code, _, _ := e.send(tokenR, svcForm, header); code != 401 {
		t.Fatal("header trusted in direct mode")
	}
	cfg := proxyCfg
	cfg.Roots = roots
	e.h.cfg.MTLS = cfg
	for name, v := range map[string]string{
		"escaped pem":  leaf.escaped(),
		"base64 der":   base64.StdEncoding.EncodeToString(leaf.cert.Raw),
		"rfc9440":      ":" + base64.StdEncoding.EncodeToString(leaf.cert.Raw) + ":",
		"query escape": strings.ReplaceAll(url.QueryEscape(leaf.pem()), "+", "%20"),
	} {
		if code, out, _ := e.send(tokenR, svcForm, proxied("10.1.2.3", v)); code != 200 {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
	if code, out, _ := e.send(tokenR, svcForm, proxied("::ffff:10.1.2.3", leaf.escaped())); code != 200 {
		t.Errorf("mapped proxy address: %d %v", code, out)
	}
	e.h.cfg.TrustProxy = true // forwarded addresses must not make a peer trusted
	for name, mod := range map[string]func(*http.Request){
		"untrusted peer": proxied("203.0.113.66", leaf.escaped()),
		"spoofed xff": func(r *http.Request) {
			proxied("203.0.113.66", leaf.escaped())(r)
			r.Header.Set("X-Forwarded-For", "10.1.2.3")
		},
		"two headers":        proxied("10.1.2.3", leaf.escaped(), leaf.escaped()),
		"client plus proxy":  proxied("10.1.2.3", "junk", leaf.escaped()),
		"empty":              proxied("10.1.2.3", ""),
		"junk":               proxied("10.1.2.3", "not-a-certificate"),
		"two certificates":   proxied("10.1.2.3", url.PathEscape(leaf.pem()+e.ca.pem())),
		"trailing data":      proxied("10.1.2.3", url.PathEscape(leaf.pem()+"x")),
		"der plus data":      proxied("10.1.2.3", base64.StdEncoding.EncodeToString(append(append([]byte{}, leaf.cert.Raw...), 0))),
		"private key pem":    proxied("10.1.2.3", url.PathEscape("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n")),
		"oversized":          proxied("10.1.2.3", strings.Repeat("A", certHeaderMax+4)),
		"other header name":  func(r *http.Request) { r.RemoteAddr = "10.1.2.3:1"; r.Header.Set("Ssl-Client-Cert", leaf.escaped()) },
		"connection instead": func(r *http.Request) { direct(leaf)(r); r.RemoteAddr = "10.1.2.3:1" },
	} {
		if code, out, _ := e.send(tokenR, svcForm, mod); code != 401 {
			t.Errorf("%s: %d %v", name, code, out)
		}
	}
}

func TestMTLSConfigValidate(t *testing.T) {
	pf := []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32")}
	for name, x := range map[string]struct {
		c       MTLSConfig
		ok      bool
		enabled bool
	}{
		"off":             {MTLSConfig{}, true, false},
		"direct":          {MTLSConfig{Direct: true}, true, true},
		"proxy":           {MTLSConfig{ProxyHeader: "Client-Cert", TrustedProxies: pf}, true, true},
		"both":            {MTLSConfig{Direct: true, ProxyHeader: "Client-Cert", TrustedProxies: pf}, false, false},
		"no proxies":      {MTLSConfig{ProxyHeader: "Client-Cert"}, false, false},
		"proxies only":    {MTLSConfig{TrustedProxies: pf}, false, false},
		"everyone v4":     {MTLSConfig{ProxyHeader: "Client-Cert", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}, false, false},
		"everyone v6":     {MTLSConfig{ProxyHeader: "Client-Cert", TrustedProxies: []netip.Prefix{netip.MustParsePrefix("::/0")}}, false, false},
		"zero prefix":     {MTLSConfig{ProxyHeader: "Client-Cert", TrustedProxies: []netip.Prefix{{}}}, false, false},
		"authorization":   {MTLSConfig{ProxyHeader: "Authorization", TrustedProxies: pf}, false, false},
		"bad header name": {MTLSConfig{ProxyHeader: "a b", TrustedProxies: pf}, false, false},
	} {
		if err := x.c.Validate(); (err == nil) != x.ok || x.c.Enabled() != x.enabled {
			t.Errorf("%s: %v enabled=%v", name, err, x.c.Enabled())
		}
	}
}

// ---- certificate-bound access tokens ----

func (e *tlsEnv) userinfoCall(scheme, at string, mod ...func(*http.Request)) int {
	req := httptest.NewRequest("GET", userinfR, nil)
	req.Header.Set("Authorization", scheme+" "+at)
	req.RemoteAddr = "203.0.113.20:1"
	for _, m := range mod {
		m(req)
	}
	w := httptest.NewRecorder()
	e.h.ServeHTTP(w, req)
	return w.Code
}

func thumb(t *testing.T, at string) string {
	t.Helper()
	cnf, _ := claimsOf(t, at)["cnf"].(map[string]any)
	s, _ := cnf["x5t#S256"].(string)
	return s
}

func (e *tlsEnv) code(t *testing.T) url.Values {
	t.Helper()
	code := "mtls-code-" + randToken(8)
	if err := e.st.PutAuthCode(context.Background(), core.AuthCode{CodeHash: HashSecret(code), Realm: "r", ClientID: "svc",
		UserID: "u1", RedirectURI: cb, Scope: "openid offline_access", CodeChallenge: challenge(verifier), ChallengeMeth: "S256",
		AuthTime: e.now, ExpiresAt: e.now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	return url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {cb}, "client_id": {"svc"},
		"code_verifier": {verifier}}
}

func TestCertificateBoundTokens(t *testing.T) {
	e := newTLSEnv(t)
	e.configure(t, e.cl, core.ClientAuth{Method: core.AuthMethodTLS, TLSSubjectDN: "CN=client1,O=Acme", CertBoundTokens: true})
	second := mkCert(t, e.now, &e.ca, nil) // also authenticates the client, another certificate

	at := mustToken(t, e, e.code(t), direct(e.leaf))
	if thumb(t, at) != certThumbprint(e.leaf.cert) {
		t.Fatalf("cnf: %v", claimsOf(t, at)["cnf"])
	}
	if code := e.userinfoCall("Bearer", at, direct(e.leaf)); code != 200 {
		t.Fatalf("same certificate: %d", code)
	}
	for name, c := range map[string]int{
		"no certificate":    e.userinfoCall("Bearer", at),
		"other certificate": e.userinfoCall("Bearer", at, direct(second)),
		"dpop scheme":       e.userinfoCall("DPoP", at, direct(e.leaf)),
		"header spoof":      e.userinfoCall("Bearer", at, proxied("10.1.2.3", e.leaf.escaped())),
	} {
		if c != 401 {
			t.Errorf("%s: %d", name, c)
		}
	}
	code, out, _ := e.send(introR, url.Values{"token": {at}, "client_id": {"svc"}}, direct(second))
	cnf, _ := out["cnf"].(map[string]any)
	if code != 200 || out["active"] != true || out["token_type"] != "Bearer" || cnf["x5t#S256"] != certThumbprint(e.leaf.cert) {
		t.Fatalf("introspect: %d %v", code, out)
	}
	// Refresh and client_credentials bind to the certificate of that request.
	_, first, _ := e.send(tokenR, e.code(t), direct(e.leaf))
	rf := url.Values{"grant_type": {"refresh_token"}, "client_id": {"svc"}, "refresh_token": {first["refresh_token"].(string)}}
	if code, o, _ := e.send(tokenR, rf); code != 401 {
		t.Fatalf("refresh without a certificate: %d %v", code, o)
	}
	rat := mustToken(t, e, rf, direct(second))
	if thumb(t, rat) != certThumbprint(second.cert) {
		t.Fatal("refreshed token not bound")
	}
	if thumb(t, mustToken(t, e, svcForm, direct(e.leaf))) != certThumbprint(e.leaf.cert) {
		t.Fatal("client_credentials token not bound")
	}
	// A deployment that stopped accepting certificates refuses bound tokens.
	e.h.cfg.MTLS = MTLSConfig{}
	if code := e.userinfoCall("Bearer", at, direct(e.leaf)); code != 401 {
		t.Fatalf("mtls off: %d", code)
	}
}

// Binding is independent of how the client authenticates; without a
// certificate nothing is issued and nothing is consumed.
func TestCertificateBindingWithOtherMethods(t *testing.T) {
	e := newTLSEnv(t)
	e.configure(t, e.cl, core.ClientAuth{Method: core.AuthMethodSecretPost, CertBoundTokens: true})
	own := mkCert(t, e.now, nil, nil) // binding does not need a trusted chain
	f := e.code(t)
	f.Set("client_secret", "s3cret")
	code, out, _ := e.send(tokenR, f)
	if code != 400 || out["error"] != "invalid_request" || out["access_token"] != nil {
		t.Fatalf("no certificate: %d %v", code, out)
	}
	expired := mkCert(t, e.now, nil, func(c *x509.Certificate) { c.NotAfter = e.now.Add(-time.Second) })
	if code, _, _ := e.send(tokenR, f, direct(expired)); code != 400 {
		t.Fatalf("expired certificate: %d", code)
	}
	at := mustToken(t, e, f, direct(own)) // the code survived the refusals
	if thumb(t, at) != certThumbprint(own.cert) {
		t.Fatal("not bound")
	}
	// private_key_jwt plus binding.
	e.configure(t, e.cl, core.ClientAuth{Method: core.AuthMethodPrivateKeyJWT, JWKS: jwksOf(e.key), CertBoundTokens: true})
	code, out, _ = e.send(tokenR, withAssertion(ccForm, e.assertion(t, "svc", e.key, aOpt{})))
	if code != 400 || out["access_token"] != nil {
		t.Fatalf("pkjwt without certificate: %d %v", code, out)
	}
	at = mustToken(t, e, withAssertion(ccForm, e.assertion(t, "svc", e.key, aOpt{})), direct(own))
	if thumb(t, at) != certThumbprint(own.cert) {
		t.Fatal("pkjwt token not bound")
	}
}

// With DPoP as well, a resource request must satisfy both constraints.
func TestCertificateBoundAndDPoP(t *testing.T) {
	e := newTLSEnv(t)
	e.configure(t, e.cl, core.ClientAuth{Method: core.AuthMethodTLS, TLSSubjectDN: "CN=client1,O=Acme", CertBoundTokens: true})
	k := newES(t)
	f := e.code(t)
	proof := e.proof(t, k, pOpt{})
	at := mustToken(t, e, f, direct(e.leaf), func(r *http.Request) { r.Header.Set("DPoP", proof) })
	cnf, _ := claimsOf(t, at)["cnf"].(map[string]any)
	if cnf["jkt"] != k.jkt || cnf["x5t#S256"] != certThumbprint(e.leaf.cert) {
		t.Fatalf("cnf: %v", cnf)
	}
	res := func() func(*http.Request) {
		p := e.proof(t, k, pOpt{htu: userinfoURL, htm: "GET", ath: atHash(at)})
		return func(r *http.Request) { r.Header.Set("DPoP", p) }
	}
	if code := e.userinfoCall("DPoP", at, direct(e.leaf), res()); code != 200 {
		t.Fatalf("both: %d", code)
	}
	if code := e.userinfoCall("DPoP", at, res()); code != 401 {
		t.Fatalf("proof without certificate: %d", code)
	}
	if code := e.userinfoCall("DPoP", at, direct(e.leaf)); code != 401 {
		t.Fatalf("certificate without proof: %d", code)
	}
	if code := e.userinfoCall("Bearer", at, direct(e.leaf)); code != 401 {
		t.Fatalf("bearer: %d", code)
	}
}

// A grant that issues an unbound token for a client that requires binding is
// stopped.
func TestUnboundTokenIsNeverReturned(t *testing.T) {
	e := newTLSEnv(t)
	r := httptest.NewRequest("POST", tokenR, nil)
	r = r.WithContext(context.WithValue(r.Context(), certCtxKey{}, "thumb"))
	unbound, _ := fakeSigner{}.Sign(context.Background(), "r", core.Claims{"sub": "x"})
	other, _ := fakeSigner{}.Sign(context.Background(), "r", core.Claims{"cnf": map[string]any{"x5t#S256": "someone-else"}})
	good, _ := fakeSigner{}.Sign(context.Background(), "r", core.Claims{"cnf": map[string]any{"x5t#S256": "thumb"}})
	for name, at := range map[string]string{"unbound": unbound, "other": other, "opaque": "abc", "none": ""} {
		if e.h.mtlsTokenDone(r, map[string]any{"access_token": at}) == nil {
			t.Errorf("%s token passed", name)
		}
	}
	if terr := e.h.mtlsTokenDone(r, map[string]any{"access_token": good}); terr != nil {
		t.Errorf("bound token refused: %v", terr)
	}
}

// The same checks against a real TLS handshake.
func TestMTLSOverRealTLS(t *testing.T) {
	e := newTLSEnv(t)
	srv := httptest.NewUnstartedServer(e.h)
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	defer srv.Close()
	post := func(c *testCert, form url.Values) (int, map[string]any) {
		tr := srv.Client().Transport.(*http.Transport).Clone()
		if c != nil {
			tr.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{c.cert.Raw}, PrivateKey: c.key}}
		}
		defer tr.CloseIdleConnections()
		res, err := (&http.Client{Transport: tr}).PostForm(srv.URL+tokenR, form)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = res.Body.Close() }()
		var out map[string]any
		_ = json.NewDecoder(res.Body).Decode(&out)
		return res.StatusCode, out
	}
	if code, out := post(&e.leaf, svcForm); code != 200 {
		t.Fatalf("with certificate: %d %v", code, out)
	}
	if code, _ := post(nil, svcForm); code != 401 {
		t.Fatalf("without: %d", code)
	}
}
