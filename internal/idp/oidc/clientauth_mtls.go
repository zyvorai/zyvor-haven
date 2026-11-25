// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/zyvorai/haven/internal/idp/core"
)

// Mutual TLS (RFC 8705): client authentication with a certificate, and access
// tokens bound to it (cnf.x5t#S256).
//
// A client certificate only counts when the deployment says where it comes
// from. Exactly one of:
//
//   - Direct: haven-idp terminates TLS itself; the certificate is the one of
//     the TLS connection, whose private key the handshake proved.
//   - ProxyHeader: a TLS-terminating proxy forwards the certificate in a named
//     header, and ONLY requests whose TCP peer is in TrustedProxies are
//     believed. The proxy must require the client to prove possession in its
//     handshake and must overwrite or remove the header on every request.
//
// With neither, no header and no connection state is ever consulted.

// MTLSConfig says where client certificates come from. The zero value turns
// mutual TLS off.
type MTLSConfig struct {
	// Direct takes the certificate of the server's own TLS connection. The
	// listener must request client certificates (tls.RequestClientCert).
	Direct bool
	// ProxyHeader is the request header in which a trusted TLS-terminating
	// proxy forwards the client certificate: URL-encoded PEM (nginx
	// $ssl_client_escaped_cert), base64 DER, or the RFC 9440 byte sequence
	// ":base64:". Never set it unless the proxy strips it from incoming requests.
	ProxyHeader string
	// TrustedProxies are the source addresses the header is accepted from.
	// Required with ProxyHeader.
	TrustedProxies []netip.Prefix
	// Roots are the trust anchors of tls_client_auth (the PKI method). Nil
	// leaves that method off. Intermediates the proxy does not forward belong
	// in here too.
	Roots *x509.CertPool
}

var headerNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$`)

// Validate reports a configuration that must not be used.
func (m MTLSConfig) Validate() error {
	switch {
	case m.Direct && m.ProxyHeader != "":
		return errors.New("mtls: choose direct TLS or a proxy header, not both")
	case m.ProxyHeader == "" && len(m.TrustedProxies) > 0:
		return errors.New("mtls: trusted proxies are set but no proxy header")
	case m.ProxyHeader == "":
		return nil
	case !headerNameRE.MatchString(m.ProxyHeader):
		return errors.New("mtls: the proxy header name is not valid")
	case slices.Contains([]string{"authorization", "cookie", "dpop", "host", "x-forwarded-for"}, strings.ToLower(m.ProxyHeader)):
		return errors.New("mtls: that header cannot carry the client certificate")
	case len(m.TrustedProxies) == 0:
		return errors.New("mtls: a proxy header needs the list of trusted proxy addresses")
	}
	for _, p := range m.TrustedProxies {
		if !p.IsValid() || p.Bits() == 0 {
			return errors.New("mtls: a trusted proxy range must be valid and must not cover every address")
		}
	}
	return nil
}

// Enabled reports whether client certificates are accepted at all.
func (m MTLSConfig) Enabled() bool {
	return (m.Direct || m.ProxyHeader != "") && m.Validate() == nil
}

const certHeaderMax = 16 << 10

// parseCertHeader reads exactly one certificate from a proxy header value.
func parseCertHeader(v string) (*x509.Certificate, error) {
	bad := errors.New("unreadable certificate header")
	v = strings.TrimSpace(v)
	if v == "" || len(v) > certHeaderMax {
		return nil, bad
	}
	if len(v) > 2 && v[0] == ':' && v[len(v)-1] == ':' { // RFC 9440 / RFC 8941 byte sequence
		v = v[1 : len(v)-1]
	} else if strings.Contains(v, "%") {
		u, err := url.PathUnescape(v) // not QueryUnescape: "+" is base64 data
		if err != nil {
			return nil, bad
		}
		v = strings.TrimSpace(u)
	}
	var der []byte
	if strings.HasPrefix(v, "-----BEGIN ") {
		block, rest := pem.Decode([]byte(v))
		if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
			return nil, bad
		}
		der = block.Bytes
	} else {
		var err error
		if der, err = base64.StdEncoding.DecodeString(v); err != nil {
			return nil, bad
		}
	}
	c, err := x509.ParseCertificate(der) // refuses trailing data, so a chain is not accepted
	if err != nil {
		return nil, bad
	}
	return c, nil
}

// clientCert returns the client certificate of the request according to the
// deployment's configuration, with any further certificates the client sent
// (direct TLS only).
func (p *Provider) clientCert(r *http.Request) (leaf *x509.Certificate, rest []*x509.Certificate, ok bool) {
	m := p.cfg.MTLS
	if !m.Enabled() {
		return nil, nil, false
	}
	if m.Direct {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			return nil, nil, false
		}
		return r.TLS.PeerCertificates[0], r.TLS.PeerCertificates[1:], true
	}
	vals := r.Header.Values(m.ProxyHeader)
	if len(vals) == 0 {
		return nil, nil, false
	}
	// The TCP peer, never a forwarded address: only the proxy may speak for a certificate.
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	trusted := err == nil && slices.ContainsFunc(m.TrustedProxies, func(pf netip.Prefix) bool { return pf.Contains(ap.Addr().Unmap()) })
	if !trusted {
		p.cfg.Logger.Warn("oidc: client certificate header from an address that is not a trusted proxy was ignored")
		return nil, nil, false
	}
	if len(vals) != 1 { // a second value means something other than the proxy added one
		return nil, nil, false
	}
	c, err := parseCertHeader(vals[0])
	if err != nil {
		return nil, nil, false
	}
	return c, nil, true
}

// usableCert is the part of certificate checking common to every use.
func (p *Provider) usableCert(c *x509.Certificate) bool {
	now := p.now()
	return !now.Before(c.NotBefore) && !now.After(c.NotAfter) && strongPublicKey(c.PublicKey)
}

// certSubjectMatches compares the one configured identifier of a
// tls_client_auth client with the certificate.
func certSubjectMatches(c *x509.Certificate, cfg core.ClientAuth) bool {
	switch {
	case cfg.TLSSubjectDN != "":
		// The DER sequence as encoded (RFC 4514 string form), so that attribute
		// order matters.
		var seq pkix.RDNSequence
		rest, err := asn1.Unmarshal(c.RawSubject, &seq)
		return err == nil && len(rest) == 0 && seq.String() == cfg.TLSSubjectDN
	case cfg.TLSSANDNS != "":
		return slices.ContainsFunc(c.DNSNames, func(n string) bool { return strings.EqualFold(n, cfg.TLSSANDNS) })
	case cfg.TLSSANURI != "":
		return slices.ContainsFunc(c.URIs, func(u *url.URL) bool { return u.String() == cfg.TLSSANURI })
	case cfg.TLSSANIP != "":
		want, err := netip.ParseAddr(cfg.TLSSANIP)
		if err != nil {
			return false
		}
		for _, ip := range c.IPAddresses {
			if a, ok := netip.AddrFromSlice(ip); ok && a.Unmap() == want.Unmap() {
				return true
			}
		}
	case cfg.TLSSANEmail != "":
		return slices.Contains(c.EmailAddresses, cfg.TLSSANEmail)
	}
	return false
}

// verifyClientCert authenticates the request's certificate for cfg. It returns
// "" on success, otherwise a fixed label for the log.
func (p *Provider) verifyClientCert(r *http.Request, cfg core.ClientAuth) string {
	cert, rest, ok := p.clientCert(r)
	if !ok {
		return "no_certificate"
	}
	if !p.usableCert(cert) {
		return "certificate_expired_or_weak"
	}
	switch cfg.Method {
	case core.AuthMethodTLS:
		if p.cfg.MTLS.Roots == nil { // never fall back to the system roots
			return "no_trust_anchors"
		}
		inter := x509.NewCertPool()
		for i, c := range rest {
			if i == 8 {
				break
			}
			inter.AddCert(c)
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: p.cfg.MTLS.Roots, Intermediates: inter, CurrentTime: p.now(),
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			return "untrusted_chain"
		}
		if !certSubjectMatches(cert, cfg) {
			return "subject_mismatch"
		}
		return ""
	case core.AuthMethodSelfSignedTLS:
		same := func(keys []clientKey) bool {
			return slices.ContainsFunc(keys, func(k clientKey) bool { return k.cert != nil && bytes.Equal(k.cert, cert.Raw) })
		}
		keys, err := p.clientKeys(r.Context(), cfg, same)
		if err != nil {
			return "keys_unavailable"
		}
		if !same(keys) {
			return "certificate_not_registered"
		}
		return ""
	}
	return "wrong_method"
}

// ---- certificate-bound access tokens ----

const x5tClaim = "x5t#S256"

func certThumbprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return base64.RawURLEncoding.EncodeToString(s[:])
}

type certCtxKey struct{}

func boundThumbprint(ctx context.Context) string {
	s, _ := ctx.Value(certCtxKey{}).(string)
	return s
}

// mtlsToken runs at the token endpoint after client authentication: for a
// client that wants certificate-bound tokens it requires a certificate (before
// anything is consumed) and remembers its thumbprint for the access token.
func (p *Provider) mtlsToken(r *http.Request, rl core.Realm, cl core.Client) (*http.Request, *tokenErr) {
	cfg, found, err := p.clientAuthConfig(r.Context(), rl.Name, cl)
	if err != nil {
		p.cfg.Logger.Error("oidc: token client authentication settings", "err", err)
		return r, &tokenErr{http.StatusInternalServerError, "server_error", "temporary error"}
	}
	if !found || !cfg.CertBoundTokens {
		return r, nil
	}
	cert, _, ok := p.clientCert(r)
	if !ok || !p.usableCert(cert) {
		return r, oerr("invalid_request", "this client requires a client certificate")
	}
	return r.WithContext(context.WithValue(r.Context(), certCtxKey{}, certThumbprint(cert))), nil
}

// mtlsBindClaims adds cnf.x5t#S256 (next to cnf.jkt when DPoP is used too).
func mtlsBindClaims(ctx context.Context, claims core.Claims) {
	t := boundThumbprint(ctx)
	if t == "" {
		return
	}
	cnf, _ := claims["cnf"].(map[string]any)
	if cnf == nil {
		cnf = map[string]any{}
	}
	cnf[x5tClaim] = t
	claims["cnf"] = cnf
}

// mtlsTokenDone makes sure the grant really bound the token it issued: a grant
// that forgot to must not hand an unbound token to a client that requires one.
func (p *Provider) mtlsTokenDone(r *http.Request, resp map[string]any) *tokenErr {
	want := boundThumbprint(r.Context())
	if want == "" {
		return nil
	}
	at, _ := resp["access_token"].(string)
	var c struct {
		Cnf map[string]any `json:"cnf"`
	}
	if parts := strings.Split(at, "."); len(parts) == 3 {
		if b, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			_ = json.Unmarshal(b, &c)
		}
	}
	if got, _ := c.Cnf[x5tClaim].(string); got != want {
		p.cfg.Logger.Error("oidc: a grant issued an access token that is not bound to the client certificate")
		return oerr("unauthorized_client", "this grant cannot issue certificate-bound tokens")
	}
	return nil
}

// certConstraintOK reports whether the request presents the certificate a
// token's cnf names. A cnf without x5t#S256 passes.
func (p *Provider) certConstraintOK(r *http.Request, cnf map[string]any) bool {
	v, has := cnf[x5tClaim]
	if !has {
		return true
	}
	want, _ := v.(string)
	cert, _, ok := p.clientCert(r)
	return ok && want != "" && subtle.ConstantTimeCompare([]byte(certThumbprint(cert)), []byte(want)) == 1
}
