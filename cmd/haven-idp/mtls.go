// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/netip"
	"os"

	"github.com/zyvorai/haven/internal/idp/oidc"
)

// TLSSettings configures TLS termination and where client certificates come
// from (docs/client-authentication.md). All empty = plain HTTP and mutual TLS
// off, as before.
type TLSSettings struct {
	CertFile, KeyFile string   // serve HTTPS with this certificate
	ClientCerts       string   // "direct": ask TLS clients for a certificate
	ProxyHeader       string   // header a trusted proxy puts the client certificate in
	TrustedProxies    []string // addresses or CIDRs the header is accepted from
	ClientCAFile      string   // trust anchors of tls_client_auth
}

func tlsSettingsFromEnv() TLSSettings {
	return TLSSettings{
		CertFile:       os.Getenv("HAVEN_IDP_TLS_CERT_FILE"),
		KeyFile:        os.Getenv("HAVEN_IDP_TLS_KEY_FILE"),
		ClientCerts:    os.Getenv("HAVEN_IDP_MTLS"),
		ProxyHeader:    os.Getenv("HAVEN_IDP_MTLS_PROXY_HEADER"),
		TrustedProxies: splitList(os.Getenv("HAVEN_IDP_MTLS_TRUSTED_PROXIES")),
		ClientCAFile:   os.Getenv("HAVEN_IDP_MTLS_CA_FILE"),
	}
}

// build turns the settings into the provider's mTLS configuration and the
// listener's TLS configuration (nil = plain HTTP). A half or contradictory
// configuration is an error: the server refuses to start rather than running
// with something weaker than asked for.
func (s TLSSettings) build() (oidc.MTLSConfig, *tls.Config, error) {
	var m oidc.MTLSConfig
	var tc *tls.Config
	if (s.CertFile == "") != (s.KeyFile == "") {
		return m, nil, errors.New("set both HAVEN_IDP_TLS_CERT_FILE and HAVEN_IDP_TLS_KEY_FILE, or neither")
	}
	if s.CertFile != "" {
		pair, err := tls.LoadX509KeyPair(s.CertFile, s.KeyFile) // #nosec G304 -- operator-provided paths
		if err != nil {
			return m, nil, fmt.Errorf("load TLS certificate: %w", err)
		}
		tc = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
	}
	switch s.ClientCerts {
	case "":
	case "direct":
		if tc == nil {
			return m, nil, errors.New("HAVEN_IDP_MTLS=direct needs HAVEN_IDP_TLS_CERT_FILE and HAVEN_IDP_TLS_KEY_FILE")
		}
		m.Direct = true
		// Ask for a certificate without requiring or chain-checking it here:
		// the handshake proves possession of its key, and the provider checks
		// it per client (registered certificate, or the configured CAs).
		tc.ClientAuth = tls.RequestClientCert
	default:
		return m, nil, errors.New(`HAVEN_IDP_MTLS must be empty or "direct" (for a proxy set HAVEN_IDP_MTLS_PROXY_HEADER)`)
	}
	m.ProxyHeader = s.ProxyHeader
	for _, v := range s.TrustedProxies {
		pf, err := netip.ParsePrefix(v)
		if err != nil {
			a, aerr := netip.ParseAddr(v)
			if aerr != nil {
				return m, nil, fmt.Errorf("HAVEN_IDP_MTLS_TRUSTED_PROXIES: %q is not an address or CIDR", v)
			}
			pf = netip.PrefixFrom(a, a.BitLen())
		}
		m.TrustedProxies = append(m.TrustedProxies, pf.Masked())
	}
	if err := m.Validate(); err != nil {
		return m, nil, err
	}
	if s.ClientCAFile != "" {
		if !m.Enabled() {
			return m, nil, errors.New("HAVEN_IDP_MTLS_CA_FILE is set but mutual TLS is off (set HAVEN_IDP_MTLS=direct or HAVEN_IDP_MTLS_PROXY_HEADER)")
		}
		b, err := os.ReadFile(s.ClientCAFile) // #nosec G304 G703 -- operator-provided path
		if err != nil {
			return m, nil, fmt.Errorf("read client CA file: %w", err)
		}
		m.Roots = x509.NewCertPool()
		if !m.Roots.AppendCertsFromPEM(b) {
			return m, nil, errors.New("HAVEN_IDP_MTLS_CA_FILE holds no certificate")
		}
	}
	return m, tc, nil
}
