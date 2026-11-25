// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writePair(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func TestTLSSettings(t *testing.T) {
	cert, key := writePair(t)
	m, tc, err := (TLSSettings{}).build()
	if err != nil || tc != nil || m.Enabled() {
		t.Fatalf("default must be plain HTTP with mTLS off: %v %v %+v", err, tc, m)
	}
	m, tc, err = TLSSettings{CertFile: cert, KeyFile: key}.build()
	if err != nil || tc == nil || m.Enabled() || tc.ClientAuth != tls.NoClientCert || tc.MinVersion != tls.VersionTLS12 {
		t.Fatalf("https only: %v %+v %+v", err, tc, m)
	}
	m, tc, err = TLSSettings{CertFile: cert, KeyFile: key, ClientCerts: "direct", ClientCAFile: cert}.build()
	if err != nil || tc.ClientAuth != tls.RequestClientCert || !m.Direct || m.Roots == nil || !m.Enabled() {
		t.Fatalf("direct: %v %+v", err, m)
	}
	m, tc, err = TLSSettings{ProxyHeader: "Client-Cert", TrustedProxies: []string{"10.0.0.1", "192.168.1.7/24", "fd00::1"}}.build()
	if err != nil || tc != nil || !m.Enabled() || m.Direct || len(m.TrustedProxies) != 3 ||
		m.TrustedProxies[0].String() != "10.0.0.1/32" || m.TrustedProxies[1].String() != "192.168.1.0/24" || m.TrustedProxies[2].String() != "fd00::1/128" {
		t.Fatalf("proxy: %v %+v", err, m)
	}
	for name, s := range map[string]TLSSettings{
		"cert without key":      {CertFile: cert},
		"key without cert":      {KeyFile: key},
		"unreadable pair":       {CertFile: cert, KeyFile: cert},
		"direct without tls":    {ClientCerts: "direct"},
		"unknown mode":          {ClientCerts: "require", CertFile: cert, KeyFile: key},
		"header without list":   {ProxyHeader: "Client-Cert"},
		"list without header":   {TrustedProxies: []string{"10.0.0.1"}},
		"trust everyone":        {ProxyHeader: "Client-Cert", TrustedProxies: []string{"0.0.0.0/0"}},
		"bad address":           {ProxyHeader: "Client-Cert", TrustedProxies: []string{"proxy.internal"}},
		"direct and header":     {CertFile: cert, KeyFile: key, ClientCerts: "direct", ProxyHeader: "Client-Cert", TrustedProxies: []string{"10.0.0.1"}},
		"ca without mtls":       {ClientCAFile: cert},
		"ca file missing":       {CertFile: cert, KeyFile: key, ClientCerts: "direct", ClientCAFile: cert + ".nope"},
		"ca file without certs": {CertFile: cert, KeyFile: key, ClientCerts: "direct", ClientCAFile: key},
	} {
		if _, _, err := s.build(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestTLSSettingsFromEnv(t *testing.T) {
	t.Setenv("HAVEN_IDP_MTLS_PROXY_HEADER", "Client-Cert")
	t.Setenv("HAVEN_IDP_MTLS_TRUSTED_PROXIES", "10.0.0.1, 10.0.0.2")
	t.Setenv("HAVEN_IDP_BASE_URL", "https://idp.example")
	c, err := configFromEnv()
	if err != nil || c.TLS.ProxyHeader != "Client-Cert" || len(c.TLS.TrustedProxies) != 2 {
		t.Fatalf("%v %+v", err, c.TLS)
	}
}
