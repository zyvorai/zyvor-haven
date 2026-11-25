// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package kubeauth makes a Kubernetes API server trust haven-idp: it renders
// the API server settings (flags or AuthenticationConfiguration), kubeadm and
// k3s snippets, a kubeconfig user using `haven exec-credential` and RBAC
// bindings for identity-server groups; it registers the public client through
// the Admin API; and it diagnoses a setup that does not work. See
// docs/kubernetes-login.md.
package kubeauth

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// Defaults.
const (
	DefaultClientID   = "kubernetes"
	DefaultPrefix     = "haven:"
	DefaultProfile    = "kubernetes"
	DefaultUserName   = "haven"
	DefaultNodeCAPath = "/etc/kubernetes/haven/oidc-ca.pem"

	// AuthnV1 is served by Kubernetes 1.34 and later, AuthnV1Beta1 by 1.30
	// and later.
	AuthnV1      = "v1"
	AuthnV1Beta1 = "v1beta1"

	// SigningAlg is what haven-idp signs with. kube-apiserver's flag default
	// is RS256 only, so --oidc-signing-algs must name it.
	SigningAlg = "ES256"

	maxCABytes = 256 << 10
)

// Username claims the generator supports.
var usernameClaims = []string{"preferred_username", "sub"}

// Options describes one cluster's trust in one realm.
type Options struct {
	Issuer         string // https://host[:port][/path]/realms/{realm}
	ClientID       string // the audience the API server accepts
	CAPEM          []byte // CA of the issuer's TLS certificate; empty = public CA
	NodeCAPath     string // where the CA lives on control-plane nodes (flags mode)
	UsernameClaim  string
	UsernamePrefix string
	GroupsPrefix   string
	AuthnVersion   string // AuthnV1 or AuthnV1Beta1

	Bindings []Binding
	// AllowClusterAdmin permits bindings to cluster-admin (off by default).
	AllowClusterAdmin bool

	// kubeconfig
	UserName    string
	Profile     string // haven credentials profile
	ClusterName string // when set, a context is emitted for this existing cluster
}

var (
	clientIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$`)
	prefixRE   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,62}:$`)
	profileRE  = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	kubeNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,252}$`)
	nodePathRE = regexp.MustCompile(`^/[A-Za-z0-9._/-]{1,255}$`)
)

// ValidatePrefix refuses a username or groups prefix that would let a name
// from the identity server collide with Kubernetes' own: it must be
// non-empty, end in ":" and not start with "system" (so that no suffix can
// complete it to "system:...").
func ValidatePrefix(p string) error {
	if !prefixRE.MatchString(p) {
		return fmt.Errorf("prefix %q must be 2 to 64 letters, digits, '.', '_', '/', '-' or ':', start with a letter or digit and end with ':' (an empty prefix is refused)", p)
	}
	if strings.HasPrefix(strings.ToLower(p), "system") {
		return fmt.Errorf("prefix %q is refused: names starting with \"system:\" are reserved by Kubernetes", p)
	}
	return nil
}

// ValidateIssuer checks an issuer URL as the API server will: https, no query,
// fragment or user info. haven-idp's issuer has no trailing slash and the
// comparison with the token's `iss` is exact, so one is refused too.
func ValidateIssuer(s string) (*url.URL, error) {
	if s == "" {
		return nil, errors.New("the issuer URL is required")
	}
	if len(s) > 1024 || strings.IndexFunc(s, func(r rune) bool { return r <= ' ' || r > '~' || strings.ContainsRune(`"'\<>`+"`", r) }) >= 0 {
		return nil, errors.New("the issuer URL has spaces, quotes or non-ASCII characters")
	}
	u, err := url.Parse(s)
	if err != nil {
		return nil, errors.New("the issuer URL cannot be parsed")
	}
	switch {
	case u.Scheme != "https":
		return nil, errors.New("the issuer must be an https URL: kube-apiserver refuses anything else (put TLS in front of haven-idp and set HAVEN_IDP_BASE_URL to the https address)")
	case u.Host == "" || u.Opaque != "":
		return nil, errors.New("the issuer URL has no host")
	case u.User != nil:
		return nil, errors.New("the issuer URL must not contain user information")
	case u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#"):
		return nil, errors.New("the issuer URL must not contain a query or fragment")
	case strings.HasSuffix(s, "/"):
		return nil, errors.New("the issuer URL must not end in '/': it has to equal the token's iss claim exactly")
	}
	return u, nil
}

// LoopbackHost reports whether the host name only reaches the machine it is
// used on.
func LoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ParseCA returns the certificates of a PEM file, re-encoded. Anything that is
// not a certificate (a private key in a combined file, say) is an error, so it
// cannot end up in a generated configuration.
func ParseCA(b []byte) (certs []*x509.Certificate, canonical []byte, err error) {
	if len(b) > maxCABytes {
		return nil, nil, errors.New("CA file: larger than 256 KiB")
	}
	rest := b
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("CA file: contains a %q block; give only the CA certificate(s), never a key", printable(blk.Type, 40))
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return nil, nil, errors.New("CA file: invalid certificate")
		}
		certs = append(certs, c)
		canonical = append(canonical, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: blk.Bytes})...)
	}
	if len(certs) == 0 {
		return nil, nil, errors.New("CA file: no PEM certificate found")
	}
	return certs, canonical, nil
}

// Normalize applies defaults and validates o. Every rendering function
// requires a normalized value.
func (o Options) Normalize() (Options, error) {
	def := func(p *string, v string) {
		if *p == "" {
			*p = v
		}
	}
	def(&o.ClientID, DefaultClientID)
	def(&o.UsernameClaim, usernameClaims[0])
	def(&o.AuthnVersion, AuthnV1)
	def(&o.UserName, DefaultUserName)
	def(&o.Profile, DefaultProfile)
	def(&o.NodeCAPath, DefaultNodeCAPath)
	// The prefixes have no "unset means none": an empty prefix becomes the default.
	def(&o.UsernamePrefix, DefaultPrefix)
	def(&o.GroupsPrefix, DefaultPrefix)

	if _, err := ValidateIssuer(o.Issuer); err != nil {
		return o, err
	}
	if !clientIDRE.MatchString(o.ClientID) {
		return o, fmt.Errorf("invalid client id %q", o.ClientID)
	}
	if o.UsernameClaim != "preferred_username" && o.UsernameClaim != "sub" {
		return o, fmt.Errorf("username claim must be one of %s, got %q", strings.Join(usernameClaims, ", "), o.UsernameClaim)
	}
	if err := ValidatePrefix(o.UsernamePrefix); err != nil {
		return o, fmt.Errorf("username %w", err)
	}
	if err := ValidatePrefix(o.GroupsPrefix); err != nil {
		return o, fmt.Errorf("groups %w", err)
	}
	if o.AuthnVersion != AuthnV1 && o.AuthnVersion != AuthnV1Beta1 {
		return o, fmt.Errorf("AuthenticationConfiguration version must be v1 or v1beta1, got %q", o.AuthnVersion)
	}
	if !profileRE.MatchString(o.Profile) {
		return o, fmt.Errorf("invalid profile name %q", o.Profile)
	}
	if !kubeNameRE.MatchString(o.UserName) {
		return o, fmt.Errorf("invalid kubeconfig user name %q", o.UserName)
	}
	if o.ClusterName != "" && !kubeNameRE.MatchString(o.ClusterName) {
		return o, fmt.Errorf("invalid cluster name %q", o.ClusterName)
	}
	if !nodePathRE.MatchString(o.NodeCAPath) {
		return o, fmt.Errorf("the CA path on the node must be a plain absolute path, got %q", o.NodeCAPath)
	}
	if len(o.CAPEM) > 0 {
		_, canon, err := ParseCA(o.CAPEM)
		if err != nil {
			return o, err
		}
		o.CAPEM = canon
	}
	seen := map[string]bool{}
	for _, b := range o.Bindings {
		// Bindings built by hand get the same refusals as parsed ones.
		if err := b.validate(o.AllowClusterAdmin); err != nil {
			return o, err
		}
		if seen[b.key()] {
			return o, fmt.Errorf("binding %s is given twice", b.describe())
		}
		seen[b.key()] = true
	}
	return o, nil
}

// printable strips control and format characters from text that came from a
// file or a server, and bounds its length.
func printable(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > n {
		s = string(r[:n]) + "..."
	}
	return s
}
