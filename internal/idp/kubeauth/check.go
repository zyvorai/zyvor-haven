// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package kubeauth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/zyvorai/haven/internal/havencli"
	"github.com/zyvorai/haven/internal/idp/core"
)

// Result states. Only StateFail makes a report fail.
const (
	StateOK   = "ok"
	StateWarn = "warn"
	StateFail = "fail"
	StateSkip = "skip"
)

const (
	maxDoc        = 1 << 20
	maxTokenBytes = 64 << 10
	certSoon      = 14 * 24 * time.Hour
)

// Result is one check.
type Result struct {
	Check   string `json:"check"`
	State   string `json:"state"`
	Message string `json:"message"`
	Fix     string `json:"fix,omitempty"`
}

// Identity is who the API server would see for the sample token.
type Identity struct {
	Username string   `json:"username"`
	Groups   []string `json:"groups"`
}

// Report is the outcome of Check. It never contains the token.
type Report struct {
	OK       bool      `json:"ok"`
	Results  []Result  `json:"results"`
	Identity *Identity `json:"identity,omitempty"`
}

func (r *Report) add(check, state, msg, fix string) {
	r.Results = append(r.Results, Result{check, state, msg, fix})
}
func (r *Report) ok(check, msg string)        { r.add(check, StateOK, msg, "") }
func (r *Report) warn(check, msg, fix string) { r.add(check, StateWarn, msg, fix) }
func (r *Report) fail(check, msg, fix string) { r.add(check, StateFail, msg, fix) }
func (r *Report) skip(check, msg, fix string) { r.add(check, StateSkip, msg, fix) }
func (r *Report) finish() Report {
	r.OK = !slices.ContainsFunc(r.Results, func(x Result) bool { return x.State == StateFail })
	return *r
}

// CheckInput is what Check examines. Options needs the issuer; the claim,
// prefix and client settings default as in Normalize.
type CheckInput struct {
	Options
	Token         string   // sample ID token; empty = token checks are skipped
	RequireGroups []string // haven-idp groups the token must carry
	Timeout       time.Duration
	Now           func() time.Time
}

type discoveryDoc struct {
	Issuer         string   `json:"issuer"`
	JWKSURI        string   `json:"jwks_uri"`
	DeviceEndpoint string   `json:"device_authorization_endpoint"`
	Algs           []string `json:"id_token_signing_alg_values_supported"`
	Scopes         []string `json:"scopes_supported"`
}

// Check verifies, from this machine, what the API server needs: an https
// issuer with a certificate the given CA (or the system roots) vouches for, a
// matching discovery document, usable keys, and, given a sample token, that
// the API server would accept it and see the expected user and groups. The
// token is never sent anywhere.
func Check(ctx context.Context, in CheckInput) (Report, error) {
	in.Bindings = nil
	o, err := in.Normalize()
	rep := &Report{}
	if err != nil {
		// An unusable issuer is a finding; other bad settings are usage errors.
		if _, ierr := ValidateIssuer(in.Issuer); ierr != nil {
			rep.fail("issuer-url", ierr.Error(), "use the https issuer exactly as in the discovery document: https://HOST/realms/REALM")
			return rep.finish(), nil
		}
		return Report{}, err
	}
	if in.Now == nil {
		in.Now = time.Now
	}
	if in.Timeout <= 0 {
		in.Timeout = 15 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, in.Timeout)
	defer cancel()
	u, _ := url.Parse(o.Issuer) // validated above
	if LoopbackHost(u.Hostname()) {
		rep.warn("issuer-url", "the issuer is a loopback address: only an API server on this same host can reach it", "use a name every control-plane node resolves to haven-idp")
	} else {
		rep.ok("issuer-url", "https issuer")
	}

	var roots *x509.CertPool // nil = system roots
	if len(o.CAPEM) > 0 {
		// Like the API server: a configured CA REPLACES the system roots.
		certs, _, err := ParseCA(o.CAPEM)
		if err != nil {
			return Report{}, err
		}
		roots = x509.NewCertPool()
		for _, c := range certs {
			roots.AddCert(c)
		}
	}
	tr := &http.Transport{
		Proxy:           http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
	}
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	disco, jwks := checkEndpoints(ctx, rep, hc, o, in.Now())
	if disco != nil {
		if slices.Contains(disco.Scopes, core.GroupsScope) {
			rep.ok("groups-scope", "the issuer offers the groups scope")
		} else {
			rep.warn("groups-scope", "the discovery document does not list the groups scope: no client of this realm is opted in to the groups claim",
				"set HAVEN_IDP_GROUPS_CLAIM_CLIENTS="+realmOfIssuer(o.Issuer)+"/"+o.ClientID+" on haven-idp and restart it")
		}
		if disco.DeviceEndpoint == "" {
			rep.warn("device-endpoint", "no device_authorization_endpoint: `haven login` cannot work against this issuer", "")
		}
	}
	if in.Token == "" {
		rep.skip("token", "no sample token given", fmt.Sprintf("haven token --id-token --profile %s | haven-idp kube-config check --issuer %s --client-id %s --token-file -", o.Profile, o.Issuer, o.ClientID))
		return rep.finish(), nil
	}
	checkToken(rep, o, in, jwks)
	return rep.finish(), nil
}

// RealmFromIssuer returns the realm of a haven-idp issuer (BASE/realms/R) and
// the base URL.
func RealmFromIssuer(issuer string) (base, realm string, ok bool) {
	i := strings.LastIndex(issuer, "/realms/")
	if i < 0 {
		return "", "", false
	}
	base, realm = issuer[:i], issuer[i+len("/realms/"):]
	if realm == "" || strings.Contains(realm, "/") {
		return "", "", false
	}
	return base, realm, true
}

func realmOfIssuer(issuer string) string {
	if _, r, ok := RealmFromIssuer(issuer); ok {
		return r
	}
	return "REALM"
}

func checkEndpoints(ctx context.Context, rep *Report, hc *http.Client, o Options, now time.Time) (*discoveryDoc, []byte) {
	durl := o.Issuer + "/.well-known/openid-configuration"
	status, body, state, err := get(ctx, hc, durl)
	if err != nil {
		msg, fix := explainNet(err, len(o.CAPEM) > 0)
		rep.fail("connect", msg, fix)
		return nil, nil
	}
	if state != nil && len(state.PeerCertificates) > 0 {
		left := state.PeerCertificates[0].NotAfter.Sub(now)
		if left < certSoon {
			rep.warn("tls", fmt.Sprintf("the TLS certificate expires on %s", state.PeerCertificates[0].NotAfter.UTC().Format("2006-01-02")), "renew it; API server logins stop when it expires")
		} else if len(o.CAPEM) > 0 {
			rep.ok("tls", "the certificate chains to the given CA")
		} else {
			rep.ok("tls", "the certificate chains to this machine's system roots (the control-plane nodes must trust it too, else pass --ca-file)")
		}
	}
	switch {
	case status >= 300 && status < 400:
		rep.fail("discovery", fmt.Sprintf("the discovery URL redirects (HTTP %d)", status), "use the issuer URL that serves the document directly")
		return nil, nil
	case status == http.StatusNotFound:
		rep.fail("discovery", "HTTP 404 for "+durl, "check the realm name (and that the realm is enabled) and any path prefix of the proxy")
		return nil, nil
	case status != http.StatusOK:
		rep.fail("discovery", fmt.Sprintf("HTTP %d for %s", status, durl), "check haven-idp and the proxy in front of it")
		return nil, nil
	}
	var d discoveryDoc
	if err := json.Unmarshal(body, &d); err != nil {
		rep.fail("discovery", "the discovery document is not valid JSON", "check that a proxy is not answering with its own page")
		return nil, nil
	}
	if d.Issuer != o.Issuer {
		rep.fail("discovery", fmt.Sprintf("the document says the issuer is %q, not %q; the API server requires an exact match", printable(d.Issuer, 200), o.Issuer),
			"set HAVEN_IDP_BASE_URL to the public https URL, or use the printed issuer")
		return nil, nil
	}
	rep.ok("discovery", "discovery document served and its issuer matches")
	if slices.Contains(d.Algs, SigningAlg) {
		rep.ok("algorithms", "ID tokens are signed with ES256 (the flags need --oidc-signing-algs=ES256)")
	} else {
		rep.fail("algorithms", "the issuer does not advertise ES256", "this tool generates settings for haven-idp, which signs with ES256")
	}
	ju, err := url.Parse(d.JWKSURI)
	if err != nil || ju.Scheme != "https" || ju.Host == "" {
		rep.fail("jwks", "jwks_uri is missing or not https", "fix HAVEN_IDP_BASE_URL")
		return &d, nil
	}
	status, jwks, _, err := get(ctx, hc, d.JWKSURI)
	if err != nil {
		msg, fix := explainNet(err, len(o.CAPEM) > 0)
		rep.fail("jwks", msg, fix)
		return &d, nil
	}
	var set struct {
		Keys []struct {
			Kty string `json:"kty"`
		} `json:"keys"`
	}
	if status != http.StatusOK || json.Unmarshal(jwks, &set) != nil || len(set.Keys) == 0 {
		rep.fail("jwks", fmt.Sprintf("no usable key set at jwks_uri (HTTP %d)", status), "check haven-idp's logs")
		return &d, nil
	}
	rep.ok("jwks", fmt.Sprintf("%d signing key(s)", len(set.Keys)))
	return &d, jwks
}

func get(ctx context.Context, hc *http.Client, u string) (int, []byte, *tls.ConnectionState, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := hc.Do(req) // #nosec G704 -- the operator names the issuer to examine; GET only, no credentials
	if err != nil {
		return 0, nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxDoc+1))
	if err != nil {
		return 0, nil, nil, err
	}
	if len(b) > maxDoc {
		return 0, nil, nil, errors.New("response larger than 1 MiB")
	}
	return resp.StatusCode, b, resp.TLS, nil
}

// explainNet turns a transport error into a message and a remedy.
func explainNet(err error, haveCA bool) (string, string) {
	var (
		unknown x509.UnknownAuthorityError
		host    x509.HostnameError
		invalid x509.CertificateInvalidError
		dns     *net.DNSError
		record  tls.RecordHeaderError
		verify  *tls.CertificateVerificationError
		ne      net.Error
	)
	text := printable(err.Error(), 300)
	switch {
	case errors.As(err, &host):
		return "TLS: the certificate is not valid for this host name: " + text, "issue a certificate whose subject alternative names include the issuer host"
	case errors.As(err, &invalid) && invalid.Reason == x509.Expired:
		return "TLS: the certificate is expired or not yet valid: " + text, "renew the certificate and check the clocks"
	case errors.As(err, &unknown) && haveCA:
		return "TLS: the certificate is not signed by the CA in --ca-file: " + text, "pass the CA that actually signed the server certificate (the file replaces the system roots, as in the API server); serve intermediates with the certificate"
	case !haveCA && (errors.As(err, &unknown) || errors.As(err, &verify)):
		// Platform verifiers (macOS) report their own error types here.
		return "TLS: the certificate is not trusted by this machine's system roots: " + text, "pass the issuing CA with --ca-file; the API server needs the same (certificateAuthority or --oidc-ca-file)"
	case errors.As(err, &verify), errors.As(err, &invalid):
		return "TLS: certificate verification failed: " + text, "fix the certificate chain of the issuer"
	case errors.As(err, &record):
		return "TLS: the server does not speak TLS on this port", "terminate TLS in front of haven-idp and use that address"
	case errors.As(err, &dns):
		return "DNS: cannot resolve the issuer host: " + text, "create the DNS record; control-plane nodes must resolve it too"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused: " + text, "check that haven-idp (or its proxy) listens on that port and the firewall allows it"
	case errors.Is(err, context.DeadlineExceeded), errors.As(err, &ne) && ne.Timeout():
		return "timed out reaching the issuer: " + text, "check routing and firewalls between this host and haven-idp"
	}
	return "cannot reach the issuer: " + text, "check the URL, the network and any HTTPS_PROXY setting"
}

func checkToken(rep *Report, o Options, in CheckInput, jwks []byte) {
	tok := strings.TrimSpace(in.Token)
	if len(tok) > maxTokenBytes {
		rep.fail("token", "the sample token is larger than 64 KiB", "pass one ID token")
		return
	}
	hdr, c, err := havencli.DecodeJWT(tok)
	if err != nil {
		rep.fail("token", "the sample is not a JWT: "+err.Error(), "pass the raw ID token: haven token --id-token")
		return
	}
	str := func(m map[string]any, k string) string { s, _ := m[k].(string); return s }

	switch alg := str(hdr, "alg"); {
	case alg != SigningAlg && alg != "RS256":
		rep.fail("token-signature", fmt.Sprintf("unsupported signing algorithm %q", printable(alg, 16)), "use an ID token issued by haven-idp")
	case jwks == nil:
		rep.fail("token-signature", "the signature could not be checked: the issuer's keys were not fetched", "fix the connection findings above")
	default:
		if _, err := havencli.VerifyJWT(tok, jwks); err != nil {
			rep.fail("token-signature", err.Error(), "the token is from another issuer or realm, was altered, or was signed with a removed key: sign in again")
		} else if alg != SigningAlg {
			rep.warn("token-signature", "signed with "+alg+": the generated flags allow only ES256", "")
		} else {
			rep.ok("token-signature", "the signature verifies against the issuer's keys")
		}
	}

	if iss := str(c, "iss"); iss == o.Issuer {
		rep.ok("token-issuer", "iss matches")
	} else {
		rep.fail("token-issuer", fmt.Sprintf("iss is %q, expected %q", printable(iss, 200), o.Issuer), "sign in against this exact issuer")
	}

	var auds []string
	switch a := c["aud"].(type) {
	case string:
		auds = []string{a}
	case []any:
		for _, v := range a {
			if s, ok := v.(string); ok {
				auds = append(auds, s)
			}
		}
	}
	if slices.Contains(auds, o.ClientID) {
		rep.ok("token-audience", "aud contains "+o.ClientID)
	} else {
		rep.fail("token-audience", fmt.Sprintf("aud is %q, which does not contain %q: the token was issued to another client", printable(strings.Join(auds, " "), 200), o.ClientID),
			"sign in with --client-id "+o.ClientID+", or generate the settings for the client you use")
	}

	if typ := str(c, "typ"); typ == "ID" {
		rep.ok("token-type", "it is an ID token")
	} else {
		rep.fail("token-type", fmt.Sprintf("typ is %q: this is not an ID token and the generated settings refuse it", printable(typ, 32)), "use the ID token (haven token --id-token), not the access token")
	}

	now := in.Now()
	num := func(k string) (time.Time, bool) {
		f, ok := c[k].(float64)
		if !ok || f <= 0 || f > 1e12 {
			return time.Time{}, false
		}
		return time.Unix(int64(f), 0), true
	}
	switch exp, ok := num("exp"); {
	case !ok:
		rep.fail("token-time", "no usable exp claim", "use an ID token issued by haven-idp")
	case !now.Before(exp):
		rep.fail("token-time", "expired at "+exp.UTC().Format(time.RFC3339), "get a fresh token (haven token --id-token); if it was just issued, check the clocks")
	default:
		if nbf, ok := num("nbf"); ok && now.Before(nbf) {
			rep.fail("token-time", "not valid before "+nbf.UTC().Format(time.RFC3339), "check the clocks")
		} else if iat, ok := num("iat"); ok && iat.After(now.Add(time.Minute)) {
			rep.warn("token-time", "issued in the future: the clock here or on haven-idp is wrong", "synchronise clocks (NTP)")
		} else {
			rep.ok("token-time", "valid until "+exp.UTC().Format(time.RFC3339))
		}
	}

	id := &Identity{Groups: []string{}}
	if name := str(c, o.UsernameClaim); name == "" {
		rep.fail("username", fmt.Sprintf("no %q claim", o.UsernameClaim), "a service token cannot be used; sign in as a user, or choose --username-claim sub")
	} else {
		id.Username = o.UsernamePrefix + printable(name, 256)
		rep.ok("username", "the API server would see user "+id.Username)
	}

	raw, present := c[core.GroupsScope]
	var groups []string
	valid := true
	switch g := raw.(type) {
	case string:
		groups = []string{g}
	case []any:
		for _, v := range g {
			s, ok := v.(string)
			valid = valid && ok
			groups = append(groups, s)
		}
	default:
		valid = false
	}
	realm := realmOfIssuer(o.Issuer)
	switch {
	case !present:
		rep.fail("groups", "the token has no groups claim, so no group binding applies",
			fmt.Sprintf("both are needed: (1) haven-idp runs with HAVEN_IDP_GROUPS_CLAIM_CLIENTS containing %s/%s; (2) the login asked for the scope: %s. Then sign in again", realm, o.ClientID, o.LoginCommand()))
		for _, want := range in.RequireGroups {
			rep.fail("require-group", "missing group "+printable(want, 200), "")
		}
	case !valid:
		rep.fail("groups", "the groups claim is not a string or a list of strings", "use an ID token issued by haven-idp")
	default:
		bad := false
		for _, g := range groups {
			if strings.HasPrefix(strings.ToLower(g), core.ReservedGroupPrefix) {
				bad = true
				rep.fail("groups", fmt.Sprintf("the claim contains the reserved group %q", printable(g, 200)), "haven-idp never emits system: groups; this token is not from it, or something rewrote it")
				continue
			}
			id.Groups = append(id.Groups, o.GroupsPrefix+printable(g, 256))
		}
		switch {
		case bad:
		case len(groups) == 0:
			rep.warn("groups", "the groups claim is empty: the user is in no group", "add the user to a group in haven-idp, then sign in again or wait for the token to refresh")
		default:
			rep.ok("groups", "the API server would see groups "+strings.Join(id.Groups, ", "))
		}
		for _, want := range in.RequireGroups {
			v := strings.TrimPrefix(strings.TrimPrefix(want, o.GroupsPrefix), "/")
			if slices.Contains(groups, v) {
				rep.ok("require-group", "in group "+printable(v, 200))
			} else {
				rep.fail("require-group", "missing group "+printable(v, 200), "add the user to it in haven-idp (the name is the group path without the leading '/'), then get a fresh token")
			}
		}
	}
	rep.Identity = id
}
