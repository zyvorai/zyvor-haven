// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

// `haven-idp kube-config generate|check` (docs/kubernetes-login.md). It lives
// in haven-idp, the operator's tool, because it writes control-plane settings
// and uses the Admin API; the user's `haven` CLI only logs in and answers
// kubectl.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/zyvorai/haven/internal/idp/kubeauth"
	"github.com/zyvorai/haven/internal/idp/native"
)

const kubeUsage = `haven-idp kube-config: make a Kubernetes API server trust a haven-idp realm

Usage:
  haven-idp kube-config generate --issuer https://idp.example.com/realms/R [options]
  haven-idp kube-config check    --issuer https://idp.example.com/realms/R [options]

Both:
  --issuer URL            the realm's https issuer (required)
  --client-id ID          client id the API server accepts (default kubernetes)
  --ca-file PEM           CA of the issuer's certificate (replaces the system roots)
  --username-claim C      preferred_username (default) or sub
  --username-prefix P     default haven:
  --groups-prefix P       default haven:

generate:
  --bind GROUP=ROLE[@NS]  bind a haven-idp group to a ClusterRole (repeatable); with @NS a
                          RoleBinding; GROUP=role/NAME@NS binds a namespaced Role
  --allow-cluster-admin   allow binding cluster-admin
  --authn-api-version V   v1 (Kubernetes 1.34+, default) or v1beta1 (1.30+)
  --only SECTION          flags, authn, kubeadm, k3s, kubeconfig or rbac
  --out-dir DIR           write one file per section instead of printing (--force overwrites)
  --profile NAME          haven credentials profile in the kubeconfig (default kubernetes)
  --user-name NAME        kubeconfig user name (default haven)
  --cluster NAME          also emit a kubeconfig context for this cluster entry
  --node-ca-path PATH     CA path on control-plane nodes for --oidc-ca-file
  --ensure-client         create the public client through the Admin API (idempotent)
  --redirect URI          with --ensure-client: also allow authorization code + PKCE (repeatable)
  --update-client         with --ensure-client: add what an existing public client is missing
  --url URL               haven-idp base URL for the Admin API (default: from --issuer)
  --admin-realm R         realm of the admin client (HAVEN_IDP_ADMIN_REALM)
  --admin-client-id ID    admin client id (default haven-admin); secret from
                          HAVEN_IDP_ADMIN_CLIENT_SECRET or ..._SECRET_FILE
  --env-file FILE         load unset variables from this file

check:
  --token-file FILE|-     a sample ID token (or ExecCredential JSON); never a flag value
  --require-group G       the token must carry this group (repeatable)
  --format text|json
  --timeout 15s

Exit codes: 0 ok, 1 failed, 2 usage.
`

const exitUsage = 2

// kubeAdmin opens the Admin API with an optional private CA; tests replace it.
var kubeAdmin = func(c connInfo, caPEM []byte) (kubeauth.ClientAPI, error) {
	h := &http.Client{Timeout: 30 * time.Second,
		// The admin client secret and token must never follow a redirect.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if len(caPEM) > 0 {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("CA file: no certificate found")
		}
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		h.Transport = tr
	}
	return native.New(native.Config{BaseURL: c.URL, Realm: c.AdminRealm, ClientID: c.ClientID, ClientSecret: c.Secret, HTTP: h}), nil
}

func cmdKubeConfig(args []string, io_ cfgIO) int {
	sub := ""
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	var (
		code int
		err  error
	)
	switch sub {
	case "generate":
		code, err = runKubeGenerate(args, io_)
	case "check":
		code, err = runKubeCheck(args, io_)
	case "help", "-h", "--help":
		_, _ = fmt.Fprint(io_.Stdout, kubeUsage)
		return exitOK
	default:
		_, _ = fmt.Fprint(io_.Stderr, kubeUsage)
		return exitUsage
	}
	if errors.Is(err, flag.ErrHelp) {
		_, _ = fmt.Fprint(io_.Stdout, kubeUsage)
		return exitOK
	}
	if err != nil {
		_, _ = fmt.Fprintln(io_.Stderr, "haven-idp:", err)
	}
	return code
}

type kubeCommon struct {
	opts   kubeauth.Options
	caFile string
}

func (c *kubeCommon) bind(fs *flag.FlagSet) {
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.opts.Issuer, "issuer", "", "")
	fs.StringVar(&c.opts.ClientID, "client-id", kubeauth.DefaultClientID, "")
	fs.StringVar(&c.caFile, "ca-file", "", "")
	fs.StringVar(&c.opts.UsernameClaim, "username-claim", "preferred_username", "")
	fs.StringVar(&c.opts.UsernamePrefix, "username-prefix", kubeauth.DefaultPrefix, "")
	fs.StringVar(&c.opts.GroupsPrefix, "groups-prefix", kubeauth.DefaultPrefix, "")
}

// parse parses flags and loads the CA. An explicitly empty value is an error:
// it must not silently become a default (an empty prefix would suggest "none").
func (c *kubeCommon) parse(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return fmt.Errorf("%w (see haven-idp kube-config help)", err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	var empty string
	fs.Visit(func(f *flag.Flag) {
		if f.Value.String() == "" {
			empty = f.Name
		}
	})
	if empty != "" {
		return fmt.Errorf("--%s must not be empty", empty)
	}
	if c.opts.Issuer == "" {
		return errors.New("--issuer is required")
	}
	if c.caFile != "" {
		b, err := readBounded(c.caFile, 256<<10)
		if err != nil {
			return fmt.Errorf("--ca-file: %w", err)
		}
		if _, c.opts.CAPEM, err = kubeauth.ParseCA(b); err != nil {
			return err
		}
	}
	return nil
}

func readBounded(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) // #nosec G304 -- operator-provided path
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, limit)
	}
	return b, nil
}

func runKubeGenerate(args []string, io_ cfgIO) (int, error) {
	var (
		c                                      kubeCommon
		binds, redirects                       multiFlag
		allowAdmin, ensure, update, force      bool
		only, outDir                           string
		adminURL, adminRealm, adminID, envFile string
	)
	fs := flag.NewFlagSet("kube-config generate", flag.ContinueOnError)
	c.bind(fs)
	fs.Var(&binds, "bind", "")
	fs.BoolVar(&allowAdmin, "allow-cluster-admin", false, "")
	fs.StringVar(&c.opts.AuthnVersion, "authn-api-version", kubeauth.AuthnV1, "")
	fs.StringVar(&only, "only", "", "")
	fs.StringVar(&outDir, "out-dir", "", "")
	fs.BoolVar(&force, "force", false, "")
	fs.StringVar(&c.opts.Profile, "profile", kubeauth.DefaultProfile, "")
	fs.StringVar(&c.opts.UserName, "user-name", kubeauth.DefaultUserName, "")
	fs.StringVar(&c.opts.ClusterName, "cluster", "", "")
	fs.StringVar(&c.opts.NodeCAPath, "node-ca-path", kubeauth.DefaultNodeCAPath, "")
	fs.BoolVar(&ensure, "ensure-client", false, "")
	fs.Var(&redirects, "redirect", "")
	fs.BoolVar(&update, "update-client", false, "")
	fs.StringVar(&adminURL, "url", "", "")
	fs.StringVar(&adminRealm, "admin-realm", "", "")
	fs.StringVar(&adminID, "admin-client-id", "", "")
	fs.StringVar(&envFile, "env-file", "", "")
	if err := c.parse(fs, args); err != nil {
		return exitUsage, err
	}
	if !ensure && (len(redirects) > 0 || update || adminURL != "" || adminRealm != "" || adminID != "" || envFile != "") {
		return exitUsage, errors.New("--redirect, --update-client, --url, --admin-realm, --admin-client-id and --env-file only apply with --ensure-client")
	}
	if only != "" && outDir != "" {
		return exitUsage, errors.New("--only and --out-dir cannot be combined")
	}
	c.opts.AllowClusterAdmin = allowAdmin
	for _, s := range binds {
		// A group typed with the prefix would be bound as "haven:haven:...".
		if g := strings.TrimPrefix(s, "/"); strings.HasPrefix(g, c.opts.GroupsPrefix) {
			return exitError, fmt.Errorf("binding %q: give the haven-idp group without the %q prefix; it is added for you", s, c.opts.GroupsPrefix)
		}
		b, err := kubeauth.ParseBinding(s, allowAdmin)
		if err != nil {
			return exitError, err
		}
		c.opts.Bindings = append(c.opts.Bindings, b)
	}
	opts, err := c.opts.Normalize()
	if err != nil {
		return exitError, err
	}
	sections, err := kubeauth.Sections(opts)
	if err != nil {
		return exitError, err
	}
	if only != "" {
		i := slices.IndexFunc(sections, func(s kubeauth.Section) bool { return s.Name == only })
		if i < 0 {
			return exitUsage, fmt.Errorf("--only must be flags, authn, kubeadm, k3s, kubeconfig or rbac, got %q", only)
		}
		sections = sections[i : i+1]
	}

	note := func(format string, a ...any) { _, _ = fmt.Fprintf(io_.Stderr, format+"\n", a...) }
	base, realm, isRealm := kubeauth.RealmFromIssuer(opts.Issuer)
	if ensure {
		if !isRealm {
			return exitError, errors.New("--ensure-client needs a haven-idp issuer (.../realms/REALM)")
		}
		res, err := ensureKubeClient(opts, realm, base, cfgFlags{url: adminURL, adminRealm: adminRealm, clientID: adminID, envFile: envFile},
			kubeauth.ClientSpec{ClientID: opts.ClientID, Redirects: redirects, Update: update})
		if err != nil {
			return exitError, err
		}
		note("Client %q in realm %q: %s.", opts.ClientID, realm, res.Action)
		for _, ch := range res.Changes {
			note("  changed: %s", ch)
		}
		for _, w := range res.Warnings {
			note("WARNING: %s", w)
		}
	}

	if outDir != "" {
		files := sections
		if len(opts.CAPEM) > 0 {
			files = append(slices.Clone(files), kubeauth.Section{File: "oidc-ca.pem", Body: string(opts.CAPEM)})
		}
		if err := writeSections(outDir, files, force); err != nil {
			return exitError, err
		}
		for _, s := range files {
			note("wrote %s", filepath.Join(outDir, s.File))
		}
	} else {
		for i, s := range sections {
			if only == "" {
				if i > 0 {
					_, _ = fmt.Fprintln(io_.Stdout)
				}
				_, _ = fmt.Fprintf(io_.Stdout, "# ===== %s =====\n", s.Title)
			}
			if _, err := io.WriteString(io_.Stdout, s.Body); err != nil {
				return exitError, err
			}
		}
	}

	for _, b := range opts.Bindings {
		if w := b.Warning(); w != "" {
			note("WARNING: %s.", w)
		}
	}
	if u, err := url.Parse(opts.Issuer); err == nil && kubeauth.LoopbackHost(u.Hostname()) {
		note("WARNING: the issuer is a loopback address; only an API server on the same host can reach it.")
	}
	if only == "" {
		note("\nNext steps:")
		if isRealm {
			note("  1. Run haven-idp with HAVEN_IDP_GROUPS_CLAIM_CLIENTS=%s/%s (comma separated list) and restart it.", realm, opts.ClientID)
		}
		if !ensure {
			note("  -  The public client %q (device flow) must exist: add --ensure-client or create it yourself.", opts.ClientID)
		}
		note("  2. Configure the API server with the flags OR the AuthenticationConfiguration, never both.")
		note("  3. kubectl apply -f the RBAC section.")
		note("  4. Each user: %s", opts.LoginCommand())
		note("  5. Verify: haven token --id-token --profile %s | haven-idp kube-config check --issuer %s --client-id %s --token-file -", opts.Profile, opts.Issuer, opts.ClientID)
	}
	return exitOK, nil
}

// ensureKubeClient connects to the Admin API (same settings as plan/apply; the
// URL defaults to the issuer's base) and creates or verifies the client.
func ensureKubeClient(o kubeauth.Options, realm, base string, f cfgFlags, spec kubeauth.ClientSpec) (kubeauth.EnsureResult, error) {
	var none kubeauth.EnsureResult
	c, err := resolveConnection(f, base)
	if err != nil {
		return none, err
	}
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !kubeauth.LoopbackHost(u.Hostname()))) {
		return none, errors.New("the Admin API URL must be https (http only on loopback): the admin secret is sent to it")
	}
	api, err := kubeAdmin(c, o.CAPEM)
	if err != nil {
		return none, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return kubeauth.EnsureClient(ctx, api, realm, spec)
}

// writeSections writes one file per section (0600), refusing to overwrite
// anything unless force is set; nothing is written when any file exists.
func writeSections(dir string, sections []kubeauth.Section, force bool) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if !force {
		for _, s := range sections {
			if _, err := os.Lstat(filepath.Join(dir, s.File)); err == nil {
				return fmt.Errorf("%s already exists (use --force to overwrite)", filepath.Join(dir, s.File))
			}
		}
	}
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	for _, s := range sections {
		path := filepath.Join(dir, s.File)
		if force {
			// Replace the directory entry: never write through a symlink.
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		f, err := os.OpenFile(path, flags, 0o600) // #nosec G304 -- operator-provided directory, fixed file name
		if err != nil {
			return err
		}
		if _, err := io.WriteString(f, s.Body); err != nil {
			_ = f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

// readToken reads a sample token from a file or stdin; ExecCredential JSON
// (what `haven exec-credential` prints) is accepted too.
func readToken(path string, stdin io.Reader) (string, error) {
	var b []byte
	var err error
	if path == "-" {
		b, err = io.ReadAll(io.LimitReader(stdin, 128<<10))
	} else {
		b, err = readBounded(path, 128<<10)
	}
	if err != nil {
		return "", fmt.Errorf("--token-file: %w", err)
	}
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, "{") {
		var ec struct {
			Status struct {
				Token string `json:"token"`
			} `json:"status"`
		}
		if err := json.Unmarshal([]byte(s), &ec); err != nil || ec.Status.Token == "" {
			return "", errors.New("--token-file: the JSON is not an ExecCredential with status.token")
		}
		s = ec.Status.Token
	}
	if s == "" {
		return "", errors.New("--token-file: no token read (is `haven login` done?)")
	}
	return s, nil
}

func runKubeCheck(args []string, io_ cfgIO) (int, error) {
	var (
		c                 kubeCommon
		tokenFile, format string
		require           multiFlag
		timeout           time.Duration
	)
	fs := flag.NewFlagSet("kube-config check", flag.ContinueOnError)
	c.bind(fs)
	fs.StringVar(&tokenFile, "token-file", "", "")
	fs.Var(&require, "require-group", "")
	fs.StringVar(&format, "format", "text", "")
	fs.DurationVar(&timeout, "timeout", 15*time.Second, "")
	if err := c.parse(fs, args); err != nil {
		return exitUsage, err
	}
	if format != "text" && format != "json" {
		return exitUsage, fmt.Errorf("--format must be text or json, got %q", format)
	}
	if len(require) > 0 && tokenFile == "" {
		return exitUsage, errors.New("--require-group needs --token-file")
	}
	in := kubeauth.CheckInput{Options: c.opts, RequireGroups: require, Timeout: timeout}
	if tokenFile != "" {
		tok, err := readToken(tokenFile, io_.Stdin)
		if err != nil {
			return exitError, err
		}
		in.Token = tok
	}
	rep, err := kubeauth.Check(context.Background(), in)
	if err != nil {
		return exitUsage, err
	}
	code := exitOK
	if !rep.OK {
		code = exitError
	}
	if format == "json" {
		return code, writeJSON(io_.Stdout, rep)
	}
	for _, r := range rep.Results {
		_, _ = fmt.Fprintf(io_.Stdout, "%-4s  %-15s %s\n", strings.ToUpper(r.State), r.Check, r.Message)
		if r.Fix != "" {
			_, _ = fmt.Fprintf(io_.Stdout, "      %-15s fix: %s\n", "", r.Fix)
		}
	}
	if rep.OK {
		_, _ = fmt.Fprintln(io_.Stdout, "\nNo failures. This was checked from this machine; the control-plane nodes need the same network path and trust.")
	} else {
		_, _ = fmt.Fprintln(io_.Stdout, "\nThe check failed.")
	}
	return code, nil
}
