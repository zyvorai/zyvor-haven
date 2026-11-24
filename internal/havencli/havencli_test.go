// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package havencli

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func assertNoSecrets(t *testing.T, f *fakeIdP, outputs ...string) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.issued) == 0 {
		t.Fatal("scan is vacuous: no tokens were issued")
	}
	for _, o := range outputs {
		for _, s := range f.issued {
			if strings.Contains(o, s) {
				t.Fatalf("a secret leaked into output: %.12s...", s)
			}
		}
	}
}

func TestLoginHappyPath(t *testing.T) {
	f := newFake(t, false)
	f.polls = []string{"pending", "pending", "ok"}
	te := newEnv(t, t.TempDir())
	if c := te.run(loginArgs(f)...); c != 0 {
		t.Fatalf("exit %d, stderr: %s", c, te.errb.String())
	}
	out := te.out.String()
	for _, want := range []string{f.url() + "/activate", "ABCD-EFGH", "expires in 10m0s", "Logged in as alice <alice@example.com>", "Profile: default"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if len(te.opened) != 1 || te.opened[0] != f.url()+"/activate?user_code=ABCD-EFGH" {
		t.Errorf("browser opened %v", te.opened)
	}
	want := []time.Duration{5 * time.Second, 5 * time.Second, 5 * time.Second}
	if len(te.sleeps) != 3 || te.sleeps[0] != want[0] || te.sleeps[2] != want[2] {
		t.Errorf("sleeps = %v", te.sleeps)
	}
	p := loadProfile(t, te, "default")
	if p == nil || p.AccessToken == "" || p.RefreshToken == "" || p.IDToken == "" || p.Issuer != f.url() || p.ClientID != "haven-cli" {
		t.Fatalf("stored profile = %+v", p)
	}
	assertNoSecrets(t, f, te.out.String(), te.errb.String())
}

func TestLoginNoBrowser(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	if c := te.run(loginArgs(f, "--no-browser")...); c != 0 {
		t.Fatal(te.errb.String())
	}
	if len(te.opened) != 0 {
		t.Fatalf("browser opened despite --no-browser: %v", te.opened)
	}
}

func TestLoginBrowserFailureIsNotFatal(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	te.env.OpenBrowser = func(string) error { return os.ErrNotExist }
	if c := te.run(loginArgs(f)...); c != 0 {
		t.Fatal(te.errb.String())
	}
	if !strings.Contains(te.out.String(), "could not open a browser") {
		t.Error("no hint printed")
	}
}

func TestSlowDownGrowsInterval(t *testing.T) {
	f := newFake(t, false)
	f.polls = []string{"pending", "slow_down", "pending", "slow_down", "ok"}
	te := newEnv(t, t.TempDir())
	if c := te.run(loginArgs(f)...); c != 0 {
		t.Fatal(te.errb.String())
	}
	s := time.Second
	want := []time.Duration{5 * s, 5 * s, 10 * s, 10 * s, 15 * s}
	if len(te.sleeps) != len(want) {
		t.Fatalf("sleeps = %v", te.sleeps)
	}
	for i := range want {
		if te.sleeps[i] != want[i] {
			t.Fatalf("sleeps = %v, want %v", te.sleeps, want)
		}
	}
}

func TestLoginDeniedAndExpired(t *testing.T) {
	for _, tc := range []struct{ poll, msg string }{{"denied", "denied"}, {"expired", "expired"}} {
		t.Run(tc.poll, func(t *testing.T) {
			f := newFake(t, false)
			f.polls = []string{"pending", tc.poll}
			te := newEnv(t, t.TempDir())
			if c := te.run(loginArgs(f)...); c != ExitError {
				t.Fatalf("exit %d", c)
			}
			if !strings.Contains(te.errb.String(), tc.msg) {
				t.Errorf("stderr %q", te.errb.String())
			}
			if loadProfile(t, te, "default") != nil {
				t.Error("credentials stored after failure")
			}
		})
	}
}

func TestLoginLocalDeadline(t *testing.T) {
	f := newFake(t, false)
	f.polls = []string{"pending"}
	f.deviceExpires = 12
	te := newEnv(t, t.TempDir())
	if c := te.run(loginArgs(f)...); c != ExitError {
		t.Fatalf("exit %d", c)
	}
	if !strings.Contains(te.errb.String(), "expired") {
		t.Error(te.errb.String())
	}
}

func TestLoginCancelled(t *testing.T) {
	f := newFake(t, false)
	f.polls = []string{"pending"}
	te := newEnv(t, t.TempDir())
	ctx, cancel := context.WithCancel(context.Background())
	te.env.Sleep = func(ctx context.Context, d time.Duration) error { cancel(); return ctx.Err() }
	if c := Run(ctx, loginArgs(f), te.env); c != ExitError || !strings.Contains(te.errb.String(), "cancelled") {
		t.Fatalf("exit %d stderr %q", c, te.errb.String())
	}
	if loadProfile(t, te, "default") != nil {
		t.Error("credentials stored after cancel")
	}
}

func TestLoginRejectsBadIDTokens(t *testing.T) {
	for name, set := range map[string]func(*fakeIdP){
		"aud":       func(f *fakeIdP) { f.badAud = true },
		"iss":       func(f *fakeIdP) { f.badIss = true },
		"signature": func(f *fakeIdP) { f.badSig = true },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFake(t, false)
			set(f)
			te := newEnv(t, t.TempDir())
			if c := te.run(loginArgs(f)...); c != ExitError {
				t.Fatalf("exit %d, want 1", c)
			}
			if loadProfile(t, te, "default") != nil {
				t.Error("credentials stored for a bad ID token")
			}
		})
	}
}

func TestTokenValidIsPrintedAloneAndNotRefreshed(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	mustLogin(t, f, te)
	if c := te.run("token"); c != 0 {
		t.Fatal(te.errb.String())
	}
	p := loadProfile(t, te, "default")
	if te.out.String() != p.AccessToken+"\n" {
		t.Fatalf("stdout = %q", te.out.String())
	}
	if te.errb.Len() != 0 {
		t.Errorf("stderr noise: %q", te.errb.String())
	}
	if f.refreshCalls != 0 {
		t.Error("refreshed a valid token")
	}
	te.out.Reset()
	if c := te.run("token", "--id-token"); c != 0 || te.out.String() != p.IDToken+"\n" {
		t.Fatalf("id token output wrong (exit %d)", c)
	}
}

func TestTokenRefreshAndRotation(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	mustLogin(t, f, te)
	before := loadProfile(t, te, "default")
	expireAccess(t, te)
	if c := te.run("token"); c != 0 {
		t.Fatal(te.errb.String())
	}
	after := loadProfile(t, te, "default")
	if f.refreshCalls != 1 {
		t.Fatalf("refresh calls %d", f.refreshCalls)
	}
	if after.AccessToken == before.AccessToken || after.RefreshToken == before.RefreshToken {
		t.Fatal("tokens not rotated in the store")
	}
	if te.out.String() != after.AccessToken+"\n" {
		t.Fatalf("stdout %q", te.out.String())
	}
	// A second call needs no refresh.
	te.out.Reset()
	te.run("token")
	if f.refreshCalls != 1 {
		t.Fatal("refreshed again")
	}
}

func TestTokenMinValidityForcesRefresh(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	mustLogin(t, f, te)
	if c := te.run("token", "--min-validity", "2h"); c != 0 || f.refreshCalls != 1 {
		t.Fatalf("exit %d refreshes %d", c, f.refreshCalls)
	}
}

func TestExpiredRefreshTokenCleansUp(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	mustLogin(t, f, te)
	expireAccess(t, te)
	f.alwaysInvalidRT = true
	if c := te.run("token"); c != ExitNotLoggedIn {
		t.Fatalf("exit %d", c)
	}
	if !strings.Contains(te.errb.String(), "haven login") {
		t.Errorf("no hint: %q", te.errb.String())
	}
	if te.out.Len() != 0 {
		t.Error("stdout not empty on failure")
	}
	if loadProfile(t, te, "default") != nil {
		t.Fatal("dead credentials were not deleted")
	}
}

func TestRefreshNetworkErrorKeepsCredentials(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	mustLogin(t, f, te)
	expireAccess(t, te)
	f.srv.Close()
	if c := te.run("token"); c != ExitError {
		t.Fatalf("exit %d", c)
	}
	if loadProfile(t, te, "default") == nil {
		t.Fatal("credentials deleted on a transient error")
	}
}

func TestTokenNotLoggedIn(t *testing.T) {
	te := newEnv(t, t.TempDir())
	if c := te.run("token"); c != ExitNotLoggedIn || te.out.Len() != 0 || !strings.Contains(te.errb.String(), "haven login") {
		t.Fatalf("exit %d out %q err %q", c, te.out.String(), te.errb.String())
	}
}

func TestConcurrentTokenRefreshesOnce(t *testing.T) {
	f := newFake(t, false)
	f.refreshDelay = 150 * time.Millisecond
	dir := t.TempDir()
	te := newEnv(t, dir)
	mustLogin(t, f, te)
	expireAccess(t, te)
	const n = 8
	outs := make([]string, n)
	codes := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := newEnv(t, dir)
			codes[i] = e.run("token")
			outs[i] = e.out.String()
		}()
	}
	wg.Wait()
	if f.refreshCalls != 1 || f.refreshReuse != 0 {
		t.Fatalf("refresh calls %d (stale reuse %d), want exactly 1", f.refreshCalls, f.refreshReuse)
	}
	want := loadProfile(t, te, "default").AccessToken + "\n"
	for i := range outs {
		if codes[i] != 0 || outs[i] != want {
			t.Fatalf("caller %d: exit %d out %q", i, codes[i], outs[i])
		}
	}
}

// TestHelperProcess is re-executed by TestConcurrentTokenSubprocesses.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("HAVEN_HELPER") != "1" {
		return
	}
	var args []string
	for i, a := range os.Args {
		if a == "--" {
			args = os.Args[i+1:]
		}
	}
	os.Exit(Run(context.Background(), args, DefaultEnv()))
}

func TestConcurrentTokenSubprocesses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cross-process lock is a no-op on windows")
	}
	f := newFake(t, false)
	f.refreshDelay = 300 * time.Millisecond
	dir := t.TempDir()
	te := newEnv(t, dir)
	mustLogin(t, f, te)
	expireAccess(t, te)
	const n = 6
	outs := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestHelperProcess$", "--", "token")
			cmd.Env = append(os.Environ(), "HAVEN_HELPER=1", "XDG_CONFIG_HOME="+dir)
			outs[i], errs[i] = cmd.Output()
		}()
	}
	wg.Wait()
	if f.refreshCalls != 1 || f.refreshReuse != 0 {
		t.Fatalf("refresh calls %d (stale reuse %d), want exactly 1", f.refreshCalls, f.refreshReuse)
	}
	want := loadProfile(t, te, "default").AccessToken + "\n"
	for i := range outs {
		if errs[i] != nil || string(outs[i]) != want {
			t.Fatalf("process %d: err %v out %q", i, errs[i], outs[i])
		}
	}
}

func TestCredentialFileModesAndTightening(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix modes")
	}
	f := newFake(t, false)
	dir := t.TempDir()
	te := newEnv(t, dir)
	mustLogin(t, f, te)
	cfg := filepath.Join(dir, "haven")
	di, _ := os.Stat(cfg)
	fi, _ := os.Stat(filepath.Join(cfg, "credentials.json"))
	if di.Mode().Perm() != 0o700 || fi.Mode().Perm() != 0o600 {
		t.Fatalf("modes dir %v file %v", di.Mode().Perm(), fi.Mode().Perm())
	}
	// No temp files left behind by the atomic write.
	ents, _ := os.ReadDir(cfg)
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("leftover temp file %s", e.Name())
		}
	}
	// A loosened file is repaired with a warning, not refused.
	if err := os.Chmod(filepath.Join(cfg, "credentials.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cfg, 0o755); err != nil {
		t.Fatal(err)
	}
	if c := te.run("token"); c != 0 {
		t.Fatalf("exit %d: %s", c, te.errb.String())
	}
	fi, _ = os.Stat(filepath.Join(cfg, "credentials.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("file mode not tightened: %v", fi.Mode().Perm())
	}
	if !strings.Contains(te.errb.String(), "tightening") {
		t.Errorf("no warning: %q", te.errb.String())
	}
}

func TestConfigDirXDGAndFallback(t *testing.T) {
	env := &Env{Getenv: func(k string) string {
		if k == "XDG_CONFIG_HOME" {
			return "/x/cfg"
		}
		return ""
	}, UserHomeDir: func() (string, error) { return "/home/u", nil }}
	if d, _ := configDir(env); d != filepath.FromSlash("/x/cfg/haven") {
		t.Errorf("xdg: %s", d)
	}
	env.Getenv = func(string) string { return "" }
	if d, _ := configDir(env); d != filepath.FromSlash("/home/u/.config/haven") {
		t.Errorf("fallback: %s", d)
	}
	env.Getenv = func(string) string { return "relative/path" } // XDG says absolute only
	if d, _ := configDir(env); d != filepath.FromSlash("/home/u/.config/haven") {
		t.Errorf("relative XDG not ignored: %s", d)
	}
}

func TestProfilesAreIndependent(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	if c := te.run(loginArgs(f, "--profile", "work")...); c != 0 {
		t.Fatal(te.errb.String())
	}
	if loadProfile(t, te, "default") != nil || loadProfile(t, te, "work") == nil {
		t.Fatal("profile keying broken")
	}
	if c := te.run("token", "--profile", "../evil"); c != ExitUsage {
		t.Errorf("bad profile name exit %d", c)
	}
}

func TestHTTPIssuerRefusal(t *testing.T) {
	te := newEnv(t, t.TempDir())
	if c := te.run("login", "--issuer", "http://idp.example.com", "--client-id", "x"); c != ExitUsage {
		t.Fatalf("exit %d", c)
	}
	if !strings.Contains(te.errb.String(), "plain http") {
		t.Errorf("stderr %q", te.errb.String())
	}
	for _, ok := range []string{"http://localhost:8081/realms/demo", "http://127.0.0.1:1", "http://[::1]:1", "https://idp.example.com"} {
		if _, err := parseIssuer(ok, netOpts{}); err != nil {
			t.Errorf("%s refused: %v", ok, err)
		}
	}
	if _, err := parseIssuer("http://idp.example.com", netOpts{InsecureHTTP: true}); err != nil {
		t.Errorf("--insecure-http not honoured: %v", err)
	}
	if _, err := newOIDC("http://idp.example.com", netOpts{InsecureHTTP: true}, te.errb); err != nil || !strings.Contains(te.errb.String(), "WARNING") {
		t.Errorf("no loud warning: %v %q", err, te.errb.String())
	}
	for _, bad := range []string{"idp.example.com", "ftp://x", "https://u:p@x", "https://x?a=b", "https://x#f"} {
		if _, err := parseIssuer(bad, netOpts{}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestIssuerMismatch(t *testing.T) {
	f := newFake(t, false)
	f.issuerOverride = "https://other.example.com"
	te := newEnv(t, t.TempDir())
	if c := te.run(loginArgs(f)...); c != ExitError || !strings.Contains(te.errb.String(), "issuer mismatch") {
		t.Fatalf("exit %d stderr %q", c, te.errb.String())
	}
	if f.deviceCalls != 0 {
		t.Error("proceeded to the device endpoint after a mismatch")
	}
}

func TestCrossOriginEndpointRefusal(t *testing.T) {
	evil := newFake(t, false)
	f := newFake(t, false)
	f.tokenEndpoint = evil.url() + "/token"
	te := newEnv(t, t.TempDir())
	if c := te.run(loginArgs(f)...); c != ExitError || !strings.Contains(te.errb.String(), "different origin") {
		t.Fatalf("exit %d stderr %q", c, te.errb.String())
	}
	f.deviceEndpoint = evil.url() + "/device"
	te = newEnv(t, t.TempDir())
	if c := te.run(loginArgs(f)...); c != ExitError || !strings.Contains(te.errb.String(), "different origin") {
		t.Fatalf("device endpoint: exit %d stderr %q", c, te.errb.String())
	}
	// Plain-http non-loopback endpoint is refused even with the cross-origin flag.
	iss, _ := parseIssuer("https://idp.example.com", netOpts{})
	if err := checkEndpoint("token_endpoint", "http://idp.example.com/token", iss, netOpts{AllowCross: true}); err == nil {
		t.Error("http endpoint accepted")
	}
	if err := checkEndpoint("token_endpoint", "https://idp.example.com:443/token", iss, netOpts{}); err != nil {
		t.Errorf("default port spelled out refused: %v", err)
	}
	if err := checkEndpoint("token_endpoint", "https://auth.example.com/token", iss, netOpts{AllowCross: true}); err != nil {
		t.Errorf("--allow-cross-origin-endpoints not honoured: %v", err)
	}
}

func TestTokenEndpointRedirectRefused(t *testing.T) {
	evil := newFake(t, false)
	f := newFake(t, false)
	f.redirectToken = evil.url() + "/token"
	te := newEnv(t, t.TempDir())
	if c := te.run(loginArgs(f)...); c != ExitError {
		t.Fatalf("exit %d", c)
	}
	evil.mu.Lock()
	n := evil.pollCount
	evil.mu.Unlock()
	if n != 0 || !strings.Contains(te.errb.String(), "redirect") {
		t.Fatalf("redirect followed? polls on evil=%d stderr=%q", n, te.errb.String())
	}
}

func TestResponseSizeLimit(t *testing.T) {
	f := newFake(t, false)
	f.hugeToken = true
	te := newEnv(t, t.TempDir())
	if c := te.run(loginArgs(f)...); c != ExitError || !strings.Contains(te.errb.String(), "exceeds") {
		t.Fatalf("exit %d stderr %q", c, te.errb.String())
	}
}

func TestTLSWithCAFile(t *testing.T) {
	f := newFake(t, true)
	te := newEnv(t, t.TempDir())
	if c := te.run(loginArgs(f)...); c != ExitError {
		t.Fatalf("untrusted CA accepted (exit %d)", c)
	}
	if c := te.run(loginArgs(f, "--ca-file", f.caFile(t))...); c != 0 {
		t.Fatalf("with CA: exit %d %s", c, te.errb.String())
	}
	// the CA path is remembered, so a refresh works without the flag
	expireAccess(t, te)
	if c := te.run("token"); c != 0 {
		t.Fatalf("refresh over private CA: exit %d %s", c, te.errb.String())
	}
	if c := te.run("login", "--issuer", f.url(), "--client-id", "x", "--ca-file", "/nonexistent.pem"); c != ExitError {
		t.Errorf("missing ca-file exit %d", c)
	}
}

func TestExecCredentialGolden(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	mustLogin(t, f, te)
	p := loadProfile(t, te, "default")
	if c := te.run("exec-credential", "--issuer", f.url(), "--client-id", "haven-cli"); c != 0 {
		t.Fatal(te.errb.String())
	}
	golden := `{"apiVersion":"client.authentication.k8s.io/v1","kind":"ExecCredential","status":{"token":"` + p.IDToken +
		`","expirationTimestamp":"` + p.IDExpiry.UTC().Format(time.RFC3339) + `"}}` + "\n"
	if te.out.String() != golden {
		t.Fatalf("got  %q\nwant %q", te.out.String(), golden)
	}
	if te.errb.Len() != 0 {
		t.Errorf("stderr noise %q", te.errb.String())
	}
	if _, err := time.Parse(time.RFC3339, p.IDExpiry.UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
}

func TestExecCredentialNeverPromptsWhenLoggedOut(t *testing.T) {
	te := newEnv(t, t.TempDir())
	if c := te.run("exec-credential", "--issuer", "https://idp.example.com", "--client-id", "x"); c != ExitNotLoggedIn {
		t.Fatalf("exit %d", c)
	}
	if te.out.Len() != 0 || !strings.Contains(te.errb.String(), "haven login") {
		t.Fatalf("out %q err %q", te.out.String(), te.errb.String())
	}
	if len(te.opened) != 0 {
		t.Error("opened a browser")
	}
}

func TestExecCredentialRefreshesAndChecksIssuer(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	mustLogin(t, f, te)
	expireAccess(t, te)
	if c := te.run("exec-credential", "--issuer", f.url(), "--client-id", "haven-cli"); c != 0 || f.refreshCalls != 1 {
		t.Fatalf("exit %d refreshes %d", c, f.refreshCalls)
	}
	var ec map[string]any
	if err := json.Unmarshal(te.out.Bytes(), &ec); err != nil {
		t.Fatal(err)
	}
	te.out.Reset()
	if c := te.run("exec-credential", "--issuer", "https://other.example.com", "--client-id", "haven-cli"); c != ExitNotLoggedIn || te.out.Len() != 0 {
		t.Fatalf("issuer mismatch exit %d out %q", c, te.out.String())
	}
}

func TestWhoami(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	mustLogin(t, f, te)
	if c := te.run("whoami"); c != 0 {
		t.Fatal(te.errb.String())
	}
	out := te.out.String()
	for _, w := range []string{"alice <alice@example.com>", "signature: verified against the issuer's JWKS (ES256)", "preferred_username", "Userinfo:", "sub-123"} {
		if !strings.Contains(out, w) {
			t.Errorf("missing %q in:\n%s", w, out)
		}
	}
	assertNoSecrets(t, f, out, te.errb.String())
	te.out.Reset()
	if c := te.run("whoami", "--json"); c != 0 {
		t.Fatal(te.errb.String())
	}
	var rep map[string]any
	if err := json.Unmarshal(te.out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep["id_token_signature_verified"] != true || rep["userinfo"].(map[string]any)["sub"] != "sub-123" {
		t.Errorf("json: %v", rep)
	}
	assertNoSecrets(t, f, te.out.String())
}

func TestWhoamiSaysWhenSignatureNotVerified(t *testing.T) {
	f := newFake(t, false)
	f.noJWKS = true
	te := newEnv(t, t.TempDir())
	mustLogin(t, f, te)
	if c := te.run("whoami"); c != 0 {
		t.Fatal(te.errb.String())
	}
	if !strings.Contains(te.out.String(), "NOT verified") {
		t.Errorf("no disclaimer:\n%s", te.out.String())
	}
}

func TestWhoamiFlagsUserinfoSubMismatch(t *testing.T) {
	f := newFake(t, false)
	f.userinfoSub = "someone-else"
	te := newEnv(t, t.TempDir())
	mustLogin(t, f, te)
	te.run("whoami", "--json")
	if !strings.Contains(te.out.String(), "does not match") {
		t.Errorf("sub mismatch not reported: %s", te.out.String())
	}
}

func TestLogoutRevokesAndDeletes(t *testing.T) {
	f := newFake(t, false)
	te := newEnv(t, t.TempDir())
	mustLogin(t, f, te)
	rt := loadProfile(t, te, "default").RefreshToken
	if c := te.run("logout"); c != 0 {
		t.Fatal(te.errb.String())
	}
	if len(f.revoked) != 1 || f.revoked[0]["token"][0] != rt || f.revoked[0]["token_type_hint"][0] != "refresh_token" || f.revoked[0]["client_id"][0] != "haven-cli" {
		t.Fatalf("revoke calls: %v", f.revoked)
	}
	if loadProfile(t, te, "default") != nil {
		t.Fatal("credentials not deleted")
	}
	assertNoSecrets(t, f, te.out.String(), te.errb.String())
	// Logging out again is a harmless no-op.
	if c := te.run("logout"); c != 0 {
		t.Errorf("second logout exit %d", c)
	}
}

func TestLogoutDeletesEvenWhenRevocationFails(t *testing.T) {
	f := newFake(t, false)
	f.revokeStatus = 500
	te := newEnv(t, t.TempDir())
	mustLogin(t, f, te)
	if c := te.run("logout"); c != 0 {
		t.Fatalf("exit %d", c)
	}
	if loadProfile(t, te, "default") != nil {
		t.Fatal("credentials kept")
	}
	if !strings.Contains(te.errb.String(), "could not revoke") {
		t.Errorf("no warning: %q", te.errb.String())
	}
}

func TestUsageAndHelp(t *testing.T) {
	te := newEnv(t, t.TempDir())
	for _, args := range [][]string{{}, {"bogus"}, {"login"}, {"token", "--nope"}, {"token", "extra"}, {"exec-credential"}} {
		te.errb.Reset()
		if c := te.run(args...); c != ExitUsage {
			t.Errorf("%v: exit %d", args, c)
		}
	}
	if c := te.run("help"); c != 0 || !strings.Contains(te.out.String(), "Exit codes") {
		t.Error("help")
	}
	te.out.Reset()
	if c := te.run("version"); c != 0 || !strings.HasPrefix(te.out.String(), "haven ") {
		t.Error("version")
	}
	if c := te.run("token", "-h"); c != 0 {
		t.Errorf("-h exit %d", c)
	}
}

func TestCleanStripsTerminalEscapes(t *testing.T) {
	if got := clean("ok\x1b[31mred\x07\n", 50); strings.ContainsAny(got, "\x1b\x07\n") {
		t.Errorf("escape survived: %q", got)
	}
}

func TestVerifySignatureRejectsNoneAndHS256(t *testing.T) {
	f := newFake(t, false)
	_, claimsJSON := f.mintID("a"), ""
	_ = claimsJSON
	tok := f.mintID("a")
	parts := strings.Split(tok, ".")
	for _, alg := range []string{"none", "HS256"} {
		h := b64([]byte(`{"alg":"` + alg + `"}`))
		if _, err := verifySignature(h+"."+parts[1]+"."+parts[2], nil); err == nil {
			t.Errorf("alg %s accepted", alg)
		}
	}
}
