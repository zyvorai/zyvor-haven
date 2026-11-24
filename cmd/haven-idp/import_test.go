// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/configcode"
)

const fixture = "../../internal/idp/kcimport/testdata/realm-export.json"

func runImp(t *testing.T, stdin string, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = cmdImportNoSignal(args[0], args[1:], cfgIO{Stdin: strings.NewReader(stdin), Stdout: &out, Stderr: &errb})
	return code, out.String(), errb.String()
}

func cmdImportNoSignal(name string, args []string, io_ cfgIO) int {
	code, err := runImport(context.Background(), name, args, io_)
	if err != nil {
		_, _ = fmt.Fprintln(io_.Stderr, "haven-idp:", err)
		if code == exitOK {
			code = exitError
		}
	}
	return code
}

func TestImportKeycloakDryRun(t *testing.T) {
	code, out, errs := runImp(t, "", "import-keycloak", "-f", fixture)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errs)
	}
	for _, want := range []string{"realm corp", "6 (4 with an importable password", "NEW client secrets", "billing-svc, legacy-wiki", "Dry run", "client.saml_skipped", "notmigrated"} {
		if !strings.Contains(out, want) && want != "notmigrated" {
			t.Errorf("output lacks %q", want)
		}
	}
	if strings.Contains(out, "$pbkdf2") || strings.Contains(out, "SECRET-") {
		t.Error("secret material in output")
	}
}

func TestImportKeycloakOutDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "out")
	code, out, errs := runImp(t, "", "import-keycloak", "-f", fixture, "--out-dir", dir)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errs)
	}
	yp, up := filepath.Join(dir, "realm.yaml"), filepath.Join(dir, "users.json")
	if st, err := os.Stat(yp); err != nil || st.Mode().Perm() != 0o644 {
		t.Errorf("realm.yaml: %v %v", st, err)
	}
	if st, err := os.Stat(up); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("users.json: %v %v", st, err)
	}
	if !strings.Contains(out, "haven-idp apply -f") {
		t.Errorf("no next-step hint: %s", out)
	}
	// The fixture's Google identity provider is converted (disabled, no secret).
	ib, err := os.ReadFile(filepath.Join(dir, "identity-providers.json"))
	if err != nil {
		t.Fatalf("identity-providers.json: %v", err)
	}
	var ips []idp.IdentityProvider
	if err := json.Unmarshal(ib, &ips); err != nil || len(ips) != 1 || ips[0].Alias != "google" || ips[0].Enabled || ips[0].Config["clientSecret"] != "" {
		t.Errorf("identity-providers.json: %v %+v", err, ips)
	}
	yb, _ := os.ReadFile(yp)
	if _, err := configcode.Parse(bytes.NewReader(yb)); err != nil {
		t.Errorf("realm.yaml does not parse: %v", err)
	}
	ub, _ := os.ReadFile(up)
	var users []idp.ImportUser
	if err := json.Unmarshal(ub, &users); err != nil || len(users) != 6 {
		t.Fatalf("users.json: %v (%d)", err, len(users))
	}
	if !strings.HasPrefix(users[0].PasswordHash, "$") {
		t.Errorf("alice has no hash: %+v", users[0])
	}
	if strings.Contains(out, users[0].PasswordHash) {
		t.Error("hash printed")
	}

	// second run refuses to overwrite and leaves the files untouched
	code, _, errs = runImp(t, "", "import-keycloak", "-f", fixture, "--out-dir", dir)
	if code != 1 || !strings.Contains(errs, "refusing to overwrite") {
		t.Errorf("second run: code %d err %q", code, errs)
	}
	if b, _ := os.ReadFile(up); !bytes.Equal(b, ub) {
		t.Error("users.json modified")
	}
	// one existing file blocks both
	_ = os.Remove(up)
	if code, _, _ = runImp(t, "", "import-keycloak", "-f", fixture, "--out-dir", dir); code != 1 {
		t.Errorf("realm.yaml overwrite allowed (code %d)", code)
	}
	if _, err := os.Stat(up); err == nil {
		t.Error("users.json written despite refusal")
	}
}

func TestImportKeycloakStdinAndJSON(t *testing.T) {
	raw, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errs := runImp(t, string(raw), "import-keycloak", "-f", "-", "--format", "json", "--realm", "renamed")
	if code != 0 {
		t.Fatalf("code %d: %s", code, errs)
	}
	var rep map[string]any
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	if rep["targetRealm"] != "renamed" || rep["sourceRealm"] != "corp" {
		t.Errorf("realm = %v / %v", rep["sourceRealm"], rep["targetRealm"])
	}
	if strings.Contains(out, "$pbkdf2") || strings.Contains(out, "SECRET-") {
		t.Error("secret in JSON report")
	}
}

func TestImportKeycloakErrors(t *testing.T) {
	cases := []struct {
		name  string
		stdin string
		args  []string
		want  string
	}{
		{"no file", "", []string{"import-keycloak"}, "-f FILE"},
		{"bad format", "", []string{"import-keycloak", "-f", fixture, "--format", "xml"}, "--format"},
		{"bad realm", "", []string{"import-keycloak", "-f", fixture, "--realm", "Bad Realm"}, "not a valid realm"},
		{"missing file", "", []string{"import-keycloak", "-f", "/nonexistent/x.json"}, "no such file"},
		{"not json", "hello", []string{"import-keycloak", "-f", "-"}, "not valid JSON"},
		{"stray arg", "", []string{"import-keycloak", "-f", fixture, "extra"}, "unexpected argument"},
	}
	for _, c := range cases {
		code, _, errs := runImp(t, c.stdin, c.args...)
		if code != 1 || !strings.Contains(errs, c.want) {
			t.Errorf("%s: code %d err %q", c.name, code, errs)
		}
	}
}

type fakeImporter struct {
	idp.Provider
	batches [][]idp.ImportUser
	fail    map[string]string
	exist   map[string]bool
	err     error
}

func (f *fakeImporter) ImportUsers(_ context.Context, realm string, users []idp.ImportUser) (*idp.ImportResult, error) {
	if f.err != nil {
		return nil, f.err
	}
	f.batches = append(f.batches, append([]idp.ImportUser(nil), users...))
	res := &idp.ImportResult{}
	for _, u := range users {
		switch {
		case f.fail[u.Username] != "":
			res.Errors = append(res.Errors, idp.ImportError{Username: u.Username, Reason: f.fail[u.Username]})
		case f.exist[u.Username]:
			res.Skipped++
		default:
			res.Created++
		}
	}
	return res, nil
}

type plainProvider struct{ idp.Provider }

func useProvider(t *testing.T, p idp.Provider) {
	t.Helper()
	old := cfgConnect
	t.Cleanup(func() { cfgConnect = old })
	cfgConnect = func(connInfo) (idp.Provider, error) { return p, nil }
	t.Setenv("HAVEN_IDP_ADMIN_CLIENT_SECRET", "x")
	t.Setenv("HAVEN_IDP_ENV_FILE", "")
}

var connArgs = []string{"--url", "http://idp.test", "--admin-realm", "platform"}

func writeUsers(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "users.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestImportUsersPartialFailure(t *testing.T) {
	hash := "$pbkdf2-sha256$i=27500$c2FsdHNhbHRzYWx0c2FsdA$YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU"
	fake := &fakeImporter{fail: map[string]string{"bad": "role \"x\" does not exist"}, exist: map[string]bool{"old": true}}
	useProvider(t, fake)
	p := writeUsers(t, fmt.Sprintf(`{"users":[{"username":"a","enabled":true,"passwordHash":%q},{"username":"bad","passwordHash":%q},{"username":"old"}]}`, hash, hash))
	code, out, errs := runImp(t, "", append([]string{"import-users", "-f", p, "--realm", "corp"}, connArgs...)...)
	if code != 4 {
		t.Fatalf("code %d (stderr %q)", code, errs)
	}
	for _, want := range []string{"created: 1", "skipped (already existed): 1", "failed:  1", "- bad: role"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out+errs, "$pbkdf2") {
		t.Error("hash printed")
	}
	if len(fake.batches) != 1 || fake.batches[0][0].PasswordHash != hash {
		t.Errorf("batches = %+v", fake.batches)
	}
}

func TestImportUsersBatchingArrayAndJSON(t *testing.T) {
	fake := &fakeImporter{}
	useProvider(t, fake)
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < 1203; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		fmt.Fprintf(&sb, `{"username":"u%d","enabled":true}`, i)
	}
	sb.WriteString("]")
	p := writeUsers(t, sb.String())
	code, out, errs := runImp(t, "", append([]string{"import-users", "-f", p, "--realm", "corp", "--format", "json"}, connArgs...)...)
	if code != 0 {
		t.Fatalf("code %d: %s", code, errs)
	}
	if len(fake.batches) != 3 || len(fake.batches[0]) != 500 || len(fake.batches[2]) != 203 {
		t.Errorf("batch sizes wrong: %d batches", len(fake.batches))
	}
	var got struct{ Created, Skipped, Failed int }
	if err := json.Unmarshal([]byte(out), &got); err != nil || got.Created != 1203 {
		t.Errorf("json %v: %s", err, out)
	}
}

func TestImportUsersStdinAndRedaction(t *testing.T) {
	fake := &fakeImporter{fail: map[string]string{"u": "invalid hash $pbkdf2-sha256$i=1$abc$def"}}
	useProvider(t, fake)
	code, out, _ := runImp(t, `[{"username":"u"}]`, append([]string{"import-users", "-f", "-", "--realm", "corp"}, connArgs...)...)
	if code != 4 || strings.Contains(out, "$pbkdf2") || !strings.Contains(out, "[redacted]") {
		t.Errorf("code %d out %q", code, out)
	}
}

func TestImportUsersRefusals(t *testing.T) {
	good := writeUsers(t, `[{"username":"u"}]`)
	cases := []struct {
		name string
		prov idp.Provider
		args []string
		in   string
		want string
	}{
		{"not an importer", plainProvider{}, []string{"-f", good, "--realm", "corp"}, "", "does not support user import"},
		{"no realm", &fakeImporter{}, []string{"-f", good}, "", "usage"},
		{"bad shape", &fakeImporter{}, []string{"-f", "-", "--realm", "corp"}, `"hello"`, "not a users file"},
		{"object without users", &fakeImporter{}, []string{"-f", "-", "--realm", "corp"}, `{"a":1}`, "not a users file"},
		{"truncated", &fakeImporter{}, []string{"-f", "-", "--realm", "corp"}, `[{"username":"u"},{"user`, "invalid user entry"},
		{"server error", &fakeImporter{err: fmt.Errorf("boom")}, []string{"-f", good, "--realm", "corp"}, "", "boom"},
	}
	for _, c := range cases {
		useProvider(t, c.prov)
		code, _, errs := runImp(t, c.in, append(append([]string{"import-users"}, c.args...), connArgs...)...)
		if code != 1 || !strings.Contains(errs, c.want) {
			t.Errorf("%s: code %d err %q", c.name, code, errs)
		}
	}
}

func TestImportKeycloakEndToEnd(t *testing.T) {
	// import-keycloak output feeds import-users unchanged
	dir := t.TempDir()
	if code, _, errs := runImp(t, "", "import-keycloak", "-f", fixture, "--out-dir", dir); code != 0 {
		t.Fatalf("%d %s", code, errs)
	}
	fake := &fakeImporter{}
	useProvider(t, fake)
	code, out, errs := runImp(t, "", append([]string{"import-users", "-f", filepath.Join(dir, "users.json"), "--realm", "corp"}, connArgs...)...)
	if code != 0 || !strings.Contains(out, "created: 6") {
		t.Fatalf("%d %s %s", code, out, errs)
	}
}

// --trust-emails is an explicit opt-in: without it unverified users are reported
// as locked out and left unverified; with it they are marked verified.
func TestImportKeycloakTrustEmailsFlag(t *testing.T) {
	doc := `{"realm":"r","verifyEmail":true,"users":[{"username":"u1","email":"u1@x.test","enabled":true,"emailVerified":false,"credentials":[{"type":"password","hashedSaltedValue":"AAAAAAAAAAAAAAAAAAAAAAAAAAA=","salt":"AAAAAAAAAAAAAAAAAAAAAA==","hashIterations":27500,"algorithm":"pbkdf2-sha256"}]}]}`
	dir := t.TempDir()
	code, out, errs := runImp(t, doc, "import-keycloak", "-f", "-", "--out-dir", dir+"/a")
	if code != 0 || !strings.Contains(out, "user.email_unverified_blocked") {
		t.Fatalf("default run must warn about the lockout (exit %d):\n%s%s", code, out, errs)
	}
	b, _ := os.ReadFile(dir + "/a/users.json")
	if !strings.Contains(string(b), `"emailVerified": false`) && !strings.Contains(string(b), `"emailVerified":false`) {
		t.Fatalf("users must stay unverified by default:\n%s", b)
	}
	code, out, errs = runImp(t, doc, "import-keycloak", "-f", "-", "--out-dir", dir+"/b", "--trust-emails")
	if code != 0 || strings.Contains(out, "user.email_unverified_blocked") || !strings.Contains(out, "user.emails_marked_verified") {
		t.Fatalf("--trust-emails must report the opt-in and no lockout (exit %d):\n%s%s", code, out, errs)
	}
	b, _ = os.ReadFile(dir + "/b/users.json")
	if !strings.Contains(string(b), `"emailVerified": true`) && !strings.Contains(string(b), `"emailVerified":true`) {
		t.Fatalf("users must be verified with --trust-emails:\n%s", b)
	}
	// The flag exists only on import-keycloak.
	if code, _, _ := runImp(t, "[]", "import-users", "-f", "-", "--realm", "r", "--trust-emails"); code == 0 {
		t.Fatal("import-users must not accept --trust-emails")
	}
}
