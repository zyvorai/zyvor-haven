// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package kcimport

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp/configcode"
)

var update = flag.Bool("update", false, "rewrite golden files")

func open(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func conv(t *testing.T, doc string) *Result {
	t.Helper()
	res, err := Convert(strings.NewReader(doc), Options{})
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	return res
}

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	p := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(p, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("%s differs from golden (run with -update):\n%s", name, got)
	}
}

func reportJSON(t *testing.T, r Report) []byte {
	t.Helper()
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

func TestFixtureGolden(t *testing.T) {
	res, err := Convert(open(t, "realm-export.json"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	y, err := configcode.Marshal(res.Spec)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "realm.golden.yaml", y)
	golden(t, "report.golden.json", reportJSON(t, res.Report))
	if err := res.Spec.Validate(); err != nil {
		t.Fatalf("spec invalid: %v", err)
	}
	// round trip through the real parser
	if _, err := configcode.Parse(bytes.NewReader(y)); err != nil {
		t.Fatalf("Parse(Marshal): %v", err)
	}
}

func TestFixtureDeterministic(t *testing.T) {
	a, _ := Convert(open(t, "realm-export.json"), Options{})
	b, _ := Convert(open(t, "realm-export.json"), Options{})
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) {
		t.Fatal("two conversions differ")
	}
}

func TestFixtureUsers(t *testing.T) {
	res, err := Convert(open(t, "realm-export.json"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]int{}
	for i, u := range res.Users {
		by[u.Username] = i
	}
	if _, ok := by["service-account-billing-svc"]; ok {
		t.Error("service account user imported")
	}
	if len(res.Users) != 6 {
		t.Fatalf("users = %d, want 6", len(res.Users))
	}
	get := func(n string) (u struct {
		Hash   string
		Roles  []string
		Groups []string
		Acts   []string
	}) {
		x := res.Users[by[n]]
		u.Hash, u.Roles, u.Groups, u.Acts = x.PasswordHash, x.Roles, x.Groups, x.RequiredActions
		return
	}
	if h := get("alice").Hash; !strings.HasPrefix(h, "$pbkdf2-sha256$i=27500$") {
		t.Errorf("alice hash prefix: %.25s", h)
	}
	if r := get("alice").Roles; len(r) != 1 || r[0] != "admin" {
		t.Errorf("alice roles = %v", r)
	}
	if h := get("bob").Hash; !strings.HasPrefix(h, "$pbkdf2-sha512$i=210000$") {
		t.Errorf("bob: %.25s", h)
	}
	if g := get("bob").Groups; len(g) != 0 {
		t.Errorf("bob nested group kept: %v", g)
	}
	if a := get("bob").Acts; len(a) != 1 || a[0] != "UPDATE_PASSWORD" {
		t.Errorf("bob actions = %v", a)
	}
	if h := get("carol").Hash; !strings.HasPrefix(h, "$pbkdf2-sha1$i=20000$") {
		t.Errorf("carol legacy: %.25s", h)
	}
	if h := get("dave").Hash; !strings.HasPrefix(h, "$argon2id$") {
		t.Errorf("dave: %.25s", h)
	}
	if h := get("erin").Hash; h != "" {
		t.Errorf("erin (argon2d) must import without password")
	}
	if h := get("frank").Hash; h != "" || res.Users[by["frank"]].Enabled {
		t.Errorf("frank wrong")
	}
	wc := res.Report.WarningCounts
	for _, code := range []string{"user.otp_not_migrated", "user.federated_identity_dropped", "user.password_unsupported", "user.no_password", "user.attributes_dropped", "user.service_account_skipped", "user.nested_group_dropped", "user.required_action_dropped"} {
		if wc[code] != 1 {
			t.Errorf("warning %s count = %d, want 1", code, wc[code])
		}
	}
	if res.Report.Mapped.UsersWithPassword != 4 || res.Report.Mapped.UsersWithoutPassword != 2 {
		t.Errorf("counts = %+v", res.Report.Mapped)
	}
}

func TestInputShapes(t *testing.T) {
	for _, name := range []string{"array-export.json", "partial-export.json"} {
		res, err := Convert(open(t, name), Options{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := res.Spec.Validate(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "partial-export.json" && (res.Spec.Realm != "partial" || len(res.Users) != 0 || len(res.Spec.Clients) != 1) {
			t.Errorf("partial: %+v", res.Spec)
		}
	}
	// the repo's example partial exports
	for _, f := range []string{"realm-secure.json", "realm-risky.json"} {
		fh, err := os.Open(filepath.Join("..", "..", "..", "examples", f))
		if err != nil {
			t.Fatal(err)
		}
		res, err := Convert(fh, Options{})
		_ = fh.Close()
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if err := res.Spec.Validate(); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
	}
}

func TestRealmOverride(t *testing.T) {
	res, err := Convert(strings.NewReader(`{"realm":"corp","clients":[]}`), Options{Realm: "new-name"})
	if err != nil || res.Spec.Realm != "new-name" || res.Report.SourceRealm != "corp" {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := Convert(strings.NewReader(`{"clients":[]}`), Options{}); err == nil || !strings.Contains(err.Error(), "--realm") {
		t.Errorf("missing realm name: %v", err)
	}
	if _, err := Convert(strings.NewReader(`{"realm":"x"}`), Options{Realm: "Bad Name"}); err == nil {
		t.Error("invalid override accepted")
	}
}

func TestErrors(t *testing.T) {
	huge := strings.Repeat("A", 3<<20)
	cases := map[string]struct{ in, want string }{
		"empty":        {"", "empty"},
		"not json":     {"hello world", "not valid JSON"},
		"scalar":       {"42", "expected a realm object"},
		"string":       {`"x"`, "expected a realm object"},
		"empty array":  {"[]", "empty"},
		"two realms":   {`[{"realm":"a"},{"realm":"b"}]`, "more than one"},
		"array of num": {`[1]`, "realm object"},
		"no realm key": {`{"foo":1,"bar":[1,2]}`, "not a realm export"},
		"truncated":    {`{"realm":"a","users":[{"username":"u1"},{"user`, "truncated"},
		"trailing":     {`{"realm":"a"} {"x":1}`, "unexpected data"},
		"wrong type":   {`{"realm":"a","users":{"a":1}}`, "array"},
		"bad field":    {`{"realm":"a","users":[{"username":5}]}`, "wrong type"},
		"huge realm":   {`{"realm":"` + huge + `"}`, "not valid"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Convert(strings.NewReader(c.in), Options{})
			if err == nil {
				t.Fatal("expected an error")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error %q lacks %q", truncate(err.Error()), c.want)
			}
			if len(err.Error()) > 1000 {
				t.Errorf("error echoes content (%d bytes)", len(err.Error()))
			}
		})
	}
}

func truncate(s string) string {
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}

func TestHugeStringsDoNotCrash(t *testing.T) {
	huge := strings.Repeat("A", 2<<20)
	doc := fmt.Sprintf(`{"realm":"r","users":[{"username":"%s","enabled":true},{"username":"ok","email":"%s"}],"clients":[{"clientId":"%s"}],"roles":{"realm":[{"name":"%s"}]}}`, huge, huge, huge, huge)
	res := conv(t, doc)
	if len(res.Users) != 0 || len(res.Spec.Clients) != 0 || len(res.Spec.Roles) != 0 {
		t.Errorf("oversized entries kept: users=%d clients=%d roles=%d", len(res.Users), len(res.Spec.Clients), len(res.Spec.Roles))
	}
	b, _ := json.Marshal(res.Report)
	if len(b) > 20000 {
		t.Errorf("report echoes huge values (%d bytes)", len(b))
	}
}

func TestSizeCap(t *testing.T) {
	r := io.MultiReader(strings.NewReader(`{"realm":"a","x":"`), zeroReader{}, strings.NewReader(`"}`))
	_, err := Convert(r, Options{})
	if err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("got %v", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

// TestNoSecretsLeak: nothing secret from the fixture may appear in the Report,
// the Spec YAML or any error text.
func TestNoSecretsLeak(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "realm-export.json"))
	if err != nil {
		t.Fatal(err)
	}
	secrets := []string{"SECRET-billing-svc-7c1e9f0a2b", "SECRET-legacy-wiki-44d1ab90", "SECRET-orders-api-0000", "SECRET-policy-enforcer-5e5e", "OTPSECRETVALUE123", "LDAPBINDSECRET"}
	var doc struct {
		Users []kcUser `json:"users"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, u := range doc.Users {
		for _, c := range u.Credentials {
			var sd secretData
			if json.Unmarshal([]byte(c.SecretData), &sd) == nil && sd.Value != "" {
				secrets = append(secrets, sd.Value, sd.Salt)
			}
			if c.HashedSaltedValue != "" {
				secrets = append(secrets, c.HashedSaltedValue, c.Salt)
			}
		}
	}
	res, err := Convert(bytes.NewReader(raw), Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range res.Users {
		if u.PasswordHash != "" {
			secrets = append(secrets, strings.TrimRight(u.PasswordHash[strings.LastIndexByte(u.PasswordHash, '$')+1:], "="))
		}
	}
	y, _ := configcode.Marshal(res.Spec)
	rj, _ := json.Marshal(res.Report)
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if bytes.Contains(rj, []byte(s)) || bytes.Contains(y, []byte(s)) {
			t.Errorf("secret %.12s... leaked into report or spec", s)
		}
	}
	if bytes.Contains(rj, []byte("$pbkdf2")) || bytes.Contains(rj, []byte("$argon2")) {
		t.Error("hash prefix in report")
	}
	// errors: corrupt the credential structure and make sure the text stays clean
	for _, bad := range []string{
		strings.Replace(string(raw), `"users": [`, `"users": [ {"username":"SECRET-billing-svc-7c1e9f0a2b","enabled":"yes"},`, 1),
		string(raw)[:len(raw)/2],
	} {
		_, err := Convert(strings.NewReader(bad), Options{})
		if err == nil {
			t.Fatal("expected error")
		}
		for _, s := range secrets {
			if s != "" && strings.Contains(err.Error(), s) {
				t.Errorf("secret in error text")
			}
		}
	}
	// a malformed credential must not echo its content into the report
	bad := `{"realm":"r","users":[{"username":"x","credentials":[{"type":"password","secretData":"{not json SUPERSECRETXYZ","credentialData":"{}"}]},{"username":"y","credentials":[{"type":"password","hashedSaltedValue":"SUPERSECRETABC!!","salt":"@@","algorithm":"SUPERSECRETALG","hashIterations":5}]}]}`
	r2 := conv(t, bad)
	b, _ := json.Marshal(r2.Report)
	if bytes.Contains(b, []byte("SUPERSECRET")) {
		t.Errorf("credential content leaked: %s", b)
	}
	if r2.Report.WarningCounts["user.password_unreadable"] != 1 || r2.Report.WarningCounts["user.password_unsupported"] != 1 {
		t.Errorf("counts: %v", r2.Report.WarningCounts)
	}
}

func TestStreaming200k(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	const n = 200_000
	pr, pw := io.Pipe()
	go func() {
		bw := bufio.NewWriter(pw)
		bw.WriteString(`{"realm":"big","clients":[],"users":[`)
		for i := 0; i < n; i++ {
			if i > 0 {
				bw.WriteString(",")
			}
			fmt.Fprintf(bw, `{"username":"user%d","enabled":true,"emailVerified":true,"credentials":[{"type":"password","secretData":"{\"value\":\"YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU=\",\"salt\":\"c2FsdHNhbHRzYWx0c2FsdA==\"}","credentialData":"{\"hashIterations\":27500,\"algorithm\":\"pbkdf2-sha256\"}"}]}`, i)
		}
		bw.WriteString(`]}`)
		_ = bw.Flush()
		_ = pw.Close()
	}()
	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)
	res, err := Convert(pr, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Users) != n || res.Report.Mapped.UsersWithPassword != n {
		t.Fatalf("users=%d withPassword=%d", len(res.Users), res.Report.Mapped.UsersWithPassword)
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	growth := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	// ~230 MB of JSON went through; retained memory is the converted users only.
	if growth > 400<<20 {
		t.Errorf("heap grew %d MiB for %d users", growth>>20, n)
	}
	runtime.KeepAlive(res)
	if res.Users[0].Username != "user0" || res.Users[1].Username != "user1" {
		t.Errorf("not sorted: %s %s", res.Users[0].Username, res.Users[1].Username)
	}
}
