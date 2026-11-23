// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package obs

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestDocsVerifierSnippet extracts the verifier program from
// docs/observability.md and runs it against good and tampered streams.
func TestDocsVerifierSnippet(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not on PATH")
	}
	doc, err := os.ReadFile("../../../docs/observability.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)<!-- verifier -->\n```go\n(.*?)```").FindSubmatch(doc)
	if m == nil {
		t.Fatal("verifier snippet not found in docs")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "verify.go")
	bin := filepath.Join(dir, "verify")
	if err := os.WriteFile(src, m[1], 0o600); err != nil {
		t.Fatal(err)
	}
	build := exec.Command("go", "build", "-o", bin, src)
	build.Dir = dir
	build.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GO111MODULE=off")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	var c, c2 chain
	var lines [][]byte
	for i := 0; i < 5; i++ {
		lines = append(lines, c.seal(ev(i)))
	}
	lines = append(lines, c2.seal(ev(0)), c2.seal(ev(1)))
	join := func(ls [][]byte) []byte { return append(bytes.Join(ls, []byte("\n")), '\n') }
	run := func(in []byte) (string, error) {
		cmd := exec.Command(bin)
		cmd.Stdin = bytes.NewReader(in)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := run(join(lines)); err != nil || !strings.Contains(out, "OK: 7 events, 2 chain(s)") {
		t.Fatalf("good stream: %v %q", err, out)
	}
	bad := append(append([][]byte{}, lines[:2]...), lines[3:]...)
	if _, err := run(join(bad)); err == nil {
		t.Fatal("verifier accepted a stream with a removed event")
	}
	mod := append([][]byte{}, lines...)
	mod[1] = bytes.Replace(mod[1], []byte("LOGIN"), []byte("LOGON"), 1)
	if _, err := run(join(mod)); err == nil {
		t.Fatal("verifier accepted a modified event")
	}
}
