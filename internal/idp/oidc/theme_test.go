// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"bytes"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Every HTML page must take its look from the shared theme: one <style> block,
// carrying the nonce, with exactly themeCSS inside.
func TestEveryPageUsesSharedTheme(t *testing.T) {
	const nonce = "NONCE123"
	pages := map[string]struct {
		tmpl *template.Template
		data any
	}{
		"login/forgot/error": {pageTmpl, pageData{Nonce: nonce, Title: "t", Message: "m"}},
		"logout": {logoutTmpl, struct {
			Nonce, Realm, CSRF, Action string
			Hidden                     []hiddenField
		}{Nonce: nonce}},
		"device":    {deviceTmpl, deviceView{Nonce: nonce, Mode: "done"}},
		"ciba":      {cibaTmpl, cibaView{Nonce: nonce, Mode: "done"}},
		"passkeys":  {pkAcctTmpl, pkAcctData{Nonce: nonce}},
		"step/mfa/": {stepTemplate(""), StepData{Nonce: nonce, Title: "t"}},
	}
	for name, pg := range pages {
		var b bytes.Buffer
		if err := pg.tmpl.Execute(&b, pg.data); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out := b.String()
		if n := strings.Count(out, "<style"); n != 1 {
			t.Errorf("%s: %d <style> blocks, want exactly the shared one", name, n)
		}
		if !strings.Contains(out, `<style nonce="`+nonce+`">`) {
			t.Errorf("%s: <style> lacks the nonce", name)
		}
		if !strings.Contains(out, strings.TrimSpace(themeCSS)[:60]) || !strings.Contains(out, "prefers-color-scheme:dark") {
			t.Errorf("%s: shared theme missing", name)
		}
		if !strings.Contains(out, `<svg class="hero"`) || !strings.Contains(out, `aria-hidden="true"`) {
			t.Errorf("%s: missing aria-hidden hero illustration", name)
		}
		if strings.Contains(out, "style=") {
			t.Errorf("%s: inline style attribute (blocked by CSP)", name)
		}
	}
}

// No Go file may carry its own <style> or page skeleton outside the shared
// theme path.
func TestNoPageDefinesOwnStyle(t *testing.T) {
	root := filepath.Join("..")
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "devui" {
			return fs.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || filepath.Base(path) == "theme.go" {
			return nil
		}
		raw, err := os.ReadFile(path) // #nosec G304 G122 -- repository source files in a test
		if err != nil {
			return err
		}
		src := string(raw)
		if strings.Contains(src, "<style") {
			t.Errorf("%s defines its own <style>; use the shared theme", path)
		}
		if strings.Contains(src, "<!doctype html>\n<html lang=\"en\"><head>") && !strings.Contains(src, "withTheme(") {
			t.Errorf("%s has a page template without withTheme", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestWithThemePanicsWithoutMarker(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	withTheme("<html></html>")
}
