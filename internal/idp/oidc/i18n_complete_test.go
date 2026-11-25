// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import (
	"go/ast"
	"go/parser"
	"go/token"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"text/template/parse"

	"github.com/zyvorai/haven/internal/idp/i18n"
)

// These tests keep every user-facing string of the pages and emails in the
// catalogue. A page that has not opted in (docs/branding-and-i18n.md) is not
// listed here and is simply shown in English.

// localizedPages are the templates that have opted in. A new opted-in page
// template or step body belongs in this list.
func localizedPages() map[string]*template.Template {
	m := map[string]*template.Template{
		"page": pageTmpl, "logout": logoutTmpl, "device": deviceTmpl, "ciba": cibaTmpl, "passkey account": pkAcctTmpl,
	}
	for name, body := range map[string]string{
		"mfa verify": verifyBody, "mfa enroll": enrollBody, "mfa codes": doneBody, "mfa account": acctBody,
		"passkey step": pkStepBody + altFragment, "consent": consentBody, "consent account": consentAcctBody,
		"email change": ecBody, "email confirm": ecConfirmBody,
	} {
		m["step "+name] = stepTemplate(body)
	}
	return m
}

// localizedFiles are the Go files whose page messages must be translated. A
// new file that opts in belongs in this list.
var localizedFiles = []string{
	"actions.go", "authorize.go", "authsteps.go", "ciba.go", "consent.go", "device.go", "emailchange.go",
	"fallback.go", "fapi.go", "federation.go", "logout.go", "mfa.go", "mfa_account.go", "mfa_login.go",
	"passkeys.go", "passkeys_account.go", "stepup.go", "ui.go", "../mail/templates.go",
}

func walk(n parse.Node, f func(parse.Node)) {
	if n == nil {
		return
	}
	f(n)
	branch := func(b *parse.BranchNode) {
		walk(b.Pipe, f)
		if b.List != nil {
			walk(b.List, f)
		}
		if b.ElseList != nil {
			walk(b.ElseList, f)
		}
	}
	switch x := n.(type) {
	case *parse.ListNode:
		for _, c := range x.Nodes {
			walk(c, f)
		}
	case *parse.ActionNode:
		walk(x.Pipe, f)
	case *parse.PipeNode:
		if x != nil {
			for _, c := range x.Cmds {
				walk(c, f)
			}
		}
	case *parse.CommandNode:
		for _, a := range x.Args {
			walk(a, f)
		}
	case *parse.IfNode:
		branch(&x.BranchNode)
	case *parse.RangeNode:
		branch(&x.BranchNode)
	case *parse.WithNode:
		branch(&x.BranchNode)
	}
}

// templateKeys returns the literal texts a template passes to .L.T and .L.H.
func templateKeys(tm *template.Template) []string {
	var out []string
	for _, t := range tm.Templates() {
		if t.Tree == nil {
			continue
		}
		walk(t.Tree.Root, func(n parse.Node) {
			c, ok := n.(*parse.CommandNode)
			if !ok || len(c.Args) < 2 {
				return
			}
			var ident []string
			switch f := c.Args[0].(type) {
			case *parse.FieldNode:
				ident = f.Ident
			case *parse.VariableNode:
				ident = f.Ident[1:]
			}
			if len(ident) != 2 || ident[0] != "L" || (ident[1] != "T" && ident[1] != "H") {
				return
			}
			if s, ok := c.Args[1].(*parse.StringNode); ok {
				out = append(out, s.Text)
			}
		})
	}
	return out
}

func translated(t *testing.T, where, key string) {
	t.Helper()
	for _, lang := range i18n.Supported() {
		if lang == i18n.Default {
			continue
		}
		if _, ok := i18n.Lookup(lang, key); !ok {
			t.Errorf("%s: no %s translation of %q (add it to internal/idp/i18n/catalog_%s.go)", where, lang, key, lang)
		}
	}
}

var (
	stripRE    = regexp.MustCompile(`(?s)<style[^>]*>.*?</style>|<script[^>]*>.*?</script>|<svg.*?</svg>|<!--.*?-->`)
	attrTextRE = regexp.MustCompile(`(?:aria-label|placeholder|title|alt)="([^"]*)"`)
	tagRE      = regexp.MustCompile(`<[^<>]*>`)
	letterRE   = regexp.MustCompile(`\p{L}{2,}`)
)

func TestTemplatesAreFullyTranslated(t *testing.T) {
	for name, tm := range localizedPages() {
		keys := templateKeys(tm)
		if len(keys) == 0 {
			t.Errorf("%s: no translated text found", name)
		}
		for _, k := range keys {
			translated(t, name, k)
		}
		for _, sub := range tm.Templates() {
			if sub.Tree == nil {
				continue
			}
			var b strings.Builder
			walk(sub.Tree.Root, func(n parse.Node) {
				if x, ok := n.(*parse.TextNode); ok {
					b.Write(x.Text)
				}
			})
			text := stripRE.ReplaceAllString(b.String(), " ")
			for _, m := range attrTextRE.FindAllStringSubmatch(text, -1) {
				if letterRE.MatchString(m[1]) && m[1] != "XXXX-XXXX" {
					t.Errorf("%s: untranslated attribute text %q", name, m[1])
				}
			}
			text = tagRE.ReplaceAllString(text, " ")
			if w := letterRE.FindString(text); w != "" {
				t.Errorf("%s: literal text outside .L.T near %q: %q", name, w, strings.Join(strings.Fields(text), " "))
			}
		}
	}
}

var (
	sentenceRE  = regexp.MustCompile(`^(%s )?[A-Z][a-z'-]*,? [^<>{}]*$`)
	capitalRE   = regexp.MustCompile(`^[A-Z][a-z]`)
	renderCalls = []string{"errorPage", "simplePage", "actionPage", "stepPage", "mfaPage", "pkNotice", "loginPage",
		"deviceEntry", "brokerFail", "status", "page", "again", "show", "render", "consentPage", "enrollPage", "verifyPage"}
	// calls whose strings are for logs, protocol errors or programmers.
	quietCalls = []string{"Error", "Info", "Warn", "New", "Errorf", "panic", "oerr", "redirectErr", "fail", "parFail", "writeErr"}
	// strings that are not shown on a page or in an email.
	notShown = []string{"Referrer-Policy"}
)

func callName(c *ast.CallExpr) string {
	switch f := c.Fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	}
	return ""
}

func literal(e ast.Expr) (string, bool) {
	l, ok := e.(*ast.BasicLit)
	if !ok || l.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(l.Value)
	return s, err == nil
}

func TestPageMessagesAreTranslated(t *testing.T) {
	for _, file := range localizedFiles {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.CallExpr:
				name := callName(x)
				// logger calls and error constructors never reach a page
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok && slices.Contains(quietCalls, name) {
					if name != "Error" || strings.Contains(types(sel.X), "Logger") {
						return false
					}
				} else if _, plain := x.Fun.(*ast.Ident); plain && name == "panic" {
					return false
				}
				for i, a := range x.Args {
					s, ok := literal(a)
					if !ok {
						continue
					}
					switch {
					case (name == "T" || name == "t") && i == 0:
						translated(t, file, s)
					case slices.Contains(renderCalls, name) && capitalRE.MatchString(s):
						translated(t, file, s)
					}
				}
			case *ast.BasicLit:
				s, ok := literal(x)
				if ok && sentenceRE.MatchString(s) && !slices.Contains(notShown, s) {
					translated(t, file, s)
				}
			}
			return true
		})
	}
}

func types(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return types(x.X) + "." + x.Sel.Name
	}
	return ""
}

// A catalogue entry nothing uses is a typo or a leftover.
func TestNoStaleCatalogueEntries(t *testing.T) {
	used := map[string]bool{}
	for _, tm := range localizedPages() {
		for _, k := range templateKeys(tm) {
			used[k] = true
		}
	}
	err := filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == "i18n" {
			return fs.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path) // #nosec G304 G122 -- repository source files in a test
		if err != nil {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, raw, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if x, ok := n.(*ast.BasicLit); ok {
				if s, ok := literal(x); ok {
					used[s] = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Built with a format string in the password package.
	used["password policy: %s(%d) not satisfied"] = true
	for _, k := range i18n.Keys("de") {
		if !used[k] {
			t.Errorf("catalogue entry %q is used nowhere", k)
		}
	}
}
