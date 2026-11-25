// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package branding

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"testing"

	"github.com/zyvorai/haven/internal/idp/core"
)

func TestContrast(t *testing.T) {
	if r := Contrast(RGB{}, RGB{255, 255, 255}); math.Abs(r-21) > 0.01 {
		t.Errorf("black on white = %v", r)
	}
	if r := Contrast(RGB{0x76, 0x76, 0x76}, RGB{255, 255, 255}); r < 4.5 || r > 4.6 {
		t.Errorf("#767676 on white = %v", r)
	}
}

func TestCheckAccent(t *testing.T) {
	for _, c := range []struct {
		light, dark string
		ok          bool
	}{
		{"", "", true},
		{"#0066cc", "", true},
		{"#0066CC", "#66b3ff", true},
		{"#000000", "", true},
		{"#767676", "", true},
		{"#777777", "", false}, // 4.48:1 on white
		{"#ffff00", "", false}, // yellow on white
		{"#ffffff", "", false},
		{"#0071e3", "#003366", false}, // dark accent unreadable on the dark card
		{"#0066cc", "#1d1d1f", false},
		{"", "#66b3ff", false}, // dark without light
		{"0066cc", "", false},
		{"#06c", "", false},
		{"#0066cc;", "", false},
		{"#0066c", "", false},
		{"#gg66cc", "", false},
		{"#+066cc", "", false},
		{"red", "", false},
		{"#0066cc}body{display:none}", "", false},
		{"rgb(0,0,0)", "", false},
		{"#0066cc", "#66b3ff</style><script>", false},
		{"var(--x)", "", false},
	} {
		_, _, err := CheckAccent(c.light, c.dark)
		if (err == nil) != c.ok {
			t.Errorf("CheckAccent(%q, %q) = %v, want ok=%v", c.light, c.dark, err, c.ok)
		}
	}
}

// Every accepted accent produces readable text in both colour schemes: links
// against the card, and button labels against the button, including hover.
func TestAcceptedAccentsAreReadable(t *testing.T) {
	accepted := 0
	for r := 0; r < 256; r += 15 {
		for g := 0; g < 256; g += 15 {
			for b := 0; b < 256; b += 15 {
				in := fmt.Sprintf("#%02x%02x%02x", r, g, b)
				css := CSS(in, "")
				if css == "" {
					continue
				}
				accepted++
				blocks := strings.SplitN(css, "@media", 2)
				for i, block := range blocks {
					card := LightCard
					if i == 1 {
						card = DarkCard
					}
					get := func(name string) RGB {
						m := regexp.MustCompile(`[{;]` + name + `:(#[0-9a-f]{6})`).FindStringSubmatch(block)
						if m == nil {
							t.Fatalf("%s: no %s in %s", in, name, block)
						}
						c, err := ParseColor(m[1])
						if err != nil {
							t.Fatal(err)
						}
						return c
					}
					if x := Contrast(get("--link"), card); x < MinContrast {
						t.Fatalf("%s: link contrast %.2f in block %d", in, x, i)
					}
					on := get("--on-accent")
					for _, bg := range []string{"--accent", "--accent-h", "--accent-a"} {
						if x := Contrast(get(bg), on); x < MinContrast {
							t.Fatalf("%s: label contrast on %s %.2f in block %d", in, bg, x, i)
						}
					}
				}
			}
		}
	}
	if accepted < 500 {
		t.Fatalf("only %d colours accepted", accepted)
	}
}

func TestCSSIsBuiltFromNumbersOnly(t *testing.T) {
	re := regexp.MustCompile(`^(?::root\{(?:--[a-z-]+:(?:#[0-9a-f]{6}|rgba\([0-9]+,[0-9]+,[0-9]+,\.[0-9]+\));?)+\}|@media \(prefers-color-scheme:dark\)\{|\})+$`)
	if css := CSS("#0A6644", "#66ddaa"); !re.MatchString(css) || !strings.Contains(css, "--accent:#0a6644") || !strings.Contains(css, "#66ddaa") {
		t.Errorf("css: %q", css)
	}
	for _, bad := range []string{"#0066cc}*{display:none}", "</style>", "url(https://evil)", "#ffffff"} {
		if CSS(bad, "") != "" || CSS("#ffffff", bad) != "" {
			t.Errorf("CSS emitted for %q as the accent", bad)
		}
	}
	// A bad dark colour drops the whole rule set, not just half of it.
	for _, bad := range []string{"#0066cc}*{display:none}", "</style>", "#111111"} {
		if css := CSS("#0066cc", bad); css != "" {
			t.Errorf("CSS emitted for dark %q: %s", bad, css)
		}
	}
}

func TestCheckLink(t *testing.T) {
	for _, ok := range []string{"", "https://example.com", "https://help.example.com:8443/a?b=c#d", "https://xn--bcher-kva.example/"} {
		if err := CheckLink(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://example.com", "javascript:alert(1)", "data:text/html,x", "//example.com", "/help",
		"example.com", "https://", "https:///x", "https:example.com", "https://user:pw@example.com", "https://user@example.com",
		"https://exa mple.com", "https://example.com/\"x", "https://example.com/<x>", "https://example.com\\@evil",
		"https://example.com/\n", " https://example.com", "https://bücher.example", "https://:443/",
		"https://example.com/" + strings.Repeat("a", 600)} {
		if err := CheckLink(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestCheckName(t *testing.T) {
	for _, ok := range []string{"", "Acme", "Booking.example Co.", "आकमे क्\u200dष", "O'Brien & Sons"} {
		if err := CheckName(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{" x", "x ", "a\nb", "a\x00b", "a\u202eb", "a\u200bb", "a\u2028b", "https://evil", "a@b", "<b>",
		strings.Repeat("a", 65), "\xff"} {
		if err := CheckName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

const goodLogo = `<?xml version="1.0" encoding="UTF-8"?>
<!-- exported -->
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="120px" height="40" viewBox="0 0 120 40" fill="currentColor">
  <g transform="translate(2,2) scale(1.5)" fill="#0a6644">
    <path d="M0 0h10v10H0z" fill-rule="evenodd"/>
    <rect x="12" y="0" width="10" height="10" rx="2" stroke="#000" stroke-width="1.5" stroke-linejoin="round"/>
    <circle cx="30" cy="5" r="5" opacity=".5"/>
    <ellipse cx="44" cy="5" rx="6" ry="4"/>
    <line x1="52" y1="0" x2="60" y2="10" stroke="currentColor"/>
    <polyline points="0,12 5,18 10,12" fill="none"/>
    <polygon points="12 12 18 18 24 12"/>
  </g>
</svg>`

func TestParseLogo(t *testing.T) {
	l, err := ParseLogo(goodLogo)
	if err != nil {
		t.Fatal(err)
	}
	doc := l.Document()
	if strings.Contains(doc, "exported") || strings.Contains(doc, "120px") || !strings.Contains(doc, `viewBox="0 0 120 40"`) {
		t.Errorf("document: %s", doc)
	}
	again, err := ParseLogo(doc)
	if err != nil || again.Document() != doc {
		t.Fatalf("stored form is not stable: %v\n%s", err, doc)
	}
	in := l.Inline("logo", `A"><script>`)
	if !strings.Contains(in, `class="logo"`) || !strings.Contains(in, `width="144" height="48"`) || strings.Contains(in, "<script>") ||
		!strings.Contains(in, `role="img"`) || strings.Contains(in, "xmlns") {
		t.Errorf("inline: %s", in)
	}
	wide, err := ParseLogo(`<svg viewBox="0 0 1000 10"><path d="M0 0h1"/></svg>`)
	if err != nil || !strings.Contains(wide.Inline("logo", "x"), `width="280" height="3"`) {
		t.Errorf("wide logo: %v %s", err, wide.Inline("logo", "x"))
	}
}

func TestParseLogoRefuses(t *testing.T) {
	in := func(s string) string { return `<svg viewBox="0 0 10 10">` + s + `</svg>` }
	for name, src := range map[string]string{
		"script":             in(`<script>alert(1)</script>`),
		"style element":      in(`<style>*{display:none}</style>`),
		"style attr":         in(`<path d="M0 0" style="fill:red"/>`),
		"class attr":         in(`<path d="M0 0" class="err"/>`),
		"id attr":            in(`<path id="hg" d="M0 0"/>`),
		"onload":             `<svg viewBox="0 0 1 1" onload="alert(1)"><path d="M0 0"/></svg>`,
		"onclick":            in(`<path d="M0 0" onclick="x()"/>`),
		"href":               in(`<a href="javascript:alert(1)"><path d="M0 0"/></a>`),
		"xlink":              `<svg xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 1 1"><use xlink:href="#a"/></svg>`,
		"use":                in(`<use href="#a"/>`),
		"image":              in(`<image href="https://evil/x.png"/>`),
		"foreignObject":      in(`<foreignObject><p>x</p></foreignObject>`),
		"animate":            in(`<animate attributeName="href" values="javascript:alert(1)"/>`),
		"set":                in(`<set attributeName="onmouseover" to="alert(1)"/>`),
		"text":               in(`<text>hello</text>`),
		"chardata":           in(`hello`),
		"cdata":              in(`<![CDATA[<script>]]>`),
		"nested svg":         in(`<svg viewBox="0 0 1 1"><path d="M0 0"/></svg>`),
		"html breakout":      in(`<p><path d="M0 0"/></p>`),
		"url paint":          in(`<path d="M0 0" fill="url(#a)"/>`),
		"url external":       in(`<path d="M0 0" fill="url(https://evil/x)"/>`),
		"named colour junk":  in(`<path d="M0 0" fill="expression(alert(1))"/>`),
		"quote in d":         in(`<path d="M0 0&quot;&gt;&lt;script&gt;"/>`),
		"letters in d":       in(`<path d="M0 0 javascript"/>`),
		"bad transform":      in(`<g transform="url(x)"><path d="M0 0"/></g>`),
		"bad number":         in(`<circle r="1;x"/>`),
		"foreign ns":         in(`<x:path xmlns:x="http://evil" d="M0 0"/>`),
		"default ns":         `<svg xmlns="http://www.w3.org/1999/xhtml" viewBox="0 0 1 1"><path d="M0 0"/></svg>`,
		"doctype":            `<!DOCTYPE svg [<!ENTITY a "b">]>` + in(`<path d="M0 0"/>`),
		"entity":             in(`<path d="&a;"/>`),
		"processing":         in(`<?php x ?>`),
		"stylesheet pi":      `<?xml-stylesheet href="x"?>` + in(`<path d="M0 0"/>`),
		"duplicate attr":     in(`<path d="M0 0" d="M1 1"/>`),
		"two roots":          in(`<path d="M0 0"/>`) + in(`<path d="M0 0"/>`),
		"not svg":            `<html></html>`,
		"no viewbox":         `<svg width="1" height="1"><path d="M0 0"/></svg>`,
		"zero viewbox":       `<svg viewBox="0 0 0 10"><path d="M0 0"/></svg>`,
		"nan viewbox":        `<svg viewBox="0 0 NaN 10"><path d="M0 0"/></svg>`,
		"inf viewbox":        `<svg viewBox="0 0 1e999 10"><path d="M0 0"/></svg>`,
		"empty":              in(``),
		"unclosed":           `<svg viewBox="0 0 1 1"><path d="M0 0"/>`,
		"mismatched":         `<svg viewBox="0 0 1 1"><g></svg></g>`,
		"png":                "\x89PNG\r\n\x1a\n",
		"too big":            in(`<path d="` + strings.Repeat("M0 0 ", 4000) + `"/>`),
		"too many":           in(strings.Repeat(`<path d="M0 0"/>`, 201)),
		"too deep":           in(strings.Repeat("<g>", 9) + strings.Repeat("</g>", 9)),
		"data uri":           `data:image/svg+xml;base64,PHN2Zz4=`,
		"leading html":       `<img src=x onerror=alert(1)>`,
		"root attr unknown":  `<svg viewBox="0 0 1 1" preserveAspectRatio="none"><path d="M0 0"/></svg>`,
		"namespaced element": `<svg:svg xmlns:svg="http://www.w3.org/2000/svg" viewBox="0 0 1 1"></svg:svg>`,
	} {
		if _, err := ParseLogo(src); err == nil {
			t.Errorf("%s: accepted", name)
		}
		if got := LogoMarkup(src, "", "x"); got != "" {
			t.Errorf("%s: rendered %s", name, got)
		}
	}
}

func TestLogoMarkup(t *testing.T) {
	a := `<svg viewBox="0 0 10 10"><path d="M0 0h1"/></svg>`
	b := `<svg viewBox="0 0 10 10"><path d="M0 0h2"/></svg>`
	if got := LogoMarkup(a, "", "N"); strings.Count(got, "<svg") != 1 || !strings.Contains(got, `class="logo"`) {
		t.Errorf("single: %s", got)
	}
	got := LogoMarkup(a, b, "N")
	if strings.Count(got, "<svg") != 2 || !strings.Contains(got, `class="logo logo-light"`) || !strings.Contains(got, `class="logo logo-dark"`) {
		t.Errorf("pair: %s", got)
	}
	if got := LogoMarkup(a, "<script>", "N"); strings.Contains(got, "script") || !strings.Contains(got, `class="logo"`) {
		t.Errorf("bad dark logo: %s", got)
	}
	if LogoMarkup("", b, "N") != "" {
		t.Error("dark alone rendered")
	}
}

func TestNormalize(t *testing.T) {
	out, err := Normalize(core.Branding{AccentColor: "#0A6644", LogoLight: goodLogo, DefaultLocale: "de"})
	if err != nil || out.AccentColor != "#0a6644" || !strings.HasPrefix(out.LogoLight, "<svg xmlns=") {
		t.Fatalf("%v %+v", err, out)
	}
	for name, b := range map[string]core.Branding{
		"locale":    {DefaultLocale: "fr"},
		"dark logo": {LogoDark: goodLogo},
		"logo":      {LogoLight: "<svg/>"},
		"dark2":     {LogoLight: goodLogo, LogoDark: "x"},
		"support":   {SupportURL: "http://x.example"},
		"privacy":   {PrivacyURL: "javascript:1"},
		"terms":     {TermsURL: "ftp://x"},
		"colour":    {AccentColor: "#eeeeee"},
		"name":      {DisplayName: "a\nb"},
	} {
		if _, err := Normalize(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func FuzzParseLogo(f *testing.F) {
	f.Add(goodLogo)
	f.Add(`<svg viewBox="0 0 1 1"><g transform="scale(2)"><path d="M0 0"/></g></svg>`)
	allowed := regexp.MustCompile(`^(?:<(?:svg|g|path|rect|circle|ellipse|line|polyline|polygon)(?: [a-zA-Z0-9-]+="[^"<>&]*")*>|</(?:svg|g|path|rect|circle|ellipse|line|polyline|polygon)>)+$`)
	f.Fuzz(func(t *testing.T, s string) {
		l, err := ParseLogo(s)
		if err != nil {
			return
		}
		out := l.Inline("logo", "label")
		if !allowed.MatchString(out) {
			t.Fatalf("output outside the vocabulary: %q from %q", out, s)
		}
	})
}
