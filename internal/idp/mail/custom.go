// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package mail

import (
	"errors"
	"fmt"
	"html"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zyvorai/haven/internal/idp/i18n"
)

// A realm's own email wording. It is NOT a Go template: the only syntax is
// {{name}}, replaced once by the value of a variable from a fixed list per
// kind. There are no conditionals, loops, functions or field access, so a
// template cannot execute anything or read anything it was not given.
//
// The second rule is that a template cannot send the reader anywhere but to
// us: the only link it may contain is {{link}}, which the server fills with its
// own single-use URL. Literal web addresses, e-mail addresses and anything a
// mail program would turn into a link are refused, and HTML is limited to a
// short list of formatting tags with no images and no other URL-bearing
// attribute.

// Custom is a realm's template for one kind and language.
type Custom struct {
	Subject string
	Text    string
	HTML    string // optional
}

const (
	maxSubject = 200
	maxText    = 16 << 10
	maxHTML    = 64 << 10
	linkVar    = "link"
)

type kindSpec struct {
	kind Kind
	vars []string
}

var kindSpecs = []kindSpec{
	{KindVerifyEmail, []string{"realm", "username", linkVar, "hours"}},
	{KindResetPassword, []string{"realm", "username", linkVar, "hours"}},
	{KindPasswordChanged, []string{"realm", "username", "when", "via"}},
	{KindChangeEmail, []string{"realm", "username", linkVar, "hours"}},
	{KindEmailChangeRequested, []string{"realm", "username", "new_email", "when"}},
	{KindEmailChanged, []string{"realm", "username", "new_email", "when"}},
	{KindCIBAApproval, []string{"realm", "username", linkVar, "client", "binding", "scope", "resources", "minutes"}},
}

// Kinds returns every kind of email, in a fixed order.
func Kinds() []Kind {
	out := make([]Kind, len(kindSpecs))
	for i, s := range kindSpecs {
		out[i] = s.kind
	}
	return out
}

// Variables returns the placeholders a template of kind may use, or nil for an
// unknown kind.
func Variables(kind Kind) []string {
	for _, s := range kindSpecs {
		if s.kind == kind {
			return slices.Clone(s.vars)
		}
	}
	return nil
}

// NeedsLink reports whether emails of kind carry the action link, which a
// template must then include. Kinds that do not must never carry one.
func NeedsLink(kind Kind) bool { return slices.Contains(Variables(kind), linkVar) }

// segment is literal text, or a placeholder when name is set.
type segment struct{ lit, name string }

func parsePlaceholders(s string, allowed []string) ([]segment, error) {
	var out []segment
	for {
		i := strings.Index(s, "{{")
		lit := s
		if i >= 0 {
			lit = s[:i]
		}
		if strings.Contains(lit, "}}") {
			return nil, errors.New(`unmatched "}}"`)
		}
		if lit != "" {
			out = append(out, segment{lit: lit})
		}
		if i < 0 {
			return out, nil
		}
		rest := s[i+2:]
		j := strings.Index(rest, "}}")
		if j < 0 {
			return nil, errors.New(`unmatched "{{"`)
		}
		name := strings.Trim(rest[:j], " ")
		if !slices.Contains(allowed, name) {
			if len(name) > 40 {
				name = name[:40]
			}
			return nil, fmt.Errorf("unknown placeholder %q; available: {{%s}}", name, strings.Join(allowed, "}}, {{"))
		}
		out = append(out, segment{name: name})
		s = rest[j+2:]
	}
}

func checkChars(s string, multiline bool) error {
	if !utf8.ValidString(s) {
		return errors.New("not valid UTF-8")
	}
	for _, r := range s {
		if multiline && (r == '\n' || r == '\r' || r == '\t') {
			continue
		}
		// The two joiners are ordinary spelling in several scripts; other
		// invisible formatting characters (bidirectional overrides, zero
		// width space) can disguise text.
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' ||
			(unicode.Is(unicode.Cf, r) && r != '\u200c' && r != '\u200d') {
			return fmt.Errorf("control or invisible formatting character U+%04X", r)
		}
	}
	return nil
}

// linkLike is what mail programs turn into a link.
var linkLike = []*regexp.Regexp{
	regexp.MustCompile(`://`),
	regexp.MustCompile(`//[^\s/]`),
	regexp.MustCompile(`\\\\`),
	regexp.MustCompile(`(?i)(?:mailto|tel|sms|data|javascript|vbscript|file|ftps?|https?|facetime|skype):\S`),
	regexp.MustCompile(`(?i)www\.`),
	regexp.MustCompile(`@`),
	regexp.MustCompile(`[\p{L}\p{M}\p{N}-]\.(?:[\p{L}\p{M}]{2,}|(?i:xn--))`),
	regexp.MustCompile(`(?:[0-9]{1,3}\.){3}[0-9]{1,3}`),
}

// fold undoes the spellings that hide an address from a plain search but not
// from a mail program: joiners, full-width letters and ideographic full stops.
func fold(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\u200c' || r == '\u200d':
			return -1
		case r == '\u3002' || r == '\uff61':
			return '.'
		case r >= '\uff01' && r <= '\uff5e':
			return r - 0xfee0
		}
		return r
	}, s)
}

func checkProse(s string) error {
	s = fold(s)
	for _, re := range linkLike {
		if m := re.FindString(s); m != "" {
			return fmt.Errorf("contains something a mail program would turn into a link or address (near %q); the only link allowed is {{link}}", m)
		}
	}
	return nil
}

// prose joins the segments for the address check: other placeholders become a
// plain word, so literal text cannot be completed into an address by a value
// ("evil.{{realm}}"), and the link, which must stand alone, becomes a space.
func prose(segs []segment) (string, error) {
	var b strings.Builder
	for i, s := range segs {
		switch s.name {
		case "":
			b.WriteString(s.lit)
		case linkVar:
			alone := func(j int, last bool) bool {
				if j < 0 || j >= len(segs) {
					return true
				}
				if segs[j].name != "" {
					return false
				}
				var r rune
				if last {
					r, _ = utf8.DecodeLastRuneInString(segs[j].lit)
				} else {
					r, _ = utf8.DecodeRuneInString(segs[j].lit)
				}
				return unicode.IsSpace(r)
			}
			if !alone(i-1, true) || !alone(i+1, false) {
				return "", errors.New("{{link}} must stand on its own, separated from other text by a space or line break")
			}
			b.WriteString(" ")
		default:
			b.WriteString("zz")
		}
	}
	return b.String(), nil
}

func hasLink(segs []segment) bool {
	return slices.ContainsFunc(segs, func(s segment) bool { return s.name == linkVar })
}

func checkPlain(s string, vars []string) ([]segment, error) {
	segs, err := parsePlaceholders(s, vars)
	if err != nil {
		return nil, err
	}
	p, err := prose(segs)
	if err != nil {
		return nil, err
	}
	return segs, checkProse(p)
}

// ValidateCustom checks a template of kind. The error text is meant for the
// administrator who wrote it.
func ValidateCustom(kind Kind, c Custom) error {
	vars := Variables(kind)
	if vars == nil {
		return fmt.Errorf("unknown email kind %q", kind)
	}
	needs := NeedsLink(kind)
	if strings.TrimSpace(c.Subject) == "" || utf8.RuneCountInString(c.Subject) > maxSubject {
		return fmt.Errorf("subject is required and at most %d characters", maxSubject)
	}
	if err := checkChars(c.Subject, false); err != nil {
		return fmt.Errorf("subject: %w", err)
	}
	noLink := slices.DeleteFunc(slices.Clone(vars), func(v string) bool { return v == linkVar })
	if _, err := checkPlain(c.Subject, noLink); err != nil {
		return fmt.Errorf("subject: %w", err)
	}
	if strings.TrimSpace(c.Text) == "" || len(c.Text) > maxText {
		return fmt.Errorf("text is required and at most %d bytes", maxText)
	}
	if err := checkChars(c.Text, true); err != nil {
		return fmt.Errorf("text: %w", err)
	}
	segs, err := checkPlain(c.Text, vars)
	if err != nil {
		return fmt.Errorf("text: %w", err)
	}
	if needs && !hasLink(segs) {
		return errors.New("text must contain {{link}}")
	}
	if c.HTML == "" {
		return nil
	}
	if len(c.HTML) > maxHTML {
		return fmt.Errorf("html is at most %d bytes", maxHTML)
	}
	if err := checkChars(c.HTML, true); err != nil {
		return fmt.Errorf("html: %w", err)
	}
	links, err := checkHTML(c.HTML, vars)
	if err != nil {
		return fmt.Errorf("html: %w", err)
	}
	if needs && links == 0 {
		return errors.New(`html must contain {{link}}, for example <a href="{{link}}">...</a>`)
	}
	return nil
}

var (
	openTagRE  = regexp.MustCompile(`^<([a-zA-Z][a-zA-Z0-9]*)((?:[ \t\r\n]+[a-zA-Z][a-zA-Z-]*(?:="[^"<>]*")?)*)[ \t\r\n]*/?>`)
	closeTagRE = regexp.MustCompile(`^</([a-zA-Z][a-zA-Z0-9]*)[ \t\r\n]*>`)
	attrRE     = regexp.MustCompile(`([a-zA-Z][a-zA-Z-]*)(?:="([^"<>]*)")?`)
	doctypeRE  = regexp.MustCompile(`^(?i:<!doctype html>)`)
	styleValRE = regexp.MustCompile(`^[a-zA-Z0-9 #%.,'-]*$`)
)

// htmlTags: formatting only. True marks inline elements, whose text runs
// together on screen.
var htmlTags = map[string]bool{
	"a": true, "b": true, "code": true, "em": true, "i": true, "small": true, "span": true, "strong": true, "u": true, "s": true,
	"blockquote": false, "body": false, "br": false, "div": false, "h1": false, "h2": false, "h3": false, "h4": false,
	"head": false, "hr": false, "html": false, "li": false, "meta": false, "ol": false, "p": false, "pre": false,
	"table": false, "tbody": false, "td": false, "th": false, "thead": false, "title": false, "tr": false, "ul": false,
}

var htmlAttrs = map[string]*regexp.Regexp{
	"align":       regexp.MustCompile(`^(?:left|right|center)$`),
	"valign":      regexp.MustCompile(`^(?:top|middle|bottom)$`),
	"dir":         regexp.MustCompile(`^(?:ltr|rtl|auto)$`),
	"lang":        regexp.MustCompile(`^[a-zA-Z-]{1,16}$`),
	"role":        regexp.MustCompile(`^presentation$`),
	"width":       regexp.MustCompile(`^[0-9]{1,4}%?$`),
	"height":      regexp.MustCompile(`^[0-9]{1,4}%?$`),
	"border":      regexp.MustCompile(`^[0-9]{1,2}$`),
	"cellpadding": regexp.MustCompile(`^[0-9]{1,3}$`),
	"cellspacing": regexp.MustCompile(`^[0-9]{1,3}$`),
	"bgcolor":     regexp.MustCompile(`^#[0-9a-fA-F]{6}$`),
}

var styleProps = []string{"background-color", "border", "border-radius", "border-top", "border-bottom", "color",
	"font-family", "font-size", "font-style", "font-weight", "line-height", "margin", "margin-top", "margin-bottom",
	"max-width", "padding", "padding-top", "padding-bottom", "text-align", "text-decoration", "width"}

func checkStyle(v string) error {
	for _, decl := range strings.Split(v, ";") {
		if strings.TrimSpace(decl) == "" {
			continue
		}
		prop, val, ok := strings.Cut(decl, ":")
		if !ok || !slices.Contains(styleProps, strings.ToLower(strings.TrimSpace(prop))) || !styleValRE.MatchString(val) {
			return fmt.Errorf("style declaration %q is not allowed (plain colours, sizes, spacing and fonts only; no functions such as url())", strings.TrimSpace(decl))
		}
	}
	return nil
}

// checkHTML walks the template and returns the number of {{link}} placeholders.
func checkHTML(src string, vars []string) (int, error) {
	if _, err := parsePlaceholders(src, vars); err != nil {
		return 0, err
	}
	links := 0
	var visible strings.Builder
	rest := strings.TrimLeft(src, " \t\r\n")
	rest = doctypeRE.ReplaceAllString(rest, "")
	for rest != "" {
		i := strings.IndexByte(rest, '<')
		text := rest
		if i >= 0 {
			text = rest[:i]
		}
		if text != "" {
			segs, err := parsePlaceholders(text, vars)
			if err != nil {
				return 0, errors.New("a placeholder must not be split by a tag")
			}
			// Entities are decoded before the address check, as a mail program does.
			for j := range segs {
				switch segs[j].name {
				case "":
					segs[j].lit = html.UnescapeString(segs[j].lit)
					if strings.Contains(segs[j].lit, "{{") || strings.Contains(segs[j].lit, "}}") {
						return 0, errors.New("braces written as entities are not allowed")
					}
					if err := checkChars(segs[j].lit, true); err != nil {
						return 0, err
					}
				case linkVar:
					links++
				}
			}
			p, err := prose(segs)
			if err != nil {
				return 0, err
			}
			visible.WriteString(p)
		}
		if i < 0 {
			break
		}
		rest = rest[i:]
		if m := closeTagRE.FindStringSubmatch(rest); m != nil {
			inline, ok := htmlTags[strings.ToLower(m[1])]
			if !ok {
				return 0, fmt.Errorf("element <%s> is not allowed", m[1])
			}
			if !inline {
				visible.WriteString(" ")
			}
			rest = rest[len(m[0]):]
			continue
		}
		m := openTagRE.FindStringSubmatch(rest)
		if m == nil {
			return 0, errors.New(`malformed markup, a comment or a stray "<" (write it as &lt;); attribute values need double quotes`)
		}
		name := strings.ToLower(m[1])
		inline, ok := htmlTags[name]
		if !ok {
			return 0, fmt.Errorf("element <%s> is not allowed (no scripts, styles, images, forms, frames or <link>)", name)
		}
		if !inline {
			visible.WriteString(" ")
		}
		for _, a := range attrRE.FindAllStringSubmatch(m[2], -1) {
			an, av := strings.ToLower(a[1]), a[2]
			switch {
			case name == "meta":
				if an != "charset" || !strings.EqualFold(av, "utf-8") {
					return 0, errors.New(`only <meta charset="utf-8"> is allowed`)
				}
			case an == "href" && name == "a":
				segs, err := parsePlaceholders(av, vars)
				if err != nil || len(segs) != 1 || segs[0].name != linkVar {
					return 0, errors.New(`href must be exactly "{{link}}"; links to other addresses are not allowed`)
				}
				links++
			case an == "style":
				if err := checkStyle(av); err != nil {
					return 0, err
				}
			default:
				re, ok := htmlAttrs[an]
				if !ok || !re.MatchString(av) {
					return 0, fmt.Errorf("attribute %q on <%s> is not allowed or has a value that is not allowed", an, name)
				}
			}
		}
		rest = rest[len(m[0]):]
	}
	return links, checkProse(visible.String())
}

func values(kind Kind, d TemplateData) map[string]string {
	hours := d.Hours
	if hours < 1 {
		hours = 1
	}
	via := ""
	if d.Via != "" {
		via = i18n.T(d.Lang, d.Via)
	}
	all := map[string]string{
		"realm": d.Realm, "username": d.Username, "hours": strconv.Itoa(hours), "when": d.When, "via": via,
		"new_email": d.NewEmail, "client": d.Client, "binding": quoted(d.Binding), "scope": d.Scope,
		"resources": strings.Join(d.Resources, ", "), "minutes": strconv.Itoa(max(1, d.Minutes)), linkVar: "",
	}
	out := map[string]string{}
	for _, v := range Variables(kind) {
		out[v] = all[v]
	}
	return out
}

// RenderCustom validates c again and fills it in. Values are inserted exactly
// once (a value that looks like a placeholder stays literal) and are escaped
// in the HTML part. To is left empty.
func RenderCustom(kind Kind, c Custom, d TemplateData) (Message, error) {
	if err := ValidateCustom(kind, c); err != nil {
		return Message{}, fmt.Errorf("mail: %w", err)
	}
	vals := values(kind, d)
	if NeedsLink(kind) {
		link, err := checkLink(d.Link)
		if err != nil {
			return Message{}, err
		}
		vals[linkVar] = link
	}
	for name, v := range vals {
		if hasCtl(v) {
			return Message{}, fmt.Errorf("mail: %s contains control characters", name)
		}
	}
	fill := func(src string, escape bool) (string, error) {
		segs, err := parsePlaceholders(src, Variables(kind))
		if err != nil {
			return "", err
		}
		var b strings.Builder
		for _, s := range segs {
			switch {
			case s.name == "":
				b.WriteString(s.lit)
			case escape:
				b.WriteString(html.EscapeString(vals[s.name]))
			default:
				b.WriteString(vals[s.name])
			}
		}
		return b.String(), nil
	}
	var m Message
	var err error
	if m.Subject, err = fill(c.Subject, false); err != nil {
		return Message{}, err
	}
	if m.Text, err = fill(c.Text, false); err != nil {
		return Message{}, err
	}
	if c.HTML != "" {
		if m.HTML, err = fill(c.HTML, true); err != nil {
			return Message{}, err
		}
	}
	return m, nil
}
