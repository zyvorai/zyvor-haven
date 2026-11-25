// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package branding

import (
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Logos are accepted as a small subset of SVG: flat shapes with numeric
// geometry and literal colours. The upload is parsed and REBUILT; not one byte
// of it is copied into a page unless it matched one of the closed patterns
// below. Anything outside the subset (scripts, event handlers, style, ids,
// references, links, images, text, foreignObject, other namespaces, entities,
// doctypes) rejects the whole upload rather than being silently removed.
const (
	maxLogoBytes    = 16 << 10
	maxLogoElements = 200
	maxLogoDepth    = 8
	maxCoordinate   = 100000
	logoHeight      = 48
	logoMaxWidth    = 280
	svgNS           = "http://www.w3.org/2000/svg"
)

var (
	numberRE    = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]{1,3})?%?$`)
	pathRE      = regexp.MustCompile(`^[MmZzLlHhVvCcSsQqTtAa0-9eE+\-., \t\r\n]+$`)
	pointsRE    = regexp.MustCompile(`^[0-9eE+\-., \t\r\n]+$`)
	transformRE = regexp.MustCompile(`^(?:(?:translate|scale|rotate|matrix|skewX|skewY) ?\([0-9eE+\-., \t\r\n]*\)[, \t\r\n]*)+$`)
	paintRE     = regexp.MustCompile(`^(?:none|currentColor|#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6})$`)
	keywordRE   = map[string]*regexp.Regexp{
		"fill-rule":       regexp.MustCompile(`^(?:nonzero|evenodd)$`),
		"clip-rule":       regexp.MustCompile(`^(?:nonzero|evenodd)$`),
		"stroke-linecap":  regexp.MustCompile(`^(?:butt|round|square)$`),
		"stroke-linejoin": regexp.MustCompile(`^(?:miter|round|bevel)$`),
	}
)

// presentation attributes every shape and group may carry.
var commonAttrs = []string{"fill", "stroke", "stroke-width", "stroke-linecap", "stroke-linejoin", "stroke-miterlimit",
	"fill-rule", "clip-rule", "opacity", "fill-opacity", "stroke-opacity", "transform"}

// logoElements maps each allowed element to its geometry attributes.
var logoElements = map[string][]string{
	"g":        nil,
	"path":     {"d"},
	"rect":     {"x", "y", "width", "height", "rx", "ry"},
	"circle":   {"cx", "cy", "r"},
	"ellipse":  {"cx", "cy", "rx", "ry"},
	"line":     {"x1", "y1", "x2", "y2"},
	"polyline": {"points"},
	"polygon":  {"points"},
}

// Logo is a parsed, safe logo.
type Logo struct {
	viewBox string
	w, h    float64
	fill    string
	body    string // rebuilt child elements
}

func attrOK(name, v string) bool {
	switch name {
	case "d":
		return pathRE.MatchString(v)
	case "points":
		return pointsRE.MatchString(v)
	case "transform":
		return transformRE.MatchString(v)
	case "fill", "stroke":
		return paintRE.MatchString(v)
	}
	if re, ok := keywordRE[name]; ok {
		return re.MatchString(v)
	}
	return len(v) <= 32 && numberRE.MatchString(v)
}

// ParseLogo validates an SVG document and rebuilds it.
func ParseLogo(src string) (Logo, error) {
	var l Logo
	if len(src) > maxLogoBytes {
		return l, fmt.Errorf("logo is larger than %d bytes", maxLogoBytes)
	}
	if !utf8.ValidString(src) {
		return l, errors.New("logo is not valid UTF-8")
	}
	d := xml.NewDecoder(strings.NewReader(strings.TrimPrefix(src, "\ufeff")))
	d.Strict = true
	var out strings.Builder
	var stack []string
	elements, rootDone := 0, false
	for {
		tok, err := d.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return l, errors.New("logo is not well-formed XML (entities and unquoted attributes are not accepted)")
		}
		switch t := tok.(type) {
		case xml.Comment: // never re-emitted
		case xml.ProcInst:
			if t.Target != "xml" || elements > 0 {
				return l, errors.New("logo: processing instructions are not allowed")
			}
		case xml.Directive:
			return l, errors.New("logo: DOCTYPE and other directives are not allowed")
		case xml.CharData:
			if strings.TrimSpace(string(t)) != "" {
				return l, errors.New("logo: text content is not allowed (convert text to paths)")
			}
		case xml.StartElement:
			elements++
			if elements > maxLogoElements {
				return l, fmt.Errorf("logo has more than %d elements", maxLogoElements)
			}
			if t.Name.Space != "" && t.Name.Space != svgNS {
				return l, errors.New("logo: elements from other namespaces are not allowed")
			}
			name := t.Name.Local
			seen := map[string]bool{}
			for _, a := range t.Attr {
				if a.Name.Space != "" {
					return l, errors.New("logo: namespaced attributes (such as xlink:href) are not allowed")
				}
				if seen[a.Name.Local] {
					return l, errors.New("logo: duplicate attribute")
				}
				seen[a.Name.Local] = true
			}
			if len(stack) == 0 {
				if rootDone || name != "svg" {
					return l, errors.New("logo must be exactly one <svg> document")
				}
				rootDone = true
				if err := l.root(t.Attr); err != nil {
					return l, err
				}
				stack = append(stack, name)
				continue
			}
			geom, ok := logoElements[name]
			if !ok {
				return l, fmt.Errorf("logo: element <%s> is not allowed (only g, path, rect, circle, ellipse, line, polyline, polygon)", clip(name))
			}
			if len(stack) >= maxLogoDepth {
				return l, errors.New("logo is nested too deeply")
			}
			out.WriteString("<" + name)
			for _, a := range t.Attr {
				n := a.Name.Local
				if !slices.Contains(geom, n) && !slices.Contains(commonAttrs, n) {
					return l, fmt.Errorf("logo: attribute %q is not allowed on <%s> (use presentation attributes, not style or class)", clip(n), name)
				}
				v := strings.TrimSpace(a.Value)
				if !attrOK(n, v) {
					return l, fmt.Errorf("logo: attribute %q of <%s> has a value that is not allowed", n, name)
				}
				// Values matched a pattern without quotes, ampersands or angle
				// brackets; escaping is a second line of defence.
				out.WriteString(" " + n + `="` + html.EscapeString(v) + `"`)
			}
			out.WriteString(">")
			stack = append(stack, name)
		case xml.EndElement:
			if len(stack) == 0 {
				return l, errors.New("logo is not well-formed XML")
			}
			name := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if len(stack) > 0 {
				out.WriteString("</" + name + ">")
			}
		}
	}
	if !rootDone || len(stack) != 0 {
		return l, errors.New("logo must be exactly one <svg> document")
	}
	l.body = out.String()
	if l.body == "" {
		return l, errors.New("logo draws nothing")
	}
	if len(l.Document()) > 2*maxLogoBytes {
		return l, errors.New("logo is too large")
	}
	return l, nil
}

func clip(s string) string {
	if len(s) > 32 {
		s = s[:32]
	}
	return s
}

// root validates the attributes of the <svg> element. Only viewBox (required)
// and fill are kept; xmlns, version, width and height are accepted and dropped
// because the page sets the size.
func (l *Logo) root(attrs []xml.Attr) error {
	for _, a := range attrs {
		v := strings.TrimSpace(a.Value)
		switch a.Name.Local {
		case "xmlns":
			if v != svgNS {
				return errors.New("logo: the default namespace must be SVG")
			}
		case "version":
			if v != "1.0" && v != "1.1" && v != "2" {
				return errors.New("logo: unknown SVG version")
			}
		case "width", "height":
			if len(v) > 32 || !numberRE.MatchString(strings.TrimSuffix(v, "px")) {
				return errors.New("logo: width and height must be numbers")
			}
		case "fill":
			if !paintRE.MatchString(v) {
				return errors.New("logo: fill must be a colour")
			}
			l.fill = v
		case "viewBox":
			f := strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' || r == '\n' || r == '\r' })
			if len(f) != 4 {
				return errors.New("logo: viewBox must be four numbers")
			}
			var n [4]float64
			for i, s := range f {
				x, err := strconv.ParseFloat(s, 64)
				if err != nil || math.IsNaN(x) || math.Abs(x) > maxCoordinate || !numberRE.MatchString(s) {
					return errors.New("logo: viewBox must be four numbers")
				}
				n[i] = x
			}
			if n[2] <= 0 || n[3] <= 0 {
				return errors.New("logo: viewBox width and height must be positive")
			}
			l.w, l.h, l.viewBox = n[2], n[3], strings.Join(f, " ")
		default:
			return fmt.Errorf("logo: attribute %q is not allowed on <svg>", clip(a.Name.Local))
		}
	}
	if l.viewBox == "" {
		return errors.New("logo: <svg> needs a viewBox")
	}
	return nil
}

func (l Logo) fillAttr() string {
	if l.fill == "" {
		return ""
	}
	return ` fill="` + html.EscapeString(l.fill) + `"`
}

// Document is the canonical stored form. ParseLogo accepts it unchanged.
func (l Logo) Document() string {
	return `<svg xmlns="` + svgNS + `" viewBox="` + html.EscapeString(l.viewBox) + `"` + l.fillAttr() + `>` + l.body + `</svg>`
}

// Inline is the markup placed in a page: an <svg> element with the given class
// names and accessible label. It needs no Content-Security-Policy permission:
// it is part of the document, loads nothing, and carries no style or script.
func (l Logo) Inline(class, label string) string {
	w, h := math.Round(logoHeight*l.w/l.h), float64(logoHeight)
	if w > logoMaxWidth {
		w, h = logoMaxWidth, math.Round(logoMaxWidth*l.h/l.w)
	}
	w, h = max(w, 1), max(h, 1)
	return `<svg class="` + html.EscapeString(class) + `" viewBox="` + html.EscapeString(l.viewBox) + `" width="` +
		strconv.Itoa(int(w)) + `" height="` + strconv.Itoa(int(h)) + `"` + l.fillAttr() +
		` role="img" aria-label="` + html.EscapeString(label) + `" focusable="false">` + l.body + `</svg>`
}

// LogoMarkup renders the stored logos of a realm for a page, or "" when there
// is none or a stored value no longer passes validation.
func LogoMarkup(light, dark, label string) string {
	if light == "" {
		return ""
	}
	l, err := ParseLogo(light)
	if err != nil {
		return ""
	}
	if dark == "" {
		return l.Inline("logo", label)
	}
	d, err := ParseLogo(dark)
	if err != nil {
		return l.Inline("logo", label)
	}
	return l.Inline("logo logo-light", label) + d.Inline("logo logo-dark", label)
}
