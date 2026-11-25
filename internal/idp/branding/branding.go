// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package branding validates a realm's look (colours, logo, links, name) and
// turns the accent colour into CSS. Every value is checked when it is stored
// and checked again when it is rendered, and nothing an administrator typed is
// ever copied into a stylesheet or into markup as it is: CSS is formatted from
// parsed integers and logos are rebuilt from a closed vocabulary (svg.go).
// See docs/branding-and-i18n.md.
package branding

import (
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/zyvorai/haven/internal/idp/core"
	"github.com/zyvorai/haven/internal/idp/i18n"
)

const (
	// MinContrast is the WCAG 2 AA contrast ratio for body text.
	MinContrast  = 4.5
	maxNameRunes = 64
	maxURL       = 512
)

// RGB is a parsed colour.
type RGB struct{ R, G, B uint8 }

// The card surfaces of the shared theme (internal/idp/oidc/theme.go) that an
// accent colour is read against, and the two possible button label colours.
var (
	LightCard = RGB{0xff, 0xff, 0xff}
	DarkCard  = RGB{0x1d, 0x1d, 0x1f}
	white     = RGB{0xff, 0xff, 0xff}
	black     = RGB{0, 0, 0}
)

// ParseColor accepts exactly "#rrggbb".
func ParseColor(s string) (RGB, error) {
	bad := errors.New(`colour must be written "#rrggbb"`)
	if len(s) != 7 || s[0] != '#' {
		return RGB{}, bad
	}
	// Hex digits only: ParseUint alone would be the same today, but the set
	// of accepted spellings should be visible here.
	if strings.Trim(s[1:], "0123456789abcdefABCDEF") != "" {
		return RGB{}, bad
	}
	var out [3]uint8
	for i := range out {
		v, err := strconv.ParseUint(s[1+2*i:3+2*i], 16, 8)
		if err != nil {
			return RGB{}, bad
		}
		out[i] = uint8(v)
	}
	return RGB{out[0], out[1], out[2]}, nil
}

// String is the canonical "#rrggbb" form.
func (c RGB) String() string { return fmt.Sprintf("#%02x%02x%02x", c.R, c.G, c.B) }

func channel(v uint8) float64 {
	f := float64(v) / 255
	if f <= 0.03928 {
		return f / 12.92
	}
	return math.Pow((f+0.055)/1.055, 2.4)
}

func (c RGB) luminance() float64 {
	return 0.2126*channel(c.R) + 0.7152*channel(c.G) + 0.0722*channel(c.B)
}

// Contrast is the WCAG 2 contrast ratio of two colours, between 1 and 21.
func Contrast(a, b RGB) float64 {
	x, y := a.luminance(), b.luminance()
	if x < y {
		x, y = y, x
	}
	return (x + 0.05) / (y + 0.05)
}

// mix blends t (0..1) of b into a.
func mix(a, b RGB, t float64) RGB {
	m := func(x, y uint8) uint8 {
		v := math.Round(float64(x) + (float64(y)-float64(x))*t)
		return uint8(max(0, min(255, v))) // #nosec G115 -- clamped to 0..255 just above
	}
	return RGB{m(a.R, b.R), m(a.G, b.G), m(a.B, b.B)}
}

// DeriveDark returns the first mix of c with white that is readable on the
// dark card.
func DeriveDark(c RGB) RGB {
	for i := 0; i <= 20; i++ {
		if m := mix(c, white, float64(i)/20); Contrast(m, DarkCard) >= MinContrast {
			return m
		}
	}
	return white
}

// onAccent is the button label colour with the better contrast on c.
func onAccent(c RGB) RGB {
	if Contrast(c, white) >= Contrast(c, black) {
		return white
	}
	return black
}

// CheckAccent validates the accent colours of a realm and returns them in
// canonical form. light is used for links and button fills on the white card
// and so must contrast with it; dark (optional) likewise on the dark card.
func CheckAccent(light, dark string) (string, string, error) {
	if light == "" {
		if dark != "" {
			return "", "", errors.New("accentColorDark needs accentColor")
		}
		return "", "", nil
	}
	l, err := ParseColor(light)
	if err != nil {
		return "", "", fmt.Errorf("accentColor: %w", err)
	}
	if r := Contrast(l, LightCard); r < MinContrast {
		return "", "", fmt.Errorf("accentColor %s is unreadable on a light background: contrast %.2f:1, at least %.1f:1 is required; choose a darker colour", l, r, MinContrast)
	}
	if dark == "" {
		return l.String(), "", nil
	}
	d, err := ParseColor(dark)
	if err != nil {
		return "", "", fmt.Errorf("accentColorDark: %w", err)
	}
	if r := Contrast(d, DarkCard); r < MinContrast {
		return "", "", fmt.Errorf("accentColorDark %s is unreadable on the dark background: contrast %.2f:1, at least %.1f:1 is required; choose a lighter colour", d, r, MinContrast)
	}
	return l.String(), d.String(), nil
}

// DarkAccent is the colour used in dark mode: the realm's own, or derived.
func DarkAccent(light, dark string) string {
	l, d, err := CheckAccent(light, dark)
	if err != nil || l == "" {
		return ""
	}
	if d != "" {
		return d
	}
	c, err := ParseColor(l)
	if err != nil {
		return ""
	}
	return DeriveDark(c).String()
}

func vars(c RGB, shade RGB, ringAlpha string) string {
	on := onAccent(c)
	// Hover and pressed states move away from the label colour, so they are
	// never less readable than the accent itself.
	return fmt.Sprintf(":root{--accent:%s;--accent-h:%s;--accent-a:%s;--link:%s;--on-accent:%s;--ring:rgba(%d,%d,%d,%s)}",
		c, mix(c, shade, 0.08), mix(c, shade, 0.16), c, on, c.R, c.G, c.B, ringAlpha)
}

// CSS returns the stylesheet rules that apply the accent colours, to be placed
// in the page's nonce'd style element after the theme. It returns "" unless
// both stored values still pass CheckAccent; the output is built only from
// parsed integers.
func CSS(light, dark string) string {
	l, d, err := CheckAccent(light, dark)
	if err != nil || l == "" {
		return ""
	}
	lc, err := ParseColor(l)
	if err != nil {
		return ""
	}
	dc := DeriveDark(lc)
	if d != "" {
		if dc, err = ParseColor(d); err != nil {
			return ""
		}
	}
	away := func(c RGB) RGB {
		if onAccent(c) == white {
			return black
		}
		return white
	}
	return vars(lc, away(lc), ".25") + "@media (prefers-color-scheme:dark){" + vars(dc, away(dc), ".35") + "}"
}

// CheckLink accepts "" or an absolute https URL without credentials, written
// in printable ASCII (internationalised host names in their punycode form).
func CheckLink(s string) error {
	if s == "" {
		return nil
	}
	if len(s) > maxURL {
		return fmt.Errorf("link is longer than %d characters", maxURL)
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f || strings.IndexByte("\"'<>\\`", s[i]) >= 0 {
			return errors.New("link contains a space, a quote, a backslash or a non-ASCII character")
		}
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.Opaque != "" || u.User != nil {
		return errors.New("link must be an absolute https URL without user name or password")
	}
	return nil
}

// CheckName accepts "" or a short single-line display name.
func CheckName(s string) error {
	if s == "" {
		return nil
	}
	if !utf8.ValidString(s) || utf8.RuneCountInString(s) > maxNameRunes || strings.TrimSpace(s) != s {
		return fmt.Errorf("displayName must be at most %d characters without leading or trailing space", maxNameRunes)
	}
	for _, r := range s {
		// Format characters include the bidirectional overrides; the two
		// joiners are ordinary spelling in several scripts.
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' ||
			(unicode.Is(unicode.Cf, r) && r != '\u200c' && r != '\u200d') {
			return errors.New("displayName contains a control or invisible formatting character")
		}
	}
	if strings.Contains(s, "://") || strings.ContainsAny(s, "@<>") {
		return errors.New(`displayName must not contain "://", "@", "<" or ">"`)
	}
	return nil
}

// Normalize validates b as a whole and returns the form to store.
func Normalize(b core.Branding) (core.Branding, error) {
	var err error
	if err = CheckName(b.DisplayName); err != nil {
		return b, err
	}
	if b.AccentColor, b.AccentColorDark, err = CheckAccent(b.AccentColor, b.AccentColorDark); err != nil {
		return b, err
	}
	for _, l := range []struct{ name, v string }{{"supportUrl", b.SupportURL}, {"privacyUrl", b.PrivacyURL}, {"termsUrl", b.TermsURL}} {
		if err = CheckLink(l.v); err != nil {
			return b, fmt.Errorf("%s: %w", l.name, err)
		}
	}
	if b.DefaultLocale != "" && !i18n.IsSupported(b.DefaultLocale) {
		return b, fmt.Errorf("defaultLocale must be one of %s", strings.Join(i18n.Supported(), ", "))
	}
	if b.LogoDark != "" && b.LogoLight == "" {
		return b, errors.New("logoDark needs logoLight")
	}
	for _, l := range []struct {
		name string
		v    *string
	}{{"logoLight", &b.LogoLight}, {"logoDark", &b.LogoDark}} {
		if *l.v == "" {
			continue
		}
		logo, err := ParseLogo(*l.v)
		if err != nil {
			return b, fmt.Errorf("%s: %w", l.name, err)
		}
		*l.v = logo.Document()
	}
	return b, nil
}
