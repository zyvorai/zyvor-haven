// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package password

import (
	_ "embed"
	"strings"
	"sync"
	"unicode"
)

// commonRaw is the embedded weak-password list: sorted, lower-case,
// newline-delimited. It is PATTERN-DERIVED (see gen_common.go), not a breach
// corpus.
//
//go:embed common.txt
var commonRaw string

var (
	commonOnce sync.Once
	commonSet  map[string]struct{}
)

func commonList() map[string]struct{} {
	commonOnce.Do(func() {
		lines := strings.Split(commonRaw, "\n")
		commonSet = make(map[string]struct{}, len(lines))
		for _, l := range lines {
			if l != "" {
				commonSet[l] = struct{}{}
			}
		}
	})
	return commonSet
}

// CommonListSize reports how many entries the embedded list has.
func CommonListSize() int { return len(commonList()) }

// minStrippedLen is the shortest base word accepted after trailing characters
// are stripped, so "abc1" does not match a hypothetical "abc".
const minStrippedLen = 4

// maxStrip is the most trailing digit/symbol characters removed.
const maxStrip = 3

// leetFold applies the single documented leet-speak mapping:
// 0->o 3->e 4->a 5->s 7->t @->a $->s, and 1->one (l or i, chosen by one).
func leetFold(s string, one rune) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '0':
			return 'o'
		case '1':
			return one
		case '3':
			return 'e'
		case '4':
			return 'a'
		case '5':
			return 's'
		case '7':
			return 't'
		case '@':
			return 'a'
		case '$':
			return 's'
		}
		return r
	}, s)
}

// normalise lower-cases and trims pw.
func normalise(pw string) string { return strings.ToLower(strings.TrimSpace(pw)) }

// IsCommon reports whether pw is "too common": after lower-casing and
// trimming, it matches the list exactly, or after stripping up to three
// trailing non-letter characters (digits or symbols; base must stay at least
// four runes), or after leet-speak folding of any of those forms.
func IsCommon(pw string) bool {
	set := commonList()
	base := []rune(normalise(pw))
	if len(base) == 0 {
		return false
	}
	for strip := 0; strip <= maxStrip; strip++ {
		end := len(base) - strip
		if end < minStrippedLen && strip > 0 {
			break
		}
		if end <= 0 {
			break
		}
		if strip > 0 && unicode.IsLetter(base[end]) {
			break // only digits/symbols are stripped
		}
		cand := string(base[:end])
		if _, ok := set[cand]; ok {
			return true
		}
		if !strings.ContainsAny(cand, "013457@$") {
			continue
		}
		for _, one := range "li" {
			if _, ok := set[leetFold(cand, one)]; ok {
				return true
			}
			if !strings.Contains(cand, "1") {
				break
			}
		}
	}
	return false
}
