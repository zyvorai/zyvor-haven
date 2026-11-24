// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package password

import "strings"

// Personal is what notPersonal() compares a password against.
type Personal struct {
	Username, Email, FirstName, LastName string
}

// minPersonalLen is the shortest identifier considered; shorter ones would
// reject too many innocent passwords.
const minPersonalLen = 4

// containsPersonal reports whether pw contains (case-insensitively, also
// after leet folding) the username, the email local part, or a first/last
// name of at least minPersonalLen runes.
func containsPersonal(pw string, p Personal) bool {
	local := p.Email
	if i := strings.IndexByte(local, '@'); i >= 0 {
		local = local[:i]
	}
	var needles []string
	for _, s := range []string{p.Username, local, p.FirstName, p.LastName} {
		s = normalise(s)
		if len([]rune(s)) >= minPersonalLen {
			needles = append(needles, s)
		}
	}
	if len(needles) == 0 {
		return false
	}
	lower := normalise(pw)
	hay := []string{lower, leetFold(lower, 'l'), leetFold(lower, 'i')}
	for _, n := range needles {
		for _, h := range hay {
			if strings.Contains(h, n) {
				return true
			}
		}
	}
	return false
}
