// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package oidc

import "testing"

// An authenticator that always reports counter 0 has no counter protection:
// single-use challenges are then the only thing stopping a replay.
func TestPasskeyAssertionReplayWithZeroCounter(t *testing.T) {
	for _, mode := range []string{"login", "2fa"} {
		e := newPKEnv(t, nil, nil, nil)
		a := e.register(-7)
		a.Counting, a.SignCount = false, 0
		e.forget()
		var pg pkPage
		if mode == "login" {
			pg = parsePKPage(t, e.loginPage())
		} else {
			pg = parsePKPage(t, e.passwordLogin(pkPW))
		}
		f := assertionForm(pg, mode, a, pkOrigin)
		if w := e.do("POST", authPath+authQuery(nil).Encode(), f); !isCode(w) {
			t.Fatalf("%s: first use failed: %d", mode, w.Code)
		}
		e.forget()
		f.Set("csrf", parsePKPage(t, e.loginPage()).csrf)
		if w := e.do("POST", authPath+authQuery(nil).Encode(), f); isCode(w) {
			t.Fatalf("%s: captured assertion verified twice", mode)
		}
	}
}
