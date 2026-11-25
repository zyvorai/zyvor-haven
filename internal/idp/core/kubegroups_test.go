// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import "testing"

func TestGroupClaimValue(t *testing.T) {
	for in, want := range map[string]string{
		"/devs": "devs", "/eng/dev": "eng/dev", "/Ops Team": "Ops Team", "/team/system:masters": "team/system:masters",
		"/systems": "systems", "/équipe": "équipe",
	} {
		if got, ok := GroupClaimValue(in); !ok || got != want {
			t.Errorf("%q: %q %v", in, got, ok)
		}
	}
	for _, in := range []string{"", "/", "devs", "system:masters", "/system:masters", "/System:Masters", "/SYSTEM:", "//system:masters",
		"//devs", "/devs/", "/ devs", "/devs ", "/de\nvs", "/de\x00vs", "/de\u200bvs", "/\u202edevs", "/de\xffvs"} {
		if got, ok := GroupClaimValue(in); ok {
			t.Errorf("%q accepted as %q", in, got)
		}
	}
}
