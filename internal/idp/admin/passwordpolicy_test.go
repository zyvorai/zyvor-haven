// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package admin_test

import "testing"

func TestAdminPasswordResetHonoursPersonalAndCommonRules(t *testing.T) {
	e := newEnv(t)
	r := "/realms/" + realm
	e.api(204, "PUT", r, map[string]any{"realm": realm, "enabled": true,
		"passwordPolicy": "length(8) and notCommon() and notPersonal()"})
	id := e.createID(r+"/users", map[string]any{"username": "Marguerite", "email": "mg@example.com",
		"firstName": "Marguerite", "lastName": "Lindqvist", "enabled": true})
	put := func(want int, pw string) {
		t.Helper()
		e.api(want, "PUT", r+"/users/"+id+"/password", map[string]any{"type": "password", "value": pw})
	}
	put(400, "password123")        // common
	put(400, "xMarguerite-77#q")   // contains the username/first name
	put(400, "Lindqvist-2025-xyz") // contains the last name
	put(204, "Tr0ub4dor&3-xyz")
}
