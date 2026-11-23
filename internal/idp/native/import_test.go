// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package native

import (
	"errors"
	"strconv"
	"testing"

	"github.com/zyvorai/haven/internal/idp"
)

func TestImportUsersChunking(t *testing.T) {
	c, f := setup(t)
	users := make([]idp.ImportUser, 1200)
	for i := range users {
		users[i] = idp.ImportUser{Username: "u" + strconv.Itoa(i), Enabled: true}
	}
	users[0].Username = "old0"
	users[600].Username = ""
	res, err := c.ImportUsers(ctx(), "r", users)
	if err != nil {
		t.Fatal(err)
	}
	if f.importCalls != 3 {
		t.Fatalf("requests: %d", f.importCalls)
	}
	if res.Created != 1198 || res.Skipped != 1 || len(res.Errors) != 1 {
		t.Fatalf("result: %+v", res)
	}
	// Errors are capped at 100 across chunks.
	for i := range users {
		users[i].Username = ""
	}
	res, err = c.ImportUsers(ctx(), "r", users)
	if err != nil || len(res.Errors) != 100 {
		t.Fatalf("cap: %v %d", err, len(res.Errors))
	}
}

func TestImportUsersPartialFailure(t *testing.T) {
	c, f := setup(t)
	f.importFailAt = 2
	users := make([]idp.ImportUser, 1200)
	for i := range users {
		users[i] = idp.ImportUser{Username: "u" + strconv.Itoa(i)}
	}
	res, err := c.ImportUsers(ctx(), "r", users)
	if err == nil {
		t.Fatal("want error")
	}
	var se *idp.StatusError
	if !errors.As(err, &se) || se.Code != 500 {
		t.Fatalf("err: %v", err)
	}
	if res == nil || res.Created != 500 || f.importCalls != 2 {
		t.Fatalf("partial: %+v calls=%d", res, f.importCalls)
	}
}
