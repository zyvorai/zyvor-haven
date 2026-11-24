// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package idmodel

import (
	"testing"

	"github.com/zyvorai/haven/internal/idp"
)

func TestFromClientBackchannelLogoutURL(t *testing.T) {
	if got := FromClient(idp.Client{BackchannelLogoutURL: "https://a/bc"}).BackchannelLogoutURL; got != "https://a/bc" {
		t.Errorf("field: %q", got)
	}
	kc := idp.Client{Attributes: map[string]string{BackchannelLogoutAttr: "https://kc/bc"}}
	if got := FromClient(kc).BackchannelLogoutURL; got != "https://kc/bc" {
		t.Errorf("keycloak attribute: %q", got)
	}
	both := idp.Client{BackchannelLogoutURL: "https://a/bc", Attributes: map[string]string{BackchannelLogoutAttr: "https://kc/bc"}}
	if got := FromClient(both).BackchannelLogoutURL; got != "https://a/bc" {
		t.Errorf("field must win: %q", got)
	}
	if FromClient(idp.Client{}).BackchannelLogoutURL != "" {
		t.Error("unset must be empty")
	}
}
