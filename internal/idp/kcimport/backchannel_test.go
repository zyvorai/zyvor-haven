// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package kcimport

import (
	"strings"
	"testing"
)

func TestBackchannelLogoutMapping(t *testing.T) {
	client := func(attrs string) *Result {
		return conv(t, realmWith(`"clients":[{"clientId":"app","protocol":"openid-connect","publicClient":true,
			"standardFlowEnabled":true,"redirectUris":["https://app.example.com/cb"],"attributes":{`+attrs+`}}]`))
	}
	ok := client(`"backchannel.logout.url":"https://app.example.com/bc"`)
	if got := ok.Spec.Clients[0].BackchannelLogoutURL; got != "https://app.example.com/bc" {
		t.Errorf("valid url not carried: %q", got)
	}
	if ok.Report.WarningCounts["client.backchannel_logout_dropped"] != 0 {
		t.Errorf("unexpected warning: %v", ok.Report.WarningCounts)
	}
	dev := client(`"backchannel.logout.url":"http://localhost:8080/bc"`)
	if dev.Spec.Clients[0].BackchannelLogoutURL == "" {
		t.Error("loopback http must be kept")
	}
	for _, u := range []string{"http://app.example.com/bc", "https://user:pw@app.example.com/bc", "not a url", "https://app.example.com/bc#x"} {
		r := client(`"backchannel.logout.url":"` + u + `"`)
		if r.Spec.Clients[0].BackchannelLogoutURL != "" || r.Report.WarningCounts["client.backchannel_logout_dropped"] != 1 {
			t.Errorf("%q: url=%q warnings=%v", u, r.Spec.Clients[0].BackchannelLogoutURL, r.Report.WarningCounts)
		}
		for _, w := range r.Report.Warnings {
			if strings.Contains(w.Message, "pw") {
				t.Errorf("warning leaks URL credentials: %q", w.Message)
			}
		}
	}
	fc := client(`"frontchannel.logout.url":"https://app.example.com/fc"`)
	if fc.Report.WarningCounts["client.frontchannel_logout_unsupported"] != 1 || fc.Spec.Clients[0].BackchannelLogoutURL != "" {
		t.Errorf("front-channel: %v", fc.Report.WarningCounts)
	}
}
