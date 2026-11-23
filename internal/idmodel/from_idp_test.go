// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package idmodel

import (
	"testing"

	"github.com/zyvorai/haven/internal/idp"
)

func TestFromRealmHardeningNilStaysNil(t *testing.T) {
	if FromRealm(idp.Realm{Realm: "a"}).Hardening != nil {
		t.Fatal("no hardening reported must stay nil")
	}
	s := "none"
	got := FromRealm(idp.Realm{Realm: "a", RealmHardening: &idp.RealmHardening{SSLRequired: &s}})
	if got.Hardening == nil || got.Hardening.TransportSecurity == nil || *got.Hardening.TransportSecurity != "none" {
		t.Fatalf("hardening not mapped: %+v", got.Hardening)
	}
}

func TestFromClientPKCEEitherKey(t *testing.T) {
	for _, k := range PKCEAttrKeys() {
		c := FromClient(idp.Client{ClientID: "x", Attributes: map[string]string{k: " S256 "}})
		if c.PKCEMethod != "S256" {
			t.Errorf("%s: PKCEMethod=%q", k, c.PKCEMethod)
		}
	}
	if FromClient(idp.Client{ClientID: "x"}).PKCEMethod != "" {
		t.Error("unset PKCE must be empty")
	}
}

func TestFromUserServiceAccount(t *testing.T) {
	if !FromUser(idp.User{Username: "service-account-ci"}).IsServiceAccount {
		t.Error("service account prefix not detected")
	}
}
