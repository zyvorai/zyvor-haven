// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package core

import "testing"

type fakeFeature interface{ Feature() string }

type base struct{ Store }

type withFeature struct{ base }

func (withFeature) Feature() string { return "yes" }

type wrapper struct{ Store }

func (w wrapper) Unwrap() Store { return w.Store }

func TestStoreAs(t *testing.T) {
	if _, ok := StoreAs[fakeFeature](base{}); ok {
		t.Error("store without the feature reported it")
	}
	if f, ok := StoreAs[fakeFeature](withFeature{}); !ok || f.Feature() != "yes" {
		t.Error("direct implementation not found")
	}
	// Decorators must not hide the feature (the audit wrapper is one).
	if f, ok := StoreAs[fakeFeature](wrapper{wrapper{withFeature{}}}); !ok || f.Feature() != "yes" {
		t.Error("feature hidden by wrappers")
	}
	if _, ok := StoreAs[fakeFeature](wrapper{base{}}); ok {
		t.Error("wrapped store without the feature reported it")
	}
	if _, ok := StoreAs[fakeFeature](nil); ok {
		t.Error("nil store reported a feature")
	}
}
