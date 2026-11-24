// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package deploytest

import (
	"os"
	"path/filepath"
	"testing"
)

// The plain manifest gives the controller read access to Ingresses for the
// registration feature and nothing more: it must not be able to change or
// delete a user's Ingress.
func TestPlainManifestIngressesReadOnly(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "k8s", "controller", "deployment.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	rules := clusterRoleRules(parse(t, raw), "haven-controller")
	for _, verb := range []string{"create", "update", "patch", "delete"} {
		if granted(rules, "networking.k8s.io", "ingresses", verb) {
			t.Errorf("plain manifest grants %q on ingresses; registration only needs get/list/watch", verb)
		}
	}
	for _, verb := range []string{"get", "list", "watch"} {
		if !granted(rules, "networking.k8s.io", "ingresses", verb) {
			t.Errorf("plain manifest lacks %q on ingresses", verb)
		}
	}
}
