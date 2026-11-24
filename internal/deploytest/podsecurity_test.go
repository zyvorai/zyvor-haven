// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package deploytest

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// restrictedViolations returns what Pod Security "restricted" would object to
// in a pod spec. It mirrors the checks the real API server made when these
// manifests were validated against a namespace enforcing that level, so a
// regression here is a regression there.
func restrictedViolations(pod map[string]any) []string {
	var v []string
	podSC := m(pod["securityContext"])
	for _, k := range []string{"hostNetwork", "hostPID", "hostIPC"} {
		if b, _ := pod[k].(bool); b {
			v = append(v, k+" is set")
		}
	}
	for _, vol := range list(pod["volumes"]) {
		if m(vol)["hostPath"] != nil {
			v = append(v, "hostPath volume "+str(m(vol)["name"]))
		}
	}
	seccomp := func(sc map[string]any) string { return str(m(sc["seccompProfile"])["type"]) }
	nonRoot := func(sc map[string]any) (bool, bool) { b, ok := sc["runAsNonRoot"].(bool); return b, ok }
	conts := append(list(pod["containers"]), list(pod["initContainers"])...)
	for _, c := range conts {
		cm := m(c)
		name := str(cm["name"])
		sc := m(cm["securityContext"])
		if p, _ := sc["privileged"].(bool); p {
			v = append(v, name+": privileged")
		}
		if b, ok := sc["allowPrivilegeEscalation"].(bool); !ok || b {
			v = append(v, name+": allowPrivilegeEscalation must be false")
		}
		drops := false
		for _, d := range list(m(sc["capabilities"])["drop"]) {
			drops = drops || strings.EqualFold(str(d), "ALL")
		}
		if !drops {
			v = append(v, name+": capabilities.drop must include ALL")
		}
		if s := seccomp(sc); s == "" && seccomp(podSC) == "" {
			v = append(v, name+": seccompProfile must be RuntimeDefault or Localhost")
		} else if s == "Unconfined" || seccomp(podSC) == "Unconfined" {
			v = append(v, name+": seccompProfile Unconfined")
		}
		if b, ok := nonRoot(sc); ok && !b {
			v = append(v, name+": runAsNonRoot=false")
		} else if !ok {
			if pb, pok := nonRoot(podSC); !pok || !pb {
				v = append(v, name+": runAsNonRoot must be true (container or pod)")
			}
		}
	}
	return v
}

func podSpecOf(o obj) (map[string]any, bool) {
	switch o.kind() {
	case "Deployment", "StatefulSet", "DaemonSet", "Job":
		return m(m(m(o["spec"])["template"])["spec"]), true
	}
	return nil, false
}

func TestWorkloadsArePodSecurityRestricted(t *testing.T) {
	root := repoRoot(t)
	b, err := os.ReadFile(filepath.Join(root, "deploy/k8s/controller/deployment.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	sets := map[string][]obj{"plain controller manifest": parse(t, b)}
	for name, args := range map[string][]string{
		"chart: controller+console": {"--set", "controller.enabled=true", "--set", "console.enabled=true"},
		"chart: idp":                {"--set", "idp.enabled=true", "--set", "idp.baseUrl=https://auth.example.com", "--set", "console.enabled=true"},
	} {
		sets["helm "+name] = run(t, "helm", append([]string{"template", "haven", "charts/haven", "-n", "identity"}, args...)...)
	}
	for name, objs := range sets {
		n := 0
		for _, o := range objs {
			pod, ok := podSpecOf(o)
			if !ok {
				continue
			}
			n++
			if vs := restrictedViolations(pod); len(vs) > 0 {
				t.Errorf("%s: %s/%s would violate Pod Security restricted:\n  %s", name, o.kind(), o.name(), strings.Join(vs, "\n  "))
			}
		}
		if n == 0 {
			t.Errorf("%s: no workloads found, the test checks nothing", name)
		}
	}
}

// The check itself must be able to fail, or a green run proves nothing.
func TestRestrictedCheckCatchesViolations(t *testing.T) {
	bad := map[string]any{"containers": []any{map[string]any{"name": "c", "securityContext": map[string]any{"privileged": true}}}}
	got := fmt.Sprint(restrictedViolations(bad))
	for _, want := range []string{"privileged", "allowPrivilegeEscalation", "capabilities.drop", "seccompProfile", "runAsNonRoot"} {
		if !strings.Contains(got, want) {
			t.Errorf("violation %q not reported: %s", want, got)
		}
	}
	good := map[string]any{
		"securityContext": map[string]any{"runAsNonRoot": true, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
		"containers": []any{map[string]any{"name": "c", "securityContext": map[string]any{
			"allowPrivilegeEscalation": false, "capabilities": map[string]any{"drop": []any{"ALL"}}}}},
	}
	if vs := restrictedViolations(good); len(vs) != 0 {
		t.Errorf("compliant pod flagged: %v", vs)
	}
}
