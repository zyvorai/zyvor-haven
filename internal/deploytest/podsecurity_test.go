// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package deploytest

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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
		// runAsNonRoot is only enforceable when the kubelet can tell the user is
		// not root: that needs a numeric runAsUser here, or a numeric USER in the
		// image. Our images are distroless "nonroot" (a NAME), which the kubelet
		// cannot verify, so a pod that relies on the image fails at start with
		// "image has non-numeric user (nonroot), cannot verify user is non-root".
		// An API-server dry-run does not catch this; only a real kubelet does.
		uid := func(sc map[string]any) (float64, bool) { f, ok := sc["runAsUser"].(float64); return f, ok }
		if u, ok := uid(sc); ok {
			if u == 0 {
				v = append(v, name+": runAsUser is 0 (root)")
			}
		} else if u, ok := uid(podSC); !ok {
			v = append(v, name+": no numeric runAsUser (container or pod): the kubelet cannot verify runAsNonRoot against a named image user")
		} else if u == 0 {
			v = append(v, name+": pod runAsUser is 0 (root)")
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
	for _, want := range []string{"privileged", "allowPrivilegeEscalation", "capabilities.drop", "seccompProfile", "runAsNonRoot", "numeric runAsUser"} {
		if !strings.Contains(got, want) {
			t.Errorf("violation %q not reported: %s", want, got)
		}
	}
	good := map[string]any{
		"securityContext": map[string]any{"runAsNonRoot": true, "runAsUser": float64(65532), "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
		"containers": []any{map[string]any{"name": "c", "securityContext": map[string]any{
			"allowPrivilegeEscalation": false, "capabilities": map[string]any{"drop": []any{"ALL"}}}}},
	}
	if vs := restrictedViolations(good); len(vs) != 0 {
		t.Errorf("compliant pod flagged: %v", vs)
	}
}

// The exact mistake that shipped: runAsNonRoot true, no numeric user.
func TestRestrictedCheckCatchesUnverifiableNonRoot(t *testing.T) {
	pod := map[string]any{
		"securityContext": map[string]any{"runAsNonRoot": true, "seccompProfile": map[string]any{"type": "RuntimeDefault"}},
		"containers": []any{map[string]any{"name": "c", "securityContext": map[string]any{
			"allowPrivilegeEscalation": false, "capabilities": map[string]any{"drop": []any{"ALL"}}}}},
	}
	if got := fmt.Sprint(restrictedViolations(pod)); !strings.Contains(got, "numeric runAsUser") {
		t.Fatalf("runAsNonRoot without a numeric runAsUser was not flagged: %s", got)
	}
	pod["securityContext"].(map[string]any)["runAsUser"] = float64(0)
	if got := fmt.Sprint(restrictedViolations(pod)); !strings.Contains(got, "root") {
		t.Fatalf("runAsUser 0 was not flagged: %s", got)
	}
}

// Images must declare a numeric USER too, so they are verifiably non-root even
// when a manifest forgets runAsUser.
func TestDockerfilesUseANumericUser(t *testing.T) {
	root := repoRoot(t)
	files, _ := filepath.Glob(filepath.Join(root, "Dockerfile.*"))
	if len(files) == 0 {
		t.Fatal("no Dockerfiles found")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var last string
		for _, line := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "USER ") {
				last = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "USER "))
			}
		}
		if last == "" {
			t.Errorf("%s: no USER instruction (the image would run as root)", filepath.Base(f))
			continue
		}
		uid, _, _ := strings.Cut(last, ":")
		if n, err := strconv.Atoi(uid); err != nil || n == 0 {
			t.Errorf("%s: final USER %q must be a non-zero NUMERIC id", filepath.Base(f), last)
		}
		if strings.Contains(last, "#") {
			t.Errorf("%s: USER line carries a trailing comment, which Dockerfiles treat as part of the value", filepath.Base(f))
		}
	}
}
