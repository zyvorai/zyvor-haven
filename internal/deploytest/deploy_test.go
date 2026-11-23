// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package deploytest renders the kustomize overlays and the Helm chart and asserts the
// haven-idp deployment contract (internal/render/IDP_CONTRACT.md) on the output. It shells out to
// `kubectl kustomize` and `helm template` and skips when those binaries are missing.
package deploytest

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

type obj map[string]any

func (o obj) kind() string { return str(o["kind"]) }
func (o obj) name() string { return str(m(o["metadata"])["name"]) }

func m(v any) map[string]any {
	if x, ok := v.(map[string]any); ok {
		return x
	}
	return map[string]any{}
}

func list(v any) []any {
	if x, ok := v.([]any); ok {
		return x
	}
	return nil
}

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func strMap(v any) map[string]string {
	out := map[string]string{}
	for k, val := range m(v) {
		out[k] = str(val)
	}
	return out
}

func subset(sel, labels map[string]string) bool {
	if len(sel) == 0 {
		return false
	}
	for k, v := range sel {
		if labels[k] != v {
			return false
		}
	}
	return true
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

func parse(t *testing.T, out []byte) []obj {
	t.Helper()
	var objs []obj
	for _, doc := range regexp.MustCompile(`(?m)^---\s*$`).Split(string(out), -1) {
		if strings.TrimSpace(doc) == "" {
			continue
		}
		var o obj
		if err := yaml.Unmarshal([]byte(doc), &o); err != nil {
			t.Fatalf("parse rendered manifest: %v\n%s", err, doc)
		}
		if o.kind() != "" {
			objs = append(objs, o)
		}
	}
	return objs
}

func run(t *testing.T, bin string, args ...string) []obj {
	t.Helper()
	path, err := exec.LookPath(bin)
	if err != nil {
		t.Skipf("%s not installed", bin)
	}
	cmd := exec.Command(path, args...)
	cmd.Dir = repoRoot(t)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", bin, strings.Join(args, " "), err, out)
	}
	return parse(t, out)
}

type external struct{ name, key string }

// secretKeyRefs yields every secretKeyRef (not marked optional) in a pod spec's containers.
func secretKeyRefs(pod map[string]any) (refs []external) {
	for _, c := range list(pod["containers"]) {
		for _, e := range list(m(c)["env"]) {
			ref := m(m(m(e)["valueFrom"])["secretKeyRef"])
			if len(ref) == 0 || ref["optional"] == true {
				continue
			}
			refs = append(refs, external{str(ref["name"]), str(ref["key"])})
		}
	}
	return refs
}

var sensitiveEnv = regexp.MustCompile(`(?i)^(.*_)?(SECRET|PASSWORD|DSN|CSRF_KEY|TOKEN)(_[A-Z]+)?$`)

// checkCommon asserts rules that hold for every rendered set.
//
// allowPlaceholders is true only for the dev overlay, whose Secrets carry marked CHANGE_ME values.
// externals lists Secret keys that are documented as created outside the manifests.
func checkCommon(t *testing.T, objs []obj, allowPlaceholders bool, externals map[string][]string) {
	t.Helper()
	secrets := map[string]map[string]bool{}
	services := map[string]obj{}
	sas := map[string]bool{}
	clusters := map[string]bool{}
	type podInfo struct {
		name   string
		labels map[string]string
		spec   map[string]any
	}
	var pods []podInfo

	for _, o := range objs {
		meta := m(o["metadata"])
		switch o.kind() {
		case "Secret":
			keys := map[string]bool{}
			for k := range m(o["data"]) {
				keys[k] = true
			}
			if len(m(o["stringData"])) > 0 && !allowPlaceholders {
				t.Errorf("Secret %s carries stringData but placeholders are only allowed in the dev overlay", o.name())
			}
			for k, v := range m(o["stringData"]) {
				keys[k] = true
				if allowPlaceholders {
					if k != "username" && !strings.Contains(str(v), "CHANGE_ME") {
						t.Errorf("Secret %s key %s is not a CHANGE_ME placeholder", o.name(), k)
					}
					if str(strMap(meta["annotations"])["haven.identity/dev-placeholder"]) != "true" {
						t.Errorf("Secret %s lacks the haven.identity/dev-placeholder annotation", o.name())
					}
				}
			}
			secrets[o.name()] = keys
		case "Service":
			services[o.name()] = o
		case "ServiceAccount":
			sas[o.name()] = true
		case "Cluster":
			clusters[o.name()] = true
		case "Deployment":
			tpl := m(m(o["spec"])["template"])
			labels := strMap(m(tpl["metadata"])["labels"])
			sel := strMap(m(m(o["spec"])["selector"])["matchLabels"])
			if !subset(sel, labels) {
				t.Errorf("Deployment %s: selector %v is not a subset of pod labels %v", o.name(), sel, labels)
			}
			pods = append(pods, podInfo{o.name(), labels, m(tpl["spec"])})
		}
	}

	// secretKeyRefs resolve to a Secret in the output or a documented external one.
	for _, p := range pods {
		for _, r := range secretKeyRefs(p.spec) {
			if keys, ok := secrets[r.name]; ok {
				if !keys[r.key] {
					t.Errorf("Deployment %s: secret %s has no key %s", p.name, r.name, r.key)
				}
				continue
			}
			found := false
			for _, k := range externals[r.name] {
				found = found || k == r.key
			}
			if !found {
				t.Errorf("Deployment %s: secretKeyRef %s/%s is neither defined here nor documented external", p.name, r.name, r.key)
			}
		}
		// No plaintext secrets in env values.
		for _, c := range list(p.spec["containers"]) {
			for _, e := range list(m(c)["env"]) {
				name := str(m(e)["name"])
				if _, plain := m(e)["value"]; plain && sensitiveEnv.MatchString(name) {
					t.Errorf("Deployment %s: env %s has a plaintext value; use secretKeyRef", p.name, name)
				}
			}
		}
	}

	// Service selectors match pods; named target ports exist.
	for name, svc := range services {
		sel := strMap(m(svc["spec"])["selector"])
		matched := false
		for _, p := range pods {
			if subset(sel, p.labels) {
				matched = true
			}
		}
		// Console Services are not rendered by the chart; only check ones with a selector.
		if len(sel) > 0 && !matched {
			t.Errorf("Service %s selector %v matches no pod template", name, sel)
		}
	}

	// PDB, NetworkPolicy, ServiceMonitor selectors.
	for _, o := range objs {
		switch o.kind() {
		case "PodDisruptionBudget":
			sel := strMap(m(m(o["spec"])["selector"])["matchLabels"])
			ok := false
			for _, p := range pods {
				ok = ok || subset(sel, p.labels)
			}
			if !ok {
				t.Errorf("PDB %s selector %v matches no pod", o.name(), sel)
			}
		case "NetworkPolicy":
			sel := strMap(m(m(o["spec"])["podSelector"])["matchLabels"])
			ok := clusters[sel["cnpg.io/cluster"]]
			for _, p := range pods {
				ok = ok || subset(sel, p.labels)
			}
			if !ok {
				t.Errorf("NetworkPolicy %s podSelector %v matches no pod or CNPG cluster", o.name(), sel)
			}
		case "ServiceMonitor":
			sel := strMap(m(m(o["spec"])["selector"])["matchLabels"])
			var svc obj
			for _, s := range services {
				if subset(sel, strMap(m(s["metadata"])["labels"])) {
					svc = s
				}
			}
			if svc == nil {
				t.Errorf("ServiceMonitor %s selects no Service", o.name())
				continue
			}
			for _, e := range list(m(o["spec"])["endpoints"]) {
				port := str(m(e)["port"])
				found := false
				for _, sp := range list(m(svc["spec"])["ports"]) {
					found = found || str(m(sp)["name"]) == port
				}
				if !found {
					t.Errorf("ServiceMonitor %s endpoint port %q not on Service %s", o.name(), port, svc.name())
				}
			}
		case "Ingress":
			for _, r := range list(m(o["spec"])["rules"]) {
				for _, p := range list(m(m(r)["http"])["paths"]) {
					be := m(m(m(p)["backend"])["service"])
					checkBackend(t, "Ingress "+o.name(), services, str(be["name"]), int(num(m(be["port"])["number"])))
				}
			}
		case "HTTPRoute":
			for _, r := range list(m(o["spec"])["rules"]) {
				for _, b := range list(m(r)["backendRefs"]) {
					checkBackend(t, "HTTPRoute "+o.name(), services, str(m(b)["name"]), int(num(m(b)["port"])))
				}
			}
		}
	}
	_ = sas
}

func num(v any) float64 {
	f, _ := v.(float64)
	return f
}

// checkBackend accepts a Service defined in the output. Backends that are deployed separately
// (the console) are listed in externalBackends.
var externalBackends = map[string]bool{"haven-console": true}

func checkBackend(t *testing.T, from string, services map[string]obj, name string, port int) {
	t.Helper()
	svc, ok := services[name]
	if !ok {
		if !externalBackends[name] {
			t.Errorf("%s: backend Service %s does not exist in the output", from, name)
		}
		return
	}
	for _, sp := range list(m(svc["spec"])["ports"]) {
		if int(num(m(sp)["port"])) == port {
			return
		}
	}
	t.Errorf("%s: Service %s has no port %d", from, name, port)
}

// checkIdpDeployment asserts the haven-idp pod contract.
func checkIdpDeployment(t *testing.T, objs []obj, plane string, wantReplicasPDB bool) {
	t.Helper()
	var dep obj
	sas := map[string]bool{}
	var svc, pdb obj
	for _, o := range objs {
		switch {
		case o.kind() == "Deployment" && o.name() == plane+"-idp":
			dep = o
		case o.kind() == "ServiceAccount":
			sas[o.name()] = true
		case o.kind() == "Service" && o.name() == plane+"-idp":
			svc = o
		case o.kind() == "PodDisruptionBudget" && o.name() == plane+"-idp":
			pdb = o
		}
	}
	if dep == nil {
		t.Fatalf("Deployment %s-idp not rendered", plane)
	}
	if svc == nil {
		t.Errorf("Service %s-idp not rendered", plane)
	}
	if wantReplicasPDB && pdb == nil {
		t.Errorf("replicas > 1 but no PodDisruptionBudget %s-idp", plane)
	}
	if !wantReplicasPDB && pdb != nil {
		t.Errorf("single replica must not render a PDB")
	}

	spec := m(m(m(dep["spec"])["template"])["spec"])
	labels := strMap(m(m(m(dep["spec"])["template"])["metadata"])["labels"])
	for k, v := range map[string]string{
		"app.kubernetes.io/name":      "haven-idp",
		"app.kubernetes.io/instance":  plane,
		"app.kubernetes.io/part-of":   "haven",
		"app.kubernetes.io/component": "identity",
		"haven.identity/managed":      "true",
		"haven.identity/plane":        plane,
	} {
		if labels[k] != v {
			t.Errorf("pod label %s = %q, want %q", k, labels[k], v)
		}
	}
	sel := strMap(m(m(dep["spec"])["selector"])["matchLabels"])
	if len(sel) != 2 || sel["app.kubernetes.io/name"] != "haven-idp" || sel["app.kubernetes.io/instance"] != plane {
		t.Errorf("selector must be exactly name+instance, got %v", sel)
	}
	if spec["automountServiceAccountToken"] != false {
		t.Error("automountServiceAccountToken must be false")
	}
	if !sas[str(spec["serviceAccountName"])] {
		t.Errorf("serviceAccountName %q is not rendered", str(spec["serviceAccountName"]))
	}
	psc := m(spec["securityContext"])
	if psc["runAsNonRoot"] != true || num(psc["runAsUser"]) != 65532 || m(psc["seccompProfile"])["type"] != "RuntimeDefault" {
		t.Errorf("pod securityContext does not match contract: %v", psc)
	}

	cs := list(spec["containers"])
	if len(cs) != 1 {
		t.Fatalf("want 1 container, got %d", len(cs))
	}
	c := m(cs[0])
	if c["name"] != "haven-idp" {
		t.Errorf("container name %v", c["name"])
	}
	if fmt.Sprint(c["args"]) != "[serve]" {
		t.Errorf("args = %v, want [serve]", c["args"])
	}
	ports := map[string]float64{}
	for _, p := range list(c["ports"]) {
		ports[str(m(p)["name"])] = num(m(p)["containerPort"])
	}
	if ports["http"] != 8081 || ports["metrics"] != 9100 {
		t.Errorf("ports = %v", ports)
	}
	for probe, path := range map[string]string{"livenessProbe": "/healthz", "readinessProbe": "/readyz"} {
		hg := m(m(c[probe])["httpGet"])
		if hg["path"] != path || hg["port"] != "http" {
			t.Errorf("%s = %v, want GET %s on http", probe, hg, path)
		}
	}
	sc := m(c["securityContext"])
	caps := fmt.Sprint(m(sc["capabilities"])["drop"])
	if sc["allowPrivilegeEscalation"] != false || sc["readOnlyRootFilesystem"] != true || sc["runAsNonRoot"] != true ||
		caps != "[ALL]" || m(sc["seccompProfile"])["type"] != "RuntimeDefault" {
		t.Errorf("container securityContext does not match contract: %v", sc)
	}

	env := map[string]map[string]any{}
	for _, e := range list(c["env"]) {
		env[str(m(e)["name"])] = m(e)
	}
	wantRef := map[string][2]string{
		"HAVEN_IDP_DSN":                 {plane + "-idp-db", "dsn"},
		"HAVEN_IDP_CSRF_KEY":            {plane + "-idp", "csrf-key"},
		"HAVEN_IDP_BOOTSTRAP_PASSWORD":  {plane + "-idp", "admin-password"},
		"HAVEN_IDP_ADMIN_CLIENT_SECRET": {plane + "-idp", "admin-client-secret"},
	}
	for name, w := range wantRef {
		ref := m(m(env[name]["valueFrom"])["secretKeyRef"])
		if str(ref["name"]) != w[0] || str(ref["key"]) != w[1] {
			t.Errorf("env %s secretKeyRef = %v, want %v", name, ref, w)
		}
	}
	wantVal := map[string]string{
		"HAVEN_IDP_LISTEN":         ":8081",
		"HAVEN_IDP_TRUST_PROXY":    "1",
		"HAVEN_IDP_BOOTSTRAP_USER": "admin",
		"HAVEN_IDP_METRICS_LISTEN": ":9100",
		"HAVEN_IDP_AUDIT":          "stdout",
	}
	for name, v := range wantVal {
		if str(env[name]["value"]) != v {
			t.Errorf("env %s = %q, want %q", name, str(env[name]["value"]), v)
		}
	}
	for _, name := range []string{"HAVEN_IDP_BASE_URL", "HAVEN_IDP_BOOTSTRAP_REALM"} {
		if str(env[name]["value"]) == "" {
			t.Errorf("env %s missing", name)
		}
	}
}

var idpExternals = func(plane string) map[string][]string {
	return map[string][]string{
		plane + "-idp":    {"csrf-key", "admin-password", "admin-client-secret"},
		plane + "-idp-db": {"username", "password", "dsn"},
	}
}

func TestDevOverlay(t *testing.T) {
	objs := run(t, "kubectl", "kustomize", "deploy/overlays/dev")
	checkCommon(t, objs, true, nil)
	checkIdpDeployment(t, objs, "platform", false)
	for _, o := range objs {
		if o.kind() == "Deployment" && strings.Contains(o.name(), "keycloak") {
			t.Error("dev overlay must not deploy Keycloak")
		}
	}
	// The CNPG bootstrap secret and the idp DSN must agree on the role.
	var dsn, owner string
	for _, o := range objs {
		if o.kind() == "Secret" && o.name() == "platform-idp-db" {
			dsn = str(m(o["stringData"])["dsn"])
		}
		if o.kind() == "Cluster" {
			owner = str(m(m(m(o["spec"])["bootstrap"])["initdb"])["owner"])
		}
	}
	if owner != "haven_idp" || !strings.Contains(dsn, "postgres://haven_idp:") || !strings.Contains(dsn, "/haven_idp?sslmode=require") {
		t.Errorf("db owner %q / dsn do not agree on haven_idp", owner)
	}
}

func TestProdOverlay(t *testing.T) {
	objs := run(t, "kubectl", "kustomize", "deploy/overlays/prod")
	checkCommon(t, objs, false, idpExternals("platform"))
	checkIdpDeployment(t, objs, "platform", true)
	var np obj
	for _, o := range objs {
		if o.kind() == "NetworkPolicy" && o.name() == "platform-idp" {
			np = o
		}
	}
	if np == nil {
		t.Fatal("prod overlay lacks NetworkPolicy platform-idp")
	}
	ports := map[string]bool{}
	for _, r := range list(m(np["spec"])["ingress"]) {
		for _, p := range list(m(r)["ports"]) {
			ports[fmt.Sprint(m(p)["port"])] = true
		}
	}
	if !ports["8081"] || !ports["9100"] {
		t.Errorf("NetworkPolicy must allow 8081 and 9100 ingress, got %v", ports)
	}
	egress := fmt.Sprint(m(np["spec"])["egress"])
	if !strings.Contains(egress, "53") || !strings.Contains(egress, "5432") {
		t.Errorf("NetworkPolicy egress must allow DNS and 5432: %s", egress)
	}
}

func TestChart(t *testing.T) {
	cases := []struct {
		name string
		args []string
		idp  bool
		pdb  bool
	}{
		{"default", nil, false, false},
		{"native-workloads", []string{"--set", "controller.enabled=true", "--set", "console.enabled=true"}, false, false},
		{"keycloak", []string{"--set", "identity.backend=keycloak", "--set", "console.enabled=true", "--set", "controller.enabled=true"}, false, false},
		{"idp", []string{"--set", "idp.enabled=true", "--set", "idp.baseUrl=https://auth.example.com", "--set", "console.enabled=true"}, true, false},
		{"idp-ha-monitoring", []string{"--set", "idp.enabled=true", "--set", "idp.baseUrl=https://auth.example.com", "--set", "idp.replicas=3", "--set", "observability.serviceMonitor=true"}, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			objs := run(t, "helm", append([]string{"template", "haven", "charts/haven", "-n", "identity"}, tc.args...)...)
			checkCommon(t, objs, false, idpExternals("platform"))
			if tc.idp {
				checkIdpDeployment(t, objs, "platform", tc.pdb)
			}
			hasMon := false
			for _, o := range objs {
				hasMon = hasMon || o.kind() == "ServiceMonitor"
			}
			if hasMon != (tc.name == "idp-ha-monitoring") {
				t.Errorf("ServiceMonitor rendered = %v", hasMon)
			}
		})
	}
}

func TestChartConsoleBackendEnv(t *testing.T) {
	envOf := func(objs []obj) map[string]bool {
		got := map[string]bool{}
		for _, o := range objs {
			if o.kind() == "Deployment" && o.name() == "haven-console" {
				for _, c := range list(m(m(m(o["spec"])["template"])["spec"])["containers"]) {
					for _, e := range list(m(c)["env"]) {
						got[str(m(e)["name"])] = true
					}
				}
			}
		}
		return got
	}
	native := envOf(run(t, "helm", "template", "haven", "charts/haven", "--set", "console.enabled=true"))
	for _, n := range []string{"HAVEN_IDP_BACKEND", "HAVEN_IDP_URL", "HAVEN_IDP_ADMIN_REALM", "HAVEN_IDP_ADMIN_CLIENT_SECRET"} {
		if !native[n] {
			t.Errorf("native console missing env %s", n)
		}
	}
	kc := envOf(run(t, "helm", "template", "haven", "charts/haven", "--set", "console.enabled=true", "--set", "identity.backend=keycloak"))
	if !kc["KEYCLOAK_URL"] || kc["HAVEN_IDP_BACKEND"] {
		t.Errorf("keycloak backend env wrong: %v", kc)
	}
}

func TestRBACSecretsNeverDelete(t *testing.T) {
	objs := run(t, "helm", "template", "haven", "charts/haven")
	for _, o := range objs {
		if o.kind() != "ClusterRole" {
			continue
		}
		for _, r := range list(o["rules"]) {
			rule := m(r)
			if !strings.Contains(fmt.Sprint(rule["resources"]), "secrets") {
				continue
			}
			if strings.Contains(fmt.Sprint(rule["verbs"]), "delete") {
				t.Error("controller must not be able to delete secrets")
			}
		}
	}
}
