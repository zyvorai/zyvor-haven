// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package render

import (
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"

	"github.com/zyvorai/haven/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var update = flag.Bool("update", false, "rewrite golden files")

func testPlane(profile v1alpha1.PlaneProfile) *v1alpha1.IdentityPlane {
	return &v1alpha1.IdentityPlane{
		ObjectMeta: metav1.ObjectMeta{Name: "platform", Namespace: "identity"},
		Spec: v1alpha1.IdentityPlaneSpec{
			Engine:   v1alpha1.EngineNative,
			Profile:  profile,
			Hostname: "id.example.com",
		},
	}
}

func golden(t *testing.T, name string, v any) {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := "testdata/" + name + ".golden.json"
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run with -update)", err)
	}
	if string(want) != string(got) {
		t.Fatalf("%s differs from golden; run go test ./internal/render -update and review the diff\n%s", name, got)
	}
}

func TestIdPDeploymentGolden(t *testing.T) {
	p := testPlane(v1alpha1.ProfileProduction)
	golden(t, "idp_deployment_production", IdPDeployment(p, IdPImage(&p.Spec, ""), 3))
	golden(t, "idp_service", IdPService(p))
	golden(t, "idp_pdb", IdPPodDisruptionBudget(p, 3))
	a, _ := json.Marshal(IdPDeployment(p, "img:1", 3))
	b, _ := json.Marshal(IdPDeployment(p, "img:1", 3))
	if string(a) != string(b) {
		t.Fatal("deployment render is not deterministic")
	}
}

func TestIdPDeploymentContract(t *testing.T) {
	p := testPlane(v1alpha1.ProfileDev)
	d := IdPDeployment(p, "img:1", 1)
	pod := d.Spec.Template.Spec
	c := pod.Containers[0]

	if d.Name != "platform-idp" || c.Name != "haven-idp" || len(c.Args) != 1 || c.Args[0] != "serve" {
		t.Fatalf("names/args: %s %s %v", d.Name, c.Name, c.Args)
	}
	if *pod.AutomountServiceAccountToken || *pod.TerminationGracePeriodSeconds != 30 {
		t.Fatal("token automount / grace period")
	}
	sc := c.SecurityContext
	if !*sc.RunAsNonRoot || *sc.RunAsUser != 65532 || !*sc.ReadOnlyRootFilesystem || *sc.AllowPrivilegeEscalation ||
		len(sc.Capabilities.Drop) != 1 || sc.Capabilities.Drop[0] != "ALL" || sc.SeccompProfile.Type != corev1.SeccompProfileTypeRuntimeDefault {
		t.Fatalf("security context: %+v", sc)
	}
	if c.LivenessProbe.HTTPGet.Path != "/healthz" || c.ReadinessProbe.HTTPGet.Path != "/readyz" ||
		c.ReadinessProbe.HTTPGet.Port.StrVal != "http" {
		t.Fatal("probes")
	}
	ru := d.Spec.Strategy.RollingUpdate
	if ru.MaxUnavailable.IntValue() != 0 || ru.MaxSurge.IntValue() != 1 {
		t.Fatal("rolling update")
	}
	if pod.Affinity != nil || len(pod.TopologySpreadConstraints) != 0 {
		t.Fatal("single replica must not carry spread rules")
	}
	if got := IdPDeployment(p, "img:1", 3).Spec.Template.Spec; got.Affinity == nil || len(got.TopologySpreadConstraints) != 1 {
		t.Fatal("multi replica needs anti-affinity and spread")
	}

	for k, v := range d.Spec.Selector.MatchLabels {
		if d.Spec.Template.Labels[k] != v || d.Labels[k] != v {
			t.Fatalf("selector label %s=%s missing on pod/object", k, v)
		}
	}
	if len(d.Spec.Selector.MatchLabels) != 2 {
		t.Fatalf("selector must be name+instance only: %v", d.Spec.Selector.MatchLabels)
	}
	for _, k := range []string{"app.kubernetes.io/name", "app.kubernetes.io/instance", "app.kubernetes.io/part-of",
		"app.kubernetes.io/component", "haven.identity/managed", "haven.identity/plane"} {
		if d.Labels[k] == "" {
			t.Fatalf("missing label %s", k)
		}
	}
}

func TestIdPEnvMapping(t *testing.T) {
	p := testPlane(v1alpha1.ProfileDev)
	p.Spec.ConsoleHostname = "console.example.com"
	env := map[string]corev1.EnvVar{}
	for _, e := range IdPDeployment(p, "img:1", 1).Spec.Template.Spec.Containers[0].Env {
		env[e.Name] = e
	}
	plain := map[string]string{
		"HAVEN_IDP_BASE_URL":          "https://id.example.com",
		"HAVEN_IDP_LISTEN":            ":8081",
		"HAVEN_IDP_TRUST_PROXY":       "1",
		"HAVEN_IDP_BOOTSTRAP_REALM":   "platform",
		"HAVEN_IDP_BOOTSTRAP_USER":    "admin",
		"HAVEN_IDP_CONSOLE_REDIRECTS": "https://console.example.com/api/v1/auth/oidc/callback",
		"HAVEN_IDP_METRICS_LISTEN":    ":9100",
		"HAVEN_IDP_AUDIT":             "stdout",
	}
	for k, v := range plain {
		if env[k].Value != v || env[k].ValueFrom != nil {
			t.Errorf("%s = %+v, want %q", k, env[k], v)
		}
	}
	secrets := map[string][2]string{
		"HAVEN_IDP_DSN":                 {"platform-idp-db", "dsn"},
		"HAVEN_IDP_CSRF_KEY":            {"platform-idp", "csrf-key"},
		"HAVEN_IDP_BOOTSTRAP_PASSWORD":  {"platform-idp", "admin-password"},
		"HAVEN_IDP_ADMIN_CLIENT_SECRET": {"platform-idp", "admin-client-secret"},
	}
	for k, want := range secrets {
		e := env[k]
		if e.Value != "" || e.ValueFrom == nil || e.ValueFrom.SecretKeyRef == nil ||
			e.ValueFrom.SecretKeyRef.Name != want[0] || e.ValueFrom.SecretKeyRef.Key != want[1] {
			t.Errorf("%s = %+v, want secretKeyRef %v", k, e, want)
		}
	}
	if len(env) != len(plain)+len(secrets) {
		t.Errorf("unexpected env count %d", len(env))
	}
	if IdPEnvLeaks(IdPDeployment(p, "img:1", 1).Spec.Template.Spec.Containers[0].Env, "postgres://") {
		t.Fatal("secret material in env value")
	}
}

func TestConfigHashChangesWithConfigOnly(t *testing.T) {
	p := testPlane(v1alpha1.ProfileDev)
	base := IdPDeployment(p, "img:1", 1).Spec.Template.Annotations[AnnotationConfigHash]
	if base == "" {
		t.Fatal("no config hash")
	}
	p.Spec.Hostname = "other.example.com"
	if IdPDeployment(p, "img:1", 1).Spec.Template.Annotations[AnnotationConfigHash] == base {
		t.Fatal("hostname change must change the hash")
	}
}

func TestIdPSecretsAndDSN(t *testing.T) {
	p := testPlane(v1alpha1.ProfileDev)
	db := IdPDBSecret(p, "pa/ss+w")
	if db.Name != "platform-idp-db" || string(db.Data["username"]) != "haven_idp" || string(db.Data["password"]) != "pa/ss+w" {
		t.Fatalf("db secret: %+v", db.Data)
	}
	if got, want := string(db.Data["dsn"]), "postgres://haven_idp:pa%2Fss%2Bw@platform-db-rw.identity.svc:5432/haven_idp?sslmode=require"; got != want {
		t.Fatalf("dsn %q want %q", got, want)
	}
	s := IdPSecret(p, map[string]string{"csrf-key": "x"})
	if s.Name != "platform-idp" || string(s.Data["csrf-key"]) != "x" || len(s.Data) != 1 {
		t.Fatalf("idp secret: %+v", s.Data)
	}
	if IdPPodDisruptionBudget(p, 1) != nil {
		t.Fatal("no PDB for one replica")
	}
}

func TestEngineDependentDatabaseAndEndpoints(t *testing.T) {
	n := testPlane(v1alpha1.ProfileDev)
	k := testPlane(v1alpha1.ProfileDev)
	k.Spec.Engine = v1alpha1.EngineKeycloak

	nested := func(p *v1alpha1.IdentityPlane) (string, string) {
		init := CNPGCluster(p).Object["spec"].(map[string]interface{})["bootstrap"].(map[string]interface{})["initdb"].(map[string]interface{})
		return init["database"].(string), init["owner"].(string)
	}
	if d, o := nested(n); d != "haven_idp" || o != "haven_idp" {
		t.Fatalf("native cnpg: %s %s", d, o)
	}
	if d, o := nested(k); d != "keycloak" || o != "keycloak" {
		t.Fatalf("keycloak cnpg: %s %s", d, o)
	}
	if u := DBAppSecret(n, "x").Object["stringData"].(map[string]interface{})["username"]; u != "haven_idp" {
		t.Fatalf("native app secret user %v", u)
	}
	if u := DBAppSecret(k, "x").Object["stringData"].(map[string]interface{})["username"]; u != "keycloak" {
		t.Fatalf("keycloak app secret user %v", u)
	}
	e := Endpoints(n)
	if e.IdP != "https://id.example.com" || e.Issuer != "https://id.example.com/realms/platform" ||
		e.Console != "https://haven.id.example.com" || e.Account != "" || e.Admin != "" || e.Keycloak != "" {
		t.Fatalf("native endpoints: %+v", e)
	}
	if ke := Endpoints(k); ke.Keycloak == "" || ke.Account == "" || ke.Admin == "" || ke.IdP != "" {
		t.Fatalf("keycloak endpoints: %+v", ke)
	}
}

func TestIdPImage(t *testing.T) {
	s := &v1alpha1.IdentityPlaneSpec{}
	if IdPImage(s, "") != "ghcr.io/zyvorai/haven-idp:latest" {
		t.Fatal("default")
	}
	if IdPImage(s, "reg/idp:9") != "reg/idp:9" {
		t.Fatal("operator default")
	}
	s.IdP.Version = "1.2.3"
	if IdPImage(s, "reg/idp:9") != "ghcr.io/zyvorai/haven-idp:1.2.3" {
		t.Fatal("version")
	}
	s.IdP.Image = "mine/idp:x"
	if IdPImage(s, "reg/idp:9") != "mine/idp:x" {
		t.Fatal("spec image wins")
	}
}

var _ = strings.Contains
