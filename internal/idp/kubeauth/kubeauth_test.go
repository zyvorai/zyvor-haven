// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package kubeauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	"sigs.k8s.io/yaml"
)

const testIssuer = "https://idp.example.com/realms/platform"

func testCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func section(t *testing.T, o Options, name string) string {
	t.Helper()
	s, err := Sections(o)
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range s {
		if x.Name == name {
			return x.Body
		}
	}
	t.Fatalf("no section %s", name)
	return ""
}

func parseYAML(t *testing.T, doc string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.UnmarshalStrict([]byte(doc), &m); err != nil {
		t.Fatalf("invalid YAML: %v\n%s", err, doc)
	}
	return m
}

func TestFlags(t *testing.T) {
	ca, _ := testCA(t)
	got := section(t, Options{Issuer: testIssuer}, SectionFlags)
	want := `--oidc-issuer-url=https://idp.example.com/realms/platform
--oidc-client-id=kubernetes
--oidc-username-claim=preferred_username
--oidc-username-prefix=haven:
--oidc-groups-claim=groups
--oidc-groups-prefix=haven:
--oidc-signing-algs=ES256
--oidc-required-claim=typ=ID
`
	if got != want {
		t.Fatalf("flags:\n%s", got)
	}
	if got := section(t, Options{Issuer: testIssuer, CAPEM: ca}, SectionFlags); !strings.Contains(got, "--oidc-ca-file="+DefaultNodeCAPath+"\n") {
		t.Fatalf("no CA flag: %s", got)
	}
}

type authnDoc struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	JWT        []struct {
		Issuer struct {
			URL                  string   `json:"url"`
			Audiences            []string `json:"audiences"`
			CertificateAuthority string   `json:"certificateAuthority"`
		} `json:"issuer"`
		ClaimValidationRules []struct {
			Claim         string `json:"claim"`
			RequiredValue string `json:"requiredValue"`
		} `json:"claimValidationRules"`
		ClaimMappings struct {
			Username struct{ Claim, Prefix string } `json:"username"`
			Groups   struct{ Claim, Prefix string } `json:"groups"`
		} `json:"claimMappings"`
		UserValidationRules []struct{ Expression, Message string } `json:"userValidationRules"`
	} `json:"jwt"`
}

func TestAuthnConfig(t *testing.T) {
	ca, _ := testCA(t)
	for _, ver := range []string{AuthnV1, AuthnV1Beta1} {
		body := section(t, Options{Issuer: testIssuer, CAPEM: ca, AuthnVersion: ver, ClientID: "k8s-prod", UsernameClaim: "sub",
			UsernamePrefix: "corp:", GroupsPrefix: "corp-g:"}, SectionAuthn)
		var d authnDoc
		if err := yaml.UnmarshalStrict([]byte(body), &d); err != nil {
			t.Fatalf("%v\n%s", err, body)
		}
		j := d.JWT[0]
		if d.APIVersion != "apiserver.config.k8s.io/"+ver || d.Kind != "AuthenticationConfiguration" || len(d.JWT) != 1 ||
			j.Issuer.URL != testIssuer || len(j.Issuer.Audiences) != 1 || j.Issuer.Audiences[0] != "k8s-prod" ||
			j.Issuer.CertificateAuthority != string(ca) {
			t.Fatalf("issuer: %+v", d)
		}
		if len(j.ClaimValidationRules) != 1 || j.ClaimValidationRules[0].Claim != "typ" || j.ClaimValidationRules[0].RequiredValue != "ID" {
			t.Fatalf("typ rule missing: %+v", j.ClaimValidationRules)
		}
		if j.ClaimMappings.Username.Claim != "sub" || j.ClaimMappings.Username.Prefix != "corp:" ||
			j.ClaimMappings.Groups.Claim != "groups" || j.ClaimMappings.Groups.Prefix != "corp-g:" {
			t.Fatalf("mappings: %+v", j.ClaimMappings)
		}
		all := body
		for _, want := range []string{"!user.username.startsWith('system:')", "user.groups.all(group, !group.startsWith('system:'))"} {
			if !strings.Contains(all, want) || len(j.UserValidationRules) != 2 {
				t.Fatalf("user validation rule %q missing", want)
			}
		}
	}
	if body := section(t, Options{Issuer: testIssuer}, SectionAuthn); strings.Contains(body, "certificateAuthority") {
		t.Fatal("certificateAuthority without a CA")
	}
}

func TestKubeadmK3sAndKubeconfigAreValidYAML(t *testing.T) {
	ca, _ := testCA(t)
	o := Options{Issuer: testIssuer, CAPEM: ca, ClusterName: "prod", Profile: "k8s"}
	ka := parseYAML(t, section(t, o, SectionKubeadm))
	if ka["apiVersion"] != "kubeadm.k8s.io/v1beta4" || ka["kind"] != "ClusterConfiguration" {
		t.Fatalf("kubeadm: %v", ka)
	}
	args := ka["apiServer"].(map[string]any)["extraArgs"].([]any)
	if len(args) != 1 || args[0].(map[string]any)["name"] != "authentication-config" {
		t.Fatalf("the live kubeadm args must be only the authentication config, never flags too: %v", args)
	}
	k3 := parseYAML(t, section(t, o, SectionK3s))
	if l := k3["kube-apiserver-arg+"].([]any); len(l) != 1 || l[0] != "authentication-config=/etc/rancher/k3s/haven/authn.yaml" {
		t.Fatalf("k3s: %v", k3)
	}
	// The commented flag alternative is valid once uncommented.
	for _, name := range []string{SectionKubeadm, SectionK3s} {
		body := section(t, o, name)
		_, alt, ok := strings.Cut(body, "# Alternative with flags")
		if !ok {
			t.Fatalf("%s: no alternative", name)
		}
		var un []string
		for _, l := range strings.Split(alt, "\n")[1:] {
			un = append(un, strings.TrimPrefix(l, "#"))
		}
		text := strings.Join(un, "\n")
		if name == SectionKubeadm {
			text = "apiServer:\n" + text
		} else {
			text = strings.ReplaceAll(strings.TrimPrefix(text, " "), "\n   -", "\n  -")
		}
		parseYAML(t, text)
		if !strings.Contains(alt, "oidc-required-claim") || !strings.Contains(alt, "oidc-signing-algs") {
			t.Fatalf("%s alternative incomplete", name)
		}
	}
	if body := section(t, o, SectionK3s); !strings.Contains(body, "oidc-ca-file=/etc/rancher/k3s/haven/oidc-ca.pem") {
		t.Fatalf("k3s CA path: %s", body)
	}

	kc := parseYAML(t, section(t, o, SectionKubeconfig))
	user := kc["users"].([]any)[0].(map[string]any)
	ex := user["user"].(map[string]any)["exec"].(map[string]any)
	if user["name"] != "haven" || ex["command"] != "haven" || ex["apiVersion"] != "client.authentication.k8s.io/v1" || ex["interactiveMode"] != "Never" {
		t.Fatalf("user: %v", user)
	}
	var got []string
	for _, a := range ex["args"].([]any) {
		got = append(got, a.(string))
	}
	want := "exec-credential --issuer=" + testIssuer + " --client-id=kubernetes --profile=k8s"
	if strings.Join(got, " ") != want {
		t.Fatalf("args %v", got)
	}
	if c := kc["contexts"].([]any)[0].(map[string]any)["context"].(map[string]any); c["cluster"] != "prod" || c["user"] != "haven" {
		t.Fatalf("context: %v", c)
	}
	if !strings.Contains(o.LoginCommand(), `--scope "openid offline_access groups"`) {
		t.Fatalf("login command must request groups: %s", o.LoginCommand())
	}
}

func TestIssuerValidation(t *testing.T) {
	for _, ok := range []string{testIssuer, "https://127.0.0.1:8443/realms/r", "https://h.example/idp/realms/r", "https://[::1]:1/realms/r"} {
		if _, err := ValidateIssuer(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "http://idp.example.com/realms/r", "http://127.0.0.1/realms/r", "idp.example.com/realms/r",
		"https://", "https:idp", "https://u:p@idp.example.com/realms/r", testIssuer + "/", testIssuer + "?a=b", testIssuer + "?",
		testIssuer + "#x", testIssuer + "#", "https://idp.example.com/realms/r\n--anonymous-auth=true", "https://idp.example.com/a b",
		`https://idp.example.com/"`, "https://idp.example.com/'", "https://idp.exämple.com/r", "file:///etc/passwd"} {
		if _, err := ValidateIssuer(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
		if _, err := Sections(Options{Issuer: bad}); err == nil {
			t.Errorf("%q rendered", bad)
		}
	}
}

func TestPrefixAndOptionValidation(t *testing.T) {
	for _, ok := range []string{"haven:", "corp-sso:", "a:", "https://idp.example.com/r:", "haven:team:"} {
		if err := ValidatePrefix(ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	// "-" means "no prefix" to kube-apiserver; "system" + ":masters" would be
	// "system:masters".
	for _, bad := range []string{"", "-", ":", "haven", "system", "system:", "System:", "SYSTEM:x:", "systemx:", "sys tem:", "-x:",
		"a\nb:", "a\"b:", strings.Repeat("a", 80) + ":"} {
		if err := ValidatePrefix(bad); err == nil {
			t.Errorf("prefix %q accepted", bad)
		}
		if bad == "" {
			continue // Options treat "" as the default prefix, never as none
		}
		for _, o := range []Options{{Issuer: testIssuer, GroupsPrefix: bad}, {Issuer: testIssuer, UsernamePrefix: bad}} {
			if _, err := o.Normalize(); err == nil {
				t.Errorf("options with prefix %q accepted", bad)
			}
		}
	}
	n, err := Options{Issuer: testIssuer}.Normalize()
	if err != nil || n.GroupsPrefix != "haven:" || n.UsernamePrefix != "haven:" || n.ClientID != "kubernetes" || n.AuthnVersion != "v1" {
		t.Fatalf("defaults: %+v %v", n, err)
	}
	for name, o := range map[string]Options{
		"client id":  {Issuer: testIssuer, ClientID: "a b"},
		"client id2": {Issuer: testIssuer, ClientID: "x\n--anonymous-auth"},
		"claim":      {Issuer: testIssuer, UsernameClaim: "email"},
		"version":    {Issuer: testIssuer, AuthnVersion: "v1alpha1"},
		"profile":    {Issuer: testIssuer, Profile: "../x"},
		"user":       {Issuer: testIssuer, UserName: "a\nb"},
		"cluster":    {Issuer: testIssuer, ClusterName: "a b"},
		"node path":  {Issuer: testIssuer, NodeCAPath: "relative/ca.pem"},
		"node path2": {Issuer: testIssuer, NodeCAPath: "/a\n--x"},
		"ca":         {Issuer: testIssuer, CAPEM: []byte("junk")},
	} {
		if _, err := o.Normalize(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestParseCARefusesKeys(t *testing.T) {
	cert, key := testCA(t)
	if _, canon, err := ParseCA(append([]byte("subject=CN=t\n"), append(cert, []byte("trailing text\n")...)...)); err != nil || string(canon) != string(cert) {
		t.Fatalf("certificate with surrounding text: %v", err)
	}
	for name, in := range map[string][]byte{
		"key only": key, "cert then key": append(append([]byte{}, cert...), key...), "empty": nil, "text": []byte("hello"),
		"bad cert": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("x")}),
		"huge":     make([]byte, 300<<10),
	} {
		if _, _, err := ParseCA(in); err == nil {
			t.Errorf("%s accepted", name)
		}
		if name == "cert then key" {
			if _, err := Sections(Options{Issuer: testIssuer, CAPEM: in}); err == nil {
				t.Error("a private key reached the generator")
			}
		}
	}
}

func TestBindingRefusals(t *testing.T) {
	for _, bad := range []string{
		"system:masters=view", "/system:masters=view", "System:Masters=view", "SYSTEM:authenticated=view", "system:unauthenticated=view@default",
		"//system:masters=view", " system:masters=view", "=view", "/=view", "devs=", "devs", " devs=view", "devs =view", "de\nvs=view",
		"devs=cluster-admin", "devs=cluster-admin@default", "devs=role/cluster-admin@default",
		"devs=system:masters", "devs=system:node@default", "devs=role/system:x@default", "devs=System:node",
		"devs=Cluster-Admin", "devs=view@", "devs=view@Bad_NS", "devs=view@a@b", "devs=role/x", "devs=role/@default",
		"devs=view \nkind: ClusterRoleBinding", "devs=a/b", "devs=-x", "devs=ClusterRole/cluster-admin",
	} {
		if b, err := ParseBinding(bad, false); err == nil {
			t.Errorf("%q accepted as %+v", bad, b)
		}
	}
	// --allow-cluster-admin opens only cluster-admin, never system:.
	for _, ok := range []string{"devs=cluster-admin", "devs=cluster-admin@default"} {
		if _, err := ParseBinding(ok, true); err != nil {
			t.Errorf("%q with the flag: %v", ok, err)
		}
	}
	for _, bad := range []string{"system:masters=view", "devs=system:node", "system:masters=cluster-admin"} {
		if _, err := ParseBinding(bad, true); err == nil {
			t.Errorf("%q accepted with the flag", bad)
		}
	}
	// The renderer refuses bindings built by hand too.
	for _, b := range []Binding{
		{Group: "system:masters", RoleKind: "ClusterRole", Role: "view"},
		{Group: "devs", RoleKind: "ClusterRole", Role: "cluster-admin"},
		{Group: "devs", RoleKind: "ClusterRole", Role: "system:node"},
		{Group: "devs", RoleKind: "Role", Role: "x"},
		{Group: "devs", RoleKind: "Other", Role: "x"},
	} {
		if _, err := Sections(Options{Issuer: testIssuer, Bindings: []Binding{b}}); err == nil {
			t.Errorf("hand-built %+v rendered", b)
		}
	}
	if _, err := Sections(Options{Issuer: testIssuer, AllowClusterAdmin: true,
		Bindings: []Binding{{Group: "devs", RoleKind: "ClusterRole", Role: "cluster-admin"}}}); err != nil {
		t.Errorf("allowed cluster-admin: %v", err)
	}
	b, _ := ParseBinding("devs=view", false)
	if _, err := Sections(Options{Issuer: testIssuer, Bindings: []Binding{b, b}}); err == nil {
		t.Error("duplicate binding accepted")
	}
}

func TestRBACObjects(t *testing.T) {
	var o Options
	o.Issuer = testIssuer
	for _, s := range []string{"/eng/dev=view", "eng-dev=view", "ops=edit@team-a", "ops=role/deployer@team-a", `weird "g": [x]=view@default`} {
		b, err := ParseBinding(s, false)
		if err != nil {
			t.Fatal(err)
		}
		o.Bindings = append(o.Bindings, b)
	}
	docs := strings.Split(section(t, o, SectionRBAC), "---\n")
	if len(docs) != 5 {
		t.Fatalf("%d docs", len(docs))
	}
	names := map[string]bool{}
	type want struct{ kind, ns, subject, roleKind, role string }
	wants := []want{
		{"ClusterRoleBinding", "", "haven:eng/dev", "ClusterRole", "view"},
		{"ClusterRoleBinding", "", "haven:eng-dev", "ClusterRole", "view"},
		{"RoleBinding", "team-a", "haven:ops", "ClusterRole", "edit"},
		{"RoleBinding", "team-a", "haven:ops", "Role", "deployer"},
		{"RoleBinding", "default", `haven:weird "g": [x]`, "ClusterRole", "view"},
	}
	for i, d := range docs {
		var rb rbacv1.RoleBinding // same shape as ClusterRoleBinding
		if err := yaml.UnmarshalStrict([]byte(d), &rb); err != nil {
			t.Fatalf("%v\n%s", err, d)
		}
		w := wants[i]
		if rb.Kind != w.kind || rb.Namespace != w.ns || len(rb.Subjects) != 1 || rb.Subjects[0].Kind != "Group" ||
			rb.Subjects[0].Name != w.subject || rb.RoleRef.Kind != w.roleKind || rb.RoleRef.Name != w.role ||
			rb.RoleRef.APIGroup != "rbac.authorization.k8s.io" || rb.APIVersion != "rbac.authorization.k8s.io/v1" {
			t.Errorf("doc %d: %+v", i, rb)
		}
		if rb.Name == "" || strings.ContainsAny(rb.Name, "/%: ") || names[rb.Name] {
			t.Errorf("bad or colliding name %q", rb.Name)
		}
		names[rb.Name] = true
	}
	if out := section(t, Options{Issuer: testIssuer}, SectionRBAC); strings.Contains(out, "kind:") {
		t.Errorf("bindings without --bind: %s", out)
	}
}

func TestBindingWarnings(t *testing.T) {
	for s, warn := range map[string]bool{"a=view": false, "a=edit@team": false, "a=admin": true, "a=edit": true,
		"a=edit@kube-system": true, "a=view@kube-system": false, "a=cluster-admin": true, "a=cluster-admin@x": true} {
		b, err := ParseBinding(s, true)
		if err != nil {
			t.Fatal(err)
		}
		if (b.Warning() != "") != warn {
			t.Errorf("%s: warning %q", s, b.Warning())
		}
	}
}
