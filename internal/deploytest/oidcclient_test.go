// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package deploytest

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"

	havenv1 "github.com/zyvorai/haven/api/v1alpha1"
	"sigs.k8s.io/yaml"
)

const crdFile = "haven.identity_identityplanes.yaml"

func oidcClientCRD(t *testing.T, raw []byte) obj {
	t.Helper()
	var found []obj
	for _, o := range parse(t, raw) {
		if o.kind() == "CustomResourceDefinition" && o.name() == "oidcclients.identity.haven.dev" {
			found = append(found, o)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one oidcclients CRD, found %d", len(found))
	}
	return found[0]
}

func oidcSchema(t *testing.T, crd obj) map[string]any {
	t.Helper()
	vs := list(m(crd["spec"])["versions"])
	if len(vs) != 1 {
		t.Fatalf("want one version, got %d", len(vs))
	}
	return m(m(m(vs[0])["schema"])["openAPIV3Schema"])
}

func TestOIDCClientCRDShape(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "config", "crd", crdFile))
	if err != nil {
		t.Fatal(err)
	}
	crd := oidcClientCRD(t, raw)
	spec := m(crd["spec"])
	names := m(spec["names"])
	if str(spec["group"]) != havenv1.Group || str(names["kind"]) != "OIDCClient" || str(names["plural"]) != "oidcclients" || str(spec["scope"]) != "Namespaced" {
		t.Errorf("CRD identity wrong: group=%v names=%v scope=%v", spec["group"], names, spec["scope"])
	}
	v := m(list(spec["versions"])[0])
	if str(v["name"]) != havenv1.Version || len(m(m(v["subresources"])["status"])) != 0 || m(v["subresources"])["status"] == nil {
		t.Errorf("CRD must serve %s with a status subresource: %v", havenv1.Version, v)
	}
	props := m(m(oidcSchema(t, crd)["properties"])["spec"])
	if fmt.Sprint(props["required"]) != "[planeRef]" {
		t.Errorf("spec.required = %v, want [planeRef]", props["required"])
	}
	sp := m(props["properties"])
	if fmt.Sprint(m(sp["deletionPolicy"])["enum"]) != "[Delete Retain]" || str(m(sp["deletionPolicy"])["default"]) != "Delete" {
		t.Errorf("deletionPolicy enum/default wrong: %v", sp["deletionPolicy"])
	}
	if m(sp["pkce"])["default"] != true {
		t.Errorf("pkce must default to true: %v", sp["pkce"])
	}
	ref := m(m(m(sp["planeRef"])["properties"])["name"])
	if str(ref["type"]) != "string" {
		t.Errorf("planeRef.name missing: %v", sp["planeRef"])
	}
}

// goFields returns the JSON field names of a struct type, recursing into nested
// structs and slices of structs; metav1 types are leaves.
func goFields(t reflect.Type) map[string]any {
	out := map[string]any{}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		ft := f.Type
		for ft.Kind() == reflect.Ptr || ft.Kind() == reflect.Slice {
			ft = ft.Elem()
		}
		if ft.Kind() == reflect.Struct && ft.PkgPath() == t.PkgPath() {
			out[name] = goFields(ft)
		} else {
			out[name] = nil
		}
	}
	return out
}

func crdFields(schema map[string]any) map[string]any {
	out := map[string]any{}
	if items := m(schema["items"]); len(items) > 0 {
		schema = items
	}
	for name, p := range m(schema["properties"]) {
		sub := m(p)
		if len(m(sub["properties"])) > 0 || len(m(m(sub["items"])["properties"])) > 0 {
			out[name] = crdFields(sub)
		} else {
			out[name] = nil
		}
	}
	return out
}

func diffFields(path string, goF, crdF map[string]any, errs *[]string) {
	var keys []string
	seen := map[string]bool{}
	for k := range goF {
		seen[k] = true
		keys = append(keys, k)
	}
	for k := range crdF {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		g, inGo := goF[k]
		c, inCRD := crdF[k]
		switch {
		case !inGo:
			*errs = append(*errs, fmt.Sprintf("%s.%s is in the CRD but not in the Go type", path, k))
		case !inCRD:
			*errs = append(*errs, fmt.Sprintf("%s.%s is in the Go type but not in the CRD", path, k))
		default:
			gm, _ := g.(map[string]any)
			cm, _ := c.(map[string]any)
			if k == "conditions" {
				// metav1.Condition lives in another package, so goFields sees a leaf.
				continue
			}
			if (gm == nil) != (cm == nil) {
				*errs = append(*errs, fmt.Sprintf("%s.%s: nested in only one of Go type and CRD", path, k))
			} else if gm != nil {
				diffFields(path+"."+k, gm, cm, errs)
			}
		}
	}
}

// The Go API type and the CRD schema are written by hand; a field added to one
// and not the other would be silently pruned by the API server (or never read).
func TestOIDCClientCRDMatchesGoType(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "config", "crd", crdFile))
	if err != nil {
		t.Fatal(err)
	}
	props := m(oidcSchema(t, oidcClientCRD(t, raw))["properties"])
	var errs []string
	diffFields("spec", goFields(reflect.TypeOf(havenv1.OIDCClientSpec{})), crdFields(m(props["spec"])), &errs)
	// Conditions are metav1.Condition (a leaf for goFields); the CRD declares its fields.
	diffFields("status", goFields(reflect.TypeOf(havenv1.OIDCClientStatus{})), crdFields(m(props["status"])), &errs)
	for _, e := range errs {
		t.Error(e)
	}
}

// validate checks v against a structural OpenAPI v3 schema (the subset the CRD
// uses) and returns every violation. Unknown fields are errors, as pruning
// would drop them silently.
func validate(path string, schema map[string]any, v any, errs *[]string) {
	bad := func(f string, a ...any) { *errs = append(*errs, path+": "+fmt.Sprintf(f, a...)) }
	switch str(schema["type"]) {
	case "object":
		obj, ok := v.(map[string]any)
		if !ok {
			bad("want object, got %T", v)
			return
		}
		props := m(schema["properties"])
		for _, r := range list(schema["required"]) {
			if _, ok := obj[str(r)]; !ok {
				bad("required field %q missing", str(r))
			}
		}
		keys := make([]string, 0, len(obj))
		for k := range obj {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p, ok := props[k]
			if !ok {
				if schema["x-kubernetes-preserve-unknown-fields"] != true {
					bad("unknown field %q", k)
				}
				continue
			}
			validate(path+"."+k, m(p), obj[k], errs)
		}
	case "array":
		arr, ok := v.([]any)
		if !ok {
			bad("want array, got %T", v)
			return
		}
		if mx, ok := schema["maxItems"].(float64); ok && float64(len(arr)) > mx {
			bad("more than %v items", mx)
		}
		for i, e := range arr {
			validate(fmt.Sprintf("%s[%d]", path, i), m(schema["items"]), e, errs)
		}
	case "string":
		s, ok := v.(string)
		if !ok {
			bad("want string, got %T", v)
			return
		}
		if mx, ok := schema["maxLength"].(float64); ok && float64(len(s)) > mx {
			bad("longer than %v", mx)
		}
		if mn, ok := schema["minLength"].(float64); ok && float64(len(s)) < mn {
			bad("shorter than %v", mn)
		}
		if pat := str(schema["pattern"]); pat != "" && !regexp.MustCompile(pat).MatchString(s) {
			bad("%q does not match %s", s, pat)
		}
		if en := list(schema["enum"]); len(en) > 0 {
			ok := false
			for _, e := range en {
				ok = ok || e == s
			}
			if !ok {
				bad("%q not in enum %v", s, en)
			}
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			bad("want boolean, got %T", v)
		}
	case "integer":
		if _, ok := v.(float64); !ok {
			bad("want integer, got %T", v)
		}
	}
}

func TestOIDCClientSamplesMatchCRDAndType(t *testing.T) {
	root := repoRoot(t)
	crdRaw, err := os.ReadFile(filepath.Join(root, "config", "crd", crdFile))
	if err != nil {
		t.Fatal(err)
	}
	specSchema := m(m(oidcSchema(t, oidcClientCRD(t, crdRaw))["properties"])["spec"])

	total := 0
	for _, f := range []string{"oidcclient.yaml", "identityplane-prod.yaml"} {
		raw, err := os.ReadFile(filepath.Join(root, "config", "samples", f))
		if err != nil {
			t.Fatal(err)
		}
		for _, o := range parse(t, raw) {
			if o.kind() != "OIDCClient" && o.kind() != "OidcClient" {
				continue
			}
			total++
			if o.kind() != "OIDCClient" {
				t.Errorf("%s: %s still uses the old kind %s", f, o.name(), o.kind())
				continue
			}
			var errs []string
			validate("spec", specSchema, o["spec"], &errs)
			for _, e := range errs {
				t.Errorf("%s/%s violates the CRD: %s", f, o.name(), e)
			}
			doc, err := yaml.Marshal(o)
			if err != nil {
				t.Fatal(err)
			}
			var oc havenv1.OIDCClient
			if err := yaml.UnmarshalStrict(doc, &oc); err != nil {
				t.Errorf("%s/%s does not decode strictly into the API type: %v", f, o.name(), err)
			}
		}
	}
	if total < 4 {
		t.Errorf("found %d OIDCClient samples, want the three examples plus the prod sample", total)
	}
}

// The validator itself must reject what the CRD forbids, or the sample test
// above proves nothing.
func TestOIDCClientSchemaValidatorRejects(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "config", "crd", crdFile))
	if err != nil {
		t.Fatal(err)
	}
	specSchema := m(m(oidcSchema(t, oidcClientCRD(t, raw))["properties"])["spec"])
	for name, spec := range map[string]map[string]any{
		"missing planeRef":   {"public": true},
		"unknown field":      {"planeRef": map[string]any{"name": "p"}, "redirects": []any{"x"}},
		"bad policy":         {"planeRef": map[string]any{"name": "p"}, "deletionPolicy": "Maybe"},
		"wrong type":         {"planeRef": map[string]any{"name": "p"}, "public": "yes"},
		"bad client id":      {"planeRef": map[string]any{"name": "p"}, "clientId": "-x"},
		"planeRef as string": {"planeRef": "p"},
	} {
		var errs []string
		validate("spec", specSchema, spec, &errs)
		if len(errs) == 0 {
			t.Errorf("%s: validator accepted an invalid spec", name)
		}
	}
}

// The chart ships the CRDs in crds/; it must stay byte-identical to config/crd,
// which `make crds` and kustomize use, or the two install paths diverge.
func TestChartCRDsMatchConfigCRD(t *testing.T) {
	root := repoRoot(t)
	want, err := os.ReadFile(filepath.Join(root, "config", "crd", crdFile))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "charts", "haven", "crds", "haven.identity_crds.yaml"))
	if err != nil {
		t.Fatalf("chart has no CRD file: %v", err)
	}
	if !bytes.Equal(want, got) {
		t.Error("charts/haven/crds/haven.identity_crds.yaml differs from config/crd/" + crdFile + "; copy it over")
	}
	oidcClientCRD(t, got)
}

// Rendering the chart with --include-crds must emit the OIDCClient CRD once.
func TestChartIncludesOIDCClientCRD(t *testing.T) {
	objs := run(t, "helm", "template", "haven", "charts/haven", "--include-crds")
	n := 0
	for _, o := range objs {
		if o.kind() == "CustomResourceDefinition" && o.name() == "oidcclients.identity.haven.dev" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("helm template --include-crds rendered %d oidcclients CRDs, want 1", n)
	}
}

// The controller ClusterRole in both install paths must allow what the OIDCClient
// reconciler does with Secrets: create, get and update, never delete.
func TestOIDCClientRBACSecretsAndFinalizers(t *testing.T) {
	chart := clusterRoleRules(run(t, "helm", "template", "haven", "charts/haven"), "haven-controller")
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "deploy", "k8s", "controller", "deployment.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	plain := clusterRoleRules(parse(t, raw), "haven-controller")
	for label, rules := range map[string][]any{"helm chart": chart, "plain manifest": plain} {
		for _, verb := range []string{"get", "create", "update", "patch"} {
			if !granted(rules, "", "secrets", verb) {
				t.Errorf("%s: no %q on secrets", label, verb)
			}
		}
		if !granted(rules, havenv1.Group, "oidcclients/finalizers", "update") {
			t.Errorf("%s: no update on oidcclients/finalizers", label)
		}
	}
}
