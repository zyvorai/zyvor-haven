// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package render

import (
	"reflect"
	"sort"
	"testing"

	"github.com/zyvorai/haven/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func netpolPlane() *v1alpha1.IdentityPlane {
	return &v1alpha1.IdentityPlane{ObjectMeta: metav1.ObjectMeta{Name: "platform", Namespace: "identity"}}
}

// The policy IS the security contract: who may reach the database, on which
// ports. Pin it exactly so a change has to be deliberate.
func TestDBNetworkPolicyContract(t *testing.T) {
	np := DBNetworkPolicy(netpolPlane(), "")
	if np.Name != "platform-db-ingress" || np.Namespace != "identity" {
		t.Fatalf("name/namespace: %s/%s", np.Namespace, np.Name)
	}
	if !reflect.DeepEqual(np.Spec.PodSelector.MatchLabels, map[string]string{"cnpg.io/cluster": "platform-db"}) {
		t.Errorf("selector: %v", np.Spec.PodSelector.MatchLabels)
	}
	if len(np.Spec.PolicyTypes) != 1 || string(np.Spec.PolicyTypes[0]) != "Ingress" || len(np.Spec.Egress) != 0 {
		t.Fatalf("must be ingress only: %+v", np.Spec)
	}
	type rule struct {
		from  string
		ports []int32
	}
	var got []rule
	for _, r := range np.Spec.Ingress {
		if len(r.From) != 1 {
			t.Fatalf("each rule has exactly one source: %+v", r)
		}
		var from string
		switch p := r.From[0]; {
		case p.PodSelector != nil && p.NamespaceSelector == nil:
			from = "pods:" + labelStr(p.PodSelector.MatchLabels)
		case p.NamespaceSelector != nil && p.PodSelector == nil:
			from = "ns:" + labelStr(p.NamespaceSelector.MatchLabels)
		default:
			t.Fatalf("unexpected peer: %+v", p)
		}
		var ports []int32
		for _, pt := range r.Ports {
			if pt.Protocol == nil || string(*pt.Protocol) != "TCP" {
				t.Errorf("non-TCP port in %s", from)
			}
			ports = append(ports, pt.Port.IntVal)
		}
		got = append(got, rule{from, ports})
	}
	want := []rule{
		{"pods:app.kubernetes.io/instance=platform,app.kubernetes.io/name=haven-idp", []int32{5432}},
		{"pods:cnpg.io/cluster=platform-db", []int32{5432, 8000}},
		{"ns:kubernetes.io/metadata.name=cnpg-system", []int32{5432, 8000}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ingress rules:\n got  %+v\n want %+v", got, want)
	}
	// An empty peer or an empty rule would mean "allow everything": never.
	for _, r := range np.Spec.Ingress {
		if len(r.From) == 0 || len(r.Ports) == 0 {
			t.Errorf("a rule without a source or ports allows everything: %+v", r)
		}
	}
}

func TestDBNetworkPolicyOperatorNamespaceIsConfigurable(t *testing.T) {
	np := DBNetworkPolicy(netpolPlane(), "databases")
	last := np.Spec.Ingress[len(np.Spec.Ingress)-1].From[0].NamespaceSelector.MatchLabels
	if last["kubernetes.io/metadata.name"] != "databases" {
		t.Fatalf("operator namespace not applied: %v", last)
	}
}

func labelStr(m map[string]string) string {
	var kv []string
	for k, v := range m {
		kv = append(kv, k+"="+v)
	}
	sort.Strings(kv)
	out := ""
	for i, s := range kv {
		if i > 0 {
			out += ","
		}
		out += s
	}
	return out
}
