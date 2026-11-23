package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// DeepCopyObject implements runtime.Object.
func (in *IdentityPlane) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(IdentityPlane)
	in.DeepCopyInto(out)
	return out
}

func (in *IdentityPlane) DeepCopyInto(out *IdentityPlane) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

// DeepCopyInto copies the spec; maps inside KeycloakSpec stay shared (they are
// never mutated in place by the controller).
func (in *IdentityPlaneSpec) DeepCopyInto(out *IdentityPlaneSpec) {
	*out = *in
	in.IdP.Resources.DeepCopyInto(&out.IdP.Resources)
	in.Keycloak.DeepCopyInto(&out.Keycloak)
	if in.Keycloak.Features != nil {
		out.Keycloak.Features = append([]string(nil), in.Keycloak.Features...)
	}
	if in.Expose.NetworkPolicy != nil {
		v := *in.Expose.NetworkPolicy
		out.Expose.NetworkPolicy = &v
	}
	if in.Expose.TLS.IssuerRef != nil {
		v := *in.Expose.TLS.IssuerRef
		out.Expose.TLS.IssuerRef = &v
	}
	if in.Bootstrap.Clients != nil {
		out.Bootstrap.Clients = make([]BootstrapClientSpec, len(in.Bootstrap.Clients))
		for i := range in.Bootstrap.Clients {
			c := in.Bootstrap.Clients[i]
			c.Redirects = append([]string(nil), c.Redirects...)
			c.Audiences = append([]string(nil), c.Audiences...)
			out.Bootstrap.Clients[i] = c
		}
	}
}

func (in *KeycloakSpec) DeepCopyInto(out *KeycloakSpec) { *out = *in }

func (in *IdentityPlaneStatus) DeepCopyInto(out *IdentityPlaneStatus) {
	*out = *in
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
}

// DeepCopyObject implements runtime.Object.
func (in *IdentityPlaneList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	out := new(IdentityPlaneList)
	in.DeepCopyInto(out)
	return out
}

func (in *IdentityPlaneList) DeepCopyInto(out *IdentityPlaneList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]IdentityPlane, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

func (in *IdentityPlane) DeepCopy() *IdentityPlane {
	if in == nil {
		return nil
	}
	out := new(IdentityPlane)
	in.DeepCopyInto(out)
	return out
}
