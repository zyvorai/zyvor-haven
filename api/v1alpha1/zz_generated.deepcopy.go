package v1alpha1

import "k8s.io/apimachinery/pkg/runtime"

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
	out.Spec = in.Spec
	out.Status = in.Status
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
