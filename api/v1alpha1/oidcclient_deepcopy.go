// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func (in *OIDCClient) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	return in.DeepCopy()
}

func (in *OIDCClient) DeepCopy() *OIDCClient {
	if in == nil {
		return nil
	}
	out := new(OIDCClient)
	in.DeepCopyInto(out)
	return out
}

func (in *OIDCClient) DeepCopyInto(out *OIDCClient) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func copyBoolPtr(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func (in *OIDCClientSpec) DeepCopyInto(out *OIDCClientSpec) {
	*out = *in
	out.RedirectURIs = append([]string(nil), in.RedirectURIs...)
	out.WebOrigins = append([]string(nil), in.WebOrigins...)
	out.PKCE = copyBoolPtr(in.PKCE)
	if in.Flows != nil {
		out.Flows = &OIDCClientFlows{
			AuthorizationCode: copyBoolPtr(in.Flows.AuthorizationCode),
			ClientCredentials: copyBoolPtr(in.Flows.ClientCredentials),
		}
	}
	if in.SecretRef != nil {
		v := *in.SecretRef
		out.SecretRef = &v
	}
}

func (in *OIDCClientStatus) DeepCopyInto(out *OIDCClientStatus) {
	*out = *in
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		for i := range in.Conditions {
			in.Conditions[i].DeepCopyInto(&out.Conditions[i])
		}
	}
	if in.LastSyncTime != nil {
		out.LastSyncTime = in.LastSyncTime.DeepCopy()
	}
}

func (in *OIDCClientStatus) DeepCopy() *OIDCClientStatus {
	if in == nil {
		return nil
	}
	out := new(OIDCClientStatus)
	in.DeepCopyInto(out)
	return out
}

func (in *OIDCClientList) DeepCopyObject() runtime.Object {
	if in == nil {
		return nil
	}
	return in.DeepCopy()
}

func (in *OIDCClientList) DeepCopy() *OIDCClientList {
	if in == nil {
		return nil
	}
	out := new(OIDCClientList)
	in.DeepCopyInto(out)
	return out
}

func (in *OIDCClientList) DeepCopyInto(out *OIDCClientList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]OIDCClient, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
