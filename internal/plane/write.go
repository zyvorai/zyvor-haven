// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package plane

import (
	"context"
	"fmt"
	"strings"

	havenv1 "github.com/zyvorai/haven/api/v1alpha1"
	"github.com/zyvorai/haven/internal/profiles"
	authv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Capabilities struct {
	InCluster      bool   `json:"inCluster"`
	CanCreatePlane bool   `json:"canCreatePlane"`
	Plane          string `json:"plane"`
	Namespace      string `json:"namespace"`
	Message        string `json:"message,omitempty"`
}

type CreateRequest struct {
	Name        string `json:"name,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
	Profile     string `json:"profile"`
	Hostname    string `json:"hostname"`
	ExposeClass string `json:"exposeClass,omitempty"`
	AdminEmail  string `json:"adminEmail,omitempty"`
	FirstRealm  string `json:"firstRealm,omitempty"`
	Audience    string `json:"audience,omitempty"`
}

func (r *Reader) Capabilities(ctx context.Context) Capabilities {
	out := Capabilities{
		Plane:     r.name,
		Namespace: r.ns,
		InCluster: r.client != nil,
	}
	if r.client == nil {
		out.Message = "not running in cluster — realm bootstrap only"
		return out
	}
	ssar := &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Group:     havenv1.Group,
				Version:   havenv1.Version,
				Resource:  "identityplanes",
				Namespace: r.ns,
				Verb:      "create",
			},
		},
	}
	if err := r.client.Create(ctx, ssar); err != nil {
		out.Message = "cannot evaluate create permission: " + err.Error()
		return out
	}
	out.CanCreatePlane = ssar.Status.Allowed
	if !out.CanCreatePlane {
		out.Message = "IdentityPlane create denied — realm bootstrap only"
		if ssar.Status.Reason != "" {
			out.Message += " (" + ssar.Status.Reason + ")"
		}
	}
	return out
}

func (r *Reader) CreatePlane(ctx context.Context, req CreateRequest) (*havenv1.IdentityPlane, error) {
	if r.client == nil {
		return nil, fmt.Errorf("not running in cluster")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = r.name
	}
	ns := strings.TrimSpace(req.Namespace)
	if ns == "" {
		ns = r.ns
	}
	hostname := strings.TrimSpace(req.Hostname)
	if hostname == "" {
		return nil, fmt.Errorf("hostname is required")
	}
	profile := havenv1.PlaneProfile(strings.TrimSpace(req.Profile))
	switch profile {
	case havenv1.ProfileDev, havenv1.ProfileStaging, havenv1.ProfileProduction:
	case "":
		profile = havenv1.ProfileDev
	default:
		return nil, fmt.Errorf("invalid profile %q", req.Profile)
	}
	exposeClass := strings.TrimSpace(req.ExposeClass)
	if exposeClass == "" {
		exposeClass = "gateway"
	}
	firstRealm := strings.TrimSpace(req.FirstRealm)
	if firstRealm == "" {
		firstRealm = "platform"
	}

	spec := profiles.Merge(&havenv1.IdentityPlaneSpec{
		Profile:  profile,
		Hostname: hostname,
		Expose:   havenv1.ExposeSpec{Class: exposeClass},
		Bootstrap: havenv1.BootstrapSpec{
			AdminEmail: strings.TrimSpace(req.AdminEmail),
			FirstRealm: firstRealm,
		},
	})

	if err := r.ensureNamespace(ctx, ns); err != nil {
		return nil, err
	}

	plane := &havenv1.IdentityPlane{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: ns,
			Labels: map[string]string{
				"app.kubernetes.io/part-of": "haven",
			},
		},
		Spec: spec,
	}
	if req.Audience != "" {
		if plane.Annotations == nil {
			plane.Annotations = map[string]string{}
		}
		plane.Annotations["identity.haven.dev/audience"] = req.Audience
	}

	err := r.client.Create(ctx, plane)
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			return nil, fmt.Errorf("IdentityPlane %s/%s already exists", ns, name)
		}
		if apierrors.IsForbidden(err) {
			return nil, fmt.Errorf("forbidden: console SA cannot create IdentityPlanes")
		}
		return nil, err
	}
	return plane, nil
}

func (r *Reader) ensureNamespace(ctx context.Context, ns string) error {
	var existing corev1.Namespace
	err := r.client.Get(ctx, client.ObjectKey{Name: ns}, &existing)
	if err == nil {
		return nil
	}
	if !apierrors.IsNotFound(err) {
		return err
	}
	obj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}
	if cerr := r.client.Create(ctx, obj); cerr != nil && !apierrors.IsAlreadyExists(cerr) {
		return fmt.Errorf("create namespace %s: %w", ns, cerr)
	}
	return nil
}
