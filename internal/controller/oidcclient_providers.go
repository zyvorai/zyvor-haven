// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package controller

import (
	"context"
	"fmt"
	"net/http"
	"sync"

	havenv1 "github.com/zyvorai/haven/api/v1alpha1"
	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/idp/native"
	"github.com/zyvorai/haven/internal/profiles"
	"github.com/zyvorai/haven/internal/render"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NativeProviders builds Admin API clients for native planes the same way the
// console does (docs: IDP_CONTRACT.md, "Console"): service account haven-admin
// in the plane's first realm, secret from <plane>-idp key admin-client-secret.
// The token is cached inside each native.Client; clients are cached per plane
// and rebuilt when the admin secret changes.
type NativeProviders struct {
	Reader client.Reader
	// BaseURL overrides the in-cluster URL http://<plane>-idp.<ns>.svc:8081
	// (for running the controller outside the cluster).
	BaseURL func(plane *havenv1.IdentityPlane) string
	HTTP    *http.Client

	mu    sync.Mutex
	cache map[string]cachedProvider
}

type cachedProvider struct {
	secret, url, realm string
	p                  idp.Provider
}

func (n *NativeProviders) ProviderFor(ctx context.Context, plane *havenv1.IdentityPlane) (idp.Provider, error) {
	var sec corev1.Secret
	name := types.NamespacedName{Name: render.IdPName(plane.Name), Namespace: plane.Namespace}
	if err := n.Reader.Get(ctx, name, &sec); err != nil {
		return nil, fmt.Errorf("read admin secret %s: %w", name, err)
	}
	secret := string(sec.Data[render.SecretKeyAdminClient])
	if secret == "" {
		return nil, fmt.Errorf("secret %s has no %s", name, render.SecretKeyAdminClient)
	}
	url := fmt.Sprintf("http://%s.%s.svc:8081", render.IdPName(plane.Name), plane.Namespace)
	if n.BaseURL != nil {
		url = n.BaseURL(plane)
	}
	spec := profiles.Merge(&plane.Spec)
	realm := spec.Bootstrap.FirstRealm

	key := plane.Namespace + "/" + plane.Name
	n.mu.Lock()
	defer n.mu.Unlock()
	if c, ok := n.cache[key]; ok && c.secret == secret && c.url == url && c.realm == realm {
		return c.p, nil
	}
	p := native.New(native.Config{BaseURL: url, Realm: realm, ClientID: "haven-admin", ClientSecret: secret, HTTP: n.HTTP})
	if n.cache == nil {
		n.cache = map[string]cachedProvider{}
	}
	n.cache[key] = cachedProvider{secret: secret, url: url, realm: realm, p: p}
	return p, nil
}
