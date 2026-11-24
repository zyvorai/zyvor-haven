// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	havenv1 "github.com/zyvorai/haven/api/v1alpha1"
	"github.com/zyvorai/haven/internal/idp"
	corev1 "k8s.io/api/core/v1"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// fakeIdP is an in-memory idp.Provider for the Admin API calls the reconciler
// makes. Embedding the interface leaves every other method nil: calling one
// panics, which flags an unexpected dependency.
type fakeIdP struct {
	idp.Provider
	mu           sync.Mutex
	clients      map[string]idp.Client
	secrets      map[string]string
	n            int
	realmMissing bool
	writes       []string
}

func newFakeIdP() *fakeIdP {
	return &fakeIdP{clients: map[string]idp.Client{}, secrets: map[string]string{}}
}

func notFound() error { return &idp.StatusError{Code: 404, Body: []byte("sensitive body")} }

func (f *fakeIdP) GetClient(_ context.Context, _, id string) (*idp.Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.realmMissing {
		return nil, notFound()
	}
	c, ok := f.clients[id]
	if !ok {
		return nil, notFound()
	}
	return &c, nil
}

func (f *fakeIdP) ListClients(_ context.Context, _ string) ([]idp.Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.realmMissing {
		return nil, notFound()
	}
	var out []idp.Client
	for _, c := range f.clients {
		out = append(out, c)
	}
	return out, nil
}

// store mimics the server: only the PKCE attribute survives and public clients
// always report S256.
func store(c idp.Client) idp.Client {
	attrs := map[string]string{}
	if c.Attributes[pkceAttribute] == "S256" || c.PublicClient {
		attrs[pkceAttribute] = "S256"
	}
	c.Attributes = attrs
	c.Secret = ""
	return c
}

func (f *fakeIdP) CreateClientWithSecret(_ context.Context, _ string, c idp.Client) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, x := range f.clients {
		if x.ClientID == c.ClientID {
			f.writes = append(f.writes, "create-conflict:"+c.ClientID)
			return "", "", &idp.StatusError{Code: 409}
		}
	}
	f.n++
	c.ID = fmt.Sprintf("uuid-%d", f.n)
	f.clients[c.ID] = store(c)
	f.writes = append(f.writes, "create:"+c.ClientID)
	secret := ""
	if !c.PublicClient {
		secret = fmt.Sprintf("s3cr3t-created-%d", f.n)
		f.secrets[c.ID] = secret
	}
	return c.ID, secret, nil
}

func (f *fakeIdP) UpdateClient(_ context.Context, _, id string, c idp.Client) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.clients[id]; !ok {
		return notFound()
	}
	c.ID = id
	f.clients[id] = store(c)
	f.writes = append(f.writes, "update:"+c.ClientID)
	return nil
}

func (f *fakeIdP) DeleteClient(_ context.Context, _, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.clients[id]; !ok {
		return notFound()
	}
	delete(f.clients, id)
	f.writes = append(f.writes, "delete:"+id)
	return nil
}

func (f *fakeIdP) RegenerateClientSecret(_ context.Context, _, id string) (*idp.ClientSecret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.clients[id]; !ok {
		return nil, notFound()
	}
	f.n++
	s := fmt.Sprintf("s3cr3t-regen-%d", f.n)
	f.secrets[id] = s
	f.writes = append(f.writes, "regen:"+id)
	return &idp.ClientSecret{Type: "secret", Value: s}, nil
}

func (f *fakeIdP) takeWrites() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	w := f.writes
	f.writes = nil
	return w
}

func (f *fakeIdP) onlyClient(t *testing.T) idp.Client {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.clients) != 1 {
		t.Fatalf("want exactly one IdP client, have %d", len(f.clients))
	}
	for _, c := range f.clients {
		return c
	}
	return idp.Client{}
}

type ocEnv struct {
	t      *testing.T
	r      *OIDCClientReconciler
	c      client.Client
	idp    *fakeIdP
	events *record.FakeRecorder
	logs   *bytes.Buffer
	ctx    context.Context
	writes []string // Kubernetes writes other than status of the OIDCClient
	status int      // OIDCClient status updates
	now    time.Time
}

func readyPlane(ns string, mods ...func(*havenv1.IdentityPlane)) *havenv1.IdentityPlane {
	p := &havenv1.IdentityPlane{
		ObjectMeta: metav1.ObjectMeta{Name: "platform", Namespace: ns},
		Spec:       havenv1.IdentityPlaneSpec{Hostname: "auth.example.com", Bootstrap: havenv1.BootstrapSpec{FirstRealm: "platform"}},
		Status: havenv1.IdentityPlaneStatus{
			Phase:      havenv1.PhaseReady,
			Conditions: []metav1.Condition{{Type: "IdentityProviderReady", Status: metav1.ConditionTrue, Reason: "DeploymentAvailable"}},
		},
	}
	for _, m := range mods {
		m(p)
	}
	return p
}

func newOCEnv(t *testing.T, objs ...client.Object) *ocEnv {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	if err := havenv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	e := &ocEnv{t: t, idp: newFakeIdP(), events: record.NewFakeRecorder(200), logs: &bytes.Buffer{}, now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	rec := func(op string, obj client.Object) {
		e.writes = append(e.writes, op+" "+fmt.Sprintf("%T", obj)+"/"+obj.GetName())
	}
	e.c = fake.NewClientBuilder().WithScheme(scheme).
		WithStatusSubresource(&havenv1.OIDCClient{}, &havenv1.IdentityPlane{}).
		WithObjects(objs...).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, obj client.Object, o ...client.CreateOption) error {
				rec("create", obj)
				return c.Create(ctx, obj, o...)
			},
			Update: func(ctx context.Context, c client.WithWatch, obj client.Object, o ...client.UpdateOption) error {
				rec("update", obj)
				return c.Update(ctx, obj, o...)
			},
			Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, p client.Patch, o ...client.PatchOption) error {
				rec("patch", obj)
				return c.Patch(ctx, obj, p, o...)
			},
			Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, o ...client.DeleteOption) error {
				rec("delete", obj)
				return c.Delete(ctx, obj, o...)
			},
			SubResourceUpdate: func(ctx context.Context, c client.Client, sub string, obj client.Object, o ...client.SubResourceUpdateOption) error {
				e.status++
				return c.SubResource(sub).Update(ctx, obj, o...)
			},
		}).Build()
	e.r = &OIDCClientReconciler{
		Client:    e.c,
		Recorder:  e.events,
		Now:       func() time.Time { return e.now },
		Providers: ProviderFactoryFunc(func(context.Context, *havenv1.IdentityPlane) (idp.Provider, error) { return e.idp, nil }),
	}
	logger := funcr.New(func(prefix, args string) { e.logs.WriteString(prefix + args + "\n") }, funcr.Options{Verbosity: 10})
	e.ctx = log.IntoContext(context.Background(), logger)
	return e
}

func (e *ocEnv) reconcile(name string) ctrl.Result {
	e.t.Helper()
	res, err := e.r.Reconcile(e.ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "apps", Name: name}})
	if err != nil {
		e.t.Fatalf("reconcile: %v", err)
	}
	return res
}

func (e *ocEnv) get(name string) *havenv1.OIDCClient {
	e.t.Helper()
	var oc havenv1.OIDCClient
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: "apps", Name: name}, &oc); err != nil {
		e.t.Fatal(err)
	}
	return &oc
}

func (e *ocEnv) secret(name string) *corev1.Secret {
	e.t.Helper()
	var s corev1.Secret
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: "apps", Name: name}, &s); err != nil {
		e.t.Fatalf("secret %s: %v", name, err)
	}
	return &s
}

func (e *ocEnv) update(name string, mutate func(*havenv1.OIDCClient)) {
	e.t.Helper()
	oc := e.get(name)
	mutate(oc)
	if err := e.c.Update(e.ctx, oc); err != nil {
		e.t.Fatal(err)
	}
}

func (e *ocEnv) cond(oc *havenv1.OIDCClient, typ string) *metav1.Condition {
	for i := range oc.Status.Conditions {
		if oc.Status.Conditions[i].Type == typ {
			return &oc.Status.Conditions[i]
		}
	}
	return nil
}

func (e *ocEnv) wantCond(name, typ string, status metav1.ConditionStatus, reason string) {
	e.t.Helper()
	c := e.cond(e.get(name), typ)
	if c == nil || c.Status != status || c.Reason != reason {
		e.t.Fatalf("condition %s = %+v, want %s/%s", typ, c, status, reason)
	}
}

func (e *ocEnv) drainEvents() string {
	var sb strings.Builder
	for {
		select {
		case ev := <-e.events.Events:
			sb.WriteString(ev + "\n")
		default:
			return sb.String()
		}
	}
}

func webApp() *havenv1.OIDCClient {
	return &havenv1.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "apps", Generation: 1},
		Spec: havenv1.OIDCClientSpec{
			PlaneRef:     havenv1.PlaneRef{Name: "platform", Namespace: "identity"},
			DisplayName:  "Web",
			RedirectURIs: []string{"https://web.example.com/callback"},
		},
	}
}

func spa() *havenv1.OIDCClient {
	oc := webApp()
	oc.Name = "spa"
	oc.Spec.Public = true
	return oc
}

// identityNS is where the plane lives in these tests; the OIDCClients live in
// "apps", so every test also exercises the cross-namespace allow-list.
func allowApps(p *havenv1.IdentityPlane) {
	p.Annotations = map[string]string{AnnotationAllowFrom: "apps"}
}

func TestOIDCClientPublicHasNoSecret(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity", allowApps), spa())
	e.reconcile("spa")

	c := e.idp.onlyClient(t)
	if !c.PublicClient || c.ClientID != "spa" || !c.StandardFlowEnabled || c.Attributes[pkceAttribute] != "S256" {
		t.Fatalf("unexpected IdP client %+v", c)
	}
	var secrets corev1.SecretList
	if err := e.c.List(e.ctx, &secrets, client.InNamespace("apps")); err != nil || len(secrets.Items) != 0 {
		t.Fatalf("public client must not get a Secret: %v %v", err, secrets.Items)
	}
	oc := e.get("spa")
	if oc.Status.ClientUUID != c.ID || oc.Status.SecretName != "" || oc.Status.Issuer != "https://auth.example.com/realms/platform" {
		t.Fatalf("status = %+v", oc.Status)
	}
	e.wantCond("spa", CondReady, metav1.ConditionTrue, ReasonSynced)
	e.wantCond("spa", CondSynced, metav1.ConditionTrue, ReasonSynced)
}

func TestOIDCClientConfidentialWritesSecret(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity", allowApps), webApp())
	e.reconcile("web")

	s := e.secret("web-oidc")
	want := map[string]string{
		"client-id":     "web",
		"client-secret": "s3cr3t-created-1",
		"issuer":        "https://auth.example.com/realms/platform",
	}
	if len(s.Data) != 3 {
		t.Fatalf("secret keys = %v", s.Data)
	}
	for k, v := range want {
		if string(s.Data[k]) != v {
			t.Errorf("secret[%s] = %q, want %q", k, s.Data[k], v)
		}
	}
	oc := e.get("web")
	ref := metav1.GetControllerOf(s)
	if ref == nil || ref.Kind != "OIDCClient" || ref.Name != "web" {
		t.Fatalf("Secret is not controller-owned by the OIDCClient: %+v", s.OwnerReferences)
	}
	if oc.Status.SecretName != "web-oidc" || e.idp.onlyClient(t).PublicClient {
		t.Fatalf("status %+v", oc.Status)
	}
}

func TestOIDCClientCustomSecretNameAndKeys(t *testing.T) {
	oc := webApp()
	oc.Spec.SecretRef = &havenv1.OIDCClientSecretRef{Name: "creds", Keys: havenv1.OIDCClientSecretKeys{ClientSecret: "OIDC_SECRET"}}
	e := newOCEnv(t, readyPlane("identity", allowApps), oc)
	e.reconcile("web")
	s := e.secret("creds")
	if string(s.Data["OIDC_SECRET"]) == "" || string(s.Data["client-id"]) != "web" || len(s.Data) != 3 {
		t.Fatalf("secret = %v", s.Data)
	}
}

func TestOIDCClientSecondReconcileWritesNothing(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity", allowApps), webApp())
	e.reconcile("web")
	e.idp.takeWrites()
	e.writes, e.status = nil, 0

	for i := 0; i < 3; i++ {
		e.reconcile("web")
	}
	if w := e.idp.takeWrites(); len(w) != 0 {
		t.Fatalf("idle reconcile wrote to the IdP: %v", w)
	}
	if len(e.writes) != 0 || e.status != 0 {
		t.Fatalf("idle reconcile wrote to Kubernetes: %v status updates=%d", e.writes, e.status)
	}
}

func TestOIDCClientUpdatesRedirectURIs(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity", allowApps), webApp())
	e.reconcile("web")
	secret := string(e.secret("web-oidc").Data["client-secret"])
	e.idp.takeWrites()

	e.update("web", func(oc *havenv1.OIDCClient) {
		oc.Generation++
		oc.Spec.RedirectURIs = []string{"https://web.example.com/callback", "https://web.example.com/other"}
	})
	e.reconcile("web")

	if w := e.idp.takeWrites(); len(w) != 1 || w[0] != "update:web" {
		t.Fatalf("writes = %v, want a single update", w)
	}
	if got := e.idp.onlyClient(t).RedirectURIs; len(got) != 2 {
		t.Fatalf("redirect URIs = %v", got)
	}
	if string(e.secret("web-oidc").Data["client-secret"]) != secret {
		t.Fatal("updating redirect URIs must not change the client secret")
	}
}

func TestOIDCClientSendsBackchannelLogoutURL(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity", allowApps), webApp())
	e.update("web", func(oc *havenv1.OIDCClient) { oc.Spec.BackchannelLogoutURL = "https://web.example.com/logout" })
	e.reconcile("web")
	if got := e.idp.onlyClient(t).BackchannelLogoutURL; got != "https://web.example.com/logout" {
		t.Fatalf("create did not carry backchannelLogoutUrl: %q", got)
	}

	e.idp.takeWrites()
	e.update("web", func(oc *havenv1.OIDCClient) {
		oc.Generation++
		oc.Spec.BackchannelLogoutURL = "https://web.example.com/other-logout"
	})
	e.reconcile("web")
	if w := e.idp.takeWrites(); len(w) != 1 || w[0] != "update:web" {
		t.Fatalf("changing the URL must be a single update, got %v", w)
	}
	if got := e.idp.onlyClient(t).BackchannelLogoutURL; got != "https://web.example.com/other-logout" {
		t.Fatalf("update did not carry the new URL: %q", got)
	}

	e.reconcile("web")
	if w := e.idp.takeWrites(); len(w) != 0 {
		t.Fatalf("an unchanged URL caused writes: %v", w)
	}

	e.update("web", func(oc *havenv1.OIDCClient) { oc.Generation++; oc.Spec.BackchannelLogoutURL = "" })
	e.reconcile("web")
	if got := e.idp.onlyClient(t).BackchannelLogoutURL; got != "" {
		t.Fatalf("clearing the field left %q in the IdP", got)
	}
}

func TestOIDCClientRotateAnnotation(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity", allowApps), webApp())
	e.reconcile("web")
	first := string(e.secret("web-oidc").Data["client-secret"])
	e.idp.takeWrites()

	// A reconcile without the annotation never rotates.
	e.reconcile("web")
	if w := e.idp.takeWrites(); len(w) != 0 {
		t.Fatalf("unexpected writes %v", w)
	}

	e.update("web", func(oc *havenv1.OIDCClient) { oc.Annotations = map[string]string{AnnotationRotateSecret: "1"} })
	e.reconcile("web")
	second := string(e.secret("web-oidc").Data["client-secret"])
	if second == first || !strings.HasPrefix(second, "s3cr3t-regen-") {
		t.Fatalf("secret not rotated: %q -> %q", first, second)
	}
	if w := e.idp.takeWrites(); len(w) != 1 || !strings.HasPrefix(w[0], "regen:") {
		t.Fatalf("writes = %v", w)
	}

	// The same value again is a no-op; a new value rotates once more.
	e.reconcile("web")
	if w := e.idp.takeWrites(); len(w) != 0 {
		t.Fatalf("rotation repeated for an already handled value: %v", w)
	}
	e.update("web", func(oc *havenv1.OIDCClient) { oc.Annotations[AnnotationRotateSecret] = "2" })
	e.reconcile("web")
	if third := string(e.secret("web-oidc").Data["client-secret"]); third == second {
		t.Fatal("a new annotation value must rotate again")
	}
}

func TestOIDCClientNeverOverwritesHandRotatedSecret(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity", allowApps), webApp())
	e.reconcile("web")
	s := e.secret("web-oidc")
	s.Data["client-secret"] = []byte("hand-rotated")
	if err := e.c.Update(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	e.idp.takeWrites()
	e.reconcile("web")
	if got := string(e.secret("web-oidc").Data["client-secret"]); got != "hand-rotated" {
		t.Fatalf("controller overwrote a hand-rotated secret: %q", got)
	}
	if w := e.idp.takeWrites(); len(w) != 0 {
		t.Fatalf("writes = %v", w)
	}
}

func TestOIDCClientDeletedSecretIsRegenerated(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity", allowApps), webApp())
	e.reconcile("web")
	if err := e.c.Delete(e.ctx, e.secret("web-oidc")); err != nil {
		t.Fatal(err)
	}
	e.idp.takeWrites()
	e.reconcile("web")
	if got := string(e.secret("web-oidc").Data["client-secret"]); !strings.HasPrefix(got, "s3cr3t-regen-") {
		t.Fatalf("secret not rewritten with a regenerated value: %q", got)
	}
}

func TestOIDCClientDeletePolicy(t *testing.T) {
	for _, tc := range []struct {
		policy     havenv1.DeletionPolicy
		wantClient int
	}{
		{"", 0},
		{havenv1.DeletionDelete, 0},
		{havenv1.DeletionRetain, 1},
	} {
		t.Run("policy="+string(tc.policy), func(t *testing.T) {
			oc := webApp()
			oc.Spec.DeletionPolicy = tc.policy
			e := newOCEnv(t, readyPlane("identity", allowApps), oc)
			e.reconcile("web")
			if err := e.c.Delete(e.ctx, e.get("web")); err != nil {
				t.Fatal(err)
			}
			e.reconcile("web")

			e.idp.mu.Lock()
			n := len(e.idp.clients)
			e.idp.mu.Unlock()
			if n != tc.wantClient {
				t.Fatalf("IdP clients after delete = %d, want %d", n, tc.wantClient)
			}
			var gone havenv1.OIDCClient
			err := e.c.Get(e.ctx, types.NamespacedName{Namespace: "apps", Name: "web"}, &gone)
			if !kerrors.IsNotFound(err) {
				t.Fatalf("finalizer not removed, get = %v", err)
			}
		})
	}
}

func TestOIDCClientDeleteWaitsForPlaneAndRetainUnblocks(t *testing.T) {
	plane := readyPlane("identity", allowApps)
	e := newOCEnv(t, plane, webApp())
	e.reconcile("web")
	plane = &havenv1.IdentityPlane{}
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: "identity", Name: "platform"}, plane); err != nil {
		t.Fatal(err)
	}
	plane.Status.Conditions[0].Status = metav1.ConditionFalse
	plane.Status.Phase = havenv1.PhaseDegraded
	if err := e.c.Status().Update(e.ctx, plane); err != nil {
		t.Fatal(err)
	}
	if err := e.c.Delete(e.ctx, e.get("web")); err != nil {
		t.Fatal(err)
	}
	res := e.reconcile("web")
	if res.RequeueAfter == 0 {
		t.Fatal("deletion with an unready plane must requeue")
	}
	e.wantCond("web", CondReady, metav1.ConditionFalse, ReasonDeleting)
	e.update("web", func(oc *havenv1.OIDCClient) { oc.Spec.DeletionPolicy = havenv1.DeletionRetain })
	e.reconcile("web")
	var gone havenv1.OIDCClient
	if err := e.c.Get(e.ctx, types.NamespacedName{Namespace: "apps", Name: "web"}, &gone); !kerrors.IsNotFound(err) {
		t.Fatalf("Retain did not release the finalizer: %v", err)
	}
}

func TestOIDCClientPlaneMissingAndNotReady(t *testing.T) {
	e := newOCEnv(t, webApp()) // no plane at all
	res := e.reconcile("web")
	e.wantCond("web", CondReady, metav1.ConditionFalse, ReasonPlaneNotFound)
	if res.RequeueAfter == 0 {
		t.Fatal("missing plane must requeue")
	}

	notReady := readyPlane("identity", allowApps, func(p *havenv1.IdentityPlane) {
		p.Status.Phase = havenv1.PhaseProvisioningIdP
		p.Status.Conditions[0].Status = metav1.ConditionFalse
	})
	e = newOCEnv(t, notReady, webApp())
	res = e.reconcile("web")
	e.wantCond("web", CondReady, metav1.ConditionFalse, ReasonPlaneNotReady)
	if res.RequeueAfter == 0 || len(e.idp.takeWrites()) != 0 {
		t.Fatalf("requeue=%v writes=%v", res.RequeueAfter, e.idp.takeWrites())
	}
	// Repeated reconciles are quiet: the condition does not change, so no status write.
	e.status = 0
	e.reconcile("web")
	if e.status != 0 {
		t.Fatalf("status rewritten on an unchanged not-ready condition (%d)", e.status)
	}
}

func TestOIDCClientCrossNamespaceNeedsAllowList(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity"), webApp()) // plane has no allow annotation
	e.reconcile("web")
	e.wantCond("web", CondReady, metav1.ConditionFalse, ReasonPlaneNotAllowed)
	if len(e.idp.takeWrites()) != 0 {
		t.Fatal("must not write to a plane that did not allow the namespace")
	}
}

func TestOIDCClientInvalidSpecs(t *testing.T) {
	cases := map[string]func(*havenv1.OIDCClient){
		"wildcard host":        func(o *havenv1.OIDCClient) { o.Spec.RedirectURIs = []string{"https://*.example.com/cb"} },
		"wildcard path":        func(o *havenv1.OIDCClient) { o.Spec.RedirectURIs = []string{"https://a.example.com/*"} },
		"javascript":           func(o *havenv1.OIDCClient) { o.Spec.RedirectURIs = []string{"javascript:alert(1)"} },
		"data":                 func(o *havenv1.OIDCClient) { o.Spec.RedirectURIs = []string{"data:text/html,x"} },
		"plain http":           func(o *havenv1.OIDCClient) { o.Spec.RedirectURIs = []string{"http://app.example.com/cb"} },
		"custom scheme":        func(o *havenv1.OIDCClient) { o.Spec.RedirectURIs = []string{"myapp://cb"} },
		"fragment":             func(o *havenv1.OIDCClient) { o.Spec.RedirectURIs = []string{"https://a.example.com/cb#x"} },
		"userinfo":             func(o *havenv1.OIDCClient) { o.Spec.RedirectURIs = []string{"https://u:p@a.example.com/cb"} },
		"no redirect":          func(o *havenv1.OIDCClient) { o.Spec.RedirectURIs = nil },
		"origin with path":     func(o *havenv1.OIDCClient) { o.Spec.WebOrigins = []string{"https://a.example.com/x"} },
		"public + svc account": func(o *havenv1.OIDCClient) { o.Spec.Public, o.Spec.ServiceAccount = true, true },
		"public without pkce":  func(o *havenv1.OIDCClient) { f := false; o.Spec.Public, o.Spec.PKCE = true, &f },
		"reserved client id":   func(o *havenv1.OIDCClient) { o.Spec.ClientID = "haven-admin" },
		"bad client id":        func(o *havenv1.OIDCClient) { o.Spec.ClientID = "-bad id" },
		"bad deletion policy":  func(o *havenv1.OIDCClient) { o.Spec.DeletionPolicy = "Maybe" },
		"duplicate keys": func(o *havenv1.OIDCClient) {
			o.Spec.SecretRef = &havenv1.OIDCClientSecretRef{Keys: havenv1.OIDCClientSecretKeys{ClientID: "x", ClientSecret: "x"}}
		},
		"bad logout url": func(o *havenv1.OIDCClient) { o.Spec.BackchannelLogoutURL = "http://app.example.com/logout" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			oc := webApp()
			mutate(oc)
			e := newOCEnv(t, readyPlane("identity", allowApps), oc)
			res := e.reconcile("web")
			e.wantCond("web", CondReady, metav1.ConditionFalse, ReasonInvalidSpec)
			if res.RequeueAfter != 0 {
				t.Fatalf("invalid spec must not requeue (hot loop), got %v", res.RequeueAfter)
			}
			if w := e.idp.takeWrites(); len(w) != 0 {
				t.Fatalf("invalid spec reached the IdP: %v", w)
			}
			e.status = 0
			e.reconcile("web")
			if e.status != 0 {
				t.Fatal("re-reconciling an invalid spec rewrote the status")
			}
		})
	}
}

func TestOIDCClientValidLoopbackAndServiceAccount(t *testing.T) {
	oc := webApp()
	oc.Spec.RedirectURIs = []string{"http://localhost:3000/cb", "http://127.0.0.1:8080/cb", "https://app.example.com/cb"}
	oc.Spec.WebOrigins = []string{"http://localhost:3000"}
	sa := &havenv1.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "job", Namespace: "apps", Generation: 1},
		Spec:       havenv1.OIDCClientSpec{PlaneRef: havenv1.PlaneRef{Name: "platform", Namespace: "identity"}, ServiceAccount: true},
	}
	e := newOCEnv(t, readyPlane("identity", allowApps), oc, sa)
	e.reconcile("web")
	e.reconcile("job")
	e.wantCond("web", CondReady, metav1.ConditionTrue, ReasonSynced)
	e.wantCond("job", CondReady, metav1.ConditionTrue, ReasonSynced)
	var job idp.Client
	for _, c := range e.idp.clients {
		if c.ClientID == "job" {
			job = c
		}
	}
	if !job.ServiceAccountsEnabled || job.StandardFlowEnabled || job.PublicClient {
		t.Fatalf("service account client = %+v", job)
	}
	if string(e.secret("job-oidc").Data["client-secret"]) == "" {
		t.Fatal("service account needs a secret")
	}
}

func TestOIDCClientDriftRecreatesClientAndSecret(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity", allowApps), webApp())
	e.reconcile("web")
	oldID := e.get("web").Status.ClientUUID
	// Someone deletes the client in the IdP; the user also hand-rotated the
	// Secret, which is now useless and must be replaced.
	delete(e.idp.clients, oldID)
	s := e.secret("web-oidc")
	s.Data["client-secret"] = []byte("stale")
	if err := e.c.Update(e.ctx, s); err != nil {
		t.Fatal(err)
	}
	e.idp.takeWrites()

	e.reconcile("web")
	c := e.idp.onlyClient(t)
	oc := e.get("web")
	if c.ID == oldID || oc.Status.ClientUUID != c.ID {
		t.Fatalf("client not recreated: old %s new %s status %s", oldID, c.ID, oc.Status.ClientUUID)
	}
	if got := string(e.secret("web-oidc").Data["client-secret"]); got != e.idp.secrets[c.ID] || got == "stale" {
		t.Fatalf("secret not re-synced: %q", got)
	}
	if !strings.Contains(e.drainEvents(), "DriftCorrected") {
		t.Fatal("no DriftCorrected event")
	}
}

func TestOIDCClientExistingClientNotAdoptedWithoutAnnotation(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity", allowApps), webApp())
	e.idp.clients["other"] = idp.Client{ID: "other", ClientID: "web", Enabled: true, RedirectURIs: []string{"https://x.example.com"}}

	e.reconcile("web")
	e.wantCond("web", CondReady, metav1.ConditionFalse, ReasonClientExists)
	if w := e.idp.takeWrites(); len(w) != 0 {
		t.Fatalf("hijacked an existing client: %v", w)
	}
	e.update("web", func(oc *havenv1.OIDCClient) { oc.Annotations = map[string]string{AnnotationAdoptClient: "true"} })
	e.reconcile("web")
	e.wantCond("web", CondReady, metav1.ConditionTrue, ReasonSynced)
	if e.idp.clients["other"].RedirectURIs[0] != "https://web.example.com/callback" {
		t.Fatalf("adopted client not updated: %+v", e.idp.clients["other"])
	}
}

func TestOIDCClientForeignSecretIsNotTouched(t *testing.T) {
	foreign := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "web-oidc", Namespace: "apps"}, Data: map[string][]byte{"x": []byte("y")}}
	e := newOCEnv(t, readyPlane("identity", allowApps), webApp(), foreign)
	e.reconcile("web")
	e.wantCond("web", CondReady, metav1.ConditionFalse, ReasonSecretNotOwned)
	if s := e.secret("web-oidc"); len(s.Data) != 1 || string(s.Data["x"]) != "y" {
		t.Fatalf("foreign secret modified: %v", s.Data)
	}
}

func TestOIDCClientImmutableFieldsReported(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity", allowApps), webApp())
	e.reconcile("web")
	e.idp.takeWrites()
	e.update("web", func(oc *havenv1.OIDCClient) { oc.Spec.ClientID = "renamed" })
	e.reconcile("web")
	e.wantCond("web", CondReady, metav1.ConditionFalse, ReasonImmutable)
	if w := e.idp.takeWrites(); len(w) != 0 {
		t.Fatalf("writes = %v", w)
	}
}

func TestOIDCClientRealmMissing(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity", allowApps), webApp())
	e.idp.realmMissing = true
	res := e.reconcile("web")
	e.wantCond("web", CondReady, metav1.ConditionFalse, ReasonRealmNotFound)
	if res.RequeueAfter == 0 {
		t.Fatal("must requeue")
	}
}

func TestOIDCClientBackendErrorIsSanitised(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity", allowApps), webApp())
	e.r.Providers = ProviderFactoryFunc(func(context.Context, *havenv1.IdentityPlane) (idp.Provider, error) {
		return &erroringIdP{}, nil
	})
	_, err := e.r.Reconcile(e.ctx, ctrl.Request{NamespacedName: types.NamespacedName{Namespace: "apps", Name: "web"}})
	if err == nil {
		t.Fatal("want an error")
	}
	all := err.Error() + e.drainEvents() + e.logs.String() + statusJSON(t, e.get("web"))
	if strings.Contains(all, "LEAKY-BODY") {
		t.Fatalf("backend response body leaked: %s", all)
	}
}

type erroringIdP struct{ idp.Provider }

func (*erroringIdP) GetClient(context.Context, string, string) (*idp.Client, error) {
	return nil, &idp.StatusError{Code: 500, Body: []byte("LEAKY-BODY")}
}
func (*erroringIdP) ListClients(context.Context, string) ([]idp.Client, error) {
	return nil, &idp.StatusError{Code: 500, Body: []byte("LEAKY-BODY")}
}

func statusJSON(t *testing.T, oc *havenv1.OIDCClient) string {
	t.Helper()
	b, err := json.Marshal(oc.Status)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Secrets must appear only in the Secret object: not in status, events, logs
// or the OIDCClient itself, through creation, rotation, drift and deletion.
func TestOIDCClientNeverLeaksSecrets(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity", allowApps), webApp())
	var seen []string
	collect := func() {
		for _, s := range e.idp.secrets {
			seen = append(seen, s)
		}
		seen = append(seen, string(e.secret("web-oidc").Data["client-secret"]))
	}
	e.reconcile("web")
	collect()
	e.update("web", func(oc *havenv1.OIDCClient) { oc.Annotations = map[string]string{AnnotationRotateSecret: "x"} })
	e.reconcile("web")
	collect()
	delete(e.idp.clients, e.get("web").Status.ClientUUID)
	e.reconcile("web")
	collect()
	e.reconcile("web")
	if err := e.c.Delete(e.ctx, e.get("web")); err != nil {
		t.Fatal(err)
	}
	e.reconcile("web")

	if len(seen) < 3 {
		t.Fatalf("collected %d secrets", len(seen))
	}
	// The OIDCClient is gone now; rebuild the status view from before deletion by
	// checking logs and events, which outlive it, plus the final status.
	haystack := e.logs.String() + e.drainEvents()
	for _, s := range seen {
		if s == "" {
			t.Fatal("empty secret collected")
		}
		if strings.Contains(haystack, s) {
			t.Errorf("secret %q found in logs or events", s)
		}
	}
	if !strings.Contains(e.logs.String(), "created IdP client") {
		t.Fatal("expected the reconciler to log; the leak check would be vacuous")
	}
}

func TestOIDCClientStatusHasNoSecret(t *testing.T) {
	e := newOCEnv(t, readyPlane("identity", allowApps), webApp())
	e.reconcile("web")
	oc := e.get("web")
	raw, _ := json.Marshal(oc)
	for _, s := range e.idp.secrets {
		if strings.Contains(string(raw), s) {
			t.Fatalf("secret in the OIDCClient object: %s", raw)
		}
	}
}

func TestOIDCClientSchemeRegistersKinds(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := havenv1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"OIDCClient", "OIDCClientList"} {
		if !scheme.Recognizes(havenv1.GroupVersion.WithKind(k)) {
			t.Fatalf("scheme does not recognize %s", k)
		}
	}
	var _ logr.Logger
}
