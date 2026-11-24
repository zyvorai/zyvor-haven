// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package controller

import (
	"context"
	"reflect"
	"strings"
	"testing"

	havenv1 "github.com/zyvorai/haven/api/v1alpha1"
	networkingv1 "k8s.io/api/networking/v1"
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
)

type ingEnv struct {
	t      *testing.T
	c      client.Client
	r      *IngressRegistrationReconciler
	events *record.FakeRecorder
	writes []string
}

func ingScheme(t *testing.T) *runtime.Scheme {
	s := runtime.NewScheme()
	if err := clientgoscheme.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	if err := havenv1.AddToScheme(s); err != nil {
		t.Fatal(err)
	}
	return s
}

func newIngEnv(t *testing.T, objs ...client.Object) *ingEnv {
	e := &ingEnv{t: t, events: record.NewFakeRecorder(100)}
	rec := func(op string, o client.Object) { e.writes = append(e.writes, op+" "+o.GetName()) }
	e.c = fake.NewClientBuilder().WithScheme(ingScheme(t)).WithObjects(objs...).
		WithInterceptorFuncs(interceptor.Funcs{
			Create: func(ctx context.Context, c client.WithWatch, o client.Object, op ...client.CreateOption) error {
				rec("create", o)
				return c.Create(ctx, o, op...)
			},
			Update: func(ctx context.Context, c client.WithWatch, o client.Object, op ...client.UpdateOption) error {
				rec("update", o)
				return c.Update(ctx, o, op...)
			},
			Delete: func(ctx context.Context, c client.WithWatch, o client.Object, op ...client.DeleteOption) error {
				rec("delete", o)
				return c.Delete(ctx, o, op...)
			},
		}).Build()
	e.r = &IngressRegistrationReconciler{Client: e.c, Recorder: e.events}
	return e
}

func (e *ingEnv) reconcile(ns, name string) ctrl.Result {
	e.t.Helper()
	res, err := e.r.Reconcile(context.Background(), ctrl.Request{NamespacedName: types.NamespacedName{Namespace: ns, Name: name}})
	if err != nil {
		e.t.Fatal(err)
	}
	return res
}

func (e *ingEnv) oc(ns, name string) (*havenv1.OIDCClient, bool) {
	e.t.Helper()
	var oc havenv1.OIDCClient
	err := e.c.Get(context.Background(), types.NamespacedName{Namespace: ns, Name: name}, &oc)
	if kerrors.IsNotFound(err) {
		return nil, false
	}
	if err != nil {
		e.t.Fatal(err)
	}
	return &oc, true
}

func (e *ingEnv) drain() string {
	var b strings.Builder
	for {
		select {
		case ev := <-e.events.Events:
			b.WriteString(ev + "\n")
		default:
			return b.String()
		}
	}
}

func ingress(mods ...func(*networkingv1.Ingress)) *networkingv1.Ingress {
	i := &networkingv1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name: "shop", Namespace: "apps", UID: "uid-shop",
			Annotations: map[string]string{AnnIngressEnable: "true", AnnIngressPlane: "platform", AnnIngressPlaneNS: "identity"},
		},
		Spec: networkingv1.IngressSpec{Rules: []networkingv1.IngressRule{{Host: "shop.example.com"}}},
	}
	for _, m := range mods {
		m(i)
	}
	return i
}

func ingPlane(mods ...func(*havenv1.IdentityPlane)) *havenv1.IdentityPlane {
	p := readyPlane("identity", func(p *havenv1.IdentityPlane) {
		p.Spec.Profile = havenv1.ProfileProduction
		p.Annotations = map[string]string{AnnotationAllowIngressFrom: "apps"}
	})
	for _, m := range mods {
		m(p)
	}
	return p
}

func TestIngressRegistrationCreatesOwnedClient(t *testing.T) {
	e := newIngEnv(t, ingress(), ingPlane())
	e.reconcile("apps", "shop")
	oc, ok := e.oc("apps", "ing-shop")
	if !ok {
		t.Fatal("no OIDCClient generated")
	}
	s := oc.Spec
	if s.ClientID != "ing:apps/shop" || s.PlaneRef.Name != "platform" || s.PlaneRef.Namespace != "identity" {
		t.Errorf("spec = %+v", s)
	}
	if !reflect.DeepEqual(s.RedirectURIs, []string{"https://shop.example.com/oauth2/callback"}) {
		t.Errorf("redirect URIs = %v", s.RedirectURIs)
	}
	if s.Public || len(s.WebOrigins) != 0 || s.DeletionPolicy != havenv1.DeletionDelete {
		t.Errorf("unexpected spec %+v", s)
	}
	if ref := metav1.GetControllerOf(oc); ref == nil || ref.Kind != "Ingress" || ref.UID != "uid-shop" || ref.Name != "shop" {
		t.Errorf("controller owner = %+v", ref)
	}
	if oc.Labels[LabelIngressManaged] != "true" {
		t.Errorf("labels = %v", oc.Labels)
	}
}

func TestIngressRegistrationIdempotent(t *testing.T) {
	e := newIngEnv(t, ingress(func(i *networkingv1.Ingress) {
		i.Annotations[AnnIngressScopes] = "openid, profile"
		i.Annotations[AnnIngressRedirectPaths] = "/a,/b,/a"
	}), ingPlane())
	e.reconcile("apps", "shop")
	e.writes = nil
	for i := 0; i < 3; i++ {
		e.reconcile("apps", "shop")
	}
	if len(e.writes) != 0 {
		t.Errorf("second reconciles wrote: %v", e.writes)
	}
	oc, _ := e.oc("apps", "ing-shop")
	if len(oc.Spec.RedirectURIs) != 2 {
		t.Errorf("duplicate path not collapsed: %v", oc.Spec.RedirectURIs)
	}
	if oc.Annotations[annRequestedScopes] != "openid profile" {
		t.Errorf("scopes annotation = %q", oc.Annotations[annRequestedScopes])
	}
}

func TestIngressRegistrationDriftIsReverted(t *testing.T) {
	e := newIngEnv(t, ingress(), ingPlane())
	e.reconcile("apps", "shop")
	oc, _ := e.oc("apps", "ing-shop")
	oc.Spec.RedirectURIs = append(oc.Spec.RedirectURIs, "https://evil.example.net/cb")
	oc.Spec.Public = true
	oc.Spec.DeletionPolicy = havenv1.DeletionRetain
	oc.Annotations = map[string]string{AnnotationAdoptClient: "true", "keep": "me"}
	if err := e.c.Update(context.Background(), oc); err != nil {
		t.Fatal(err)
	}
	e.reconcile("apps", "shop")
	oc, _ = e.oc("apps", "ing-shop")
	if !reflect.DeepEqual(oc.Spec.RedirectURIs, []string{"https://shop.example.com/oauth2/callback"}) || oc.Spec.Public || oc.Spec.DeletionPolicy != havenv1.DeletionDelete {
		t.Errorf("drift not reverted: %+v", oc.Spec)
	}
	if _, has := oc.Annotations[AnnotationAdoptClient]; has {
		t.Error("adopt annotation survived: a generated client could take over an IdP client")
	}
	if oc.Annotations["keep"] != "me" {
		t.Error("unrelated annotation was removed")
	}
}

func TestIngressRegistrationFollowsIngressChanges(t *testing.T) {
	e := newIngEnv(t, ingress(), ingPlane())
	e.reconcile("apps", "shop")
	var ing networkingv1.Ingress
	_ = e.c.Get(context.Background(), types.NamespacedName{Namespace: "apps", Name: "shop"}, &ing)
	ing.Spec.Rules = append(ing.Spec.Rules, networkingv1.IngressRule{Host: "Shop2.Example.com"})
	ing.Annotations[AnnIngressRedirectPaths] = "/cb"
	if err := e.c.Update(context.Background(), &ing); err != nil {
		t.Fatal(err)
	}
	e.reconcile("apps", "shop")
	oc, _ := e.oc("apps", "ing-shop")
	want := []string{"https://shop.example.com/cb", "https://shop2.example.com/cb"}
	if !reflect.DeepEqual(oc.Spec.RedirectURIs, want) {
		t.Errorf("got %v want %v", oc.Spec.RedirectURIs, want)
	}
}

func TestIngressRegistrationPublicSetsOrigins(t *testing.T) {
	e := newIngEnv(t, ingress(func(i *networkingv1.Ingress) { i.Annotations[AnnIngressPublic] = "true" }), ingPlane())
	e.reconcile("apps", "shop")
	oc, _ := e.oc("apps", "ing-shop")
	if !oc.Spec.Public || !reflect.DeepEqual(oc.Spec.WebOrigins, []string{"https://shop.example.com"}) {
		t.Errorf("spec = %+v", oc.Spec)
	}
}

// A pre-existing OIDCClient with the generated name that this Ingress does not
// own is never read as ours, changed, or deleted.
func TestIngressRegistrationNeverTouchesForeignClients(t *testing.T) {
	foreign := &havenv1.OIDCClient{
		ObjectMeta: metav1.ObjectMeta{Name: "ing-shop", Namespace: "apps"},
		Spec:       havenv1.OIDCClientSpec{PlaneRef: havenv1.PlaneRef{Name: "other"}, ClientID: "mine", RedirectURIs: []string{"https://mine.example.com/cb"}},
	}
	otherOwner := foreign.DeepCopy()
	otherOwner.Name = "ing-shop"
	cases := map[string]*havenv1.OIDCClient{
		"unowned": foreign,
		"owned by an Ingress with another UID": func() *havenv1.OIDCClient {
			o := foreign.DeepCopy()
			o.OwnerReferences = []metav1.OwnerReference{{APIVersion: "networking.k8s.io/v1", Kind: "Ingress", Name: "shop", UID: "uid-OLD", Controller: ptrBool(true)}}
			return o
		}(),
		"owner ref without controller flag": func() *havenv1.OIDCClient {
			o := foreign.DeepCopy()
			o.OwnerReferences = []metav1.OwnerReference{{APIVersion: "networking.k8s.io/v1", Kind: "Ingress", Name: "shop", UID: "uid-shop"}}
			return o
		}(),
	}
	for name, f := range cases {
		t.Run(name, func(t *testing.T) {
			e := newIngEnv(t, ingress(), ingPlane(), f.DeepCopy())
			e.reconcile("apps", "shop")
			oc, ok := e.oc("apps", "ing-shop")
			if !ok || !reflect.DeepEqual(oc.Spec, f.Spec) || len(oc.Labels) != 0 {
				t.Fatalf("foreign client modified: %+v", oc)
			}
			if len(e.writes) != 0 {
				t.Errorf("writes on a foreign client: %v", e.writes)
			}
			if !strings.Contains(e.drain(), ReasonIngressConflict) {
				t.Error("no conflict event")
			}
			// Disabling must not delete it either.
			var ing networkingv1.Ingress
			_ = e.c.Get(context.Background(), types.NamespacedName{Namespace: "apps", Name: "shop"}, &ing)
			delete(ing.Annotations, AnnIngressEnable)
			_ = e.c.Update(context.Background(), &ing)
			e.writes = nil
			e.reconcile("apps", "shop")
			if _, ok := e.oc("apps", "ing-shop"); !ok || len(e.writes) != 0 {
				t.Errorf("foreign client deleted or written when registration was switched off: %v", e.writes)
			}
		})
	}
}

func ptrBool(b bool) *bool { return &b }

func TestIngressRegistrationOtherNamespaceNameNotTouched(t *testing.T) {
	// Same name in another namespace must be unaffected by either reconcile.
	other := &havenv1.OIDCClient{ObjectMeta: metav1.ObjectMeta{Name: "ing-shop", Namespace: "elsewhere"}}
	e := newIngEnv(t, ingress(), ingPlane(), other)
	e.reconcile("apps", "shop")
	got, ok := e.oc("elsewhere", "ing-shop")
	if !ok || got.Spec.ClientID != "" {
		t.Errorf("other namespace client changed: %+v", got)
	}
}

func TestIngressRegistrationDisableDeletesOwnedOnly(t *testing.T) {
	e := newIngEnv(t, ingress(), ingPlane())
	e.reconcile("apps", "shop")
	var ing networkingv1.Ingress
	_ = e.c.Get(context.Background(), types.NamespacedName{Namespace: "apps", Name: "shop"}, &ing)
	ing.Annotations[AnnIngressEnable] = "false"
	_ = e.c.Update(context.Background(), &ing)
	e.reconcile("apps", "shop")
	if _, ok := e.oc("apps", "ing-shop"); ok {
		t.Error("owned client survived registration being switched off")
	}
}

func TestIngressRegistrationOnlyExactTrueEnables(t *testing.T) {
	for _, v := range []string{"True", "yes", "1", "", "TRUE", " true"} {
		e := newIngEnv(t, ingress(func(i *networkingv1.Ingress) { i.Annotations[AnnIngressEnable] = v }), ingPlane())
		e.reconcile("apps", "shop")
		if _, ok := e.oc("apps", "ing-shop"); ok {
			t.Errorf("value %q enabled registration", v)
		}
	}
}

func TestIngressRegistrationPlaneOptInRequired(t *testing.T) {
	for name, ann := range map[string]map[string]string{
		"no annotation": nil,
		"other ns":      {AnnotationAllowIngressFrom: "team-b"},
		"empty":         {AnnotationAllowIngressFrom: ""},
		"prefix":        {AnnotationAllowIngressFrom: "app"},
	} {
		t.Run(name, func(t *testing.T) {
			e := newIngEnv(t, ingress(), ingPlane(func(p *havenv1.IdentityPlane) { p.Annotations = ann }))
			e.reconcile("apps", "shop")
			if _, ok := e.oc("apps", "ing-shop"); ok {
				t.Error("registered without plane opt-in")
			}
			if !strings.Contains(e.drain(), ReasonIngressDenied) {
				t.Error("no denial event")
			}
		})
	}
	e := newIngEnv(t, ingress(), ingPlane(func(p *havenv1.IdentityPlane) { p.Annotations = map[string]string{AnnotationAllowIngressFrom: "x, *"} }))
	e.reconcile("apps", "shop")
	if _, ok := e.oc("apps", "ing-shop"); !ok {
		t.Error("wildcard opt-in not honoured")
	}
}

func TestIngressRegistrationInvalidInputs(t *testing.T) {
	set := func(k, v string) func(*networkingv1.Ingress) {
		return func(i *networkingv1.Ingress) { i.Annotations[k] = v }
	}
	cases := map[string]func(*networkingv1.Ingress){
		"full URL as path":         set(AnnIngressRedirectPaths, "https://evil.example.net/cb"),
		"protocol relative":        set(AnnIngressRedirectPaths, "//evil.example.net/cb"),
		"no leading slash":         set(AnnIngressRedirectPaths, "cb"),
		"wildcard path":            set(AnnIngressRedirectPaths, "/cb/*"),
		"dotdot":                   set(AnnIngressRedirectPaths, "/a/../b"),
		"encoded dotdot":           set(AnnIngressRedirectPaths, "/a/%2e%2e/b"),
		"fragment":                 set(AnnIngressRedirectPaths, "/cb#x"),
		"query":                    set(AnnIngressRedirectPaths, "/cb?x=1"),
		"backslash":                set(AnnIngressRedirectPaths, `/cb\x`),
		"empty paths":              set(AnnIngressRedirectPaths, " , "),
		"host annotation not rule": set(AnnIngressHosts, "evil.example.net"),
		"host annotation wildcard": set(AnnIngressHosts, "*.example.com"),
		"http on prod plane":       set(AnnIngressInsecureHTTP, "true"),
		"http loopback on prod plane": func(i *networkingv1.Ingress) {
			i.Annotations[AnnIngressInsecureHTTP] = "true"
			i.Spec.Rules = []networkingv1.IngressRule{{Host: "localhost"}}
		},
		"bad scope":                set(AnnIngressScopes, "openid,bad scope!"),
		"bad public":               set(AnnIngressPublic, "maybe"),
		"bad realm":                set(AnnIngressRealm, "../x"),
		"no plane":                 func(i *networkingv1.Ingress) { delete(i.Annotations, AnnIngressPlane) },
		"wildcard rule host only":  func(i *networkingv1.Ingress) { i.Spec.Rules = []networkingv1.IngressRule{{Host: "*.example.com"}} },
		"no host (catch-all rule)": func(i *networkingv1.Ingress) { i.Spec.Rules = []networkingv1.IngressRule{{}} },
		"plane's own host":         func(i *networkingv1.Ingress) { i.Spec.Rules = []networkingv1.IngressRule{{Host: "auth.example.com"}} },
		"too many hosts":           func(i *networkingv1.Ingress) { i.Spec.Rules = manyRules(11) },
		"invalid host": func(i *networkingv1.Ingress) {
			i.Spec.Rules = []networkingv1.IngressRule{{Host: "bad_host.example.com"}}
		},
		"userinfo-ish host":   func(i *networkingv1.Ingress) { i.Spec.Rules = []networkingv1.IngressRule{{Host: "a@evil.com"}} },
		"bad plane namespace": set(AnnIngressPlaneNS, "Not_A_Namespace"),
	}
	for name, mod := range cases {
		t.Run(name, func(t *testing.T) {
			e := newIngEnv(t, ingress(mod), ingPlane())
			e.reconcile("apps", "shop")
			if oc, ok := e.oc("apps", "ing-shop"); ok {
				t.Fatalf("invalid registration produced a client: %+v", oc.Spec)
			}
			if ev := e.drain(); !strings.Contains(ev, ReasonIngressInvalid) {
				t.Errorf("no invalid event: %q", ev)
			}
		})
	}
}

func manyRules(n int) []networkingv1.IngressRule {
	var r []networkingv1.IngressRule
	for i := 0; i < n; i++ {
		r = append(r, networkingv1.IngressRule{Host: "h" + string(rune('a'+i)) + ".example.com"})
	}
	return r
}

// Invalid edits never widen or delete a working registration (last known good).
func TestIngressRegistrationInvalidEditKeepsLastGood(t *testing.T) {
	e := newIngEnv(t, ingress(), ingPlane())
	e.reconcile("apps", "shop")
	var ing networkingv1.Ingress
	_ = e.c.Get(context.Background(), types.NamespacedName{Namespace: "apps", Name: "shop"}, &ing)
	ing.Annotations[AnnIngressRedirectPaths] = "https://evil.example.net/"
	_ = e.c.Update(context.Background(), &ing)
	e.writes = nil
	e.reconcile("apps", "shop")
	oc, _ := e.oc("apps", "ing-shop")
	if !reflect.DeepEqual(oc.Spec.RedirectURIs, []string{"https://shop.example.com/oauth2/callback"}) || len(e.writes) != 0 {
		t.Errorf("last-known-good lost: %v writes %v", oc.Spec.RedirectURIs, e.writes)
	}
}

func TestIngressRegistrationHTTPOnlyDevLoopback(t *testing.T) {
	dev := func(p *havenv1.IdentityPlane) { p.Spec.Profile = havenv1.ProfileDev }
	httpAnn := func(host string) func(*networkingv1.Ingress) {
		return func(i *networkingv1.Ingress) {
			i.Annotations[AnnIngressInsecureHTTP] = "true"
			i.Spec.Rules = []networkingv1.IngressRule{{Host: host}}
		}
	}
	e := newIngEnv(t, ingress(httpAnn("localhost")), ingPlane(dev))
	e.reconcile("apps", "shop")
	oc, ok := e.oc("apps", "ing-shop")
	if !ok || !reflect.DeepEqual(oc.Spec.RedirectURIs, []string{"http://localhost/oauth2/callback"}) {
		t.Fatalf("dev loopback http not generated: %+v", oc)
	}
	// Dev plane, non-loopback host: refused.
	e = newIngEnv(t, ingress(httpAnn("shop.example.com")), ingPlane(dev))
	e.reconcile("apps", "shop")
	if _, ok := e.oc("apps", "ing-shop"); ok {
		t.Error("http for a non-loopback host on a dev plane")
	}
	// Dev plane without the opt-in annotation: https.
	e = newIngEnv(t, ingress(), ingPlane(dev))
	e.reconcile("apps", "shop")
	oc, _ = e.oc("apps", "ing-shop")
	if oc == nil || !strings.HasPrefix(oc.Spec.RedirectURIs[0], "https://") {
		t.Errorf("dev plane defaulted away from https: %+v", oc)
	}
}

func TestIngressRegistrationPlaneMissing(t *testing.T) {
	e := newIngEnv(t, ingress())
	res := e.reconcile("apps", "shop")
	if _, ok := e.oc("apps", "ing-shop"); ok || res.RequeueAfter == 0 {
		t.Errorf("client without plane or no retry (requeue %v)", res.RequeueAfter)
	}
}

func TestIngressRegistrationIngressGoneIsNoop(t *testing.T) {
	e := newIngEnv(t)
	e.reconcile("apps", "gone")
	if len(e.writes) != 0 {
		t.Errorf("writes: %v", e.writes)
	}
}

func TestCheckRedirectPath(t *testing.T) {
	good := []string{"/", "/cb", "/oauth2/callback", "/a/b-c_d.e~f", "/a:b@c", "/x(1)"}
	for _, p := range good {
		if m := CheckRedirectPath(p); m != "" {
			t.Errorf("%q rejected: %s", p, m)
		}
	}
	bad := []string{"", "cb", "//x", "/a//b", "/a/./b", "/..", "/a b", "/a%2fb", "/a?b", "/a#b", `/a\b`, "/*", "/" + strings.Repeat("a", 200), "javascript:alert(1)", "/é"}
	for _, p := range bad {
		if CheckRedirectPath(p) == "" {
			t.Errorf("%q accepted", p)
		}
	}
}
