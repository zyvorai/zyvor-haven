// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package controller

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	havenv1 "github.com/zyvorai/haven/api/v1alpha1"
	"github.com/zyvorai/haven/internal/profiles"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

// Annotations read from an Ingress (see docs/ingress-registration.md).
const (
	// AnnIngressEnable turns registration on when its value is exactly "true".
	AnnIngressEnable = "haven.dev/oidc-client"
	// AnnIngressPlane names the IdentityPlane (required).
	AnnIngressPlane = "haven.dev/oidc-plane"
	// AnnIngressPlaneNS is the plane's namespace (default: the Ingress namespace).
	AnnIngressPlaneNS = "haven.dev/oidc-plane-namespace"
	// AnnIngressRealm overrides the plane's first realm.
	AnnIngressRealm = "haven.dev/oidc-realm"
	// AnnIngressRedirectPaths is a comma separated list of redirect paths
	// (default "/oauth2/callback"). Never a full URL.
	AnnIngressRedirectPaths = "haven.dev/oidc-redirect-paths"
	// AnnIngressHosts narrows the hosts to a subset of the Ingress rule hosts.
	AnnIngressHosts = "haven.dev/oidc-hosts"
	// AnnIngressScopes lists requested scopes. Advisory: OIDCClient has no scope
	// field, so it is validated and recorded, not enforced.
	AnnIngressScopes = "haven.dev/oidc-scopes"
	// AnnIngressPublic "true" registers a public (PKCE, no secret) client.
	AnnIngressPublic = "haven.dev/oidc-public"
	// AnnIngressInsecureHTTP "true" permits http, only on a dev-profile plane and
	// only for loopback hosts.
	AnnIngressInsecureHTTP = "haven.dev/oidc-insecure-http"

	// AnnotationAllowIngressFrom on an IdentityPlane lists the namespaces (comma
	// separated, or "*") whose Ingresses may register clients with it. Without it
	// no Ingress can.
	AnnotationAllowIngressFrom = "haven.zyvor.dev/allow-ingress-registration-from"

	// LabelIngressManaged marks generated OIDCClients.
	LabelIngressManaged = "haven.dev/ingress-registration"
	// annRequestedScopes records the advisory scopes on the generated OIDCClient.
	annRequestedScopes = "haven.dev/requested-scopes"

	defaultRedirectPath = "/oauth2/callback"
	maxIngressHosts     = 10
	maxRedirectPaths    = 10
	ingressRetry        = 30 * time.Second

	ReasonIngressInvalid  = "IngressRegistrationInvalid"
	ReasonIngressDenied   = "IngressRegistrationDenied"
	ReasonIngressConflict = "IngressRegistrationConflict"
	ReasonIngressSynced   = "IngressRegistrationSynced"
)

var (
	redirectPathRE = regexp.MustCompile(`^/[A-Za-z0-9/_.~:@!$&'()+,=;-]*$`)
	scopeRE        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
	realmRE        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$`)
)

// IngressRegistrationReconciler turns an annotated Ingress into an OIDCClient
// owned by it. It never talks to the identity plane: the OIDCClient controller
// does, with all its own validation, so this controller only decides what the
// OIDCClient spec should be.
type IngressRegistrationReconciler struct {
	client.Client
	Recorder record.EventRecorder
}

// IngressClientName is the name of the OIDCClient generated for an Ingress.
func IngressClientName(ingressName string) string { return "ing-" + ingressName }

// IngressClientID is the OIDC client_id: unambiguous because neither a
// namespace nor a name can contain "/".
func IngressClientID(ns, name string) string { return "ing:" + ns + "/" + name }

func (r *IngressRegistrationReconciler) event(obj client.Object, typ, reason, msg string) {
	if r.Recorder != nil {
		r.Recorder.Event(obj, typ, reason, msg)
	}
}

// CheckRedirectPath validates one redirect path. Returns "" when acceptable.
func CheckRedirectPath(p string) string {
	switch {
	case p == "":
		return "must not be empty"
	case len(p) > 200:
		return "is longer than 200 characters"
	case !strings.HasPrefix(p, "/"):
		return "must start with /"
	case strings.HasPrefix(p, "//"):
		return "must not start with //"
	case !redirectPathRE.MatchString(p):
		return "contains characters that are not allowed (no *, %, ?, #, backslash, spaces)"
	case strings.Contains(p, "//"):
		return "must not contain //"
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "." || seg == ".." {
			return "must not contain . or .. segments"
		}
	}
	return ""
}

func splitList(s string) []string {
	var out []string
	for _, v := range strings.Split(s, ",") {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ruleHosts returns the concrete (non-wildcard) hosts of the Ingress rules,
// lowercased and de-duplicated, in order. Wildcard hosts are never used.
func ruleHosts(ing *networkingv1.Ingress) []string {
	seen := map[string]bool{}
	var all []string
	for _, rule := range ing.Spec.Rules {
		h := strings.ToLower(strings.TrimSpace(rule.Host))
		if h == "" || strings.Contains(h, "*") || seen[h] {
			continue
		}
		seen[h] = true
		all = append(all, h)
	}
	return all
}

// ingressSpec is the outcome of validating an Ingress.
type ingressSpec struct {
	spec   havenv1.OIDCClientSpec
	scopes []string
}

// buildIngressSpec derives the OIDCClient spec from the Ingress alone (plus the
// plane, for the host guard and the profile; plane may be nil). problems are
// user-facing and contain no secrets.
func buildIngressSpec(ing *networkingv1.Ingress, plane *havenv1.IdentityPlane) (ingressSpec, []string) {
	var out ingressSpec
	var p []string
	a := ing.Annotations

	planeName := a[AnnIngressPlane]
	planeNS := a[AnnIngressPlaneNS]
	if planeNS == "" {
		planeNS = ing.Namespace
	}
	if planeName == "" {
		p = append(p, AnnIngressPlane+" is required")
	} else if errs := validation.IsDNS1123Subdomain(planeName); len(errs) > 0 {
		p = append(p, AnnIngressPlane+" is not a valid name")
	}
	if errs := validation.IsDNS1123Label(planeNS); len(errs) > 0 {
		p = append(p, AnnIngressPlaneNS+" is not a valid namespace")
	}
	realm := a[AnnIngressRealm]
	if realm != "" && !realmRE.MatchString(realm) {
		p = append(p, AnnIngressRealm+" is not a valid realm name")
	}

	clientID := IngressClientID(ing.Namespace, ing.Name)
	if !clientIDRE.MatchString(clientID) {
		p = append(p, "the generated clientId "+clientID+" is too long or invalid")
	}
	if len(IngressClientName(ing.Name)) > 253 {
		p = append(p, "the Ingress name is too long to derive an OIDCClient name")
	}

	// Hosts: only ever from the Ingress rules.
	hosts := ruleHosts(ing)
	if _, set := a[AnnIngressHosts]; set {
		avail := map[string]bool{}
		for _, h := range hosts {
			avail[h] = true
		}
		hosts = nil
		seen := map[string]bool{}
		for _, h := range splitList(a[AnnIngressHosts]) {
			h = strings.ToLower(h)
			switch {
			case strings.Contains(h, "*"):
				p = append(p, fmt.Sprintf("%s: wildcard host %q is not allowed", AnnIngressHosts, h))
			case !avail[h]:
				p = append(p, fmt.Sprintf("%s: %q is not a host of this Ingress's rules", AnnIngressHosts, h))
			case !seen[h]:
				seen[h] = true
				hosts = append(hosts, h)
			}
		}
	}
	if len(hosts) == 0 {
		p = append(p, "the Ingress has no concrete (non-wildcard) rule host to register")
	}
	if len(hosts) > maxIngressHosts {
		p = append(p, fmt.Sprintf("at most %d hosts", maxIngressHosts))
	}
	for _, h := range hosts {
		if errs := validation.IsDNS1123Subdomain(h); len(errs) > 0 {
			p = append(p, fmt.Sprintf("host %q is not a valid DNS name", h))
		}
	}

	dev := false
	if plane != nil {
		dev = profiles.Merge(&plane.Spec).Profile == havenv1.ProfileDev
		for _, h := range hosts {
			if h == strings.ToLower(plane.Spec.Hostname) || (plane.Spec.ConsoleHostname != "" && h == strings.ToLower(plane.Spec.ConsoleHostname)) {
				p = append(p, fmt.Sprintf("host %q belongs to the identity plane itself and cannot be registered", h))
			}
		}
	}

	// Scheme: https always; http only dev profile + explicit opt-in + loopback.
	scheme := "https"
	if v, set := a[AnnIngressInsecureHTTP]; set {
		switch {
		case v != "true":
			p = append(p, AnnIngressInsecureHTTP+` must be "true" or absent`)
		case !dev:
			p = append(p, AnnIngressInsecureHTTP+" is only honoured on a plane with profile dev")
		default:
			scheme = "http"
			for _, h := range hosts {
				if !isLoopbackHost(h) {
					p = append(p, fmt.Sprintf("http is only possible for loopback hosts, not %q", h))
				}
			}
		}
	}

	// Redirect paths: derived URIs only.
	paths := []string{defaultRedirectPath}
	if v, set := a[AnnIngressRedirectPaths]; set {
		paths = splitList(v)
		if len(paths) == 0 {
			p = append(p, AnnIngressRedirectPaths+" is set but empty")
		}
	}
	if len(paths) > maxRedirectPaths {
		p = append(p, fmt.Sprintf("at most %d redirect paths", maxRedirectPaths))
	}
	seenPath := map[string]bool{}
	var uniq []string
	for _, rp := range paths {
		if msg := CheckRedirectPath(rp); msg != "" {
			p = append(p, fmt.Sprintf("%s: %q %s", AnnIngressRedirectPaths, rp, msg))
			continue
		}
		if !seenPath[rp] {
			seenPath[rp] = true
			uniq = append(uniq, rp)
		}
	}

	// Scopes: advisory, validated.
	if v, ok := a[AnnIngressScopes]; ok {
		for _, s := range splitList(v) {
			if !scopeRE.MatchString(s) {
				p = append(p, fmt.Sprintf("%s: %q is not a valid scope", AnnIngressScopes, s))
				continue
			}
			out.scopes = append(out.scopes, s)
		}
		if len(out.scopes) > 20 {
			p = append(p, AnnIngressScopes+": at most 20 scopes")
		}
	}

	public := false
	switch a[AnnIngressPublic] {
	case "", "false":
	case "true":
		public = true
	default:
		p = append(p, AnnIngressPublic+` must be "true" or "false"`)
	}

	if len(p) > 0 {
		return out, p
	}

	var uris, origins []string
	for _, h := range hosts {
		origin := scheme + "://" + h
		origins = append(origins, origin)
		for _, rp := range uniq {
			uris = append(uris, origin+rp)
		}
	}
	// Last line of defence: the OIDCClient rules must accept every derived URI.
	for _, u := range uris {
		if msg := checkRedirectURI(u); msg != "" {
			return out, []string{fmt.Sprintf("derived redirect URI %q: %s", u, msg)}
		}
	}
	out.spec = havenv1.OIDCClientSpec{
		PlaneRef:       havenv1.PlaneRef{Name: planeName, Namespace: planeNS},
		Realm:          realm,
		ClientID:       clientID,
		DisplayName:    ing.Namespace + "/" + ing.Name,
		Public:         public,
		RedirectURIs:   uris,
		DeletionPolicy: havenv1.DeletionDelete,
	}
	if public {
		out.spec.WebOrigins = origins
	}
	return out, nil
}

func nsAllowed(list, ns string) bool {
	for _, a := range strings.Split(list, ",") {
		a = strings.TrimSpace(a)
		if a == "*" || (a != "" && a == ns) {
			return true
		}
	}
	return false
}

// ownedBy reports whether oc is controlled by this very Ingress (UID match).
func ownedBy(oc *havenv1.OIDCClient, ing *networkingv1.Ingress) bool {
	return metav1.IsControlledBy(oc, ing)
}

func (r *IngressRegistrationReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var ing networkingv1.Ingress
	if err := r.Get(ctx, req.NamespacedName, &ing); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !ing.DeletionTimestamp.IsZero() {
		return ctrl.Result{}, nil // garbage collection removes the owned OIDCClient
	}

	key := types.NamespacedName{Namespace: ing.Namespace, Name: IngressClientName(ing.Name)}
	var existing havenv1.OIDCClient
	found := true
	if err := r.Get(ctx, key, &existing); err != nil {
		if !kerrors.IsNotFound(err) {
			return ctrl.Result{}, err
		}
		found = false
	}
	if found && !ownedBy(&existing, &ing) {
		if ing.Annotations[AnnIngressEnable] == "true" {
			r.event(&ing, corev1.EventTypeWarning, ReasonIngressConflict,
				fmt.Sprintf("OIDCClient %s exists and is not owned by this Ingress; it is left untouched", key.Name))
		}
		return ctrl.Result{}, nil
	}

	if ing.Annotations[AnnIngressEnable] != "true" {
		// Registration switched off: remove only what this Ingress owns.
		if found && existing.DeletionTimestamp.IsZero() {
			if err := r.Delete(ctx, &existing, client.Preconditions{UID: &existing.UID}); err != nil && !kerrors.IsNotFound(err) {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	// Plane (needed for the opt-in, the host guard and the profile).
	planeName := ing.Annotations[AnnIngressPlane]
	planeNS := ing.Annotations[AnnIngressPlaneNS]
	if planeNS == "" {
		planeNS = ing.Namespace
	}
	var plane *havenv1.IdentityPlane
	if planeName != "" && len(validation.IsDNS1123Subdomain(planeName)) == 0 && len(validation.IsDNS1123Label(planeNS)) == 0 {
		var pl havenv1.IdentityPlane
		err := r.Get(ctx, types.NamespacedName{Namespace: planeNS, Name: planeName}, &pl)
		switch {
		case kerrors.IsNotFound(err):
			r.event(&ing, corev1.EventTypeWarning, ReasonIngressInvalid, fmt.Sprintf("IdentityPlane %s/%s not found", planeNS, planeName))
			return ctrl.Result{RequeueAfter: ingressRetry}, nil
		case err != nil:
			return ctrl.Result{}, err
		}
		plane = &pl
	}

	if plane != nil && !nsAllowed(plane.Annotations[AnnotationAllowIngressFrom], ing.Namespace) {
		r.event(&ing, corev1.EventTypeWarning, ReasonIngressDenied,
			fmt.Sprintf("IdentityPlane %s/%s does not allow Ingress registration from namespace %s (annotation %s)",
				plane.Namespace, plane.Name, ing.Namespace, AnnotationAllowIngressFrom))
		return ctrl.Result{}, nil
	}
	built, problems := buildIngressSpec(&ing, plane)
	if len(problems) > 0 {
		// Fail closed without widening: an existing generated client stays as it was.
		r.event(&ing, corev1.EventTypeWarning, ReasonIngressInvalid, strings.Join(problems, "; "))
		return ctrl.Result{}, nil
	}

	if !found {
		oc := &havenv1.OIDCClient{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}}
		applyIngressManaged(oc, built)
		if err := controllerutil.SetControllerReference(&ing, oc, r.Scheme()); err != nil {
			return ctrl.Result{}, err
		}
		if err := r.Create(ctx, oc); err != nil {
			if kerrors.IsAlreadyExists(err) {
				return ctrl.Result{Requeue: true}, nil // raced: next pass checks ownership
			}
			return ctrl.Result{}, err
		}
		r.event(&ing, corev1.EventTypeNormal, ReasonIngressSynced, "registered OIDCClient "+key.Name)
		return ctrl.Result{}, nil
	}

	want := existing.DeepCopy()
	applyIngressManaged(want, built)
	if apiequality.Semantic.DeepEqual(existing.Spec, want.Spec) &&
		apiequality.Semantic.DeepEqual(existing.Labels, want.Labels) &&
		apiequality.Semantic.DeepEqual(existing.Annotations, want.Annotations) {
		return ctrl.Result{}, nil
	}
	if err := r.Update(ctx, want); err != nil {
		return ctrl.Result{}, err
	}
	r.event(&ing, corev1.EventTypeNormal, ReasonIngressSynced, "updated OIDCClient "+key.Name)
	return ctrl.Result{}, nil
}

// applyIngressManaged overwrites everything this controller owns on oc: the
// whole spec (so hand edits revert), our label, the scopes annotation, and it
// removes the adopt annotation so a generated client can never take over an IdP
// client it did not create.
func applyIngressManaged(oc *havenv1.OIDCClient, b ingressSpec) {
	oc.Spec = b.spec
	labels := map[string]string{}
	for k, v := range oc.Labels {
		labels[k] = v
	}
	labels[LabelIngressManaged] = "true"
	oc.Labels = labels
	anns := map[string]string{}
	for k, v := range oc.Annotations {
		if k != AnnotationAdoptClient && k != annRequestedScopes {
			anns[k] = v
		}
	}
	if len(b.scopes) > 0 {
		anns[annRequestedScopes] = strings.Join(b.scopes, " ")
	}
	if len(anns) == 0 {
		anns = nil
	}
	oc.Annotations = anns
}

func (r *IngressRegistrationReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor("haven-ingress-registration")
	}
	return ctrl.NewControllerManagedBy(mgr).
		Named("ingress-registration").
		For(&networkingv1.Ingress{}).
		Owns(&havenv1.OIDCClient{}).
		Complete(r)
}
