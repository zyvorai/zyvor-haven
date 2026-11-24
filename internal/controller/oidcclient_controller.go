// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package controller

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	havenv1 "github.com/zyvorai/haven/api/v1alpha1"
	"github.com/zyvorai/haven/internal/idp"
	"github.com/zyvorai/haven/internal/profiles"
	"github.com/zyvorai/haven/internal/render"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	oidcFinalizer = "identity.haven.dev/oidcclient"

	// AnnotationRotateSecret on an OIDCClient asks for a new client secret: any
	// value that differs from the last one handled triggers one rotation.
	AnnotationRotateSecret = "haven.zyvor.dev/rotate-secret" // #nosec G101 -- annotation key name, not a credential
	// AnnotationAdoptClient on an OIDCClient allows it to take over an IdP client
	// with the same clientId that this OIDCClient did not create.
	AnnotationAdoptClient = "haven.zyvor.dev/adopt-client"
	// AnnotationAllowFrom on an IdentityPlane lists the namespaces (comma
	// separated, or "*") whose OIDCClients may reference it from another namespace.
	AnnotationAllowFrom = "haven.zyvor.dev/allow-oidcclients-from"
	// annotationRotateHandled lives on the generated Secret and records the last
	// rotate-secret value acted on. It is not secret.
	annotationRotateHandled = "haven.zyvor.dev/rotate-handled"

	pkceAttribute = "pkce.code.challenge.method"

	defaultKeyClientID = "client-id"
	defaultKeySecret   = "client-secret"
	defaultKeyIssuer   = "issuer"

	oidcResync       = 5 * time.Minute
	oidcPlaneRetry   = 20 * time.Second
	oidcBackendRetry = 30 * time.Second
)

// Condition types and reasons. Reasons are stable API for alerting.
const (
	CondReady  = "Ready"
	CondSynced = "Synced"

	ReasonSynced           = "Synced"
	ReasonInvalidSpec      = "InvalidSpec"
	ReasonPlaneNotFound    = "PlaneNotFound"
	ReasonPlaneNotAllowed  = "PlaneNotAllowed"
	ReasonPlaneNotNative   = "PlaneNotNative"
	ReasonPlaneNotReady    = "PlaneNotReady"
	ReasonPlaneUnreachable = "PlaneUnreachable"
	ReasonRealmNotFound    = "RealmNotFound"
	ReasonClientExists     = "ClientExists"
	ReasonSecretNotOwned   = "SecretNotOwned"
	ReasonImmutable        = "ImmutableFieldChanged"
	ReasonBackendError     = "BackendError"
	ReasonDeleting         = "Deleting"
)

var (
	clientIDRE     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$`)
	reservedClient = map[string]bool{"haven-admin": true, "haven-console": true}

	errRealmMissing   = errors.New("realm not found")
	errSecretNotOwned = errors.New("secret exists and is not owned by this OIDCClient")
)

// ProviderFactory returns an Admin API client for a plane.
type ProviderFactory interface {
	ProviderFor(ctx context.Context, plane *havenv1.IdentityPlane) (idp.Provider, error)
}

// ProviderFactoryFunc adapts a function to ProviderFactory.
type ProviderFactoryFunc func(ctx context.Context, plane *havenv1.IdentityPlane) (idp.Provider, error)

func (f ProviderFactoryFunc) ProviderFor(ctx context.Context, plane *havenv1.IdentityPlane) (idp.Provider, error) {
	return f(ctx, plane)
}

// OIDCClientReconciler keeps an IdP client and its Secret in line with an
// OIDCClient. It talks to the identity plane only through idp.Provider.
type OIDCClientReconciler struct {
	client.Client
	Providers ProviderFactory
	Recorder  record.EventRecorder
	Now       func() time.Time
}

func (r *OIDCClientReconciler) now() metav1.Time {
	if r.Now != nil {
		return metav1.NewTime(r.Now())
	}
	return metav1.Now()
}

func (r *OIDCClientReconciler) event(oc *havenv1.OIDCClient, typ, reason, msg string) {
	if r.Recorder != nil {
		r.Recorder.Event(oc, typ, reason, msg)
	}
}

// safeErr renders an error without the backend response body, which callers
// must treat as sensitive.
func safeErr(err error) string {
	if se := idp.AsStatus(err); se != nil {
		return fmt.Sprintf("identity backend returned %d", se.Code)
	}
	return err.Error()
}

// resolved is the OIDCClient spec with its defaults applied.
type resolved struct {
	clientID   string
	authCode   bool
	svcAccount bool
	pkce       bool
	secretName string
	keys       havenv1.OIDCClientSecretKeys
	policy     havenv1.DeletionPolicy
}

func resolveSpec(oc *havenv1.OIDCClient) resolved {
	s := &oc.Spec
	res := resolved{clientID: s.ClientID, policy: s.DeletionPolicy}
	if res.clientID == "" {
		res.clientID = oc.Name
	}
	if res.policy == "" {
		res.policy = havenv1.DeletionDelete
	}
	res.svcAccount = s.ServiceAccount
	if s.Flows != nil && s.Flows.ClientCredentials != nil && *s.Flows.ClientCredentials {
		res.svcAccount = true
	}
	switch {
	case s.Flows != nil && s.Flows.AuthorizationCode != nil:
		res.authCode = *s.Flows.AuthorizationCode
	default:
		res.authCode = !res.svcAccount || len(s.RedirectURIs) != 0
	}
	res.pkce = s.PKCE == nil || *s.PKCE
	res.secretName = oc.Name + "-oidc"
	res.keys = havenv1.OIDCClientSecretKeys{ClientID: defaultKeyClientID, ClientSecret: defaultKeySecret, Issuer: defaultKeyIssuer}
	if ref := s.SecretRef; ref != nil {
		if ref.Name != "" {
			res.secretName = ref.Name
		}
		if ref.Keys.ClientID != "" {
			res.keys.ClientID = ref.Keys.ClientID
		}
		if ref.Keys.ClientSecret != "" {
			res.keys.ClientSecret = ref.Keys.ClientSecret
		}
		if ref.Keys.Issuer != "" {
			res.keys.Issuer = ref.Keys.Issuer
		}
	}
	return res
}

// validateSpec checks everything that does not need the plane. The returned
// problems never contain user-supplied secrets (the spec has none).
func validateSpec(oc *havenv1.OIDCClient, res resolved) []string {
	s := &oc.Spec
	var p []string
	if s.PlaneRef.Name == "" {
		p = append(p, "planeRef.name is required")
	}
	if !clientIDRE.MatchString(res.clientID) {
		p = append(p, "clientId must match "+clientIDRE.String())
	}
	if reservedClient[res.clientID] {
		p = append(p, fmt.Sprintf("clientId %q is reserved for Haven itself", res.clientID))
	}
	if len(s.DisplayName) > 255 {
		p = append(p, "displayName is longer than 255 characters")
	}
	if s.Public && res.svcAccount {
		p = append(p, "a public client cannot be a service account (serviceAccount / flows.clientCredentials)")
	}
	if s.Public && !res.pkce {
		p = append(p, "pkce cannot be disabled for a public client")
	}
	if !res.authCode && !res.svcAccount {
		p = append(p, "no flow enabled: set flows.authorizationCode or serviceAccount")
	}
	if res.authCode && len(s.RedirectURIs) == 0 {
		p = append(p, "redirectUris is required when the authorization code flow is enabled")
	}
	if len(s.RedirectURIs) > 50 || len(s.WebOrigins) > 50 {
		p = append(p, "at most 50 redirectUris and 50 webOrigins")
	}
	for i, u := range s.RedirectURIs {
		if msg := checkRedirectURI(u); msg != "" {
			p = append(p, fmt.Sprintf("redirectUris[%d]: %s", i, msg))
		}
	}
	for i, u := range s.WebOrigins {
		if msg := checkWebOrigin(u); msg != "" {
			p = append(p, fmt.Sprintf("webOrigins[%d]: %s", i, msg))
		}
	}
	if s.BackchannelLogoutURL != "" {
		if msg := checkRedirectURI(s.BackchannelLogoutURL); msg != "" {
			p = append(p, "backchannelLogoutUrl: "+msg)
		}
	}
	if s.DeletionPolicy != "" && s.DeletionPolicy != havenv1.DeletionDelete && s.DeletionPolicy != havenv1.DeletionRetain {
		p = append(p, "deletionPolicy must be Delete or Retain")
	}
	if errs := validation.IsDNS1123Subdomain(res.secretName); len(errs) > 0 {
		p = append(p, "secretRef.name is not a valid Secret name")
	}
	seen := map[string]bool{}
	for _, k := range []string{res.keys.ClientID, res.keys.ClientSecret, res.keys.Issuer} {
		if errs := validation.IsConfigMapKey(k); len(errs) > 0 {
			p = append(p, fmt.Sprintf("secretRef.keys: %q is not a valid Secret key", k))
		}
		if seen[k] {
			p = append(p, fmt.Sprintf("secretRef.keys: %q is used twice", k))
		}
		seen[k] = true
	}
	return p
}

func isLoopbackHost(h string) bool {
	switch h {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

// checkRedirectURI applies the rules of the config-as-code validator: no
// wildcards, https, or http for loopback only; additionally no javascript:,
// data:, vbscript:, file: or blob: URLs, no fragment and no userinfo.
func checkRedirectURI(raw string) string {
	if raw == "" {
		return "must not be empty"
	}
	if len(raw) > 2048 {
		return "is longer than 2048 characters"
	}
	if strings.Contains(raw, "*") {
		return "wildcards are not allowed"
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return "must be an absolute URL"
	}
	switch strings.ToLower(u.Scheme) {
	case "javascript", "data", "vbscript", "file", "blob":
		return "scheme " + strings.ToLower(u.Scheme) + " is not allowed"
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return "http is only allowed for loopback hosts; use https"
		}
	default:
		return "scheme must be https (or http for loopback)"
	}
	if u.Hostname() == "" {
		return "must have a host"
	}
	if u.User != nil {
		return "must not contain credentials"
	}
	if u.Fragment != "" {
		return "must not contain a fragment"
	}
	return ""
}

func checkWebOrigin(raw string) string {
	if msg := checkRedirectURI(raw); msg != "" {
		return msg
	}
	u, _ := url.Parse(raw)
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return "must be an origin without path or query"
	}
	return ""
}

func planeReady(p *havenv1.IdentityPlane) bool {
	for _, c := range p.Status.Conditions {
		if c.Type == "IdentityProviderReady" {
			return c.Status == metav1.ConditionTrue
		}
	}
	return p.Status.Phase == havenv1.PhaseReady
}

func allowedFrom(plane *havenv1.IdentityPlane, ns string) bool {
	for _, a := range strings.Split(plane.Annotations[AnnotationAllowFrom], ",") {
		a = strings.TrimSpace(a)
		if a == "*" || (a != "" && a == ns) {
			return true
		}
	}
	return false
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func sameStringSet(a, b []string) bool {
	x, y := sortedCopy(a), sortedCopy(b)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// applyManaged overlays the fields this controller manages onto base and
// leaves every other field (description, other attributes) as the IdP has it.
func applyManaged(base idp.Client, oc *havenv1.OIDCClient, res resolved) idp.Client {
	c := base
	c.ClientID = res.clientID
	c.Name = oc.Spec.DisplayName
	c.Enabled = true
	c.PublicClient = oc.Spec.Public
	c.Protocol = "openid-connect"
	c.RedirectURIs = append([]string(nil), oc.Spec.RedirectURIs...)
	c.WebOrigins = append([]string(nil), oc.Spec.WebOrigins...)
	c.StandardFlowEnabled = res.authCode
	c.ServiceAccountsEnabled = res.svcAccount
	c.BackchannelLogoutURL = oc.Spec.BackchannelLogoutURL
	attrs := map[string]string{}
	for k, v := range base.Attributes {
		attrs[k] = v
	}
	if res.pkce || oc.Spec.Public {
		attrs[pkceAttribute] = "S256"
	} else {
		delete(attrs, pkceAttribute)
	}
	if len(attrs) == 0 {
		attrs = nil
	}
	c.Attributes = attrs
	c.Secret = ""
	return c
}

func managedEqual(cur, want idp.Client) bool {
	return cur.Name == want.Name && cur.Enabled == want.Enabled && cur.PublicClient == want.PublicClient &&
		cur.StandardFlowEnabled == want.StandardFlowEnabled && cur.ServiceAccountsEnabled == want.ServiceAccountsEnabled &&
		sameStringSet(cur.RedirectURIs, want.RedirectURIs) && sameStringSet(cur.WebOrigins, want.WebOrigins) &&
		cur.BackchannelLogoutURL == want.BackchannelLogoutURL &&
		cur.Attributes[pkceAttribute] == want.Attributes[pkceAttribute]
}

func (r *OIDCClientReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var oc havenv1.OIDCClient
	if err := r.Get(ctx, req.NamespacedName, &oc); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}
	if !oc.DeletionTimestamp.IsZero() {
		return r.finalize(ctx, &oc)
	}
	if !controllerutil.ContainsFinalizer(&oc, oidcFinalizer) {
		controllerutil.AddFinalizer(&oc, oidcFinalizer)
		if err := r.Update(ctx, &oc); err != nil {
			return ctrl.Result{}, err
		}
	}

	st := *oc.Status.DeepCopy()
	res, err := r.sync(ctx, &oc, &st)
	st.ObservedGeneration = oc.Generation
	if perr := r.persist(ctx, &oc, st); perr != nil && err == nil {
		err = perr
	}
	return res, err
}

// persist writes st to the status subresource when it differs from what is
// stored. Transition times are kept while a condition's status is unchanged.
func (r *OIDCClientReconciler) persist(ctx context.Context, oc *havenv1.OIDCClient, st havenv1.OIDCClientStatus) error {
	carryTransitionTimes(oc.Status.Conditions, st.Conditions)
	if apiequality.Semantic.DeepEqual(oc.Status, st) {
		return nil
	}
	cur := oc.Status
	oc.Status = st
	if err := r.Status().Update(ctx, oc); err != nil {
		oc.Status = cur
		return err
	}
	return nil
}

func setConds(oc *havenv1.OIDCClient, st *havenv1.OIDCClientStatus, ok bool, reason, msg string) {
	status := "False"
	if ok {
		status = "True"
	}
	st.Conditions = nil
	for _, t := range []string{CondReady, CondSynced} {
		c := render.Condition(t, status, reason, msg)
		c.ObservedGeneration = oc.Generation
		st.Conditions = append(st.Conditions, c)
	}
}

func (r *OIDCClientReconciler) fail(oc *havenv1.OIDCClient, st *havenv1.OIDCClientStatus, reason, msg string, requeue time.Duration) (ctrl.Result, error) {
	setConds(oc, st, false, reason, msg)
	r.event(oc, corev1.EventTypeWarning, reason, msg)
	return ctrl.Result{RequeueAfter: requeue}, nil
}

func (r *OIDCClientReconciler) getPlane(ctx context.Context, oc *havenv1.OIDCClient) (*havenv1.IdentityPlane, error) {
	ns := oc.Spec.PlaneRef.Namespace
	if ns == "" {
		ns = oc.Namespace
	}
	var plane havenv1.IdentityPlane
	if err := r.Get(ctx, types.NamespacedName{Name: oc.Spec.PlaneRef.Name, Namespace: ns}, &plane); err != nil {
		return nil, err
	}
	return &plane, nil
}

func realmOf(oc *havenv1.OIDCClient, plane *havenv1.IdentityPlane) string {
	if oc.Spec.Realm != "" {
		return oc.Spec.Realm
	}
	spec := profiles.Merge(&plane.Spec)
	return spec.Bootstrap.FirstRealm
}

func issuerOf(plane *havenv1.IdentityPlane, realm string) string {
	return render.Endpoints(plane).IdP + "/realms/" + realm
}

func (r *OIDCClientReconciler) sync(ctx context.Context, oc *havenv1.OIDCClient, st *havenv1.OIDCClientStatus) (ctrl.Result, error) {
	logger := log.FromContext(ctx)
	res := resolveSpec(oc)

	if problems := validateSpec(oc, res); len(problems) > 0 {
		// No requeue: only a spec change can fix this, and that triggers a reconcile.
		return r.fail(oc, st, ReasonInvalidSpec, strings.Join(problems, "; "), 0)
	}

	plane, err := r.getPlane(ctx, oc)
	if kerrors.IsNotFound(err) {
		return r.fail(oc, st, ReasonPlaneNotFound, fmt.Sprintf("IdentityPlane %q not found", oc.Spec.PlaneRef.Name), oidcBackendRetry)
	}
	if err != nil {
		return ctrl.Result{}, err
	}
	if plane.Namespace != oc.Namespace && !allowedFrom(plane, oc.Namespace) {
		return r.fail(oc, st, ReasonPlaneNotAllowed,
			fmt.Sprintf("IdentityPlane %s/%s does not allow OIDCClients from namespace %s (annotation %s)", plane.Namespace, plane.Name, oc.Namespace, AnnotationAllowFrom), 0)
	}
	if plane.Spec.Engine == havenv1.EngineKeycloak {
		return r.fail(oc, st, ReasonPlaneNotNative, "the plane runs the keycloak engine; OIDCClient needs the native engine", oidcResync)
	}

	realm := realmOf(oc, plane)
	planeKey := plane.Namespace + "/" + plane.Name
	if st.ClientUUID != "" && (st.Plane != planeKey || st.Realm != realm || st.ClientID != res.clientID) {
		return r.fail(oc, st, ReasonImmutable,
			fmt.Sprintf("planeRef, realm and clientId cannot change after creation (created as %s/%s in %s); delete and recreate the OIDCClient", st.Realm, st.ClientID, st.Plane), 0)
	}
	if !planeReady(plane) {
		return r.fail(oc, st, ReasonPlaneNotReady, fmt.Sprintf("IdentityPlane %s is not ready", planeKey), oidcPlaneRetry)
	}

	p, err := r.Providers.ProviderFor(ctx, plane)
	if err != nil {
		return r.fail(oc, st, ReasonPlaneUnreachable, "cannot build the identity backend client: "+safeErr(err), oidcBackendRetry)
	}

	cur, err := lookupClient(ctx, p, realm, res.clientID, st.ClientUUID)
	if errors.Is(err, errRealmMissing) {
		return r.fail(oc, st, ReasonRealmNotFound, fmt.Sprintf("realm %q does not exist in the plane", realm), oidcBackendRetry)
	}
	if err != nil {
		return r.backendErr(oc, st, "look up client", err)
	}

	issuer := issuerOf(plane, realm)
	changed := false
	fresh := "" // generated secret known only right after (re)creation
	var uuid string
	recreated := false

	adopt := oc.Annotations[AnnotationAdoptClient] == "true"
	switch {
	case cur == nil:
		recreated = st.ClientUUID != ""
		want := applyManaged(idp.Client{}, oc, res)
		id, secret, cerr := createClient(ctx, p, realm, want)
		if cerr != nil {
			if errors.Is(cerr, idp.ErrConflict) {
				return r.fail(oc, st, ReasonClientExists, fmt.Sprintf("client %q already exists in realm %q and was not created by this OIDCClient", res.clientID, realm), oidcResync)
			}
			return r.backendErr(oc, st, "create client", cerr)
		}
		uuid, fresh, changed = id, secret, true
		logger.Info("created IdP client", "realm", realm, "clientId", res.clientID, "recreated", recreated)
		r.event(oc, corev1.EventTypeNormal, "ClientCreated", fmt.Sprintf("created client %q in realm %q", res.clientID, realm))
		if recreated {
			r.event(oc, corev1.EventTypeWarning, "DriftCorrected", "the client was missing in the IdP and was recreated with a new secret")
		}
		// Record the UUID now so a failure below cannot orphan the client.
		st.ClientUUID, st.Plane, st.Realm, st.ClientID = uuid, planeKey, realm, res.clientID
		if perr := r.persist(ctx, oc, *st); perr != nil {
			return ctrl.Result{}, perr
		}
	case cur.ID != st.ClientUUID && !adopt:
		return r.fail(oc, st, ReasonClientExists,
			fmt.Sprintf("client %q already exists in realm %q and was not created by this OIDCClient; set annotation %s=\"true\" to take it over", res.clientID, realm, AnnotationAdoptClient), oidcResync)
	default:
		uuid = cur.ID
		want := applyManaged(*cur, oc, res)
		if !managedEqual(*cur, want) {
			if uerr := p.UpdateClient(ctx, realm, uuid, want); uerr != nil {
				return r.backendErr(oc, st, "update client", uerr)
			}
			changed = true
			logger.Info("updated IdP client", "realm", realm, "clientId", res.clientID)
		}
	}

	secretName := ""
	if !oc.Spec.Public {
		regen := func() (string, error) {
			s, rerr := p.RegenerateClientSecret(ctx, realm, uuid)
			if rerr != nil {
				return "", rerr
			}
			return s.Value, nil
		}
		wrote, serr := r.syncSecret(ctx, oc, res, issuer, fresh, regen)
		switch {
		case errors.Is(serr, errSecretNotOwned):
			return r.fail(oc, st, ReasonSecretNotOwned, fmt.Sprintf("Secret %q exists and is not owned by this OIDCClient; remove it or pick another secretRef.name", res.secretName), oidcResync)
		case serr != nil:
			return r.backendErr(oc, st, "write secret", serr)
		}
		changed = changed || wrote
		secretName = res.secretName
	}

	st.ClientUUID, st.Plane, st.Realm, st.ClientID = uuid, planeKey, realm, res.clientID
	st.Issuer, st.SecretName = issuer, secretName
	if changed || st.LastSyncTime == nil {
		t := r.now()
		st.LastSyncTime = &t
	}
	setConds(oc, st, true, ReasonSynced, "client is in sync with the identity plane")
	return ctrl.Result{RequeueAfter: oidcResync}, nil
}

func (r *OIDCClientReconciler) backendErr(oc *havenv1.OIDCClient, st *havenv1.OIDCClientStatus, what string, err error) (ctrl.Result, error) {
	msg := what + ": " + safeErr(err)
	setConds(oc, st, false, ReasonBackendError, msg)
	r.event(oc, corev1.EventTypeWarning, ReasonBackendError, msg)
	// The raw error may carry a response body; hand the caller a sanitised one.
	return ctrl.Result{}, errors.New(msg)
}

// lookupClient finds the client by UUID first, then by clientId. A nil client
// with a nil error means it does not exist.
func lookupClient(ctx context.Context, p idp.Provider, realm, clientID, uuid string) (*idp.Client, error) {
	if uuid != "" {
		cl, err := p.GetClient(ctx, realm, uuid)
		if err == nil && cl != nil && cl.ClientID == clientID {
			if cl.ID == "" {
				cl.ID = uuid
			}
			return cl, nil
		}
		if err != nil && !errors.Is(err, idp.ErrNotFound) {
			return nil, err
		}
	}
	all, err := p.ListClients(ctx, realm)
	if errors.Is(err, idp.ErrNotFound) {
		return nil, errRealmMissing
	}
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ClientID == clientID {
			return &all[i], nil
		}
	}
	return nil, nil
}

// createClient creates the client and returns its UUID and, for confidential
// clients, the generated secret (shown by the IdP exactly once).
func createClient(ctx context.Context, p idp.Provider, realm string, want idp.Client) (id, secret string, err error) {
	if sc, ok := p.(idp.SecretCreator); ok {
		return sc.CreateClientWithSecret(ctx, realm, want)
	}
	if err := p.CreateClient(ctx, realm, want); err != nil {
		return "", "", err
	}
	all, err := p.ListClients(ctx, realm)
	if err != nil {
		return "", "", err
	}
	for _, c := range all {
		if c.ClientID == want.ClientID {
			id = c.ID
		}
	}
	if id == "" {
		return "", "", fmt.Errorf("created client %q not found afterwards", want.ClientID)
	}
	if !want.PublicClient {
		s, err := p.RegenerateClientSecret(ctx, realm, id)
		if err != nil {
			return id, "", err
		}
		secret = s.Value
	}
	return id, secret, nil
}

// syncSecret creates the Secret once and then leaves the client secret alone:
// it is replaced only when it is missing or empty, when the client was just
// (re)created (fresh != ""), or when the rotate-secret annotation carries a
// value not yet handled. client-id and issuer are not secret and always follow
// the spec. It reports whether it wrote the Secret.
func (r *OIDCClientReconciler) syncSecret(ctx context.Context, oc *havenv1.OIDCClient, res resolved, issuer, fresh string, regen func() (string, error)) (bool, error) {
	key := types.NamespacedName{Name: res.secretName, Namespace: oc.Namespace}
	var sec corev1.Secret
	err := r.Get(ctx, key, &sec)
	exists := err == nil
	if err != nil && !kerrors.IsNotFound(err) {
		return false, err
	}
	if exists && !metav1.IsControlledBy(&sec, oc) {
		return false, errSecretNotOwned
	}

	rotateWant := oc.Annotations[AnnotationRotateSecret]
	rotate := exists && rotateWant != "" && sec.Annotations[annotationRotateHandled] != rotateWant
	needValue := fresh != "" || !exists || len(sec.Data[res.keys.ClientSecret]) == 0 || rotate
	value := fresh
	if needValue && value == "" {
		if value, err = regen(); err != nil {
			return false, err
		}
		if rotate {
			r.event(oc, corev1.EventTypeNormal, "SecretRotated", "client secret rotated on request")
		}
	}

	data := map[string][]byte{}
	for k, v := range sec.Data {
		data[k] = v
	}
	data[res.keys.ClientID] = []byte(res.clientID)
	data[res.keys.Issuer] = []byte(issuer)
	if needValue {
		data[res.keys.ClientSecret] = []byte(value)
	}

	if !exists {
		sec = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: key.Name, Namespace: key.Namespace,
				Labels: map[string]string{
					"haven.identity/managed":     "true",
					"app.kubernetes.io/part-of":  "haven",
					"haven.zyvor.dev/oidcclient": oc.Name,
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: data,
		}
		if rotateWant != "" {
			sec.Annotations = map[string]string{annotationRotateHandled: rotateWant}
		}
		if err := controllerutil.SetControllerReference(oc, &sec, r.Scheme()); err != nil {
			return false, err
		}
		return true, r.Create(ctx, &sec)
	}

	annotationsChanged := rotate
	if !apiequality.Semantic.DeepEqual(sec.Data, data) || annotationsChanged {
		patch := client.MergeFrom(sec.DeepCopy())
		sec.Data = data
		if rotate {
			if sec.Annotations == nil {
				sec.Annotations = map[string]string{}
			}
			sec.Annotations[annotationRotateHandled] = rotateWant
		}
		return true, r.Patch(ctx, &sec, patch)
	}
	return false, nil
}

func (r *OIDCClientReconciler) finalize(ctx context.Context, oc *havenv1.OIDCClient) (ctrl.Result, error) {
	if !controllerutil.ContainsFinalizer(oc, oidcFinalizer) {
		return ctrl.Result{}, nil
	}
	logger := log.FromContext(ctx)
	res := resolveSpec(oc)
	st := *oc.Status.DeepCopy()

	if res.policy == havenv1.DeletionDelete && oc.Status.ClientUUID != "" {
		ns, name, _ := strings.Cut(oc.Status.Plane, "/")
		var plane havenv1.IdentityPlane
		err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &plane)
		switch {
		case kerrors.IsNotFound(err):
			// The plane (and with it the IdP) is gone: nothing left to delete.
			r.event(oc, corev1.EventTypeNormal, "PlaneGone", "the IdentityPlane no longer exists; nothing to delete in the IdP")
		case err != nil:
			return ctrl.Result{}, err
		case !planeReady(&plane):
			setConds(oc, &st, false, ReasonDeleting,
				"waiting for the IdentityPlane to be ready to delete the IdP client; set spec.deletionPolicy: Retain to skip")
			if perr := r.persist(ctx, oc, st); perr != nil {
				return ctrl.Result{}, perr
			}
			return ctrl.Result{RequeueAfter: oidcPlaneRetry}, nil
		default:
			p, perr := r.Providers.ProviderFor(ctx, &plane)
			if perr != nil {
				return ctrl.Result{}, errors.New("cannot build the identity backend client: " + safeErr(perr))
			}
			if derr := p.DeleteClient(ctx, oc.Status.Realm, oc.Status.ClientUUID); derr != nil && !errors.Is(derr, idp.ErrNotFound) {
				return ctrl.Result{}, errors.New("delete client: " + safeErr(derr))
			}
			logger.Info("deleted IdP client", "realm", oc.Status.Realm, "clientId", oc.Status.ClientID)
		}
	}
	controllerutil.RemoveFinalizer(oc, oidcFinalizer)
	return ctrl.Result{}, client.IgnoreNotFound(r.Update(ctx, oc))
}

func (r *OIDCClientReconciler) SetupWithManager(mgr ctrl.Manager) error {
	if r.Providers == nil {
		r.Providers = &NativeProviders{Reader: mgr.GetClient()}
	}
	if r.Recorder == nil {
		r.Recorder = mgr.GetEventRecorderFor("haven-oidcclient") //nolint:staticcheck // Recorder is a record.EventRecorder; GetEventRecorder returns the new events API type, so migrating means changing the reconciler field and every Event call
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&havenv1.OIDCClient{}).
		Owns(&corev1.Secret{}).
		Complete(r)
}
