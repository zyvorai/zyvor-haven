// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

package plane

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	havenv1 "github.com/zyvorai/haven/api/v1alpha1"
	authv1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type Card struct {
	Label  string `json:"label"`
	Value  string `json:"value"`
	Meta   string `json:"meta"`
	OK     bool   `json:"ok"`
	Live   bool   `json:"live"`
	Config bool   `json:"configured,omitempty"`
}

type ConditionView struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

type StatusResponse struct {
	Available  bool            `json:"available"`
	Plane      string          `json:"plane"`
	Namespace  string          `json:"namespace"`
	Phase      string          `json:"phase,omitempty"`
	PhaseCard  Card            `json:"phaseCard"`
	Postgres   Card            `json:"postgres"`
	Backup     Card            `json:"backup"`
	Cert       Card            `json:"certificate"`
	Conditions []ConditionView `json:"conditions,omitempty"`
	LastSync   string          `json:"lastSync,omitempty"`
	Message    string          `json:"message,omitempty"`
}

// KeycloakHint optionally upgrades cards when Admin API is connected.
type KeycloakHint struct {
	Connected  bool
	Version    string
	RealmCount int
	URL        string
}

type Reader struct {
	client client.Client
	name   string
	ns     string
}

func NewReaderFromEnv() (*Reader, error) {
	name := os.Getenv("HAVEN_PLANE_NAME")
	if name == "" {
		name = "platform"
	}
	ns := os.Getenv("HAVEN_PLANE_NAMESPACE")
	if ns == "" {
		ns = "identity"
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		return &Reader{name: name, ns: ns}, nil
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(havenv1.AddToScheme(scheme))
	utilruntime.Must(authv1.AddToScheme(scheme))

	c, err := client.New(cfg, client.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}
	return &Reader{client: c, name: name, ns: ns}, nil
}

func (r *Reader) Status(ctx context.Context, hint *KeycloakHint) StatusResponse {
	out := StatusResponse{
		Plane:     r.name,
		Namespace: r.ns,
		LastSync:  time.Now().UTC().Format(time.RFC3339),
	}
	if r.client == nil {
		if hint != nil && hint.Connected {
			return externalFromKeycloak(out, *hint)
		}
		out.Message = "not running in cluster"
		out.PhaseCard = offlineCard("Phase", "—", out.Message)
		out.Postgres = offlineCard("Postgres primary", "—", out.Message)
		out.Backup = offlineCard("Last Backup", "—", out.Message)
		out.Cert = offlineCard("Certificate", "—", out.Message)
		return out
	}

	var plane havenv1.IdentityPlane
	err := r.client.Get(ctx, client.ObjectKey{Name: r.name, Namespace: r.ns}, &plane)
	if err != nil {
		if hint != nil && hint.Connected {
			return externalFromKeycloak(out, *hint)
		}
		out.Message = "IdentityPlane not found — deploy haven-controller and apply identityplane sample"
		return r.fallbackCNPG(ctx, out)
	}

	out.Available = true
	out.Phase = string(plane.Status.Phase)
	out.PhaseCard = Card{
		Label: "Phase",
		Value: string(plane.Status.Phase),
		Meta:  phaseMeta(plane.Status),
		OK:    plane.Status.Phase == havenv1.PhaseReady,
		Live:  true,
	}

	db := plane.Status.Database
	if db.Phase == "" && db.Ready == 0 {
		if direct, ok := r.readCNPGDirect(ctx); ok {
			db = direct
			if out.Phase == "" || out.Phase == "ProvisioningDatabase" {
				out.Phase = "Compose"
				out.PhaseCard = Card{Label: "Phase", Value: "Compose", Meta: "Direct CNPG read", OK: true, Live: true}
			}
		}
	}

	pgOK := db.Ready > 0 || strings.Contains(strings.ToLower(db.Phase), "healthy") || strings.EqualFold(db.Phase, "external")
	out.Postgres = Card{
		Label: "Postgres primary",
		Value: postgresValue(db),
		Meta:  postgresMeta(db),
		OK:    pgOK,
		Live:  true,
	}
	out.Backup = backupCard(db.LastBackup, plane.Spec.Database.Backup.Destination)
	out.Cert = certCard(plane.Status.TLS, plane.Spec.Expose.TLS.IssuerRef != nil && plane.Spec.Expose.TLS.IssuerRef.Name != "", plane.Spec.Expose.TLS.SecretName)

	for _, c := range plane.Status.Conditions {
		out.Conditions = append(out.Conditions, ConditionView{
			Type: c.Type, Status: string(c.Status), Reason: c.Reason, Message: c.Message,
		})
	}

	// Enrich with live Keycloak Admin connectivity.
	if hint != nil && hint.Connected {
		opsMissing := false
		for _, c := range out.Conditions {
			if (c.Type == "DatabaseReady" || c.Type == "KeycloakReady") &&
				(c.Reason == "DatabaseMissing" || c.Reason == "KeycloakMissing" || strings.Contains(c.Message, "no matches for kind")) {
				opsMissing = true
				break
			}
		}
		if out.Phase == "ProvisioningDatabase" || out.Phase == "ProvisioningKeycloak" || out.Phase == "" || opsMissing {
			out.Phase = "Ready"
			out.PhaseCard = Card{
				Label: "Phase",
				Value: "Ready",
				Meta:  fmt.Sprintf("Keycloak v%s · %d realms · external plane", hint.Version, hint.RealmCount),
				OK:    true,
				Live:  true,
			}
			out.Postgres = Card{
				Label: "Postgres primary",
				Value: "external",
				Meta:  "Managed with Keycloak host · operators not installed",
				OK:    true,
				Live:  true,
			}
			out.Conditions = []ConditionView{
				{Type: "KeycloakReady", Status: "True", Reason: "AdminAPI", Message: hint.URL},
				{Type: "DatabaseReady", Status: "True", Reason: "ExternalDatabase", Message: "DB owned by Keycloak host"},
				{Type: "CertificateReady", Status: "True", Reason: "HTTPMode", Message: "TLS not configured (dev)"},
				{Type: "BackupConfigured", Status: "False", Reason: "NotConfigured", Message: "no backups yet"},
				{Type: "OperatorsInstalled", Status: "False", Reason: "OperatorsMissing", Message: "CNPG / Keycloak Operator CRDs not present"},
			}
		} else if out.Phase == "Ready" && out.PhaseCard.Meta == "" {
			out.PhaseCard.Meta = fmt.Sprintf("Keycloak v%s · %d realms", hint.Version, hint.RealmCount)
		}
	}

	return out
}

func externalFromKeycloak(out StatusResponse, hint KeycloakHint) StatusResponse {
	out.Available = true
	out.Phase = "Ready"
	out.PhaseCard = Card{
		Label: "Phase",
		Value: "Ready",
		Meta:  fmt.Sprintf("Keycloak v%s · %d realms · external", hint.Version, hint.RealmCount),
		OK:    true,
		Live:  true,
	}
	out.Postgres = Card{
		Label: "Postgres primary",
		Value: "external",
		Meta:  "Managed with Keycloak host",
		OK:    true,
		Live:  true,
	}
	out.Backup = Card{Label: "Last Backup", Value: "none", Meta: "Backups not configured", OK: false, Live: true}
	out.Cert = Card{Label: "Certificate", Value: "HTTP", Meta: "TLS not configured (dev)", OK: true, Live: true, Config: false}
	out.Conditions = []ConditionView{
		{Type: "KeycloakReady", Status: "True", Reason: "AdminAPI", Message: hint.URL},
		{Type: "DatabaseReady", Status: "True", Reason: "ExternalDatabase", Message: "DB owned by Keycloak host"},
		{Type: "OperatorsInstalled", Status: "False", Reason: "OperatorsMissing", Message: "CNPG / Keycloak Operator CRDs not present"},
	}
	return out
}

func (r *Reader) readCNPGDirect(ctx context.Context) (havenv1.DatabaseStatus, bool) {
	var cluster unstructured.Unstructured
	cluster.SetGroupVersionKind(schema.GroupVersionKind{Group: "postgresql.cnpg.io", Version: "v1", Kind: "Cluster"})
	if err := r.client.Get(ctx, client.ObjectKey{Name: r.name + "-db", Namespace: r.ns}, &cluster); err != nil {
		return havenv1.DatabaseStatus{}, false
	}
	phase, _, _ := unstructured.NestedString(cluster.Object, "status", "phase")
	ready, _, _ := unstructured.NestedInt64(cluster.Object, "status", "readyInstances")
	inst, _, _ := unstructured.NestedInt64(cluster.Object, "spec", "instances")
	primary, _, _ := unstructured.NestedString(cluster.Object, "status", "currentPrimary")
	if primary == "" {
		primary = r.name + "-db-rw." + r.ns + ".svc"
	}
	return havenv1.DatabaseStatus{
		Phase:     phase,
		Ready:     int(ready),
		Instances: int(inst),
		Primary:   primary,
	}, true
}

func (r *Reader) fallbackCNPG(ctx context.Context, out StatusResponse) StatusResponse {
	if db, ok := r.readCNPGDirect(ctx); ok {
		out.Available = true
		out.PhaseCard = Card{Label: "Phase", Value: "Compose", Meta: "Direct CNPG read (no IdentityPlane CR)", OK: true, Live: true}
		out.Postgres = Card{
			Label: "Postgres primary",
			Value: postgresValue(db),
			Meta:  fmt.Sprintf("%d/%d instances · %s", db.Ready, db.Instances, db.Primary),
			OK:    strings.Contains(strings.ToLower(db.Phase), "healthy"),
			Live:  true,
		}
		out.Backup = Card{Label: "Last Backup", Value: "none", Meta: "No controller status", OK: false, Live: false}
		out.Cert = Card{Label: "Certificate", Value: "HTTP", Meta: "TLS not configured (dev)", OK: true, Live: false}
		return out
	}
	out.PhaseCard = offlineCard("Phase", "Unknown", out.Message)
	out.Postgres = offlineCard("Postgres primary", "—", out.Message)
	out.Backup = offlineCard("Last Backup", "—", out.Message)
	out.Cert = offlineCard("Certificate", "—", out.Message)
	return out
}

func offlineCard(label, value, meta string) Card {
	return Card{Label: label, Value: value, Meta: meta, OK: false, Live: false}
}

func phaseMeta(st havenv1.IdentityPlaneStatus) string {
	if strings.EqualFold(st.Database.Phase, "external") {
		return "External Keycloak plane · operators not installed"
	}
	if st.Keycloak.Instances > 0 {
		return fmt.Sprintf("Keycloak %d/%d · DB %s", st.Keycloak.Ready, st.Keycloak.Instances, st.Database.Phase)
	}
	return st.Database.Phase
}

func postgresValue(db havenv1.DatabaseStatus) string {
	if strings.EqualFold(db.Phase, "external") {
		return "external"
	}
	if db.Phase != "" {
		return db.Phase
	}
	if db.Ready > 0 {
		return "healthy"
	}
	return "pending"
}

func postgresMeta(db havenv1.DatabaseStatus) string {
	if strings.EqualFold(db.Phase, "external") {
		return "Managed outside Haven operators"
	}
	primary := db.Primary
	if primary == "" {
		primary = "—"
	}
	return fmt.Sprintf("%d/%d instances · %s", max(db.Ready, 0), max(db.Instances, 1), primary)
}

func backupCard(lastBackup, dest string) Card {
	if lastBackup == "" {
		msg := "Backups not configured"
		if dest != "" {
			msg = "Scheduled · awaiting first run"
		}
		return Card{Label: "Last Backup", Value: "none", Meta: msg, OK: dest != "", Live: true, Config: dest != ""}
	}
	t, err := time.Parse(time.RFC3339, lastBackup)
	if err != nil {
		return Card{Label: "Last Backup", Value: lastBackup, Meta: "completed", OK: true, Live: true, Config: true}
	}
	age := time.Since(t)
	return Card{
		Label: "Last Backup", Value: humanAge(age), Meta: lastBackup, OK: age < 36*time.Hour, Live: true, Config: true,
	}
}

func certCard(tls havenv1.TLSStatus, issuerConfigured bool, secretName string) Card {
	if tls.ExpiresAt != "" {
		val := fmt.Sprintf("%dd", tls.DaysRemaining)
		meta := "expires " + tls.ExpiresAt
		if len(tls.ExpiresAt) >= 10 {
			meta = "expires " + tls.ExpiresAt[:10]
		}
		return Card{Label: "Certificate", Value: val, Meta: meta, OK: tls.DaysRemaining > 14, Live: true, Config: true}
	}
	if secretName != "" {
		return Card{Label: "Certificate", Value: "external", Meta: "secret " + secretName, OK: true, Live: true, Config: true}
	}
	if !issuerConfigured {
		return Card{Label: "Certificate", Value: "HTTP", Meta: "TLS not configured (dev)", OK: true, Live: true, Config: false}
	}
	return Card{Label: "Certificate", Value: "pending", Meta: "Awaiting cert-manager", OK: false, Live: true, Config: true}
}

func humanAge(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	}
	if d < 48*time.Hour {
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
