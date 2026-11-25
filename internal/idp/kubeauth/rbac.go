// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package kubeauth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/zyvorai/haven/internal/idp/core"
)

const (
	kindClusterRole = "ClusterRole"
	kindRole        = "Role"
	clusterAdmin    = "cluster-admin"
)

// Binding grants one identity-server group a role.
type Binding struct {
	Group     string // claim value ("eng/dev"), without any prefix
	RoleKind  string // "ClusterRole" or "Role"
	Role      string
	Namespace string // empty = cluster wide (ClusterRoleBinding)
}

var (
	roleRE      = regexp.MustCompile(`^[a-z0-9]([a-z0-9._:-]{0,251}[a-z0-9])?$`)
	namespaceRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ParseBinding parses GROUP=ROLE (cluster wide), GROUP=ROLE@NAMESPACE (the
// ClusterRole, in one namespace) or GROUP=role/NAME@NAMESPACE (a namespaced
// Role). GROUP is the haven-idp group, with or without the leading "/", and
// without the Kubernetes prefix. cluster-admin needs allowClusterAdmin.
func ParseBinding(s string, allowClusterAdmin bool) (Binding, error) {
	i := strings.LastIndex(s, "=")
	if i < 0 {
		return Binding{}, fmt.Errorf("binding %q: want GROUP=ROLE or GROUP=ROLE@NAMESPACE", s)
	}
	group, target := s[:i], s[i+1:]
	b := Binding{RoleKind: kindClusterRole}
	v, ok := core.GroupClaimValue("/" + strings.TrimPrefix(group, "/"))
	if !ok {
		return Binding{}, fmt.Errorf("binding %q: refused group %q (it must be a haven-idp group; empty names, surrounding spaces, control characters and the Kubernetes \"system:\" namespace are never bound)", s, group)
	}
	b.Group = v
	role, ns, hasNS := strings.Cut(target, "@")
	if name, ok := strings.CutPrefix(role, "role/"); ok {
		b.RoleKind, role = kindRole, name
		if !hasNS {
			return Binding{}, fmt.Errorf("binding %q: a namespaced Role needs @NAMESPACE", s)
		}
	}
	b.Role, b.Namespace = role, ns
	if hasNS && ns == "" {
		return Binding{}, fmt.Errorf("binding %q: empty namespace", s)
	}
	if err := b.validate(allowClusterAdmin); err != nil {
		return Binding{}, fmt.Errorf("binding %q: %w", s, err)
	}
	return b, nil
}

func (b Binding) validate(allowClusterAdmin bool) error {
	if v, ok := core.GroupClaimValue("/" + b.Group); !ok || v != b.Group {
		return fmt.Errorf("refused group %q", b.Group)
	}
	if b.RoleKind != kindClusterRole && b.RoleKind != kindRole {
		return fmt.Errorf("unknown role kind %q", b.RoleKind)
	}
	if strings.HasPrefix(strings.ToLower(b.Role), core.ReservedGroupPrefix) {
		return fmt.Errorf("role %q is refused: \"system:\" roles belong to Kubernetes components", b.Role)
	}
	if !roleRE.MatchString(b.Role) {
		return fmt.Errorf("invalid role name %q", b.Role)
	}
	if b.Role == clusterAdmin && !allowClusterAdmin {
		return errors.New("cluster-admin is refused without --allow-cluster-admin: it gives the group full control of the cluster")
	}
	if b.RoleKind == kindRole && b.Namespace == "" {
		return errors.New("a namespaced Role needs a namespace")
	}
	if b.Namespace != "" && !namespaceRE.MatchString(b.Namespace) {
		return fmt.Errorf("invalid namespace %q", b.Namespace)
	}
	return nil
}

func (b Binding) key() string {
	return b.Group + "\x00" + b.RoleKind + "\x00" + b.Role + "\x00" + b.Namespace
}

func (b Binding) describe() string {
	where := "cluster wide"
	if b.Namespace != "" {
		where = "in namespace " + b.Namespace
	}
	return fmt.Sprintf("%s -> %s %s (%s)", b.Group, b.RoleKind, b.Role, where)
}

// Warning explains why a binding deserves a second look, or "".
func (b Binding) Warning() string {
	switch {
	case b.Role == clusterAdmin && b.Namespace == "":
		return "gives full control of the whole cluster to everyone in " + b.Group
	case b.Role == clusterAdmin:
		return "gives full control of namespace " + b.Namespace + " to everyone in " + b.Group
	case b.Namespace == "" && (b.Role == "admin" || b.Role == "edit"):
		return b.Role + " cluster wide reads Secrets and starts pods in every namespace, kube-system included, which can be escalated to cluster-admin"
	case b.Namespace == "kube-system" && b.Role != "view":
		return "write access in kube-system can be escalated to cluster-admin"
	}
	return ""
}

// name is a deterministic, collision-resistant object name.
func (b Binding) name() string {
	clean := func(s string) string {
		s = strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
				return r
			}
			return '-'
		}, strings.ToLower(s))
		if len(s) > 40 {
			s = s[:40]
		}
		return strings.Trim(s, "-")
	}
	sum := sha256.Sum256([]byte(b.key()))
	parts := []string{"haven"}
	for _, p := range []string{clean(b.Group), clean(b.Role)} {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(append(parts, hex.EncodeToString(sum[:4])), "-")
}

// RBAC renders the bindings of a normalized Options as YAML documents for
// `kubectl apply -f -`.
func (o Options) RBAC() (string, error) {
	if len(o.Bindings) == 0 {
		return "# No bindings requested (--bind GROUP=ROLE[@NAMESPACE]). Without RBAC a signed-in\n# user can only do what every authenticated user can.\n", nil
	}
	var out strings.Builder
	for i, b := range o.Bindings {
		subject := o.GroupsPrefix + b.Group
		if strings.HasPrefix(strings.ToLower(subject), core.ReservedGroupPrefix) { // unreachable after Normalize; keep it so
			return "", fmt.Errorf("refusing to bind the reserved group %q", subject)
		}
		kind := "ClusterRoleBinding"
		if b.Namespace != "" {
			kind = "RoleBinding"
		}
		if i > 0 {
			out.WriteString("---\n")
		}
		if w := b.Warning(); w != "" {
			fmt.Fprintf(&out, "# WARNING: %s.\n", w)
		}
		fmt.Fprintf(&out, "apiVersion: rbac.authorization.k8s.io/v1\nkind: %s\nmetadata:\n  name: %s\n", kind, quote(b.name()))
		if b.Namespace != "" {
			fmt.Fprintf(&out, "  namespace: %s\n", quote(b.Namespace))
		}
		out.WriteString("  labels:\n    app.kubernetes.io/managed-by: haven-idp\n")
		fmt.Fprintf(&out, "subjects:\n  - apiGroup: rbac.authorization.k8s.io\n    kind: Group\n    name: %s\n", quote(subject))
		fmt.Fprintf(&out, "roleRef:\n  apiGroup: rbac.authorization.k8s.io\n  kind: %s\n  name: %s\n", b.RoleKind, quote(b.Role))
	}
	return out.String(), nil
}
