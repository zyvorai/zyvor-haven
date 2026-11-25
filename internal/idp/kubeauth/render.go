// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package kubeauth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Section names, in output order.
const (
	SectionFlags      = "flags"
	SectionAuthn      = "authn"
	SectionKubeadm    = "kubeadm"
	SectionK3s        = "k3s"
	SectionKubeconfig = "kubeconfig"
	SectionRBAC       = "rbac"
)

// Section is one generated artifact.
type Section struct {
	Name  string
	File  string // file name used with --out-dir
	Title string
	Body  string
}

// quote renders s as a double-quoted YAML scalar (a JSON string is one).
func quote(s string) string {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	_ = e.Encode(s) // a string always encodes
	return strings.TrimSuffix(b.String(), "\n")
}

// FlagList returns the kube-apiserver --oidc-* settings as name/value pairs
// (names without the leading dashes).
func (o Options) FlagList() [][2]string {
	f := [][2]string{
		{"oidc-issuer-url", o.Issuer},
		{"oidc-client-id", o.ClientID},
		{"oidc-username-claim", o.UsernameClaim},
		{"oidc-username-prefix", o.UsernamePrefix},
		{"oidc-groups-claim", "groups"},
		{"oidc-groups-prefix", o.GroupsPrefix},
		{"oidc-signing-algs", SigningAlg},
		// Only ID tokens: haven access and logout tokens must not log anyone in.
		{"oidc-required-claim", "typ=ID"},
	}
	if len(o.CAPEM) > 0 {
		f = append(f, [2]string{"oidc-ca-file", o.NodeCAPath})
	}
	return f
}

// Flags renders the kube-apiserver command-line flags.
func (o Options) Flags() string {
	var b strings.Builder
	for _, f := range o.FlagList() {
		fmt.Fprintf(&b, "--%s=%s\n", f[0], f[1])
	}
	return b.String()
}

// AuthnConfig renders the structured AuthenticationConfiguration, the
// alternative to the flags (the API server refuses to start with both).
func (o Options) AuthnConfig() string {
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: apiserver.config.k8s.io/%s\nkind: AuthenticationConfiguration\njwt:\n", o.AuthnVersion)
	fmt.Fprintf(&b, "  - issuer:\n      url: %s\n      audiences:\n        - %s\n", quote(o.Issuer), quote(o.ClientID))
	if len(o.CAPEM) > 0 {
		b.WriteString("      certificateAuthority: |\n")
		for _, l := range strings.Split(strings.TrimRight(string(o.CAPEM), "\n"), "\n") {
			b.WriteString("        " + l + "\n")
		}
	}
	b.WriteString(`    # Only ID tokens: haven access and logout tokens must not log anyone in.
    claimValidationRules:
      - claim: typ
        requiredValue: "ID"
    claimMappings:
      username:
`)
	fmt.Fprintf(&b, "        claim: %s\n        prefix: %s\n", quote(o.UsernameClaim), quote(o.UsernamePrefix))
	fmt.Fprintf(&b, "      groups:\n        claim: \"groups\"\n        prefix: %s\n", quote(o.GroupsPrefix))
	b.WriteString(`    # Defence in depth if a prefix above is ever edited away.
    userValidationRules:
      - expression: "!user.username.startsWith('system:')"
        message: "usernames from this issuer must not use the reserved system: prefix"
      - expression: "user.groups.all(group, !group.startsWith('system:'))"
        message: "groups from this issuer must not use the reserved system: prefix"
`)
	return b.String()
}

const (
	kubeadmDir = "/etc/kubernetes/haven"
	k3sDir     = "/etc/rancher/k3s/haven"
)

// Kubeadm renders a kubeadm ClusterConfiguration fragment (v1beta4, kubeadm
// 1.31+) using the AuthenticationConfiguration, with the flags as a commented
// alternative.
func (o Options) Kubeadm() string {
	var b strings.Builder
	fmt.Fprintf(&b, `# kubeadm 1.31+ (v1beta4). Put the AuthenticationConfiguration at
# %[1]s/authn.yaml on EVERY control-plane node, then merge this into
# your ClusterConfiguration.
apiVersion: kubeadm.k8s.io/v1beta4
kind: ClusterConfiguration
apiServer:
  extraArgs:
    - name: authentication-config
      value: %[1]s/authn.yaml
  extraVolumes:
    - name: haven-authn
      hostPath: %[1]s
      mountPath: %[1]s
      readOnly: true
      pathType: DirectoryOrCreate
`, kubeadmDir)
	b.WriteString("# Alternative with flags (replace extraArgs above; never use both). " + o.caHint(o.NodeCAPath) + "\n#  extraArgs:\n")
	for _, f := range o.FlagList() {
		fmt.Fprintf(&b, "#    - name: %s\n#      value: %s\n", f[0], quote(f[1]))
	}
	return b.String()
}

func (o Options) caHint(path string) string {
	if len(o.CAPEM) == 0 {
		return ""
	}
	return "The CA certificate must be at " + path + "."
}

// K3s renders a k3s server config fragment using the
// AuthenticationConfiguration, with the flags as a commented alternative.
func (o Options) K3s() string {
	var b strings.Builder
	fmt.Fprintf(&b, `# k3s: save as /etc/rancher/k3s/config.yaml.d/haven.yaml on EVERY server node,
# put the AuthenticationConfiguration at %[1]s/authn.yaml and
# restart k3s. The trailing "+" appends to any kube-apiserver-arg already
# configured instead of replacing it.
kube-apiserver-arg+:
  - "authentication-config=%[1]s/authn.yaml"
`, k3sDir)
	k := o
	if k.NodeCAPath == DefaultNodeCAPath {
		k.NodeCAPath = k3sDir + "/oidc-ca.pem"
	}
	b.WriteString("# Alternative with flags (replace the list above; never use both). " + k.caHint(k.NodeCAPath) + "\n# kube-apiserver-arg+:\n")
	for _, f := range k.FlagList() {
		fmt.Fprintf(&b, "#   - %s\n", quote(f[0]+"="+f[1]))
	}
	return b.String()
}

// LoginCommand is the one-time sign-in that exec-credential relies on.
func (o Options) LoginCommand() string {
	c := fmt.Sprintf("haven login --issuer %s --client-id %s --profile %s --scope \"openid offline_access groups\"", o.Issuer, o.ClientID, o.Profile)
	if len(o.CAPEM) > 0 {
		c += " --ca-file CA.pem"
	}
	return c
}

// Kubeconfig renders a kubeconfig holding the user entry (and, with a cluster
// name, a context). Merge it with the cluster's kubeconfig through KUBECONFIG.
func (o Options) Kubeconfig() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Sign in once first:\n#   %s\napiVersion: v1\nkind: Config\nusers:\n  - name: %s\n", o.LoginCommand(), quote(o.UserName))
	b.WriteString(`    user:
      exec:
        apiVersion: client.authentication.k8s.io/v1
        interactiveMode: Never
        command: haven
        installHint: "Install the haven CLI, then run haven login (see docs/kubernetes-login.md)."
        args:
          - exec-credential
`)
	for _, a := range []string{"--issuer=" + o.Issuer, "--client-id=" + o.ClientID, "--profile=" + o.Profile} {
		fmt.Fprintf(&b, "          - %s\n", quote(a))
	}
	if o.ClusterName != "" {
		ctx := o.UserName + "@" + o.ClusterName
		fmt.Fprintf(&b, "contexts:\n  - name: %s\n    context:\n      cluster: %s\n      user: %s\n", quote(ctx), quote(o.ClusterName), quote(o.UserName))
	}
	return b.String()
}

// Sections normalizes o and renders every artifact.
func Sections(o Options) ([]Section, error) {
	o, err := o.Normalize()
	if err != nil {
		return nil, err
	}
	rbac, err := o.RBAC()
	if err != nil {
		return nil, err
	}
	return []Section{
		{SectionFlags, "apiserver-flags.txt", "kube-apiserver flags (alternative A)", o.Flags()},
		{SectionAuthn, "authn.yaml", "AuthenticationConfiguration (alternative B, --authentication-config; never together with the --oidc-* flags)", o.AuthnConfig()},
		{SectionKubeadm, "kubeadm.yaml", "kubeadm", o.Kubeadm()},
		{SectionK3s, "k3s.yaml", "k3s", o.K3s()},
		{SectionKubeconfig, "kubeconfig-user.yaml", "kubeconfig user entry", o.Kubeconfig()},
		{SectionRBAC, "rbac.yaml", "RBAC (kubectl apply -f)", rbac},
	}, nil
}
