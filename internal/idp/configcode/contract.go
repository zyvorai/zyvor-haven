// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package configcode

// The function set below is the package's public contract. Two authors fill it
// in parallel (engine: parse.go, validate.go, read.go, diff.go, apply.go;
// gate and presentation: gate.go, render.go), so the signatures are fixed here
// as documentation. Each is implemented in the file named on its line; this
// file is deleted once all are implemented.
//
//	parse.go     func Parse(r io.Reader) (*Spec, error)
//	             Strict YAML (unknown fields are errors, one document, size cap
//	             1 MiB), then Validate. Errors name the field.
//	parse.go     func Marshal(s *Spec) ([]byte, error)   canonical YAML, stable order
//	validate.go  func (s *Spec) Validate() error
//	             apiVersion/kind, realm name ^[a-z0-9][a-z0-9._-]{0,62}$, unique
//	             role/group/clientId, no wildcard redirect URIs, https or loopback
//	             http redirects only, transportSecurity in {none,external,all},
//	             positive TTLs, PKCE cannot be disabled for public clients,
//	             serviceAccount clients cannot be public. Returns ALL problems
//	             (errors.Join), not just the first.
//	read.go      func Read(ctx context.Context, p idp.Provider, realm string) (*Spec, error)
//	             Live state as a Spec (hardening fields always populated,
//	             built-in clients and the admin client omitted). Returns
//	             idp.ErrNotFound-wrapping error when the realm does not exist.
//	diff.go      func Diff(desired, live *Spec, o Options) *Plan
//	             live == nil means the realm is missing (RealmMissing=true, all creates).
//	             Pure and deterministic; sorted; unmanaged fields ignored.
//	apply.go     func Apply(ctx context.Context, p idp.Provider, plan *Plan, desired *Spec) (*ApplyResult, error)
//	             Executes plan.Changes in order through idp.Provider, stops at
//	             the first error (returning what was applied so far), uses
//	             idp.SecretCreator when available for confidential clients,
//	             treats "already exists"/"not found" races as success for
//	             create/delete.
//	gate.go      func Gate(desired, live *Spec, threshold posture.Severity) GateResult
//	             Evaluate Guard (posture.Evaluate via internal/idmodel) on live
//	             (nil = empty) and on the state after applying desired; diff the
//	             findings by (rule, realm, client).
//	render.go    func (p *Plan) Render(w io.Writer, color bool) / func (g GateResult) Render(w io.Writer, color bool)
//	             Human output: + create, ~ update (old -> new), - delete.
