// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

// Package obs is haven-idp's observability: Prometheus metrics, request
// tracing and logs, and a tamper-evident audit stream.
//
// Rules every implementation follows:
//   - Never block or fail a request because telemetry is slow or down.
//   - Never record secrets, tokens, codes, passwords, or query strings.
//   - Label values are bounded. Realm names are only passed for realms that
//     exist; callers pass "unknown" otherwise. Routes are mux patterns, never
//     raw paths. User names and client ids are never metric labels.
//
// Metric names (the contract the dashboards and alert rules are written
// against; all carry the haven_idp_ prefix):
//
//	haven_idp_http_requests_total{route,method,code}            counter
//	haven_idp_http_request_duration_seconds{route,method}       histogram
//	haven_idp_http_requests_in_flight                           gauge
//	haven_idp_logins_total{realm,result}                        counter   result: success|bad_credentials|locked|disabled|unverified|csrf
//	haven_idp_lockouts_total{realm}                             counter
//	haven_idp_tokens_issued_total{realm,grant,kind}             counter   grant: authorization_code|refresh_token|client_credentials  kind: access|id|refresh
//	haven_idp_token_errors_total{realm,grant,error}             counter   error: RFC 6749 error code
//	haven_idp_refresh_reuse_total{realm}                        counter   reuse detected, family revoked (security signal)
//	haven_idp_code_replay_total{realm}                          counter   authorization code presented twice (security signal)
//	haven_idp_admin_operations_total{realm,resource,action,result} counter  result: ok|error
//	haven_idp_admin_auth_failures_total{kind}                   counter   kind: missing|invalid|forbidden
//	haven_idp_store_up                                          gauge     1 when the store answers a ping
//	haven_idp_store_ping_duration_seconds                       gauge
//	haven_idp_signing_key_age_seconds{realm}                    gauge     age of the newest active key
//	haven_idp_audit_events_total{sink,result}                   counter   result: sent|dropped|error
//	haven_idp_audit_queue_length{sink}                          gauge
//	haven_idp_build_info{version,goversion}                     gauge     always 1
//
// Plus the standard Go runtime and process collectors.
package obs

import (
	"context"
	"time"
)

// Recorder receives protocol and security signals from the OIDC and admin
// handlers. Implementations are safe for concurrent use and cheap.
type Recorder interface {
	Login(realm, result string)
	Lockout(realm string)
	TokenIssued(realm, grant, kind string)
	TokenError(realm, grant, code string)
	RefreshReuse(realm string)
	CodeReplay(realm string)
	// AdminOp reports a mutating admin call: resource is one of realm, client,
	// user, role, group, secret, import; action one of create, update, delete, action.
	AdminOp(realm, resource, action string, ok bool)
	// AdminAuthFailure reports a rejected admin API call: missing, invalid, forbidden.
	AdminAuthFailure(kind string)
}

// Nop is a Recorder that does nothing; handlers default to it.
type Nop struct{}

func (Nop) Login(string, string)                 {}
func (Nop) Lockout(string)                       {}
func (Nop) TokenIssued(string, string, string)   {}
func (Nop) TokenError(string, string, string)    {}
func (Nop) RefreshReuse(string)                  {}
func (Nop) CodeReplay(string)                    {}
func (Nop) AdminOp(string, string, string, bool) {}
func (Nop) AdminAuthFailure(string)              {}

var _ Recorder = Nop{}

// Severity of an audit event.
const (
	SeverityInfo    = "info"
	SeverityWarning = "warning"
	SeverityAlert   = "alert" // active attack signals: reuse, replay, lockout
)

// AuditEvent is one record of the audit stream (also the webhook payload).
// Detail never contains secrets; IP is the client address as the server saw it.
type AuditEvent struct {
	Time      time.Time `json:"time"`
	Realm     string    `json:"realm,omitempty"`
	Type      string    `json:"type"` // LOGIN, LOGIN_ERROR, REFRESH_REUSE, CODE_REPLAY, LOCKOUT, ADMIN_CREATE, ...
	Severity  string    `json:"severity"`
	UserID    string    `json:"userId,omitempty"`
	ClientID  string    `json:"clientId,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Detail    string    `json:"detail,omitempty"`
	RequestID string    `json:"requestId,omitempty"`
	// Seq is a per-process monotonically increasing sequence so a consumer can
	// detect gaps; Prev is the SHA-256 (hex) of the previous event's JSON in
	// this stream, making truncation or reordering evident.
	Seq  uint64 `json:"seq"`
	Prev string `json:"prev,omitempty"`
}

// AuditSink delivers events out of process. Emit never blocks (drops and
// counts when the queue is full); Close flushes within ctx.
type AuditSink interface {
	Emit(AuditEvent)
	Close(ctx context.Context) error
}
