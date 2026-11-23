// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

package obs

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Config configures an Observer.
type Config struct {
	Registry *prometheus.Registry // default: a new registry
	Audit    AuditSink            // optional
	Version  string
	// Getenv reads OTEL_* settings (default os.Getenv).
	Getenv func(string) string
	// Logger receives access logs (default slog.Default()).
	Logger *slog.Logger
}

var realmRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// Observer implements Recorder, the HTTP middleware and the tracer.
type Observer struct {
	reg    *prometheus.Registry
	audit  AuditSink
	log    *slog.Logger
	tracer *tracer

	httpReqs     *prometheus.CounterVec
	httpDur      *prometheus.HistogramVec
	inflight     prometheus.Gauge
	logins       *prometheus.CounterVec
	lockouts     *prometheus.CounterVec
	tokens       *prometheus.CounterVec
	tokenErrs    *prometheus.CounterVec
	refreshReuse *prometheus.CounterVec
	codeReplay   *prometheus.CounterVec
	adminOps     *prometheus.CounterVec
	adminAuth    *prometheus.CounterVec
	storeUp      prometheus.Gauge
	storePing    prometheus.Gauge
	keyAge       *prometheus.GaugeVec
}

var _ Recorder = (*Observer)(nil)

// New builds an Observer and registers every metric on cfg.Registry.
func New(cfg Config) (*Observer, error) {
	reg := cfg.Registry
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	getenv := cfg.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	o := &Observer{reg: reg, audit: cfg.Audit, log: cfg.Logger}
	if o.log == nil {
		o.log = slog.Default()
	}
	const ns = "haven_idp_"
	cv := func(name, help string, l ...string) *prometheus.CounterVec {
		return prometheus.NewCounterVec(prometheus.CounterOpts{Name: ns + name, Help: help}, l)
	}
	o.httpReqs = cv("http_requests_total", "HTTP requests by matched route pattern.", "route", "method", "code")
	o.httpDur = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: ns + "http_request_duration_seconds", Help: "HTTP request duration.", Buckets: prometheus.DefBuckets,
	}, []string{"route", "method"})
	o.inflight = prometheus.NewGauge(prometheus.GaugeOpts{Name: ns + "http_requests_in_flight", Help: "Requests being served."})
	o.logins = cv("logins_total", "Login attempts.", "realm", "result")
	o.lockouts = cv("lockouts_total", "Account lockouts.", "realm")
	o.tokens = cv("tokens_issued_total", "Tokens issued.", "realm", "grant", "kind")
	o.tokenErrs = cv("token_errors_total", "Token endpoint errors.", "realm", "grant", "error")
	o.refreshReuse = cv("refresh_reuse_total", "Refresh token reuse detected.", "realm")
	o.codeReplay = cv("code_replay_total", "Authorization code replays.", "realm")
	o.adminOps = cv("admin_operations_total", "Admin API mutations.", "realm", "resource", "action", "result")
	o.adminAuth = cv("admin_auth_failures_total", "Rejected admin API calls.", "kind")
	o.storeUp = prometheus.NewGauge(prometheus.GaugeOpts{Name: ns + "store_up", Help: "1 when the store answers a ping."})
	o.storePing = prometheus.NewGauge(prometheus.GaugeOpts{Name: ns + "store_ping_duration_seconds", Help: "Store ping duration."})
	o.keyAge = prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: ns + "signing_key_age_seconds", Help: "Age of the newest active signing key."}, []string{"realm"})
	build := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: ns + "build_info", Help: "Build information; always 1."}, []string{"version", "goversion"})
	ver := cfg.Version
	if ver == "" {
		ver = "dev"
	}
	build.WithLabelValues(ver, runtime.Version()).Set(1)

	for _, c := range []prometheus.Collector{
		o.httpReqs, o.httpDur, o.inflight, o.logins, o.lockouts, o.tokens, o.tokenErrs,
		o.refreshReuse, o.codeReplay, o.adminOps, o.adminAuth, o.storeUp, o.storePing, o.keyAge, build,
		collectors.NewGoCollector(), collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	} {
		if err := reg.Register(c); err != nil {
			return nil, err
		}
	}
	o.tracer = newTracerFromEnv(getenv, ver, o.log)
	return o, nil
}

// Registry returns the registry the metrics live on.
func (o *Observer) Registry() *prometheus.Registry { return o.reg }

// Handler serves the Prometheus exposition. It derives no labels from the request.
func (o *Observer) Handler() http.Handler {
	return promhttp.HandlerFor(o.reg, promhttp.HandlerOpts{
		EnableOpenMetrics: false, ErrorHandling: promhttp.HTTPErrorOnError,
	})
}

// Shutdown flushes traces and the audit sink.
func (o *Observer) Shutdown(ctx context.Context) error {
	var err error
	if o.tracer != nil {
		err = o.tracer.shutdown(ctx)
	}
	if o.audit != nil {
		if e := o.audit.Close(ctx); e != nil && err == nil {
			err = e
		}
	}
	return err
}

func (o *Observer) emit(e AuditEvent) {
	if o.audit == nil {
		return
	}
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	o.audit.Emit(e)
}

func realmLabel(s string) string {
	if realmRe.MatchString(s) {
		return s
	}
	return "unknown"
}

func enum(s string, allowed ...string) string {
	for _, a := range allowed {
		if s == a {
			return s
		}
	}
	return "other"
}

var tokenErrCodes = []string{
	"invalid_request", "invalid_client", "invalid_grant", "unauthorized_client",
	"unsupported_grant_type", "invalid_scope", "server_error", "temporarily_unavailable", "access_denied",
}

func tokenGrant(g string) string {
	return enum(g, "authorization_code", "refresh_token", "client_credentials")
}

func (o *Observer) Login(realm, result string) {
	o.logins.WithLabelValues(realmLabel(realm), enum(result, "success", "bad_credentials", "locked", "disabled", "unverified", "csrf")).Inc()
}

func (o *Observer) Lockout(realm string) {
	o.lockouts.WithLabelValues(realmLabel(realm)).Inc()
	o.emit(AuditEvent{Realm: realmLabel(realm), Type: "LOCKOUT", Severity: SeverityAlert, Detail: "account locked after repeated failures"})
}

func (o *Observer) TokenIssued(realm, grant, kind string) {
	o.tokens.WithLabelValues(realmLabel(realm), tokenGrant(grant), enum(kind, "access", "id", "refresh")).Inc()
}

func (o *Observer) TokenError(realm, grant, code string) {
	o.tokenErrs.WithLabelValues(realmLabel(realm), tokenGrant(grant), enum(code, tokenErrCodes...)).Inc()
}

func (o *Observer) RefreshReuse(realm string) {
	o.refreshReuse.WithLabelValues(realmLabel(realm)).Inc()
	o.emit(AuditEvent{Realm: realmLabel(realm), Type: "REFRESH_REUSE", Severity: SeverityAlert, Detail: "refresh token reuse detected; token family revoked"})
}

func (o *Observer) CodeReplay(realm string) {
	o.codeReplay.WithLabelValues(realmLabel(realm)).Inc()
	o.emit(AuditEvent{Realm: realmLabel(realm), Type: "CODE_REPLAY", Severity: SeverityAlert, Detail: "authorization code presented twice"})
}

func (o *Observer) AdminOp(realm, resource, action string, ok bool) {
	res := "error"
	if ok {
		res = "ok"
	}
	o.adminOps.WithLabelValues(realmLabel(realm),
		enum(resource, "realm", "client", "user", "role", "group", "secret", "import"),
		enum(action, "create", "update", "delete", "action"), res).Inc()
}

func (o *Observer) AdminAuthFailure(kind string) {
	k := enum(kind, "missing", "invalid", "forbidden")
	o.adminAuth.WithLabelValues(k).Inc()
	o.emit(AuditEvent{Type: "ADMIN_AUTH_FAILURE", Severity: SeverityWarning, Detail: "admin API call rejected: " + k})
}

// SetStoreUp records the latest store ping.
func (o *Observer) SetStoreUp(up bool, d time.Duration) {
	v := 0.0
	if up {
		v = 1
	}
	o.storeUp.Set(v)
	o.storePing.Set(d.Seconds())
}
