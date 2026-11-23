# haven-idp observability

haven-idp exposes Prometheus metrics, OpenTelemetry traces, structured logs
(`slog` JSON) and a tamper-evident audit stream. Telemetry never blocks or fails
a request, and never records secrets.

Ready-made assets live in `deploy/observability/`:

| File | Use |
| --- | --- |
| `prometheus-rules.yaml` | Alert rules (PrometheusRule). For plain Prometheus: `yq '.spec' prometheus-rules.yaml > haven-idp.rules.yaml` |
| `grafana-dashboard.json` | Grafana 10+ dashboard (datasource and realm variables) |
| `servicemonitor.yaml` | prometheus-operator ServiceMonitor, port name `metrics` |
| `prometheus-scrape-config.yaml` | Plain `scrape_configs` snippet |

A Go test (`internal/idp/obs/assets_test.go`) checks that every metric in these
files exists in the contract in `internal/idp/obs/obs.go`.

## Setup

| Variable | Meaning |
| --- | --- |
| `HAVEN_IDP_METRICS_LISTEN` | Address of the metrics listener, for example `:9102`. Serve `/metrics` on a separate port and keep it off the public ingress. Empty disables it. |
| `HAVEN_IDP_AUDIT` | Audit sink spec: `stdout`, `file:/var/log/haven/audit.jsonl`, `webhook:https://siem.example/haven`, or a comma list such as `stdout,file:/var/log/haven/audit.jsonl`. Empty or `none` disables the stream. |
| `HAVEN_IDP_AUDIT_WEBHOOK_SECRET` | HMAC key for `webhook:` sinks. Required when a webhook sink is configured. |
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, `OTEL_TRACES_SAMPLER`, ... | Standard OpenTelemetry variables for trace export. |

Sink behaviour:

- `stdout`: one JSON object per line on standard output, separate from the log stream.
- `file:`: appended with mode 0600 (parent directory created with 0700). A symlink at the final path is refused. Synced on shutdown. The file is not reopened on SIGHUP; rotate with copy-truncate-free methods (restart) or ship it with an agent that follows by inode.
- `webhook:`: https only (plain http is accepted only for loopback). Batches of up to 100 events or 2 seconds are POSTed as a JSON array with headers `X-Haven-Signature: sha256=<hex HMAC-SHA256 of the exact body>` and `X-Haven-Delivery: <random id>` (the same id on retries). 5xx, 429 and network errors are retried with exponential backoff and jitter, 5 attempts in total, then the batch is counted as `error` and dropped. Other 4xx and redirects drop immediately. Redirects are never followed. Each request times out after 10 seconds.
- Every sink has a queue of 10000 events and one worker. `Emit` never blocks: when the queue is full the newest event is dropped and counted.

Receivers should verify the signature over the raw body with a constant-time compare.

## What each signal means

| Signal | Meaning | Act when |
| --- | --- | --- |
| `haven_idp_http_requests_total`, `..._duration_seconds` | Traffic by mux route, method and status code | 5xx above 2%, p99 above 1s |
| `haven_idp_logins_total{result}` | `success`, `bad_credentials`, `locked`, `disabled`, `unverified`, `csrf` | failures far above successes: credential stuffing |
| `haven_idp_lockouts_total` | Accounts locked by the brute force limiter | bursts (attack, or lockout DoS) |
| `haven_idp_tokens_issued_total`, `haven_idp_token_errors_total` | Token endpoint results by grant, kind, RFC 6749 error | spikes in `invalid_grant` or `invalid_client` |
| `haven_idp_refresh_reuse_total` | A rotated refresh token was presented again and its family revoked | any increase: likely token theft |
| `haven_idp_code_replay_total` | An authorization code was presented twice | any increase: client bug or interception |
| `haven_idp_admin_operations_total`, `haven_idp_admin_auth_failures_total` | Admin API mutations and rejected calls | repeated `invalid` or `forbidden` |
| `haven_idp_store_up`, `haven_idp_store_ping_duration_seconds` | Store health | `store_up == 0` |
| `haven_idp_signing_key_age_seconds` | Age of the newest active signing key | above 90 days: rotate |
| `haven_idp_audit_events_total{sink,result}`, `haven_idp_audit_queue_length` | Audit pipeline health: `sent`, `dropped`, `error` | any dropped or error |

Label values are bounded: realm names only for realms that exist, routes are
patterns, and user names or client ids are never labels (they are in audit
events instead).

## Alert routing

Route by the `severity` label.

- `critical` (`HavenIdpDown`, `HavenIdpStoreDown`, `HavenIdpRefreshTokenReuse`, `HavenIdpAuditDropping`): page the on-call. Reuse and audit loss are security incidents, so also notify the security channel.
- `warning`: team channel or ticket. The security-themed warnings (`LoginFailureSpike`, `CodeReplay`, `LockoutBurst`, `AdminAuthFailures`) should go to whoever reads the audit stream.

Each alert has an `action:` annotation with the first steps. Example Alertmanager route:

```yaml
route:
  routes:
    - matchers: [alertname=~"HavenIdp.*", severity="critical"]
      receiver: pagerduty
    - matchers: [alertname=~"HavenIdp(LoginFailureSpike|CodeReplay|LockoutBurst|AdminAuthFailures)"]
      receiver: security-slack
    - matchers: [alertname=~"HavenIdp.*"]
      receiver: team-slack
```

## The audit stream and its chain

Each event is a JSON object (`time`, `realm`, `type`, `severity`, `userId`,
`clientId`, `ip`, `detail`, `requestId`, `seq`, `prev`). Severity is `info`,
`warning` or `alert` (active attack signals: reuse, replay, lockout).

Tamper evidence: every sink numbers its events `seq` = 1, 2, 3, ... and sets
`prev` to the hex SHA-256 of the exact JSON bytes of the previous event that
sink emitted (the line for `stdout`/`file`, the array element for `webhook`).
Removing, reordering or editing an event breaks the chain. Dropped events
(queue full) still consume a `seq`, so a loss appears as a gap.

Limits to know:

- A process restart starts a new chain: `seq` 1 and empty `prev`. The verifier below accepts that and reports the number of chains.
- Truncating the tail of a stream is not detectable from the stream alone. Compare the last `seq` against `haven_idp_audit_events_total` or keep the stream in write-once storage.
- Each sink in a multi-sink setup has its own chain. Hashes cover the exact bytes, so verify the raw lines or array elements, not re-serialized JSON.

Verifier: reads the `stdout`/`file` lines from stdin. For webhook payloads,
store each array element's raw bytes on its own line (do not re-serialize with
a tool that changes spacing or escaping). The test suite extracts and runs this
exact program.

<!-- verifier -->
```go
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var n, chains int
	var lastSeq uint64
	var lastHash string
	for sc.Scan() {
		line := sc.Bytes()
		var e struct {
			Seq  uint64 `json:"seq"`
			Prev string `json:"prev"`
		}
		if err := json.Unmarshal(line, &e); err != nil {
			fmt.Fprintf(os.Stderr, "line %d: %v\n", n+1, err)
			os.Exit(1)
		}
		switch {
		case e.Seq == 1 && e.Prev == "":
			chains++ // new chain (process start)
		case n == 0 || e.Seq != lastSeq+1 || e.Prev != lastHash:
			fmt.Fprintf(os.Stderr, "line %d: chain broken (seq %d after %d)\n", n+1, e.Seq, lastSeq)
			os.Exit(1)
		}
		sum := sha256.Sum256(line)
		lastSeq, lastHash = e.Seq, hex.EncodeToString(sum[:])
		n++
	}
	fmt.Printf("OK: %d events, %d chain(s)\n", n, chains)
}
```

Run it with `go run verify.go < audit.jsonl`.

## Loki and Vector example

Ship the file sink with Vector and keep events as structured JSON:

```toml
[sources.haven_audit]
type = "file"
include = ["/var/log/haven/audit.jsonl"]

[transforms.haven_parse]
type = "remap"
inputs = ["haven_audit"]
source = '''
. = parse_json!(.message)
'''

[sinks.loki]
type = "loki"
inputs = ["haven_parse"]
endpoint = "http://loki:3100"
encoding.codec = "json"
labels.app = "haven-idp"
labels.severity = "{{ severity }}"
labels.realm = "{{ realm }}"
```

Keep `type`, `severity` and `realm` as labels and leave `userId`, `ip` and
`requestId` in the line (high cardinality). A LogQL alert on active attacks:
`sum by (realm) (count_over_time({app="haven-idp", severity="alert"}[10m])) > 0`.

For the `stdout` sink on Kubernetes, audit lines share the container stream
with logs; filter them in the collector with a JSON parse and a check for the
`seq` field.

## Privacy

Recorded: event time, realm, event type, severity, user id, client id, client
IP as the server saw it, a short detail (at most 512 bytes), the request id.

Never recorded: passwords, password hashes, client secrets, tokens, authorization
codes, refresh tokens, cookies, query strings or request bodies. Metric labels
never contain user names, client ids or raw paths. All string fields have
control characters stripped, so a hostile user name cannot forge log lines.

User ids and IPs are personal data under most privacy regimes. Set retention on
the audit store accordingly and restrict access to the file and webhook target.
