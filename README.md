# Aegis

Aegis is an identity-aware HTTP egress proxy. The repository currently contains
the first policy-aware slice on top of the MVP bootstrap: a runnable
HTTP/CONNECT forward proxy, config loading, plain HTTP policy enforcement,
runtime-wired Kubernetes and EC2 identity discovery, metrics, tests, CI, and
deployment scaffolding.

## Current Status

Implemented in this bootstrap:

- YAML config loading and validation.
- HTTP proxying with policy enforcement for plain HTTP requests.
- Kubernetes and EC2 identity discovery wired into the running process.
- Multiple discovery providers evaluated in deterministic config order, with
  first-match precedence.
- `CONNECT` tunneling with policy enforcement and TLS SNI validation for
  passthrough rules.
- CA-backed TLS MITM for `CONNECT` rules with `tls.mode: mitm`, including
  decrypted HTTP method/path enforcement.
- Optional Proxy Protocol v2 support on the proxy listener so identity
  resolution can use the original client IP behind an L4 load balancer.
- Live `SIGHUP` config reload for policy, DNS, discovery, and MITM CA changes.
- Global `proxy.enforcement: audit` mode for migration, with would-allow /
  would-deny metrics and logs while traffic keeps flowing.
- Per-policy `enforcement: audit|enforce` so rollout can stay selective even
  when the global mode remains `enforce`.
- Token-protected `POST /admin/enforcement?mode=audit|enforce|config` on the
  metrics port for an immediate global audit/enforce override without reload.
- Per-policy `bypass: true` shadowing so a matching policy can emit would-allow
  / would-deny signals without blocking traffic.
- Configurable `proxy.unknownIdentityPolicy: allow|deny` for production
  hard-deny behavior when a source IP cannot be resolved to a known identity.
- Admin tooling on the metrics port for identity dump and policy simulation,
  plus CLI subcommands for `validate`, `diff`, `dump-identities`, and
  `simulate`.
- Optional per-identity concurrent connection limits across plain HTTP requests
  and `CONNECT` tunnels.
- Configurable graceful shutdown with explicit CONNECT tunnel draining and
  force-close accounting when the grace period expires.
- Readiness semantics backed by discovery-provider freshness, with provider
  status metrics and a separate `/readyz` endpoint.
- Structured JSON logging with `slog`.
- Prometheus metrics and `/healthz`, including reload, Proxy Protocol, CONNECT,
  MITM certificate-cache and CA lifecycle counters, request decision counters,
  active tunnel and shutdown counters, policy-evaluation latency, upstream TLS
  error counters, and per-provider identity-map gauges.
- Container build, GitHub Actions CI, Helm chart, and Fargate starter files.

Planned but not implemented yet:

- Remaining production hardening features.

Current runtime behavior:

- Plain HTTP policy enforcement uses the configured identity resolver before any
  upstream dial.
- Kubernetes discovery providers are started at boot in listed order, followed
  by listed EC2 discovery providers. The first provider that resolves a source
  IP wins.
- Provider startup failures are tolerated as long as at least one configured
  provider becomes active; failures are surfaced through structured logs and
  Prometheus metrics.
- Active discovery providers are tracked as `active`, `stale`, or `down`.
  `/healthz` remains liveness-only, while `/readyz` fails if discovery is
  configured and no provider is currently `active`.
- `CONNECT` requests resolve identity, evaluate policy, require a TLS
  ClientHello with matching SNI, and then run in passthrough or MITM mode
  depending on the matched rule.
- When `proxy.enforcement: audit` is set, Aegis still evaluates policy and
  emits audit metrics/logs, but it does not block policy-denied traffic. To
  keep migration traffic transparent, audit-mode `CONNECT` stays in raw
  passthrough rather than active MITM inspection.
- When a matching policy sets `enforcement: audit`, that policy stays in shadow
  mode even while the global effective mode is `enforce`.
- When `admin.token` is configured, the metrics port also exposes a protected
  enforcement admin endpoint. `POST /admin/enforcement?mode=audit` forces
  global audit mode immediately, `mode=enforce` forces blocking immediately,
  and `mode=config` clears the override and returns to the configured
  `proxy.enforcement` value. `GET /admin/enforcement` reports the configured,
  override, and effective modes, `GET /admin/runtime` returns the active MITM
  CA issuer plus any loaded companion CAs, `/admin/identities` returns the
  live discovery map, `/admin/simulate` evaluates a hypothetical request
  against the active runtime state, and `aegis_enforcement_mode` exposes the
  effective mode in Prometheus.
- When a matching policy sets `bypass: true`, that policy behaves like a
  scoped shadow rule: Aegis records would-allow / would-deny outcomes for the
  match but still forwards the traffic. As with global audit mode, bypassed
  `CONNECT` requests stay in transparent passthrough rather than active MITM.
- When `proxy.unknownIdentityPolicy: deny` is set, requests from unresolved
  source IPs are denied in enforce mode and recorded as would-deny in audit
  mode before any upstream dial happens.
- TLS MITM requires `proxy.ca.certFile` and `proxy.ca.keyFile`; once
  configured, Aegis terminates client TLS, verifies upstream TLS, and evaluates
  decrypted HTTP requests before forwarding them. `proxy.ca` is always the
  active issuing CA for forged MITM leaf certificates. During CA rotation
  windows, `proxy.ca.additional[]` keeps companion CAs loaded so the runtime
  can report the full CA set and distinguish issuer rotation from
  companion-only reload changes.
- When `proxy.proxyProtocol.enabled` is set, the proxy listener requires Proxy
  Protocol v2 on inbound connections and uses the forwarded source IP for
  request identity resolution.
- `SIGHUP` reloads the config file in place. Listener settings stay immutable
  during reload: `proxy.listen`, `metrics.listen`, and `proxy.proxyProtocol.*`
  changes are rejected and require a process restart.
- Shutdown uses `shutdown.gracePeriod` to stop accepting new requests, drain
  active CONNECT tunnels, and force-close any remaining hijacked tunnels when
  the grace period expires.
- When `proxy.connectionLimits.maxConcurrentPerIdentity` is greater than zero,
  Aegis limits each resolved identity across active HTTP requests and CONNECT
  tunnels combined. Limit hits return `429 Too Many Requests`.

## Quick Start

Build and run:

```bash
make build
./bin/aegis -config aegis.example.yaml
```

`aegis.example.yaml` keeps both `discovery.kubernetes` and `discovery.ec2`
empty so the quick start runs locally without requiring cluster credentials or
AWS credentials. To enable runtime Kubernetes discovery, add a provider entry
under `discovery.kubernetes` and configure its `auth` block with
`provider: kubeconfig` for local runs, `provider: inCluster` inside a cluster,
or the managed-cluster variants `eks`, `gke`, or `aks` with their
provider-specific fields. Policies now bind explicitly through
`policies[].subjects`, so each policy must reference one or more named
discovery providers through
`subjects.kubernetes.discoveryNames` or `subjects.ec2.discoveryNames`, or one
or more source CIDRs through `subjects.cidrs`. To enable EC2 discovery, add a
provider entry under `discovery.ec2`, set the
target AWS `region`, and define the tag filters that scope instance discovery.
To enable TLS MITM for `CONNECT`, provide a proxy CA certificate and key
through `proxy.ca.certFile` and `proxy.ca.keyFile`. To preserve client IPs
behind an NLB or similar L4 balancer, enable `proxy.proxyProtocol.enabled`
and configure the balancer to emit Proxy Protocol v2 on the proxy port; when
PPv2 is enabled, `proxy.proxyProtocol.trustedCIDRs` must restrict which direct
peers are allowed to supply forwarded source addresses. To reload policy or
discovery changes without restarting the process, send `SIGHUP` to Aegis.
When rotating trust, keep the new active issuer under `proxy.ca` and keep the
old CA loaded under `proxy.ca.additional[]`, for example:

```yaml
proxy:
  proxyProtocol:
    enabled: true
    trustedCIDRs:
      - "10.0.0.0/8"
  ca:
    certFile: /etc/aegis/ca/new-ca.crt
    keyFile: /etc/aegis/ca/new-ca.key
    additional:
      - certFile: /etc/aegis/ca/old-ca.crt
        keyFile: /etc/aegis/ca/old-ca.key
    cache:
      maxEntries: 10000
```

A CIDR-only policy is also valid when you want to scope rules directly to
source networks instead of discovery-backed identities:

```yaml
policies:
  - name: allow-office
    subjects:
      cidrs:
        - "10.20.0.0/16"
    egress:
      - fqdn: "api.example.com"
        ports: [443]
        tls:
          mode: passthrough
```

For migration, set `proxy.enforcement: audit` to shadow policy decisions
without blocking traffic. For staged rollout, keep the global mode enforced and
set `policies[].enforcement: audit` on the workloads that still need shadow
mode. For a narrower escape hatch, set `bypass: true` on a specific policy
instead. To enable the global kill switch and the admin tooling endpoints, set
`admin.token` and call the metrics-port admin endpoint with
`Authorization: Bearer <token>`.
By default, Aegis also blocks loopback, private, and link-local upstream
addresses after DNS resolution to reduce DNS rebinding and SSRF risk; use
`dns.rebindingProtection.allowedHostPatterns` or
`dns.rebindingProtection.allowedCIDRs` for explicit internal destinations.
Set `proxy.unknownIdentityPolicy: deny` when you want production default-deny
behavior for traffic whose source IP does not map to a known identity.
Set `proxy.connectionLimits.maxConcurrentPerIdentity` to cap concurrent
upstream usage per resolved identity during migration or steady-state rollout.
Use `shutdown.gracePeriod` to control how long Aegis drains in-flight traffic
before it force-closes remaining CONNECT tunnels during process shutdown.

Send traffic through the proxy:

```bash
curl -x http://127.0.0.1:3128 http://example.com
curl -x http://127.0.0.1:3128 https://example.com
```

Inspect metrics:

```bash
curl http://127.0.0.1:9090/healthz
curl http://127.0.0.1:9090/readyz
curl http://127.0.0.1:9090/metrics
curl -H 'Authorization: Bearer replace-me' \
  'http://127.0.0.1:9090/admin/runtime'
curl -H 'Authorization: Bearer replace-me' \
  'http://127.0.0.1:9090/admin/identities'
curl -H 'Authorization: Bearer replace-me' \
  'http://127.0.0.1:9090/admin/simulate?sourceIP=10.0.0.10&fqdn=api.stripe.com&port=443&protocol=connect'
curl -H 'Authorization: Bearer replace-me' \
  -X POST 'http://127.0.0.1:9090/admin/enforcement?mode=audit'
```

## Performance Baselines

The repository includes a `perf/` package for reproducible `k6`-based
performance baselines against both local/subprocess and Kind/Helm deployments.
See [perf/README.md](perf/README.md) for setup, scenario descriptions, and run
commands.

## Development

Available commands:

- `make build`
- `make test`
- `make e2e`
- `make e2e-kind`
- `make lint`
- `make fmt`
- `make docker`

CLI tooling:

- `./bin/aegis validate --config aegis.example.yaml`
- `./bin/aegis diff --current old.yaml --next new.yaml`
- `./bin/aegis dump-identities --admin http://127.0.0.1:9090 --token replace-me`
- `./bin/aegis simulate --admin http://127.0.0.1:9090 --token replace-me --source-ip 10.0.0.10 --fqdn api.stripe.com --port 443 --protocol connect`

`make e2e` runs the lightweight tagged cross-process suite in `e2e/`.
It exercises the built `aegis` binary as a subprocess across reload-sensitive
runtime behavior and the main HTTPS protocol matrix: passthrough allow/deny,
no-SNI and SNI-mismatch blocking, MITM certificate generation, MITM inner HTTP
policy denial, client trust failure, upstream TLS validation, and audit-mode
plus per-policy audit and bypass allow-on-deny behavior for both HTTP and
`CONNECT`, unknown-identity deny handling, and concurrent-connection
enforcement for both protocols. The
heavier cluster-aware
suite from the original design doc is split out into
`make e2e-kind`, which creates a Kind cluster, loads a locally built Aegis
image, installs the shipped Helm chart, and verifies in-cluster proxy
allow/deny behavior plus Kubernetes-discovery-driven identity enforcement.
`make e2e-kind` requires Docker, `kind`, `kubectl`, and `helm`.

The local Go cache is not committed. If you need an isolated cache, use:

```bash
GOCACHE=$(pwd)/.cache/go-build GOMODCACHE=$(pwd)/.cache/mod go test ./...
```

## Deployment Scaffolding

`deploy/helm` contains a minimal chart that renders the current bootstrap
service. `deploy/fargate` contains starter ECS/NLB files aligned with the
current runtime shape: proxy on port `3128`, metrics on `9090`, and config
mounted at `/etc/aegis/aegis.yaml`.

These deployment files are scaffolding only. They reflect the current runtime:
plain HTTP requests are policy-enforced, while `CONNECT` now enforces policy
and validates SNI before entering passthrough or MITM mode. Kubernetes and EC2
discovery are runtime-wired today, multiple discovery providers are supported
in deterministic config order, and provider startup failures are tolerated when
at least one provider becomes active. For local development, discovery stays
disabled unless you configure a provider explicitly. The Helm chart includes an
optional `proxyCA.existingSecret` mount for the CA files referenced by
`config.proxy.ca`, and optional `serviceAccount` / `rbac` scaffolding so
in-cluster Kubernetes discovery can watch pods when you enable
`config.discovery.kubernetes`. Both `config.proxy.enforcement: audit` and
per-policy `config.policies[].enforcement: audit` or
`config.policies[].bypass: true` are supported for migration rollouts,
`config.admin.token` enables the metrics-port global kill switch and admin
tooling endpoints, `config.proxy.unknownIdentityPolicy` controls default-deny
behavior for unresolved sources, `config.proxy.ca` stays the active issuing CA
for forged MITM leaf certificates, `config.proxy.ca.additional[]` keeps
companion CAs loaded during dual-CA rotation windows so `GET /admin/runtime`
can report the full CA set and reloads can distinguish `rotated` from
`companions_changed`, and
`config.proxy.connectionLimits.maxConcurrentPerIdentity` can be used as a
simple abuse-control guardrail. The Fargate scaffold also
exposes an
`enable_proxy_protocol_v2` switch on the NLB target group so source IP
preservation can be paired with `config.proxy.proxyProtocol.enabled`.

## Design Docs

- `aegis-design-doc.md`: original product design draft.
- `docs/superpowers/specs/2026-04-24-aegis-mvp-bootstrap-design.md`: approved
  bootstrap design.
- `docs/superpowers/plans/2026-04-24-aegis-mvp-bootstrap.md`: implementation
  plan used for the bootstrap work.
