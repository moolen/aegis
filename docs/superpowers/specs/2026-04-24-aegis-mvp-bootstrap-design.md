# Aegis MVP Bootstrap Design

**Date:** 2026-04-24
**Status:** Approved for bootstrap

## Goal

Bootstrap the `aegis` repository as a runnable Phase 1 foundation for the identity-aware egress proxy described in `aegis-design-doc.md`, while keeping the codebase structured for the later full implementation.

This bootstrap is intentionally narrower than the full product. It must produce a working repository with a buildable Go service, local developer workflow, CI, containerization, and deployment scaffolding. It must not claim identity-aware enforcement, TLS inspection, or MITM support until those capabilities are implemented.

## Scope

### In scope

- Create a new Go module and repository layout matching the long-term architecture.
- Implement a runnable `aegis` binary that:
  - Loads YAML configuration.
  - Starts a proxy listener.
  - Starts a metrics and health listener.
  - Proxies plain HTTP requests.
  - Supports basic `CONNECT` tunneling.
  - Resolves upstream hosts through an internal DNS resolver abstraction.
  - Emits structured JSON logs.
- Add unit and smoke-test coverage for the bootstrap behavior.
- Add local development tooling: `Makefile`, `Dockerfile`, example config, repo hygiene files.
- Add deployment scaffolding for Fargate and Helm, clearly marked as bootstrap-grade.
- Add GitHub Actions for test, lint, and container build verification.
- Create the GitHub repository and push the bootstrap state.

### Out of scope

- Kubernetes pod discovery.
- EC2 instance discovery.
- Identity-to-policy resolution.
- Policy enforcement and default-deny semantics.
- TLS ClientHello parsing and SNI validation.
- MITM certificate generation and HTTP inspection inside TLS.
- Proxy Protocol v2 parsing.
- SIGHUP reloads and advanced runtime hardening.
- Full Kind-based e2e coverage from the main design doc.

## MVP Runtime Behavior

### Process model

The bootstrap ships a single `aegis` process. `cmd/aegis/main.go` is responsible for:

- loading config,
- constructing shared components,
- starting the proxy server,
- starting the metrics server,
- handling graceful shutdown.

The service must be runnable locally with a single config file and must support a smoke test such as:

```bash
curl -x http://127.0.0.1:3128 http://example.com
```

and a basic `CONNECT` path such as:

```bash
curl -x http://127.0.0.1:3128 https://example.com
```

### Proxy behavior

The proxy must support two request classes:

- Standard HTTP proxy requests with absolute URLs.
- `CONNECT host:port` requests for raw tunnel establishment.

For the bootstrap:

- HTTP requests are forwarded to the upstream after target parsing and DNS resolution through the internal resolver.
- `CONNECT` requests return `200 Connection Established`, then splice bytes bidirectionally between client and upstream.
- The proxy does not inspect TLS payloads after tunnel establishment.
- The proxy does not enforce identity or policy decisions yet.

### DNS behavior

All upstream dialing must go through an internal DNS resolver package instead of relying on ad hoc resolution in handlers.

The resolver must:

- allow custom DNS server configuration,
- expose a simple lookup API to the proxy layer,
- log successful and failed resolutions,
- support a small TTL-based cache,
- remain testable without external infrastructure.

If the configured custom resolver path proves unreliable in local tests, the implementation may fall back to the system resolver behind the same package interface, but the package boundary must remain stable because later phases depend on it.

### Logging and metrics

The bootstrap must emit structured JSON logs using `log/slog`.

Minimum log events:

- process startup and shutdown,
- config load success/failure,
- proxy request accepted,
- proxy upstream dial failure,
- DNS resolution success/failure.

Minimum metrics:

- total proxied requests,
- total proxy errors,
- request duration histogram,
- DNS resolution count,
- DNS resolution duration histogram.

The metrics listener must expose:

- `/metrics`
- `/healthz`

## Repository Structure

The bootstrap should create the following repository shape:

```text
aegis/
├── .editorconfig
├── .gitignore
├── .github/
│   └── workflows/
│       └── ci.yml
├── README.md
├── Dockerfile
├── Makefile
├── aegis.example.yaml
├── cmd/
│   └── aegis/
│       └── main.go
├── internal/
│   ├── config/
│   ├── dns/
│   ├── identity/
│   ├── metrics/
│   ├── policy/
│   └── proxy/
├── e2e/
├── deploy/
│   ├── fargate/
│   └── helm/
└── docs/
    └── superpowers/
        └── specs/
```

### Package responsibilities

- `internal/config`: config structs, defaults, parsing, validation.
- `internal/proxy`: HTTP proxy server, request parsing, CONNECT handling, upstream dialing.
- `internal/dns`: resolver abstraction, cache, logging, tests.
- `internal/metrics`: Prometheus registry and metrics HTTP server.
- `internal/identity`: future-facing interfaces and types only; no fake functionality.
- `internal/policy`: future-facing interfaces and types only; no fake functionality.

The main rule for placeholder packages is structural honesty: interfaces and types are allowed, but stub code must not imply those features work today.

## Deployment Scaffolding

The bootstrap must include deployment scaffolding now, but it should be minimal and explicit about its maturity.

### Fargate

Include:

- container packaging via `Dockerfile`,
- a starter ECS task definition,
- Terraform or comparable IaC skeleton for ECS service, target group, and NLB wiring,
- placeholders for secrets/config integration documented in comments or README text.

The Fargate scaffold should assume the current bootstrap service only provides generic proxying and metrics. It must not document policy enforcement or MITM as available features.

### Helm

Include:

- a minimal chart structure,
- default values,
- deployment/service/configmap templates sufficient for local or future in-cluster iteration.

The Helm chart can be intentionally thin, but it should render cleanly and reflect the actual runtime ports and config file mounting model.

## Tooling and CI

The bootstrap must establish a working developer loop:

- `make build`
- `make test`
- `make lint`
- `make docker`

GitHub Actions must verify, at minimum:

- module download and build,
- tests,
- lint or static checks,
- container build.

CI should be conservative. It is better to run a smaller set of reliable checks than to add brittle placeholders for future infrastructure.

## Testing Strategy

### Unit tests

Include tests for:

- config parsing and validation,
- DNS cache behavior,
- proxy helper behavior and request parsing,
- metrics server smoke behavior if lightweight.

### Integration or smoke tests

Include at least one test that:

- starts the proxy in-process or as a test server,
- starts a local upstream HTTP server,
- sends traffic through the proxy,
- verifies successful forwarding.

Include at least one smoke path for `CONNECT`, even if it is only validating tunnel establishment against a controlled local server.

The full Kind-based e2e suite remains a later milestone and should not be partially simulated in a confusing way.

## Error Handling

The bootstrap should implement explicit, predictable failure behavior:

- invalid config: fail process startup with a clear error,
- malformed proxy request: `400 Bad Request`,
- upstream DNS or dial failure: `502 Bad Gateway`,
- internal unexpected failure: `500 Internal Server Error`,
- shutdown: graceful stop with context timeout.

Error responses should be simple and consistent. No custom JSON API format is required for the bootstrap.

## Follow-On Work After Bootstrap

After the MVP bootstrap lands, the next implementation stages should proceed in this order:

1. Add the full Phase 1 foundation details that are still missing from bootstrap rough edges.
2. Implement TLS inspection and MITM support.
3. Implement Kubernetes and EC2 identity discovery.
4. Implement policy evaluation and enforcement.
5. Expand to Kind-based end-to-end coverage.
6. Harden runtime behavior and finish deployment support.

This ordering preserves the package boundaries established by the bootstrap and minimizes later structural churn.

## Success Criteria

The bootstrap is complete when all of the following are true:

- the repo is initialized and builds cleanly,
- `aegis` starts from config and serves proxy plus metrics endpoints,
- HTTP proxying works against a local test upstream,
- `CONNECT` tunneling works at a basic level,
- tests and CI run successfully,
- deployment scaffolding exists for Fargate and Helm,
- repository documentation accurately describes the current implemented state,
- the codebase is ready for the full implementation phases without a repo restructure.
