# Aegis

Aegis is an identity-aware HTTP egress proxy. The repository currently contains
the first policy-aware slice on top of the MVP bootstrap: a runnable
HTTP/CONNECT forward proxy, config loading, plain HTTP policy enforcement,
metrics, tests, CI, and deployment scaffolding.

## Current Status

Implemented in this bootstrap:

- YAML config loading and validation.
- HTTP proxying with policy enforcement for plain HTTP requests.
- Basic `CONNECT` tunneling that remains bootstrap-grade.
- Structured JSON logging with `slog`.
- Prometheus metrics and `/healthz`.
- Container build, GitHub Actions CI, Helm chart, and Fargate starter files.

Planned but not implemented yet:

- Kubernetes and EC2 identity discovery.
- TLS ClientHello inspection and SNI validation.
- MITM certificate generation and HTTP inspection inside TLS.
- Proxy Protocol v2 and production hardening features.

## Quick Start

Build and run:

```bash
make build
./bin/aegis -config aegis.example.yaml
```

Send traffic through the proxy:

```bash
curl -x http://127.0.0.1:3128 http://example.com
curl -x http://127.0.0.1:3128 https://example.com
```

Inspect metrics:

```bash
curl http://127.0.0.1:9090/healthz
curl http://127.0.0.1:9090/metrics
```

## Development

Available commands:

- `make build`
- `make test`
- `make lint`
- `make fmt`
- `make docker`

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
plain HTTP requests are policy-enforced, while `CONNECT` remains a basic tunnel
without identity-aware TLS inspection or interception support.

## Design Docs

- `aegis-design-doc.md`: original product design draft.
- `docs/superpowers/specs/2026-04-24-aegis-mvp-bootstrap-design.md`: approved
  bootstrap design.
- `docs/superpowers/plans/2026-04-24-aegis-mvp-bootstrap.md`: implementation
  plan used for the bootstrap work.
