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
- Basic `CONNECT` tunneling that remains bootstrap-grade.
- Structured JSON logging with `slog`.
- Prometheus metrics and `/healthz`.
- Container build, GitHub Actions CI, Helm chart, and Fargate starter files.

Planned but not implemented yet:

- TLS ClientHello inspection and SNI validation.
- MITM certificate generation and HTTP inspection inside TLS.
- Proxy Protocol v2 and production hardening features.

Current runtime behavior:

- Plain HTTP policy enforcement uses the configured identity resolver before any
  upstream dial.
- Kubernetes discovery providers are started at boot in listed order, followed
  by listed EC2 discovery providers. The first provider that resolves a source
  IP wins.
- Provider startup failures are tolerated as long as at least one configured
  provider becomes active; failures are surfaced through structured logs and
  Prometheus metrics.
- `CONNECT` remains a basic tunnel. TLS inspection and identity-aware HTTPS
  enforcement are not implemented yet.

## Quick Start

Build and run:

```bash
make build
./bin/aegis -config aegis.example.yaml
```

`aegis.example.yaml` keeps both `discovery.kubernetes` and `discovery.ec2`
empty so the quick start runs locally without requiring cluster credentials or
AWS credentials. To enable runtime Kubernetes discovery, add a provider entry
under `discovery.kubernetes` and set either `kubeconfig` for a local run or
leave it unset only when running inside the target cluster. To enable EC2
discovery, add a provider entry under `discovery.ec2`, set the target AWS
`region`, and define the tag filters that scope instance discovery.

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
without identity-aware TLS inspection or interception support. Kubernetes and
EC2 discovery are runtime-wired today, multiple discovery providers are
supported in deterministic config order, and provider startup failures are
tolerated when at least one provider becomes active. For local development,
discovery stays disabled unless you configure a provider explicitly. TLS
inspection is still pending.

## Design Docs

- `aegis-design-doc.md`: original product design draft.
- `docs/superpowers/specs/2026-04-24-aegis-mvp-bootstrap-design.md`: approved
  bootstrap design.
- `docs/superpowers/plans/2026-04-24-aegis-mvp-bootstrap.md`: implementation
  plan used for the bootstrap work.
