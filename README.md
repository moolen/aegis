# Aegis

Aegis is an identity-aware HTTP egress proxy.

This repository currently contains the MVP bootstrap: a runnable HTTP/CONNECT
forward proxy, config loading, metrics, tests, CI, and deployment scaffolding.
Identity-aware discovery, policy enforcement, and TLS inspection are planned but
not implemented yet.

## Status

Current bootstrap capabilities:

- YAML config loading and validation.
- HTTP proxying and basic `CONNECT` tunneling.
- Structured JSON logging.
- Prometheus metrics and health endpoint.
- Container build, CI workflow, and deployment scaffolding.

## Quick Start

```bash
make build
./bin/aegis -config aegis.example.yaml
```

In another terminal:

```bash
curl -x http://127.0.0.1:3128 http://example.com
curl -x http://127.0.0.1:3128 https://example.com
```
