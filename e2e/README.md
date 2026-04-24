# E2E

This directory now contains two end-to-end layers.

The lightweight cross-process smoke tests run with:

```bash
go test -tags e2e ./e2e/...
```

The current suite exercises the real `aegis` binary as a subprocess and covers
reload-sensitive runtime behavior plus the core HTTPS protocol matrix that is
awkward to prove in package-local tests:

- `CONNECT` passthrough allow and deny behavior
- no-SNI and SNI-mismatch blocking
- MITM certificate issuance and inner HTTP policy enforcement
- client trust-store failure when the proxy CA is missing
- upstream TLS validation failure on the MITM path

The deployment-facing Kind/Helm smoke tests run with:

```bash
go test -tags kind_e2e -timeout 30m ./e2e/...
```

That suite creates a Kind cluster, loads a locally built Aegis image, installs
the shipped Helm chart, and verifies live proxy traffic through the in-cluster
service. It requires Docker, `kind`, `kubectl`, and `helm`.

The broader cluster-aware suite described in `aegis-design-doc.md` can grow on
top of this base, but the core Helm deployment path is no longer just
scaffolding.
