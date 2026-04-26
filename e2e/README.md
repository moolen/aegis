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
- audit-mode allow-on-deny behavior for HTTP and `CONNECT`
- no-SNI and SNI-mismatch blocking
- MITM certificate issuance and inner HTTP policy enforcement
- client trust-store failure when the proxy CA is missing
- upstream TLS validation failure on the MITM path

The deployment-facing Kind/Helm matrix runs with:

```bash
go test -tags kind_e2e -timeout 45m ./e2e/...
```

That suite uses one shared Kind cluster and one shared locally built Aegis
image for the whole `go test` process, then runs deployment-shaped scenarios in
isolated namespaces and Helm releases. The current matrix is focused on the
shipped Helm deployment path rather than a single catch-all smoke test:

- shared-cluster/run-name isolation helpers
- Helm deployment plus in-cluster HTTP allow/deny checks
- CIDR-based policy enforcement
- Kubernetes-discovery identity enforcement with real pod labels
- readiness, health, metrics, and admin simulation checks along the deployed path

It requires Docker, `kind`, `kubectl`, and `helm`.

CI now runs the subprocess `e2e` suite in the fast `ci` job and the heavier
`kind_e2e` deployment matrix in a dedicated `kind-e2e` job on every push and
pull request.
