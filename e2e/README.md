# E2E

This directory now contains lightweight tagged cross-process smoke tests. Run
them with:

```bash
go test -tags e2e ./e2e/...
```

The current suite exercises the real `aegis` binary as a subprocess and covers
reload-sensitive runtime behavior that is awkward to prove in package-local
tests.

The heavier Kind-based and cluster-aware end-to-end suite described in
`aegis-design-doc.md` is still a later phase.
