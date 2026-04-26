# Aegis Proxy Security Hardening Implementation Plan
> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

## Goal

Close the three concrete proxy security gaps identified in review:

- Require trusted downstream CIDRs when Proxy Protocol v2 is enabled.
- Strip hop-by-hop headers correctly, including headers named by `Connection`.
- Bound the MITM certificate cache so SNI churn cannot grow it without limit.

## Scope

In scope:

- `proxy.proxyProtocol.trustedCIDRs` config and validation.
- PPv2 listener trust enforcement by direct peer IP.
- Correct request/response hop-by-hop header stripping.
- Configurable MITM cache maximum with a safe default.
- Unit and integration-style regression tests for the above.

Out of scope:

- Admin listener TLS or mTLS.
- Request or body size limits.
- Broader deployment hardening.

## Implementation Steps

- [ ] Add config fields and validation for PPv2 trusted CIDRs and MITM cache sizing in `internal/config`.
- [ ] Add failing tests covering invalid PPv2 trust config, invalid CIDRs, and invalid cache sizes.
- [ ] Add failing proxy tests covering untrusted PPv2 peers, `Connection` token stripping, and MITM cache bounds.
- [ ] Implement PPv2 trusted-peer enforcement in `internal/proxy/proxy_protocol.go` and wire the config through `cmd/aegis`.
- [ ] Implement RFC-correct hop-by-hop header stripping in `internal/proxy/server.go`.
- [ ] Implement bounded MITM cache eviction in `internal/proxy/tls_mitm.go` using a safe default cap and eviction metrics.
- [ ] Update examples/docs/Helm defaults for the new config surface.
- [ ] Run focused tests first, then full verification:
  - `go test ./internal/config ./internal/proxy`
  - `go test ./...`
  - `helm template aegis ./deploy/helm`

## Risks

- PPv2 trust checks must use the direct peer address, not the forwarded address.
- Hop-by-hop stripping must not remove end-to-end headers accidentally.
- MITM cache eviction must not race with certificate issuance or break cache metrics.

## Success Criteria

- PPv2-enabled listeners reject untrusted direct peers before honoring the forwarded source IP.
- Headers named in `Connection` are stripped on both forwarded requests and responses.
- MITM cache size is capped and eviction is observable in tests and metrics.
