# Aegis Dual-CA Rotation Design

**Date:** 2026-04-25
**Status:** Approved for implementation

## Goal

Make Aegis dual-CA MITM rotation semantics real and operationally clear.

This slice keeps a single deterministic issuing CA while loading companion CAs
during rollout windows so operators can stage trust changes without ambiguous
runtime behavior.

## Scope

### In scope

- Keep `proxy.ca` as the single active issuing CA for MITM leaf certificates.
- Load `proxy.ca.additional[]` as real companion CA material, not fingerprint
  metadata only.
- Expose the active issuer fingerprint and companion fingerprints through the
  runtime/admin surface.
- Distinguish issuer rotation from companion-set changes during reload.
- Add tests for issuer selection, companion loading, and reload
  classification.

### Out of scope

- Dynamic issuer selection per handshake.
- Automatic promotion from companion CA to active issuer.
- Client trust-store distribution.
- External secret fetch or secret-manager integration.
- Changes to policy semantics or CONNECT routing behavior.

## Design Boundary

This slice changes MITM CA runtime state and reload classification, but it does
not change the core proxy decision path.

When MITM is enabled, Aegis must still issue forged leaf certificates using one
deterministic CA only. Companion CAs exist to model rollout state explicitly
and to make that state inspectable, not to introduce issuer selection logic.

## Configuration Model

Use the existing configuration shape:

- `proxy.ca.certFile`
- `proxy.ca.keyFile`
- `proxy.ca.additional[]`

The semantic contract for this slice is:

- `proxy.ca` is the active issuing CA.
- `proxy.ca.additional[]` contains companion CAs that remain loaded during a
  transition window.

Config order is intentional and deterministic. Certificate validity dates are
not used to infer rollout intent.

## Runtime Architecture

### MITM engine state

`internal/proxy/tls_mitm.go` should keep one active issuer plus a collection of
loaded companion CA records.

Each loaded CA record should include at minimum:

- parsed leaf certificate,
- fingerprint,
- role (`issuer` or `companion`).

The engine should continue to use only the active issuer when generating forged
leaf certificates. Companion CA records are retained for runtime inspection and
reload lifecycle comparison.

### Issuance semantics

For every new MITM certificate:

- the signing key must come from `proxy.ca`,
- the authority key identifier must match the active issuer,
- companion CAs must not be selected dynamically.

This keeps certificate issuance deterministic across reloads and easy to reason
about operationally.

### Admin and runtime visibility

The runtime/admin surface should make the loaded CA set explicit:

- active issuer fingerprint,
- companion fingerprints,
- full CA set fingerprint list in stable order.

Operators should be able to tell from one runtime view whether:

- MITM is disabled,
- a single issuer is loaded,
- a rotation window is in progress with companion CAs present.

## Reload Semantics

Reload behavior should classify MITM CA changes more precisely than it does
today.

The runtime should distinguish:

- `initial` — MITM becomes active for the first time,
- `enabled` — equivalent initial activation wording already used by runtime if
  preserved,
- `disabled` — MITM is removed,
- `unchanged` — issuer and companion set unchanged,
- `rotated` — active issuer fingerprint changed,
- `companions_changed` — issuer unchanged but companion set changed.

Only an active issuer change counts as CA rotation. Companion-only changes
should remain visible but must not be reported as a full issuer rotation.

When a new runtime generation replaces the old one, the existing certificate
cache reset behavior remains acceptable for this slice.

## Failure Handling

Companion CA loading should be strict:

- invalid `proxy.ca.additional[]` entries fail startup,
- invalid companion CA material during reload rejects the new generation and
  keeps the previous generation active,
- companion CA load failures are treated the same way as primary CA load
  failures for generation construction.

This avoids partially-applied rollout state.

## Testing Strategy

### MITM engine tests

Add or extend tests in `internal/proxy/tls_mitm_test.go` to prove:

- forged certificates are always issued by the primary CA,
- companion CA load succeeds when valid,
- companion fingerprint reporting is stable and complete,
- invalid companion CA input is rejected.

### Reload/runtime tests

Add or extend tests around runtime reload handling to prove:

- active issuer change is classified as `rotated`,
- companion-only change is classified as `companions_changed`,
- unchanged issuer plus unchanged companion set remains `unchanged`,
- invalid companion CA changes do not replace the active runtime generation.

## Success Criteria

This slice is complete when:

- `proxy.ca.additional[]` loads real companion CA runtime state,
- MITM issuance remains deterministic on the active issuer only,
- runtime/admin visibility clearly exposes issuer and companion CA
  fingerprints,
- reload classification distinguishes issuer rotation from companion-only
  changes,
- invalid companion CA material fails generation construction,
- tests and builds pass.
