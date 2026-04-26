# Aegis HTTP/2 Design

Date: 2026-04-26

## Goal

Add real HTTP/2 support to the parts of Aegis that actually speak HTTP so the
MITM path can handle multiplexed client traffic efficiently and reuse upstream
HTTP/2 connections where supported.

## Scope

This slice includes:

- client-facing HTTP/2 on the MITM TLS path
- upstream HTTP/2 on the shared HTTPS transport
- explicit multiplexing verification for both directions
- regression coverage that policy and metrics still operate per request under
  multiplexed load

This slice does not include:

- `h2c`
- HTTP/2 support on the cleartext proxy listener
- changes to raw passthrough tunnel semantics
- policy model changes

## Current State

Today Aegis already has a shared upstream `http.Transport`, and it already
reuses that transport for plain HTTP and MITM upstream round trips. That gives
good pooling behavior, but the client-facing MITM side still uses a manual
`http.ReadRequest` loop on a single decrypted TLS connection. That means:

- only HTTP/1.1 is handled on the client-facing MITM path
- one client connection is processed serially
- there is no real client-side stream multiplexing

The HTTP/2 slice should fix that without changing policy semantics.

## Design

### 1. Client-facing MITM HTTP/2

The MITM TLS endpoint should advertise:

- `h2`
- `http/1.1`

The decrypted client connection should be handed to a dedicated MITM HTTP
serving path that lets Go's HTTP server stack manage HTTP/2 framing and
concurrent streams. Aegis should stop manually reading decrypted requests in a
serial loop once the client TLS handshake succeeds.

The MITM request handler should remain an Aegis-owned handler so request
processing stays unified:

- evaluate per-request policy
- enforce method/path rules
- forward through the shared upstream transport
- emit the same request and error metrics

The main behavioral requirement is that multiple concurrent client requests can
share a single TLS connection to Aegis on the MITM path.

### 2. Upstream HTTP/2

The shared upstream transport should explicitly support HTTP/2 for HTTPS
origins. That support should be treated as part of the proxy runtime contract,
not as an incidental side effect of Go defaults.

For concurrent requests to the same HTTPS origin, Aegis should reuse a small
number of upstream connections instead of opening one connection per request.

This does not change passthrough `CONNECT`: Aegis still does not inspect or
upgrade opaque tunnels.

### 3. Shared Request Semantics

HTTP/2 must not fork behavior from HTTP/1.1. For each request or stream:

- identity resolution is unchanged
- policy evaluation is unchanged
- allow/deny is decided independently per request
- one denied request must not close or poison the whole client connection
- metrics remain request-shaped, not connection-shaped

### 4. Error Handling

Client-facing MITM behavior:

- denied requests return the existing proxy/MITM error response for that stream
- malformed or broken client HTTP/2 sessions terminate cleanly without leaking
  goroutines or hanging connections

Upstream behavior:

- upstream HTTP/2 negotiation is opportunistic
- if an origin only supports HTTP/1.1, the request still succeeds over the
  existing path
- upstream connection and TLS failures continue to surface as request-scoped
  `502` responses and metrics, not connection-global proxy panics

## Verification

The implementation must prove multiplexing directly.

### Unit / integration coverage

- client MITM can negotiate `h2`
- multiple concurrent client requests share one MITM-side TLS connection
- concurrent upstream requests to one HTTP/2-capable origin reuse one upstream
  connection
- policy allow/deny still applies per request under multiplexed load
- denied requests do not break unrelated streams on the same connection

### Perf verification

The MITM perf path should be rerun after the HTTP/2 change with concurrent load.
Success is:

- no regression in correctness
- stable multiplexed behavior under concurrency
- reduced connection churn on the MITM path
- equal or improved MITM throughput / latency at the same load point

## Files Likely To Change

- `internal/proxy/server.go`
- `internal/proxy/http2_mitm.go` or equivalent new helper file
- `internal/proxy/server_test.go`
- additional focused HTTP/2 tests under `internal/proxy`
- perf docs and possibly MITM perf fixtures if they need explicit HTTP/2
  exercise

## Risks

- it is easy to accidentally enable ALPN without proving real multiplexing
- per-request policy and metrics can drift if the HTTP/2 path forks too much
  logic away from the existing HTTP/1.1 forwarding path
- test fixtures must explicitly support HTTP/2, otherwise the slice can look
  green while only exercising HTTP/1.1

## Success Criteria

This slice is complete when:

- MITM clients can successfully use HTTP/2
- concurrent requests share one client-side MITM connection
- upstream HTTPS reuse includes real HTTP/2 connection multiplexing where the
  origin supports it
- policy behavior is unchanged per request
- perf evidence shows the MITM path remains correct and performant under
  multiplexed load
