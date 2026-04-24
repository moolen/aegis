# Aegis — Identity-Aware HTTP Egress Proxy

## Design Document & Implementation Plan

**Status:** Draft
**Author:** Moritz
**Date:** 2026-04-24

---

## 1. Problem Statement

Workloads running on Kubernetes clusters and EC2 instances need controlled, auditable egress to the internet. Today, egress is either fully open or coarsely restricted via security groups / network policies that operate at L3/L4 and have no concept of workload identity or FQDN-level policy.

We need an egress proxy that:

- Understands the identity of the calling workload (K8s pod or EC2 instance) by mapping source IPs to identities via label selectors.
- Enforces per-identity policies on allowed destination FQDNs, HTTP methods, and URL paths.
- Polices TLS streams by validating SNI against policy and optionally performing MITM inspection with on-the-fly CA-signed certificates.
- Blocks TLS connections that do not present an SNI when MITM is disabled.
- Resolves DNS on the proxy side and logs all FQDN resolutions for audit.
- Runs active-active behind an NLB for HA.
- Is testable end-to-end in CI using Kind clusters.

---

## 2. Architecture Overview

```
                        ┌──────────────────────────────┐
                        │           NLB (L4)           │
                        │  (TCP passthrough, port 3128) │
                        └──────────┬───────────────────┘
                                   │
                      ┌────────────┴────────────┐
                      │                         │
               ┌──────▼──────┐          ┌───────▼─────┐
               │  Aegis #1   │          │  Aegis #2   │
               │  (Fargate)  │          │  (Fargate)  │
               └──────┬──────┘          └───────┬─────┘
                      │                         │
                      │    ┌─────────────┐      │
                      ├───►│  K8s API    │◄─────┤  (shared watches)
                      │    └─────────────┘      │
                      │    ┌─────────────┐      │
                      ├───►│  EC2 API    │◄─────┤  (shared describe)
                      │    └─────────────┘      │
                      │                         │
                      └──────► Internet ◄───────┘
```

### Component Breakdown

**Proxy Core** — A Go HTTP forward proxy handling both plain HTTP `PROXY` requests and `CONNECT` tunnels. Accepts connections on a single port (default `3128`). Uses `net/http` server with a custom handler that dispatches based on request method.

**Identity Resolver** — Maintains an in-memory IP-to-identity map. Two provider backends:
- **Kubernetes:** Uses `client-go` informers to watch Pods. On pod add/update/delete, updates the mapping of `podIP → {namespace, labels}`.
- **EC2:** Periodically calls `ec2:DescribeInstances` with tag filters defined in config. Maps `privateIpAddress → {tags}`.

**Policy Engine** — Evaluates whether a resolved identity is allowed to reach a given destination. Policies are defined per identity (via label selectors) and specify allowed FQDNs, optional path/method restrictions for HTTP, and MITM mode.

**TLS Inspector** — For CONNECT tunnels, peeks at the ClientHello to extract SNI. If MITM is enabled for the identity, terminates TLS using an on-the-fly generated certificate signed by a configured CA. If MITM is disabled, validates SNI against policy and either passes through or blocks.

**DNS Resolver** — All upstream DNS resolution happens on the proxy. The proxy resolves the requested FQDN, logs the resolution (FQDN → IPs), and connects to the resolved address. Client-provided IPs in CONNECT targets are rejected unless explicitly allowed by policy.

---

## 3. Configuration

A single YAML file drives discovery and policy. Loaded at startup and optionally watched for changes (SIGHUP reload).

```yaml
# aegis.yaml

proxy:
  listen: ":3128"
  metricsListen: ":9090"
  # On-the-fly MITM CA
  ca:
    certFile: /etc/aegis/ca.crt
    keyFile: /etc/aegis/ca.key
  # DNS resolver config
  dns:
    servers:
      - "169.254.169.253:53"   # VPC DNS
    cacheTTL: 30s

discovery:
  # Kubernetes pod discovery
  kubernetes:
    - name: production-cluster
      kubeconfig: /etc/aegis/kubeconfig-prod  # omit for in-cluster
      namespaces: []                           # empty = all namespaces
      resyncPeriod: 60s

  # EC2 instance discovery via tags
  ec2:
    - name: production-ec2
      region: eu-central-1
      tagFilters:
        - key: "aegis-managed"
          values: ["true"]
      pollInterval: 30s

# Policies are evaluated top-to-bottom; first match wins.
# An identity matches a policy if ALL selectors in the policy match
# at least one label on the identity.
policies:
  # Example: payment service in production namespace can reach Stripe
  - name: payment-stripe
    description: "Allow payment pods to reach Stripe API"
    identitySelector:
      matchLabels:
        "kubernetes.io/namespace": "production"
        "app.kubernetes.io/name": "payment-service"
    egress:
      - fqdn: "api.stripe.com"
        ports: [443]
        tls:
          mode: mitm               # mitm | passthrough
        http:                      # HTTP-level rules (only with mitm)
          allowedMethods: ["POST", "GET"]
          allowedPaths: ["/v1/*"]
      - fqdn: "hooks.stripe.com"
        ports: [443]
        tls:
          mode: passthrough

  # Example: EC2-based legacy service
  - name: legacy-reporting
    identitySelector:
      matchLabels:
        "aegis/role": "reporting"
        "aegis/env": "production"
    egress:
      - fqdn: "*.amazonaws.com"
        ports: [443]
        tls:
          mode: passthrough
      - fqdn: "reporting-api.internal.example.com"
        ports: [443, 8443]
        tls:
          mode: mitm

  # Default deny — explicit for clarity
  - name: default-deny
    identitySelector:
      matchLabels: {}             # matches everything
    egress: []                    # no allowed destinations → deny all
```

### Key design decisions in the config model

**Unified label model.** Both K8s pods and EC2 instances are represented as a flat set of labels. For K8s, the namespace is injected as `kubernetes.io/namespace`, and all pod labels are carried through. For EC2, instance tags become labels (with an `aegis/` prefix to avoid collisions). This means policy authors use a single `matchLabels` mechanism for both worlds.

**First-match-wins ordering.** This mirrors how network ACLs and iptables work. The explicit `default-deny` at the bottom ensures nothing slips through. Ordering is visible and predictable.

**FQDN glob matching.** The `fqdn` field supports `*` wildcards. `*.amazonaws.com` matches `s3.eu-central-1.amazonaws.com`. Matching is always against the FQDN the client requested (Host header for HTTP, SNI for TLS), not against resolved IPs.

**HTTP rules are only available with MITM.** When `mode: passthrough`, the proxy can only see SNI — it cannot inspect HTTP method or path. The config schema enforces this: `http` rules under a `passthrough` TLS mode are a validation error.

---

## 4. Internal Architecture

### 4.1 Request Flow — HTTP PROXY

```
Client ──HTTP PROXY──► Aegis
  1. Accept TCP connection, read HTTP request
  2. Extract source IP → resolve identity via Identity Resolver
  3. Parse Host header → FQDN + port
  4. Evaluate policy: identity × FQDN × port × method × path
  5. If denied → 403 Forbidden with JSON body
  6. DNS resolve FQDN on proxy (log resolution)
  7. Establish upstream TCP connection to resolved IP
  8. If upstream is TLS (port 443, or tls.mode configured):
     a. mitm → terminate client TLS, inspect, re-establish to upstream
     b. passthrough → not applicable (this is plain HTTP proxy, not CONNECT)
  9. Forward request, stream response back
```

### 4.2 Request Flow — CONNECT Tunnel

```
Client ──CONNECT host:port──► Aegis
  1. Accept TCP connection, parse CONNECT target (FQDN:port)
  2. Extract source IP → resolve identity
  3. DNS resolve the FQDN on the proxy (log resolution)
  4. Evaluate policy: identity × FQDN × port
  5. If denied → 403
  6. Respond 200 Connection Established
  7. Peek at client TLS ClientHello:
     a. Extract SNI
     b. If no SNI → block (RST), log event
     c. Validate SNI matches the CONNECT target FQDN
  8. Based on policy tls.mode:
     a. passthrough → splice client ↔ upstream (io.Copy both directions)
     b. mitm →
        i.   Generate cert for SNI, signed by CA
        ii.  Complete TLS handshake with client (presenting generated cert)
        iii. Establish TLS connection to upstream (verify real cert)
        iv.  Inspect HTTP traffic, apply HTTP rules (method, path)
        v.   Stream bidirectionally
```

### 4.3 Identity Resolver

```go
type Identity struct {
    Source    string            // "kubernetes" | "ec2"
    Provider string            // discovery name from config
    Name     string            // "namespace/pod-name" or instance-id
    Labels   map[string]string // unified label set
}

type IdentityResolver interface {
    Resolve(ip net.IP) (*Identity, error)
}
```

The resolver is a composite of multiple providers. On `Resolve()`, it checks each provider in registration order and returns the first match. If no provider claims the IP, the request is treated as an unknown identity — which only matches policies with an empty `matchLabels: {}` selector (i.e., the default-deny).

**Kubernetes provider internals:**
- Uses a `SharedInformerFactory` scoped to configured namespaces (or all).
- Maintains a `sync.Map` of `podIP → *Identity`.
- Handles pod IP reuse correctly: on delete, removes the mapping; on update, checks if the IP changed.
- Pod readiness is not gated — the mapping is created on pod creation with a status IP.

**EC2 provider internals:**
- Runs a polling loop at the configured interval.
- Calls `DescribeInstances` with tag filters.
- Atomically swaps the full IP→Identity map on each poll (no incremental diffs; the instance set is bounded and the call is cheap).
- Instance tags are mapped to labels with the `aegis/` prefix stripped if present, or `ec2.tag/` prefix added for raw tags.

### 4.4 Policy Engine

```go
type PolicyEngine struct {
    policies []Policy // ordered, from config
}

type Policy struct {
    Name             string
    IdentitySelector labels.Selector // k8s apimachinery label selector
    EgressRules      []EgressRule
}

type EgressRule struct {
    FQDNPattern string       // glob pattern
    Ports       []int
    TLSMode     string       // "mitm" | "passthrough"
    HTTPRules   *HTTPRules   // nil if passthrough
}

type HTTPRules struct {
    AllowedMethods []string
    AllowedPaths   []string // glob patterns
}

func (e *PolicyEngine) Evaluate(id *Identity, fqdn string, port int) *PolicyDecision
```

`Evaluate` returns a `PolicyDecision` containing whether the request is allowed, the matched policy name, the TLS mode, and the applicable HTTP rules. This decision is computed once per request and threaded through the handler chain.

### 4.5 TLS Inspector & MITM

For CONNECT tunnels, after sending `200 Connection Established`, the proxy peeks at the raw TCP stream to read the TLS ClientHello without consuming it.

```go
// Peek ClientHello from the client connection
hello, err := peekClientHello(clientConn)
if err != nil || hello.ServerName == "" {
    // No SNI → block
    clientConn.Close()
    return
}
```

**MITM path:** Uses `crypto/tls` to complete the handshake with the client, presenting a certificate generated on-the-fly:

```go
func generateCert(ca tls.Certificate, sni string) (*tls.Certificate, error) {
    // Create x509 cert with:
    //   - Subject CN = sni
    //   - SAN DNSNames = [sni]
    //   - Issuer = ca cert
    //   - Validity = 24h (short-lived)
    //   - Serial = random
    // Sign with ca private key
}
```

A cert cache (keyed by SNI, TTL-bounded) avoids regeneration on every request.

**Passthrough path:** After SNI validation, the proxy connects to the upstream and splices the two connections using `io.Copy` in both directions. The original ClientHello bytes (already peeked) are replayed to the upstream.

### 4.6 DNS Resolver

A lightweight wrapper around `net.Resolver` configured to use the specified DNS servers. All resolutions go through this resolver, never the system default.

```go
type DNSResolver struct {
    resolver *net.Resolver
    cache    *ttlcache.Cache[string, []net.IP]
    logger   *slog.Logger
}

func (d *DNSResolver) Resolve(ctx context.Context, fqdn string) ([]net.IP, error) {
    // Check cache
    // If miss, resolve via configured servers
    // Log: {"fqdn": "api.stripe.com", "resolved": ["13.1.2.3", "13.1.2.4"], "ttl": "30s"}
    // Cache with TTL
    // Return IPs
}
```

---

## 5. Observability

### 5.1 Prometheus Metrics

Exposed on a separate port (default `:9090`).

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `aegis_requests_total` | Counter | `identity`, `policy`, `fqdn`, `action` (allow/deny), `protocol` (http/connect) | Total requests processed |
| `aegis_request_duration_seconds` | Histogram | `identity`, `policy`, `fqdn`, `protocol` | Request duration |
| `aegis_bytes_transferred_total` | Counter | `identity`, `fqdn`, `direction` (tx/rx) | Bytes transferred |
| `aegis_tls_mitm_total` | Counter | `identity`, `fqdn` | Connections MITM-intercepted |
| `aegis_tls_sni_missing_total` | Counter | `identity` | Connections blocked for missing SNI |
| `aegis_dns_resolutions_total` | Counter | `fqdn`, `status` (success/failure) | DNS resolutions |
| `aegis_dns_resolution_duration_seconds` | Histogram | `fqdn` | DNS resolution latency |
| `aegis_identity_map_size` | Gauge | `provider` | Current size of IP→identity map |
| `aegis_policy_evaluation_duration_seconds` | Histogram | | Time to evaluate policy |
| `aegis_upstream_tls_errors_total` | Counter | `fqdn`, `error_type` | Upstream TLS handshake failures |

### 5.2 Structured JSON Logs

All log entries use `slog` with JSON output. Key events:

- **request.allowed** / **request.denied** — Every proxied request with identity, FQDN, port, policy matched, action.
- **dns.resolved** — FQDN→IP mappings for audit trail.
- **tls.mitm.intercept** — MITM interception events.
- **tls.sni.missing** — Blocked connections with no SNI.
- **identity.updated** — IP→identity mapping changes.
- **config.reload** — Configuration reload events.

---

## 6. Deployment

### 6.1 HA on AWS Fargate

```
                    ┌──────────────┐
                    │   NLB (L4)   │
                    │  TCP :3128   │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼────┐ ┌────▼─────┐ ┌────▼─────┐
        │ Aegis #1 │ │ Aegis #2 │ │ Aegis #3 │
        │ (Task)   │ │ (Task)   │ │ (Task)   │
        └──────────┘ └──────────┘ └──────────┘
              ECS Service (desired: 3, spread across AZs)
```

- **NLB** in TCP mode on port 3128. Health checks on the metrics port (`/healthz`).
- **ECS Service** with Fargate launch type, desired count ≥ 2, spread across AZs.
- **Config** injected via EFS mount or S3 fetch at startup.
- **CA cert/key** stored in AWS Secrets Manager, fetched at startup.
- **IAM role** for the task: `ec2:DescribeInstances` for EC2 discovery, and STS for cross-account K8s API access if needed.

Client workloads configure `HTTP_PROXY=http://<nlb-dns>:3128` and `HTTPS_PROXY=http://<nlb-dns>:3128`. For MITM, the CA cert must be in the client's trust store.

### 6.2 Networking Prerequisites

- The NLB must be reachable from both the K8s cluster VPC and EC2 VPCs (via peering, transit gateway, or same VPC).
- The proxy tasks need outbound internet access (NAT gateway or public subnet).
- The proxy tasks need access to the K8s API endpoint (EKS public endpoint or private endpoint via VPC).
- Source IPs must be preserved: NLB in TCP mode preserves source IPs via proxy protocol or client IP preservation. **Important:** Validate that Fargate tasks see the original source IP, not the NLB IP. If not, enable proxy protocol v2 on the NLB target group and parse it in Aegis.

---

## 7. Project Structure

```
aegis/
├── cmd/
│   └── aegis/
│       └── main.go                 # Entry point, config loading, wiring
├── internal/
│   ├── config/
│   │   ├── config.go               # YAML config structs + loading
│   │   └── config_test.go
│   ├── proxy/
│   │   ├── server.go               # HTTP server, CONNECT/PROXY dispatch
│   │   ├── handler_http.go         # Plain HTTP forward proxy handler
│   │   ├── handler_connect.go      # CONNECT tunnel handler
│   │   ├── tls_inspector.go        # ClientHello peek, SNI extraction
│   │   ├── tls_mitm.go             # On-the-fly cert generation, MITM
│   │   └── server_test.go
│   ├── identity/
│   │   ├── resolver.go             # Composite IdentityResolver interface
│   │   ├── kubernetes.go           # K8s informer-based provider
│   │   ├── ec2.go                  # EC2 tag-based provider
│   │   └── resolver_test.go
│   ├── policy/
│   │   ├── engine.go               # Policy evaluation logic
│   │   ├── match.go                # FQDN glob matching, label matching
│   │   └── engine_test.go
│   ├── dns/
│   │   ├── resolver.go             # DNS resolution + cache + logging
│   │   └── resolver_test.go
│   └── metrics/
│       ├── metrics.go              # Prometheus metric definitions
│       └── server.go               # /metrics + /healthz endpoint
├── e2e/
│   ├── framework/
│   │   ├── kind.go                 # Kind cluster lifecycle
│   │   ├── proxy.go                # Aegis proxy lifecycle for tests
│   │   ├── workload.go             # Test workload deployment helpers
│   │   └── assert.go               # Custom test assertions
│   ├── http_proxy_test.go          # Plain HTTP proxy e2e
│   ├── connect_proxy_test.go       # CONNECT tunnel e2e
│   ├── tls_passthrough_test.go     # SNI validation, no-SNI blocking
│   ├── tls_mitm_test.go            # MITM interception e2e
│   ├── policy_test.go              # Policy allow/deny e2e
│   ├── identity_k8s_test.go        # K8s identity resolution e2e
│   └── identity_ec2_test.go        # EC2 identity (mocked) e2e
├── deploy/
│   ├── fargate/
│   │   ├── task-definition.json
│   │   └── service.tf              # Terraform for ECS + NLB
│   └── helm/                       # Optional: run Aegis in-cluster
│       └── ...
├── hack/
│   ├── gen-ca.sh                   # Generate test CA
│   └── kind-config.yaml            # Kind cluster config for e2e
├── aegis.example.yaml              # Example config
├── go.mod
├── go.sum
├── Dockerfile
└── Makefile
```

---

## 8. Implementation Plan

### Phase 1 — Foundation (weeks 1–2)

**Goal:** A working forward proxy that handles HTTP PROXY and CONNECT, with no identity or policy — just a dumb pipe.

1. **Config loading** — Define the YAML schema as Go structs with `yaml` tags. Validation on load. Unit tests for valid/invalid configs.
2. **Proxy server** — `net/http.Server` with a handler that checks `req.Method == "CONNECT"` to dispatch. HTTP proxy: dial upstream, forward. CONNECT: respond 200, then `io.Copy` bidirectionally.
3. **DNS resolver** — Custom `net.Resolver` with configurable servers and TTL cache. Log all resolutions.
4. **Metrics server** — Prometheus handler on separate port. `/healthz` endpoint.
5. **Dockerfile + Makefile** — Multi-stage build. `make build`, `make test`, `make docker`.

**Deliverable:** A proxy you can `curl -x http://localhost:3128 https://example.com` through.

### Phase 2 — TLS Inspection (weeks 3–4)

**Goal:** SNI extraction, passthrough with validation, and MITM.

1. **TLS inspector** — `peekClientHello()` using `bufio.Reader` on the hijacked connection. Parse enough of the TLS record to extract SNI. Block if no SNI.
2. **MITM engine** — `generateCert(ca, sni)` using `crypto/x509` and `crypto/tls`. Cert cache with TTL eviction. Complete handshake with client, establish TLS to upstream, bridge.
3. **Passthrough path** — After SNI validation, replay peeked bytes + splice.
4. **HTTP inspection under MITM** — After terminating TLS, read the inner HTTP request. Apply method/path rules before forwarding.

**Deliverable:** CONNECT tunnels with working MITM and passthrough modes, selectable per request (hardcoded for now).

### Phase 3 — Identity & Policy (weeks 5–6)

**Goal:** Identity resolution from K8s and EC2, policy evaluation per request.

1. **Identity resolver interface** — `Resolve(ip) → Identity`. Composite resolver.
2. **Kubernetes provider** — `client-go` informers for Pods. `podIP → Identity` map with proper add/update/delete handling.
3. **EC2 provider** — `aws-sdk-go-v2` DescribeInstances with tag filters. Polling loop with atomic map swap.
4. **Policy engine** — `Evaluate(identity, fqdn, port) → PolicyDecision`. Label selector matching via `k8s.io/apimachinery/pkg/labels`. First-match-wins.
5. **Wire it all together** — In the proxy handlers, resolve identity → evaluate policy → act on decision. 403 responses for denied requests.

**Deliverable:** Full identity-aware proxying with policy enforcement.

### Phase 4 — E2E Tests (weeks 7–8)

**Goal:** Comprehensive e2e test suite using Kind.

See section 9 for detailed test plan.

### Phase 5 — Hardening & Deployment (weeks 9–10)

1. **Config reload** — SIGHUP handler to re-read config, rebuild policy engine, trigger identity resolver re-sync.
2. **Graceful shutdown** — Drain connections on SIGTERM with configurable timeout.
3. **Connection limits** — Per-identity concurrent connection limits to prevent abuse.
4. **Proxy protocol v2** — Parse PP2 header to recover original source IP when behind NLB. Auto-detect whether PP2 is present.
5. **Fargate deployment** — Terraform for ECS service, NLB, task definition, IAM roles, Secrets Manager.
6. **Helm chart** — For running Aegis inside K8s as an alternative deployment model.

---

## 9. E2E Test Plan

### 9.1 Framework

Tests use a shared framework that manages:
- A Kind cluster with a known CNI (kindnet, flat networking).
- An Aegis proxy binary running as a host process (not in the cluster), configured to discover pods from the Kind cluster.
- Test workloads deployed as pods with specific labels.
- An upstream HTTPS server (httpbin-style) running as a pod or host process.
- A test CA for MITM scenarios.

```go
// e2e/framework/kind.go
type TestEnvironment struct {
    KindCluster    *kind.Cluster
    ProxyAddr      string
    ProxyProcess   *exec.Cmd
    Kubeconfig     string
    CA             tls.Certificate
    UpstreamServer *httptest.Server  // TLS-enabled test server
}

func NewTestEnvironment(t *testing.T) *TestEnvironment { ... }
func (e *TestEnvironment) DeployWorkload(t *testing.T, opts WorkloadOpts) *Workload { ... }
func (e *TestEnvironment) CurlFromPod(t *testing.T, pod, target string, opts CurlOpts) CurlResult { ... }
func (e *TestEnvironment) Teardown() { ... }
```

### 9.2 Test Scenarios

**`e2e/http_proxy_test.go` — Plain HTTP Proxy**

| Test | Description |
|------|-------------|
| `TestHTTPProxy_AllowedFQDN` | Pod with allowed identity curls an HTTP URL through the proxy. Expect 200. |
| `TestHTTPProxy_DeniedFQDN` | Pod curls a disallowed FQDN. Expect 403 from proxy. |
| `TestHTTPProxy_MethodRestriction` | Policy allows GET but not POST. POST returns 403. |
| `TestHTTPProxy_PathRestriction` | Policy allows `/api/*` but not `/admin/*`. |
| `TestHTTPProxy_UnknownIdentity` | Request from an IP not in any provider → default-deny. |

**`e2e/connect_proxy_test.go` — CONNECT Tunnel**

| Test | Description |
|------|-------------|
| `TestCONNECT_PassthroughAllowed` | CONNECT to allowed FQDN:443 with valid SNI. Connection succeeds. |
| `TestCONNECT_PassthroughDenied` | CONNECT to disallowed FQDN. 403. |
| `TestCONNECT_MITMAllowed` | CONNECT with MITM policy. Client uses proxy CA in trust store. HTTP request inspected and allowed. |
| `TestCONNECT_MITMDenied` | CONNECT with MITM. HTTP request violates path/method policy. Connection reset after TLS. |

**`e2e/tls_passthrough_test.go` — TLS Validation**

| Test | Description |
|------|-------------|
| `TestTLS_NoSNI_Blocked` | Client sends TLS ClientHello without SNI. Connection blocked. |
| `TestTLS_SNIMismatch_Blocked` | CONNECT target is `a.com` but SNI is `b.com`. Blocked. |
| `TestTLS_ValidSNI_Passthrough` | SNI matches CONNECT target and policy allows it. Traffic flows. |

**`e2e/tls_mitm_test.go` — MITM Inspection**

| Test | Description |
|------|-------------|
| `TestMITM_CertGenerated` | Client receives a cert signed by the test CA with correct SNI in SAN. |
| `TestMITM_UpstreamCertValidated` | Proxy validates the real upstream cert. If upstream has invalid cert, proxy rejects. |
| `TestMITM_HTTPInspection` | Under MITM, proxy can see and enforce HTTP method + path. |
| `TestMITM_ClientWithoutCA_Fails` | Client without proxy CA in trust store gets TLS error (proves MITM is happening). |

**`e2e/policy_test.go` — Policy Evaluation**

| Test | Description |
|------|-------------|
| `TestPolicy_FirstMatchWins` | Two policies match; the first one's rules apply. |
| `TestPolicy_LabelSelectorMatching` | Pod with labels `{app: web, env: prod}` matches policy requiring both. |
| `TestPolicy_FQDNGlob` | Policy with `*.example.com` matches `api.example.com`. |
| `TestPolicy_DefaultDeny` | Pod with no matching policy gets denied. |

**`e2e/identity_k8s_test.go` — Kubernetes Identity**

| Test | Description |
|------|-------------|
| `TestK8sIdentity_PodCreated` | Deploy pod → verify it's resolved by IP within resync window. |
| `TestK8sIdentity_PodDeleted` | Delete pod → verify IP is no longer resolved (prevents stale mappings). |
| `TestK8sIdentity_PodIPReuse` | Delete pod A, create pod B with same IP → verify identity is B. |
| `TestK8sIdentity_NamespaceLabel` | Verify `kubernetes.io/namespace` label is injected into identity. |

**`e2e/identity_ec2_test.go` — EC2 Identity (Mocked)**

| Test | Description |
|------|-------------|
| `TestEC2Identity_TagDiscovery` | Mock EC2 API returns instances. Verify IPs resolve with correct labels. |
| `TestEC2Identity_InstanceTerminated` | Instance removed from API response. Verify IP no longer resolves. |
| `TestEC2Identity_PollRefresh` | Change mock response between polls. Verify new state picked up. |

### 9.3 E2E Test Infrastructure

```yaml
# hack/kind-config.yaml
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  podSubnet: "10.244.0.0/16"
  serviceSubnet: "10.96.0.0/12"
nodes:
  - role: control-plane
  - role: worker
  - role: worker
```

The test framework:

1. Creates the Kind cluster with the above config.
2. Generates a test CA (cert + key).
3. Writes an `aegis.yaml` test config pointing at the Kind cluster's kubeconfig and using a mock EC2 endpoint.
4. Starts Aegis as a subprocess with the test config.
5. Deploys test workloads (curl-capable pods with specific labels) into the Kind cluster.
6. Starts an upstream HTTPS test server (using the test CA or a separate server cert).
7. Executes tests by `kubectl exec` into pods and curling through the proxy.
8. Tears everything down.

### 9.4 CI Integration

```makefile
.PHONY: e2e
e2e:
	go test -v -timeout 15m -tags e2e ./e2e/...

.PHONY: ci
ci: lint test e2e
```

The e2e target requires Docker (for Kind) and runs in CI with a timeout. Tests are tagged with `//go:build e2e` to separate them from unit tests.

---

## 10. Security Considerations

**CA key protection.** The MITM CA private key is the most sensitive component. In production, it should be stored in a KMS-backed secret (AWS Secrets Manager with KMS encryption) and fetched at startup. The key should never be written to disk on the Fargate task; load it into memory only.

**Identity spoofing.** An attacker who can send traffic from a legitimate pod's IP could inherit its policy. Mitigation: this is inherent to IP-based identity and acceptable in a flat-network model where IP spoofing is prevented by the CNI / VPC. Document this trust assumption.

**DNS rebinding.** A malicious DNS response could map an allowed FQDN to a private IP, enabling SSRF. Mitigation: the proxy should refuse to connect to RFC 1918 / link-local addresses unless the FQDN is explicitly in an internal-destinations allowlist.

**Upstream cert validation.** When the proxy establishes TLS to the upstream (both in MITM and passthrough modes for its own connection), it must validate the upstream certificate against the system trust store. Do not skip verification.

**Denial of service.** Per-identity connection limits and request rate limits prevent a single workload from exhausting proxy resources.

---

## 11. Future Considerations (Out of Scope)

- **IPv6 support** — flat networking simplifies this, but deferred for now.
- **mTLS to upstream** — some upstreams may require client certs. Could be configured per egress rule.
- **WebSocket support** — CONNECT tunnels already handle this implicitly, but explicit protocol-aware inspection is deferred.
- **Dynamic policy via CRDs** — A Kubernetes operator that watches `EgressPolicy` CRDs and generates the YAML config.
- **WASM plugin for custom inspection** — For complex HTTP inspection logic beyond method/path matching.
