# Aegis Dual-CA Rotation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `proxy.ca.additional[]` a real MITM companion-CA runtime feature while keeping deterministic issuance on the primary CA and exposing the active CA set clearly through reload lifecycle signals and the admin surface.

**Architecture:** Keep `proxy.ca` as the single issuing CA inside `internal/proxy/tls_mitm.go`, but replace the current fingerprint-only companion handling with parsed CA records that preserve role and stable fingerprint ordering. Extend the admin API with a dedicated runtime-status view so operators can inspect the current MITM issuer and companion set, then tighten reload classification in `cmd/aegis/reload.go` so issuer rotation and companion-only changes are reported separately.

**Tech Stack:** Go 1.26, `crypto/tls`, `crypto/x509`, `slog`, Prometheus client_golang, stdlib `net/http`.

---

### Task 1: Replace fingerprint-only companion handling with real CA-set runtime state

**Files:**
- Modify: `internal/proxy/tls_mitm.go`
- Modify: `internal/proxy/tls_mitm_test.go`

- [ ] **Step 1: Write the failing MITM-engine tests**

```go
func TestMITMEngineAlwaysIssuesWithPrimaryCA(t *testing.T) {
	primary := newMITMTestCA(t)
	companion := newMITMTestCA(t)

	engine, err := NewMITMEngine(primary.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}
	if err := engine.AddAdditionalCA(companion.certificate); err != nil {
		t.Fatalf("AddAdditionalCA() error = %v", err)
	}

	cert, result, err := engine.CertificateForSNI("example.internal")
	if err != nil {
		t.Fatalf("CertificateForSNI() error = %v", err)
	}
	if result != "issued" {
		t.Fatalf("result = %q, want %q", result, "issued")
	}
	if cert.Leaf == nil {
		t.Fatal("expected leaf certificate to be parsed")
	}
	primaryLeaf, _, err := parseMITMCA(primary.certificate)
	if err != nil {
		t.Fatalf("parseMITMCA(primary) error = %v", err)
	}
	if got, want := string(cert.Leaf.AuthorityKeyId), string(primaryLeaf.SubjectKeyId); got != want {
		t.Fatalf("AuthorityKeyId = %x, want %x", cert.Leaf.AuthorityKeyId, primaryLeaf.SubjectKeyId)
	}
}

func TestMITMEngineReportsIssuerAndCompanionFingerprints(t *testing.T) {
	primary := newMITMTestCA(t)
	companionA := newMITMTestCA(t)
	companionB := newMITMTestCA(t)

	engine, err := NewMITMEngine(primary.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}
	if err := engine.AddAdditionalCA(companionA.certificate); err != nil {
		t.Fatalf("AddAdditionalCA(companionA) error = %v", err)
	}
	if err := engine.AddAdditionalCA(companionB.certificate); err != nil {
		t.Fatalf("AddAdditionalCA(companionB) error = %v", err)
	}

	status := engine.CAStatus()
	if status.IssuerFingerprint == "" {
		t.Fatal("expected issuer fingerprint")
	}
	if len(status.CompanionFingerprints) != 2 {
		t.Fatalf("CompanionFingerprints = %#v, want two companions", status.CompanionFingerprints)
	}
	if len(status.AllFingerprints) != 3 {
		t.Fatalf("AllFingerprints = %#v, want issuer plus companions", status.AllFingerprints)
	}
	if status.AllFingerprints[0] != status.IssuerFingerprint {
		t.Fatalf("AllFingerprints[0] = %q, want issuer %q", status.AllFingerprints[0], status.IssuerFingerprint)
	}
}

func TestMITMEngineRejectsInvalidAdditionalCA(t *testing.T) {
	primary := newMITMTestCA(t)
	leafOnly := primary.issueServerCertificate(t, "not-a-ca.internal")

	engine, err := NewMITMEngine(primary.certificate, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewMITMEngine() error = %v", err)
	}
	if err := engine.AddAdditionalCA(leafOnly); err == nil {
		t.Fatal("expected AddAdditionalCA() to reject a non-CA certificate")
	}
}
```

- [ ] **Step 2: Run the focused MITM tests to verify they fail**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./internal/proxy -run 'TestMITMEngine(AlwaysIssuesWithPrimaryCA|ReportsIssuerAndCompanionFingerprints|RejectsInvalidAdditionalCA)' -v`
Expected: FAIL because `CAStatus()` does not exist and companion CA state is still fingerprint-only.

- [ ] **Step 3: Implement the minimal CA-set runtime model in `internal/proxy/tls_mitm.go`**

```go
type MITMCARecord struct {
	Role        string
	Fingerprint string
	Leaf        *x509.Certificate
}

type MITMCAStatus struct {
	IssuerFingerprint     string
	CompanionFingerprints []string
	AllFingerprints       []string
}

type MITMEngine struct {
	issuer     MITMCARecord
	issuerCert tls.Certificate
	logger     *slog.Logger
	metrics    *metrics.Metrics
	now        func() time.Time
	mu         sync.Mutex
	cache      map[string]cachedMITMCertificate
	validFor   time.Duration

	companions []MITMCARecord
}

func NewMITMEngine(ca tls.Certificate, logger *slog.Logger) (*MITMEngine, error) {
	caLeaf, fingerprint, err := parseMITMCA(ca)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &MITMEngine{
		issuer: MITMCARecord{
			Role:        "issuer",
			Fingerprint: fingerprint,
			Leaf:        caLeaf,
		},
		issuerCert: ca,
		logger:     logger,
		now:        time.Now,
		cache:      make(map[string]cachedMITMCertificate),
		validFor:   defaultMITMCertificateTTL,
	}, nil
}

func (e *MITMEngine) AddAdditionalCA(ca tls.Certificate) error {
	leaf, fingerprint, err := parseMITMCA(ca)
	if err != nil {
		return err
	}
	e.companions = append(e.companions, MITMCARecord{
		Role:        "companion",
		Fingerprint: fingerprint,
		Leaf:        leaf,
	})
	return nil
}

func (e *MITMEngine) CAStatus() MITMCAStatus {
	companions := make([]string, 0, len(e.companions))
	all := []string{e.issuer.Fingerprint}
	for _, companion := range e.companions {
		companions = append(companions, companion.Fingerprint)
		all = append(all, companion.Fingerprint)
	}
	return MITMCAStatus{
		IssuerFingerprint:     e.issuer.Fingerprint,
		CompanionFingerprints: companions,
		AllFingerprints:       all,
	}
}

func (e *MITMEngine) Fingerprint() string {
	return e.issuer.Fingerprint
}

func (e *MITMEngine) Fingerprints() []string {
	return append([]string(nil), e.CAStatus().AllFingerprints...)
}

func (e *MITMEngine) generateCertificate(serverName string, now time.Time) (*tls.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate mitm certificate serial: %w", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate mitm certificate key: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: serverName,
		},
		DNSNames:              []string{serverName},
		NotBefore:             now.Add(-defaultMITMCertificateSkew),
		NotAfter:              now.Add(e.validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		AuthorityKeyId: e.issuer.Leaf.SubjectKeyId,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, e.issuer.Leaf, leafKey.Public(), e.issuerCert.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("sign mitm certificate for %q: %w", serverName, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse mitm leaf certificate for %q: %w", serverName, err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}, nil
}
```

Keep the rest of the cache behavior unchanged in this task.

- [ ] **Step 4: Run the focused MITM tests to verify they pass**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./internal/proxy -run 'TestMITMEngine(AlwaysIssuesWithPrimaryCA|ReportsIssuerAndCompanionFingerprints|RejectsInvalidAdditionalCA)' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/tls_mitm.go internal/proxy/tls_mitm_test.go
git commit -m "feat: model mitm issuer and companion ca state"
```

### Task 2: Expose MITM CA-set status through the admin runtime surface

**Files:**
- Modify: `internal/metrics/server.go`
- Modify: `internal/metrics/server_test.go`
- Modify: `cmd/aegis/reload.go`
- Modify: `cmd/aegis/main_test.go`

- [ ] **Step 1: Write the failing admin-surface tests**

```go
func TestServerReturnsAdminRuntimeStatus(t *testing.T) {
	reg := prometheus.NewRegistry()
	admin := &enforcementAdminStub{
		token: "secret",
		runtime: RuntimeStatus{
			MITM: &MITMStatus{
				Enabled:               true,
				IssuerFingerprint:     "issuer-fp",
				CompanionFingerprints: []string{"old-fp"},
				AllFingerprints:       []string{"issuer-fp", "old-fp"},
			},
		},
	}

	srv := NewServer(":0", reg, nil, admin)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/admin/runtime", nil)
	if err != nil {
		t.Fatalf("NewRequest() error = %v", err)
	}
	req.Header.Set("Authorization", "Bearer secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do() error = %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var body RuntimeStatus
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body.MITM == nil || body.MITM.IssuerFingerprint != "issuer-fp" {
		t.Fatalf("runtime MITM status = %#v, want issuer fingerprint", body.MITM)
	}
}

func TestRuntimeManagerRuntimeStatusIncludesMITMCASet(t *testing.T) {
	certA, keyA := writeTestCAFiles(t, "Primary CA")
	certB, keyB := writeTestCAFiles(t, "Companion CA")

	configPath := writeRuntimeConfig(t, runtimeConfigYAMLWithAdditionalCAs(
		"policy-a",
		":3128",
		":9090",
		certA,
		keyA,
		[][2]string{{certB, keyB}},
	))

	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(prometheus.NewRegistry()), configPath, &reloadableProxyHandler{}, nil)
	defer manager.Close()

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	status := manager.RuntimeStatus()
	if status.MITM == nil || !status.MITM.Enabled {
		t.Fatalf("RuntimeStatus().MITM = %#v, want enabled MITM status", status.MITM)
	}
	if len(status.MITM.CompanionFingerprints) != 1 {
		t.Fatalf("CompanionFingerprints = %#v, want one companion", status.MITM.CompanionFingerprints)
	}
}
```

- [ ] **Step 2: Run the admin/runtime tests to verify they fail**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./internal/metrics ./cmd/aegis -run 'Test(ServerReturnsAdminRuntimeStatus|RuntimeManagerRuntimeStatusIncludesMITMCASet)' -v`
Expected: FAIL because `/admin/runtime`, `RuntimeStatus`, and `runtimeManager.RuntimeStatus()` do not exist yet.

- [ ] **Step 3: Implement the admin runtime-status endpoint and runtime-manager projection**

```go
type RuntimeStatus struct {
	MITM *MITMStatus `json:"mitm,omitempty"`
}

type MITMStatus struct {
	Enabled               bool     `json:"enabled"`
	IssuerFingerprint     string   `json:"issuerFingerprint,omitempty"`
	CompanionFingerprints []string `json:"companionFingerprints,omitempty"`
	AllFingerprints       []string `json:"allFingerprints,omitempty"`
}

type AdminAPI interface {
	AdminToken() string
	EnforcementStatus() EnforcementStatus
	SetEnforcementMode(mode string) (EnforcementStatus, error)
	DumpIdentities() []IdentityDumpRecord
	Simulate(SimulationRequest) (SimulationResponse, error)
	RuntimeStatus() RuntimeStatus
}
```

Add a protected `GET /admin/runtime` handler in `internal/metrics/server.go`:

```go
mux.HandleFunc("/admin/runtime", func(w http.ResponseWriter, r *http.Request) {
	if !authorizeAdminEndpoint(w, r, adminAPI) {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, adminAPI.RuntimeStatus())
})
```

Project the MITM engine state in `cmd/aegis/reload.go`:

```go
func (m *runtimeManager) RuntimeStatus() appmetrics.RuntimeStatus {
	m.mu.RLock()
	mitm := m.current.mitm
	m.mu.RUnlock()

	if mitm == nil {
		return appmetrics.RuntimeStatus{}
	}
	status := mitm.CAStatus()
	return appmetrics.RuntimeStatus{
		MITM: &appmetrics.MITMStatus{
			Enabled:               true,
			IssuerFingerprint:     status.IssuerFingerprint,
			CompanionFingerprints: append([]string(nil), status.CompanionFingerprints...),
			AllFingerprints:       append([]string(nil), status.AllFingerprints...),
		},
	}
}
```

Extend the `enforcementAdminStub` in `internal/metrics/server_test.go` with a `runtime RuntimeStatus` field and a `RuntimeStatus() RuntimeStatus` method.

- [ ] **Step 4: Run the admin/runtime tests to verify they pass**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./internal/metrics ./cmd/aegis -run 'Test(ServerReturnsAdminRuntimeStatus|RuntimeManagerRuntimeStatusIncludesMITMCASet)' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/metrics/server.go internal/metrics/server_test.go cmd/aegis/reload.go cmd/aegis/main_test.go
git commit -m "feat: expose mitm ca runtime status"
```

### Task 3: Distinguish issuer rotation from companion-only reload changes

**Files:**
- Modify: `cmd/aegis/reload.go`
- Modify: `cmd/aegis/main_test.go`

- [ ] **Step 1: Write the failing reload-classification tests**

```go
func TestRuntimeManagerReloadTracksCompanionOnlyMITMCAChanges(t *testing.T) {
	issuerCert, issuerKey := writeTestCAFiles(t, "Issuer CA")
	companionACert, companionAKey := writeTestCAFiles(t, "Old Companion A")
	companionBCert, companionBKey := writeTestCAFiles(t, "Old Companion B")

	configPath := writeRuntimeConfig(t, runtimeConfigYAMLWithAdditionalCAs(
		"policy-a",
		":3128",
		":9090",
		issuerCert,
		issuerKey,
		[][2]string{{companionACert, companionAKey}},
	))

	reg := prometheus.NewRegistry()
	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(reg), configPath, &reloadableProxyHandler{}, nil)
	defer manager.Close()

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	writeRuntimeConfigAt(t, configPath, runtimeConfigYAMLWithAdditionalCAs(
		"policy-b",
		":3128",
		":9090",
		issuerCert,
		issuerKey,
		[][2]string{{companionBCert, companionBKey}},
	))
	if err := manager.ReloadFromFile(); err != nil {
		t.Fatalf("ReloadFromFile() error = %v", err)
	}

	if got := counterValue(t, reg, "aegis_mitm_ca_cycles_total", map[string]string{"result": "companions_changed"}); got != 1 {
		t.Fatalf("companions_changed metric = %v, want 1", got)
	}
	if got := counterValue(t, reg, "aegis_mitm_ca_cycles_total", map[string]string{"result": "rotated"}); got != 0 {
		t.Fatalf("rotated metric = %v, want 0", got)
	}
}

func TestRuntimeManagerReloadRejectsInvalidCompanionCA(t *testing.T) {
	issuerCert, issuerKey := writeTestCAFiles(t, "Issuer CA")
	configPath := writeRuntimeConfig(t, runtimeConfigYAMLWithCA("policy-a", ":3128", ":9090", issuerCert, issuerKey))

	manager := newRuntimeManager(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)), appmetrics.New(prometheus.NewRegistry()), configPath, &reloadableProxyHandler{}, nil)
	defer manager.Close()

	cfg, err := loadRuntimeConfig(configPath)
	if err != nil {
		t.Fatalf("loadRuntimeConfig() error = %v", err)
	}
	if err := manager.LoadInitial(cfg); err != nil {
		t.Fatalf("LoadInitial() error = %v", err)
	}

	badKeyPath := filepath.Join(t.TempDir(), "broken-companion.key")
	if err := os.WriteFile(badKeyPath, []byte("broken-key"), 0o644); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	writeRuntimeConfigAt(t, configPath, runtimeConfigYAMLWithAdditionalCAs(
		"policy-b",
		":3128",
		":9090",
		issuerCert,
		issuerKey,
		[][2]string{{issuerCert, badKeyPath}},
	))

	if err := manager.ReloadFromFile(); err == nil {
		t.Fatal("expected ReloadFromFile() to fail for invalid companion CA material")
	}
	if status := manager.RuntimeStatus(); status.MITM == nil || len(status.MITM.CompanionFingerprints) != 0 {
		t.Fatalf("RuntimeStatus().MITM = %#v, want unchanged previous generation", status.MITM)
	}
}
```

- [ ] **Step 2: Run the reload tests to verify they fail**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./cmd/aegis -run 'TestRuntimeManagerReload(TracksCompanionOnlyMITMCAChanges|RejectsInvalidCompanionCA)' -v`
Expected: FAIL because reload classification only knows `unchanged` vs `rotated` and the helpers for additional-CA config generation do not exist yet.

- [ ] **Step 3: Implement lifecycle classification and test helpers**

In `cmd/aegis/reload.go`, replace `sameMITMCASet()` with issuer-aware classification:

```go
func classifyMITMCACycle(previous *proxy.MITMEngine, next *proxy.MITMEngine, isReload bool) string {
	switch {
	case previous == nil && next == nil:
		return ""
	case previous == nil && next != nil:
		if isReload {
			return "enabled"
		}
		return "initial"
	case previous != nil && next == nil:
		return "disabled"
	}

	prevStatus := previous.CAStatus()
	nextStatus := next.CAStatus()
	switch {
	case prevStatus.IssuerFingerprint != nextStatus.IssuerFingerprint:
		return "rotated"
	case !sameStringSlice(prevStatus.CompanionFingerprints, nextStatus.CompanionFingerprints):
		return "companions_changed"
	default:
		return "unchanged"
	}
}
```

Update `recordMITMLifecycle()` to:

- log `previous_issuer_fingerprint` and `issuer_fingerprint`,
- log companion fingerprints separately,
- increment `aegis_mitm_ca_cycles_total{result="companions_changed"}`,
- keep cache-eviction reason as `reload` for companion-only changes and `rotation` only for issuer changes.

Add test-only config writers in `cmd/aegis/main_test.go`:

```go
func runtimeConfigYAMLWithAdditionalCAs(policyName string, proxyListen string, metricsListen string, certFile string, keyFile string, additional [][2]string) string {
	var b strings.Builder
	b.WriteString(runtimeConfigYAMLWithCA(policyName, proxyListen, metricsListen, certFile, keyFile))
	if len(additional) == 0 {
		return b.String()
	}
	base := strings.TrimSuffix(b.String(), "  keyFile: "+keyFile+"\n")
	var out strings.Builder
	out.WriteString(base)
	out.WriteString("  keyFile: " + keyFile + "\n")
	out.WriteString("  additional:\n")
	for _, pair := range additional {
		out.WriteString("    - certFile: " + pair[0] + "\n")
		out.WriteString("      keyFile: " + pair[1] + "\n")
	}
	return out.String()
}
```

- [ ] **Step 4: Run the reload tests to verify they pass**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./cmd/aegis -run 'TestRuntimeManagerReload(TracksCompanionOnlyMITMCAChanges|RejectsInvalidCompanionCA)' -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add cmd/aegis/reload.go cmd/aegis/main_test.go
git commit -m "feat: classify mitm companion ca reloads"
```

### Task 4: Update repo docs and run full verification

**Files:**
- Modify: `README.md`
- Modify: `aegis.example.yaml`
- Modify: `deploy/helm/values.yaml`

- [ ] **Step 1: Write the doc updates**

Update the docs to make the rollout contract explicit:

```yaml
proxy:
  ca:
    certFile: /etc/aegis/ca/new-ca.crt
    keyFile: /etc/aegis/ca/new-ca.key
    additional:
      - certFile: /etc/aegis/ca/old-ca.crt
        keyFile: /etc/aegis/ca/old-ca.key
```

Add this wording to `README.md`:

```md
`proxy.ca` is always the active issuing CA for forged MITM leaf certificates.
`proxy.ca.additional[]` keeps companion CAs loaded during trust-rotation windows
so the runtime can report the full CA set and distinguish issuer rotation from
companion-only reload changes.
```

Also mention `GET /admin/runtime` in the admin examples.

- [ ] **Step 2: Run targeted and full verification**

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./internal/proxy ./internal/metrics ./cmd/aegis -v`
Expected: PASS

Run: `mkdir -p .cache/tmp .cache/go-build .cache/mod && GOCACHE=$(pwd)/.cache/go-build GOTMPDIR=$(pwd)/.cache/tmp GOMODCACHE=$(pwd)/.cache/mod go test ./...`
Expected: PASS

Run: `/usr/local/go/bin/go build ./...`
Expected: PASS

Run: `helm template aegis ./deploy/helm`
Expected: PASS with the updated comments/examples rendered successfully

Run: `docker build -t aegis:dev .`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add README.md aegis.example.yaml deploy/helm/values.yaml
git commit -m "docs: clarify dual ca rotation semantics"
```
