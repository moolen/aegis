package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"github.com/moolen/aegis/internal/metrics"
)

const (
	defaultMITMCertificateTTL  = 24 * time.Hour
	defaultMITMCertificateSkew = 1 * time.Hour
)

type MITMEngine struct {
	issuer     mitmCARecord
	companions []mitmCARecord
	logger     *slog.Logger
	metrics    *metrics.Metrics
	now        func() time.Time
	mu         sync.Mutex
	cache      map[string]cachedMITMCertificate
	validFor   time.Duration
}

type mitmCARole string

const (
	mitmCAIssuerRole    mitmCARole = "issuer"
	mitmCACompanionRole mitmCARole = "companion"
)

type mitmCARecord struct {
	role        mitmCARole
	fingerprint string
	leaf        *x509.Certificate
	signer      *tls.Certificate
}

type MITMCAStatus struct {
	IssuerFingerprint     string
	CompanionFingerprints []string
	AllFingerprints       []string
}

type cachedMITMCertificate struct {
	certificate *tls.Certificate
	expiresAt   time.Time
}

func NewMITMEngineFromFiles(certFile string, keyFile string, logger *slog.Logger) (*MITMEngine, error) {
	ca, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load x509 key pair: %w", err)
	}

	return NewMITMEngine(ca, logger)
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
		issuer: mitmCARecord{
			role:        mitmCAIssuerRole,
			fingerprint: fingerprint,
			leaf:        caLeaf,
			signer:      &ca,
		},
		logger:   logger,
		now:      time.Now,
		cache:    make(map[string]cachedMITMCertificate),
		validFor: defaultMITMCertificateTTL,
	}, nil
}

func (e *MITMEngine) CertificateForSNI(serverName string) (*tls.Certificate, string, error) {
	if serverName == "" {
		return nil, "", fmt.Errorf("server name is required")
	}

	now := e.now()

	e.mu.Lock()
	defer e.mu.Unlock()

	if cached, ok := e.cache[serverName]; ok {
		if now.Before(cached.expiresAt) {
			return cached.certificate, "cache_hit", nil
		}
		delete(e.cache, serverName)
		e.recordCacheEntriesLocked()
		e.recordCacheEviction("expired", 1)
	}

	certificate, err := e.generateCertificate(serverName, now)
	if err != nil {
		return nil, "", err
	}

	e.cache[serverName] = cachedMITMCertificate{
		certificate: certificate,
		expiresAt:   certificate.Leaf.NotAfter,
	}
	e.recordCacheEntriesLocked()
	e.logger.Debug("issued mitm certificate", "server_name", serverName, "not_after", certificate.Leaf.NotAfter)

	return certificate, "issued", nil
}

func (e *MITMEngine) Fingerprint() string {
	e.mu.Lock()
	defer e.mu.Unlock()

	return e.issuer.fingerprint
}

func (e *MITMEngine) Fingerprints() []string {
	return e.CAStatus().AllFingerprints
}

func (e *MITMEngine) CAStatus() MITMCAStatus {
	e.mu.Lock()
	defer e.mu.Unlock()

	status := MITMCAStatus{
		IssuerFingerprint:     e.issuer.fingerprint,
		CompanionFingerprints: make([]string, 0, len(e.companions)),
		AllFingerprints:       make([]string, 0, len(e.companions)+1),
	}
	status.AllFingerprints = append(status.AllFingerprints, e.issuer.fingerprint)
	for _, companion := range e.companions {
		status.CompanionFingerprints = append(status.CompanionFingerprints, companion.fingerprint)
		status.AllFingerprints = append(status.AllFingerprints, companion.fingerprint)
	}

	return status
}

func (e *MITMEngine) AddAdditionalCA(ca tls.Certificate) error {
	_, fingerprint, err := parseMITMCA(ca)
	if err != nil {
		return err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	e.companions = append(e.companions, mitmCARecord{
		role:        mitmCACompanionRole,
		fingerprint: fingerprint,
	})
	return nil
}

func (e *MITMEngine) AddAdditionalCAFromFiles(certFile string, keyFile string) error {
	ca, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("load x509 key pair: %w", err)
	}
	return e.AddAdditionalCA(ca)
}

func (e *MITMEngine) CacheEntries() int {
	e.mu.Lock()
	defer e.mu.Unlock()

	return len(e.cache)
}

func (e *MITMEngine) AttachMetrics(m *metrics.Metrics) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.metrics = m
	e.recordCacheEntriesLocked()
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
		AuthorityKeyId:        e.issuer.leaf.SubjectKeyId,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, e.issuer.leaf, leafKey.Public(), e.issuer.signer.PrivateKey)
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

func (e *MITMEngine) recordCacheEntriesLocked() {
	if e.metrics == nil {
		return
	}

	e.metrics.MITMCertificateCacheEntries.Set(float64(len(e.cache)))
}

func (e *MITMEngine) recordCacheEviction(reason string, count int) {
	if e.metrics == nil || count <= 0 {
		return
	}

	e.metrics.MITMCertificateCacheEvictions.WithLabelValues(reason).Add(float64(count))
}

func parseMITMCA(ca tls.Certificate) (*x509.Certificate, string, error) {
	if len(ca.Certificate) == 0 {
		return nil, "", fmt.Errorf("mitm ca certificate chain is empty")
	}

	caLeaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, "", fmt.Errorf("parse mitm ca certificate: %w", err)
	}
	if !caLeaf.IsCA {
		return nil, "", fmt.Errorf("mitm ca certificate is not a certificate authority")
	}
	if ca.PrivateKey == nil {
		return nil, "", fmt.Errorf("mitm ca private key is required")
	}
	fingerprint := sha256.Sum256(caLeaf.Raw)
	return caLeaf, hex.EncodeToString(fingerprint[:]), nil
}
