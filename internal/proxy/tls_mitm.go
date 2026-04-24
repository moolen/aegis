package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"
)

const (
	defaultMITMCertificateTTL  = 24 * time.Hour
	defaultMITMCertificateSkew = 1 * time.Hour
)

type MITMEngine struct {
	ca       tls.Certificate
	caLeaf   *x509.Certificate
	logger   *slog.Logger
	now      func() time.Time
	mu       sync.Mutex
	cache    map[string]cachedMITMCertificate
	validFor time.Duration
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
	if len(ca.Certificate) == 0 {
		return nil, fmt.Errorf("mitm ca certificate chain is empty")
	}

	caLeaf, err := x509.ParseCertificate(ca.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse mitm ca certificate: %w", err)
	}
	if !caLeaf.IsCA {
		return nil, fmt.Errorf("mitm ca certificate is not a certificate authority")
	}
	if ca.PrivateKey == nil {
		return nil, fmt.Errorf("mitm ca private key is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	return &MITMEngine{
		ca:       ca,
		caLeaf:   caLeaf,
		logger:   logger,
		now:      time.Now,
		cache:    make(map[string]cachedMITMCertificate),
		validFor: defaultMITMCertificateTTL,
	}, nil
}

func (e *MITMEngine) CertificateForSNI(serverName string) (*tls.Certificate, error) {
	if serverName == "" {
		return nil, fmt.Errorf("server name is required")
	}

	now := e.now()

	e.mu.Lock()
	defer e.mu.Unlock()

	if cached, ok := e.cache[serverName]; ok && now.Before(cached.expiresAt) {
		return cached.certificate, nil
	}

	certificate, err := e.generateCertificate(serverName, now)
	if err != nil {
		return nil, err
	}

	e.cache[serverName] = cachedMITMCertificate{
		certificate: certificate,
		expiresAt:   certificate.Leaf.NotAfter,
	}
	e.logger.Debug("issued mitm certificate", "server_name", serverName, "not_after", certificate.Leaf.NotAfter)

	return certificate, nil
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
		AuthorityKeyId:        e.caLeaf.SubjectKeyId,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, e.caLeaf, leafKey.Public(), e.ca.PrivateKey)
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
