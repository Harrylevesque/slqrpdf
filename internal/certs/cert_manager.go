package certs

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CertManager manages the certificate files in a directory.
type CertManager struct {
	certDir string
}

// NewCertManager creates a new CertManager for the given directory.
func NewCertManager(certDir string) *CertManager {
	return &CertManager{certDir: certDir}
}

// LoadCertificates loads all certificates from the cert directory.
func (cm *CertManager) LoadCertificates() ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	err := filepath.Walk(cm.certDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if strings.HasSuffix(info.Name(), ".crt") || strings.HasSuffix(info.Name(), ".pem") {
			cert, err := cm.loadCertificate(path)
			if err != nil {
				return err
			}
			certs = append(certs, cert)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return certs, nil
}

// loadCertificate loads a certificate from a file.
func (cm *CertManager) loadCertificate(path string) (*x509.Certificate, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("failed to parse certificate PEM")
	}

	return x509.ParseCertificate(block.Bytes)
}

// IsExpired checks if a certificate is expired.
func (cm *CertManager) IsExpired(cert *x509.Certificate) bool {
	return cert.NotAfter.Before(time.Now())
}

// RenewCertificate renews a certificate by replacing it with a new one.
func (cm *CertManager) RenewCertificate(cert *x509.Certificate) error {
	// Implementation for renewing the certificate
	return nil
}

// RevokeCertificate revokes a certificate.
func (cm *CertManager) RevokeCertificate(cert *x509.Certificate) error {
	// Implementation for revoking the certificate
	return nil
}
