package main

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"time"
)

// neuerClient: mit TRAILR_ZERTIFIKAT und TRAILR_ZERTIFIKAT_SCHLUESSEL weist
// sich der Agent zusätzlich per mTLS aus, TRAILR_CA ersetzt die Wurzeln des
// Systems. Der Benutzer trailr muss die Dateien lesen dürfen.
func neuerClient(zertifikat, schluessel, ca string) (*http.Client, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	if zertifikat == "" && schluessel == "" && ca == "" {
		return c, nil
	}
	k := &tls.Config{MinVersion: tls.VersionTLS12}
	if ca != "" {
		roh, err := os.ReadFile(ca)
		if err != nil {
			return nil, err
		}
		k.RootCAs = x509.NewCertPool()
		if !k.RootCAs.AppendCertsFromPEM(roh) {
			return nil, errors.New("TRAILR_CA enthält kein Zertifikat")
		}
	}
	if zertifikat != "" || schluessel != "" {
		if _, err := tls.LoadX509KeyPair(zertifikat, schluessel); err != nil {
			return nil, err
		}
		// Je Verbindung gelesen: ein erneuertes Zertifikat gilt ohne Neustart.
		k.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			z, err := tls.LoadX509KeyPair(zertifikat, schluessel)
			return &z, err
		}
	}
	t, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("kein Transport")
	}
	t = t.Clone()
	t.TLSClientConfig = k
	c.Transport = t
	return c, nil
}
