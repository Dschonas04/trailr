package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestMTLS(t *testing.T) {
	d := t.TempDir()
	neu := func(name string, eltern *x509.Certificate, mit *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, string, string) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		v := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true}
		if eltern == nil {
			eltern, mit = v, k
			v.IsCA, v.KeyUsage = true, x509.KeyUsageCertSign
		} else {
			v.KeyUsage = x509.KeyUsageDigitalSignature
			v.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
			v.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		der, err := x509.CreateCertificate(rand.Reader, v, eltern, &k.PublicKey, mit)
		if err != nil {
			t.Fatal(err)
		}
		kd, err := x509.MarshalPKCS8PrivateKey(k)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		cp, kp := filepath.Join(d, name+".crt"), filepath.Join(d, name+".key")
		if err := os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), 0o600); err != nil {
			t.Fatal(err)
		}
		return c, k, cp, kp
	}
	ca, cak, caDatei, _ := neu("ca", nil, nil)
	_, _, sc, sk := neu("server", ca, cak)
	_, _, hc, hk := neu("h1", ca, cak)
	paar, err := tls.LoadX509KeyPair(sc, sk)
	if err != nil {
		t.Fatal(err)
	}
	wurzeln := x509.NewCertPool()
	wurzeln.AddCert(ca)
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	s.TLS = &tls.Config{Certificates: []tls.Certificate{paar}, ClientCAs: wurzeln, ClientAuth: tls.RequireAndVerifyClientCert}
	s.StartTLS()
	defer s.Close()
	for _, fall := range []struct {
		cert, key string
		geht      bool
	}{{hc, hk, true}, {"", "", false}} {
		c, err := neuerClient(fall.cert, fall.key, caDatei)
		if err != nil {
			t.Fatal(err)
		}
		res, err := c.Get(s.URL)
		if err == nil {
			res.Body.Close()
		}
		if (err == nil) != fall.geht {
			t.Errorf("mit %q: %v", fall.cert, err)
		}
	}
}
