package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log"
	"net/http"
	"os"
	"slices"
	"time"
)

// Mit TRAILR_MTLS_PORT nimmt Trailr Lieferungen nur noch dort an: mit dem
// Zertifikat des Hosts und seinem Schlüssel. Ohne die Variable ändert sich
// nichts und es geht kein Port auf.

// zertifikatPasst: der Name im Zertifikat ist der Host, für den geliefert wird.
func zertifikatPasst(r *http.Request, host string) bool {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return false
	}
	c := r.TLS.VerifiedChains[0][0]
	return c.Subject.CommonName == host || slices.Contains(c.DNSNames, host)
}

func (a *App) mtlsWege() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", gesund)
	m.HandleFunc("POST /api/lieferung", a.agentPruefen(func(w http.ResponseWriter, r *http.Request, host string) {
		if !zertifikatPasst(r, host) {
			alsJSON(w, http.StatusForbidden, map[string]string{"fehler": "Das Zertifikat gehört nicht zu diesem Host"})
			return
		}
		a.lieferung(w, r, host)
	}))
	return m
}

func mtlsKonfig(zertifikat, schluessel, ca string) (*tls.Config, error) {
	roh, err := os.ReadFile(ca)
	if err != nil {
		return nil, err
	}
	wurzeln := x509.NewCertPool()
	if !wurzeln.AppendCertsFromPEM(roh) {
		return nil, errors.New("TRAILR_MTLS_CA enthält kein Zertifikat")
	}
	if _, err := tls.LoadX509KeyPair(zertifikat, schluessel); err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  wurzeln,
		// Je Verbindung gelesen: ein erneuertes Zertifikat gilt ohne Neustart.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c, err := tls.LoadX509KeyPair(zertifikat, schluessel)
			return &c, err
		},
	}, nil
}

func (a *App) mtlsStarten(ctx context.Context, port string) error {
	k, err := mtlsKonfig(umgebung("TRAILR_MTLS_ZERTIFIKAT", ""), umgebung("TRAILR_MTLS_SCHLUESSELDATEI", ""), umgebung("TRAILR_MTLS_CA", ""))
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: ":" + port, Handler: a.mtlsWege(), TLSConfig: k, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("mTLS: %v", err)
		}
	}()
	go func() {
		<-ctx.Done()
		if err := srv.Close(); err != nil {
			log.Printf("mTLS: %v", err)
		}
	}()
	log.Printf("Trailr nimmt Lieferungen nur per mTLS auf :%s an", port)
	return nil
}
