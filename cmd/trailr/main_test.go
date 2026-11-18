package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGrundwege(t *testing.T) {
	srv := httptest.NewServer(neuerMux())
	defer srv.Close()

	for pfad, erwartet := range map[string]string{
		"/healthz":     "ok",
		"/api/version": `"name":"trailr"`,
		"/":            "Trailr",
	} {
		antwort, err := http.Get(srv.URL + pfad)
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := antwort.Body.Read(buf)
			b.Write(buf[:n])
			if err != nil {
				break
			}
		}
		antwort.Body.Close()
		if antwort.StatusCode != http.StatusOK || !strings.Contains(b.String(), erwartet) {
			t.Errorf("%s: %d, %q enthält %q nicht", pfad, antwort.StatusCode, b.String(), erwartet)
		}
		if antwort.Header.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s: Sicherheitskopf fehlt", pfad)
		}
	}
}
