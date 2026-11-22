package main

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// Vorprüfung und Speichern lesen gleich: was die Prüfung nicht versteht, kommt
// nicht bis zur Sperre, und unter der Sperre fragt niemand den Anbieter.
func TestVorpruefungFaelltGeschlossen(t *testing.T) {
	s := NeuesSSO("Trailr", filepath.Join(t.TempDir(), "sso.json"), "TRAILR_TEST_SSO_AUS")
	for _, roh := range []string{
		`{"aktiv":true,"aussteller":"https://anbieter.example","clientId":"app"} muell`,
		`{"aktiv":true,"aussteller":"https://anbieter.example"}{}`,
		`kein json`,
	} {
		r := httptest.NewRequest("PUT", "/api/sso/einstellungen", strings.NewReader(roh))
		if _, weiter := s.ausstellerVorab(httptest.NewRecorder(), r, []byte(roh)); weiter {
			t.Errorf("geht ungeprüft weiter: %s", roh)
		}
	}
	// Vorab hieß es "aus", gespeichert werden soll "an": abgelehnt.
	aus := `{"aktiv":false}`
	r, weiter := s.ausstellerVorab(httptest.NewRecorder(), httptest.NewRequest("PUT", "/api/sso/einstellungen", nil), []byte(aus))
	if !weiter {
		t.Fatal("Abschalten geht nicht")
	}
	an := httptest.NewRequest("PUT", "/api/sso/einstellungen",
		strings.NewReader(`{"aktiv":true,"aussteller":"https://127.0.0.1:1","clientId":"app"}`)).WithContext(r.Context())
	w := httptest.NewRecorder()
	s.einstellungenSchreiben(w, an)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "vorab") {
		t.Errorf("Anbieter unter der Sperre gefragt: %d %s", w.Code, w.Body.String())
	}
}
