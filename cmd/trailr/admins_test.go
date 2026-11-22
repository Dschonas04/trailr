package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Wer angemeldet ist, darf deshalb noch keine fremden Kennwörter setzen. Braucht
// eine Wegwerf-Datenbank pruef* in TRAILR_TEST_DB.
func TestVerwaltungNurAdmins(t *testing.T) {
	adresse := os.Getenv("TRAILR_TEST_DB")
	if adresse == "" {
		t.Skip("TRAILR_TEST_DB ist nicht gesetzt")
	}
	c, err := pgxpool.ParseConfig(adresse)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(c.ConnConfig.Database, "pruef") {
		t.Fatal("TRAILR_TEST_DB muss auf eine Datenbank pruef* zeigen")
	}
	db := datenbank(context.Background(), adresse)
	defer db.Close()
	// Fehlt die Tabelle noch, gibt es nichts zu leeren.
	_, _ = db.Exec(context.Background(), `DELETE FROM admins`)

	a := &App{db: db, v: ladeVorlagen(),
		sso: NeuesSSO("Trailr", filepath.Join(t.TempDir(), "sso.json"), "TRAILR_TEST_SSO_AUS"), schluessel: strings.Repeat("s", 32)}
	anmelden := func(name string) []*http.Cookie {
		k := ssoKonto{Name: name, Hash: ssoPasswortHash("nur-fuer-den-test-" + name)}
		a.sso.konten = append(a.sso.konten, k)
		w := httptest.NewRecorder()
		a.sso.lokalAnmelden(w, httptest.NewRequest("POST", "/", nil), k)
		return append(w.Result().Cookies(), &http.Cookie{Name: "formular", Value: strings.Repeat("a", 32)})
	}
	chefin, mitglied := anmelden("chefin"), anmelden("mitglied")
	ruf := func(kekse []*http.Cookie, methode, pfad string, f url.Values) int {
		r := httptest.NewRequest(methode, pfad, strings.NewReader(f.Encode()))
		if methode != "GET" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", "http://"+r.Host)
		}
		for _, k := range kekse {
			r.AddCookie(k)
		}
		w := httptest.NewRecorder()
		a.wege().ServeHTTP(w, r)
		return w.Code
	}

	// Wer zuerst kommt, verwaltet.
	if code := ruf(chefin, "GET", "/sso/konten", nil); code != http.StatusOK {
		t.Fatalf("erste Person sieht die Konten nicht: %d", code)
	}
	vorher, _ := a.sso.konto("chefin")
	token := strings.Repeat("a", 32)
	for _, f := range []struct {
		methode, pfad string
		werte         url.Values
	}{
		{"GET", "/sso/konten", nil},
		{"POST", "/sso/konten", url.Values{"name": {"chefin"}, "passwort": {"uebernommen-123"}, "wiederholung": {"uebernommen-123"}}},
		{"POST", "/sso/konten/loeschen", url.Values{"name": {"chefin"}}},
		{"GET", "/api/sso/einstellungen", nil},
		{"PUT", "/api/sso/einstellungen", nil},
		{"GET", "/einrichten?host=fremder-host", nil},
	} {
		if f.werte != nil {
			f.werte.Set("token", token)
		}
		if code := ruf(mitglied, f.methode, f.pfad, f.werte); code != http.StatusForbidden {
			t.Errorf("Mitglied %s %s: %d statt 403", f.methode, f.pfad, code)
		}
	}
	if nachher, da := a.sso.konto("chefin"); !da || nachher.Hash != vorher.Hash {
		t.Error("Mitglied konnte das Konto der Admin-Person verändern")
	}
}
