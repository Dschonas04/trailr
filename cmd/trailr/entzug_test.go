package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// beimLesen führt etwas aus, bevor der Inhalt der Anfrage ankommt: so sieht
// ein langsam geschicktes Formular aus.
type beimLesen struct {
	io.Reader
	tu func()
}

func (b *beimLesen) Read(p []byte) (int, error) {
	if b.tu != nil {
		b.tu()
		b.tu = nil
	}
	return b.Reader.Read(p)
}

func TestRechteEndenMitDemKonto(t *testing.T) {
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

	const passwort = "nur-fuer-den-test"
	konto := func(name string) url.Values {
		return url.Values{"name": {name}, "passwort": {passwort}, "wiederholung": {passwort}}
	}
	ruf := func(a *App, methode, pfad string, f url.Values, kekse []*http.Cookie, tu func()) *httptest.ResponseRecorder {
		r := httptest.NewRequest(methode, pfad, &beimLesen{strings.NewReader(f.Encode()), tu})
		if methode != "GET" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", "http://"+r.Host)
		}
		for _, k := range kekse {
			r.AddCookie(k)
		}
		w := httptest.NewRecorder()
		a.wege().ServeHTTP(w, r)
		return w
	}
	einrichten := func(t *testing.T) (*App, []*http.Cookie) {
		if _, err := db.Exec(context.Background(), `DELETE FROM admins`); err != nil {
			t.Fatal(err)
		}
		a := &App{db: db, v: ladeVorlagen(),
			sso: NeuesSSO("Trailr", filepath.Join(t.TempDir(), "sso.json"), "TRAILR_TEST_SSO_AUS")}
		a.sso.ErstesKonto = a.ersterAdmin
		a.sso.KontoWeg = a.adminEntziehen
		code := ruf(a, "GET", "/sso/konten?code="+a.sso.einrichtcode, nil, nil, nil).Result().Cookies()
		w := ruf(a, "POST", "/sso/konten", konto("chefin"), code, nil)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("Einrichtung: %d", w.Code)
		}
		return a, w.Result().Cookies()
	}

	t.Run("gleicher Name erbt nichts", func(t *testing.T) {
		a, chefin := einrichten(t)
		ruf(a, "POST", "/sso/konten", konto("zweite"), chefin, nil)
		ruf(a, "POST", "/sso/konten/loeschen", url.Values{"name": {"chefin"}}, chefin, nil)
		k := ssoKonto{Name: "chefin", Hash: ssoPasswortHash("ein-anderer-mensch")}
		a.sso.konten = append(a.sso.konten, k)
		w := httptest.NewRecorder()
		a.sso.lokalAnmelden(w, httptest.NewRequest("POST", "/", nil), k)
		if code := ruf(a, "GET", "/api/sso/einstellungen", nil, w.Result().Cookies(), nil).Code; code != http.StatusForbidden {
			t.Errorf("neues Konto mit altem Namen verwaltet: %d", code)
		}
	})
	t.Run("Entzug gilt auch für laufende Anfragen", func(t *testing.T) {
		a, chefin := einrichten(t)
		w := ruf(a, "POST", "/sso/konten", konto("hintertuer"), chefin, func() {
			a.sso.mu.Lock()
			a.sso.konten = nil
			a.sso.mu.Unlock()
		})
		if _, da := a.sso.konto("hintertuer"); da {
			t.Errorf("entzogene Sitzung hat ein Konto angelegt: %d", w.Code)
		}
	})
}
