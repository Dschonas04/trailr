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
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Admin wird niemand nebenbei: nur mit Einrichtungscode oder per Vorgabe des
// Betreibers. Eine fremde Kennung kann sich nicht als eigenes Konto ausgeben.
func TestWerAdminWird(t *testing.T) {
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

	neu := func(t *testing.T) *App {
		if _, err := db.Exec(context.Background(), `DELETE FROM admins`); err != nil {
			t.Fatal(err)
		}
		a := &App{db: db, v: ladeVorlagen(),
			sso: NeuesSSO("Trailr", filepath.Join(t.TempDir(), "sso.json"), "TRAILR_TEST_SSO_AUS")}
		a.sso.ErstesKonto = a.ersterAdmin
		return a
	}
	ruf := func(a *App, methode, pfad string, f url.Values, kekse []*http.Cookie) *httptest.ResponseRecorder {
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
		return w
	}
	const aussteller = "https://anbieter.example/realms/pruefung"
	perSSO := func(a *App, sub string) []*http.Cookie {
		a.sso.k = SSOKonfig{Aktiv: true, Aussteller: aussteller, ClientID: "app"}
		w := httptest.NewRecorder()
		a.sso.setzen(w, httptest.NewRequest("GET", "/", nil), ssoKeks, ssoSitzung{SSONutzer: SSONutzer{Kennung: sub, Nutzer: "irgendwer"},
			Aussteller: aussteller, ClientID: "app", Bis: time.Now().Add(time.Hour).Unix()}, time.Hour)
		return w.Result().Cookies()
	}
	darf := func(a *App, kekse []*http.Cookie) int {
		return ruf(a, "GET", "/api/sso/einstellungen", nil, kekse).Code
	}

	t.Run("erste Anmeldung macht keinen Admin", func(t *testing.T) {
		a := neu(t)
		if code := darf(a, perSSO(a, "zuerst-da")); code != http.StatusForbidden {
			t.Errorf("%d statt 403", code)
		}
	})
	t.Run("Einrichtungscode macht Admin", func(t *testing.T) {
		a := neu(t)
		mitCode := ruf(a, "GET", "/sso/konten?code="+a.sso.einrichtcode, nil, nil).Result().Cookies()
		f := url.Values{"name": {"chefin"}, "passwort": {"nur-fuer-den-test"}, "wiederholung": {"nur-fuer-den-test"}}
		w := ruf(a, "POST", "/sso/konten", f, mitCode)
		if w.Code != http.StatusSeeOther {
			t.Fatalf("Konto nicht angelegt: %d", w.Code)
		}
		if code := darf(a, w.Result().Cookies()); code != http.StatusOK {
			t.Errorf("erstes Konto verwaltet nicht: %d", code)
		}
		// Derselbe Text als sub eines Anbieters ist eine andere Person.
		if code := darf(a, perSSO(a, "konto:chefin")); code != http.StatusForbidden {
			t.Errorf("sub konto:chefin gilt als eigenes Konto: %d", code)
		}
	})
	t.Run("Vorgabe des Betreibers", func(t *testing.T) {
		a := neu(t)
		a.admins = adminListe("oidc:" + aussteller + "|betreiber")
		if code := darf(a, perSSO(a, "betreiber")); code != http.StatusOK {
			t.Errorf("Vorgabe gilt nicht: %d", code)
		}
		if code := darf(a, perSSO(a, "jemand-anderes")); code != http.StatusForbidden {
			t.Errorf("Vorgabe gilt für Fremde: %d", code)
		}
	})
}
