package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"trailr/internal/ereignis"
)

func pruefApp(t *testing.T) *App {
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
	t.Cleanup(db.Close)
	if _, err := db.Exec(t.Context(), `DELETE FROM hosts`); err != nil {
		t.Fatal(err)
	}
	return &App{db: db, schluessel: strings.Repeat("t", 32)}
}

func liefern(t *testing.T, a *App, host string, l ...ereignis.Ereignis) int {
	b, err := json.Marshal(ereignis.Lieferung{Host: host, Agent: "test", Ereignisse: l})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.lieferung(w, httptest.NewRequest("POST", "/api/lieferung", bytes.NewReader(b)), host)
	return w.Code
}

func probe(kennung, art, text string, erfolg bool) ereignis.Ereignis {
	return ereignis.Ereignis{Kennung: kennung, Zeit: time.Now(), Art: art, Benutzer: "anna", Erfolg: erfolg, Text: text}
}

func hostID(t *testing.T, a *App, name string) (id string) {
	if err := a.db.QueryRow(t.Context(), `SELECT id::text FROM hosts WHERE name=$1`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestEinEreignisBlockiertDenHostNicht(t *testing.T) {
	a := pruefApp(t)
	if c := liefern(t, a, "h1", probe("n1", "befehl", "rm\x00 -rf x", true), probe("n2", "befehl", "danach", true)); c != 200 {
		t.Errorf("Nullbyte hält die Lieferung auf: %d", c)
	}
}

func TestLoeschenFaelltAuf(t *testing.T) {
	a := pruefApp(t)
	for _, fall := range []struct{ host, was string }{
		{"vorne", `DELETE FROM ereignisse WHERE id = (SELECT min(id) FROM ereignisse WHERE host=$1::uuid)`},
		{"alles", `DELETE FROM ereignisse WHERE host=$1::uuid`},
	} {
		if c := liefern(t, a, fall.host, probe("a", "befehl", "1", true), probe("b", "befehl", "2", true), probe("c", "befehl", "3", true)); c != 200 {
			t.Fatalf("Lieferung: %d", c)
		}
		id := hostID(t, a, fall.host)
		if p := a.pruefeKette(t.Context(), id, fall.host); !p.OK {
			t.Fatalf("unverändert gilt als kaputt: %s", p.Grund)
		}
		if _, err := a.db.Exec(t.Context(), fall.was, id); err != nil {
			t.Fatal(err)
		}
		if p := a.pruefeKette(t.Context(), id, fall.host); p.OK {
			t.Errorf("%s gelöscht, Prüfung sagt unverändert", fall.host)
		}
	}
}

func TestFeldgrenzenLassenSichNichtSchieben(t *testing.T) {
	a := pruefApp(t)
	e := probe("g", "befehl", "x", true)
	e.Als, e.Sitzung = "root\x1fversteckt", ""
	if c := liefern(t, a, "grenze", e); c != 200 {
		t.Fatalf("Lieferung: %d", c)
	}
	id := hostID(t, a, "grenze")
	if _, err := a.db.Exec(t.Context(), `UPDATE ereignisse SET als='root', sitzung='versteckt' || chr(31) WHERE host=$1::uuid`, id); err != nil {
		t.Fatal(err)
	}
	if p := a.pruefeKette(t.Context(), id, "grenze"); p.OK {
		t.Error("Inhalt zwischen Feldern verschoben, Prüfung sagt unverändert")
	}
}

func TestAufraeumenBrichtDieKetteNicht(t *testing.T) {
	a := pruefApp(t)
	a.tage = 30
	var l []ereignis.Ereignis
	for _, k := range []string{"a", "b", "c"} {
		l = append(l, probe(k, "befehl", k, true))
	}
	if c := liefern(t, a, "alt", l...); c != 200 {
		t.Fatalf("Lieferung: %d", c)
	}
	id := hostID(t, a, "alt")
	for _, bis := range []string{"b", "c"} {
		if _, err := a.db.Exec(t.Context(), `UPDATE ereignisse SET empfangen = now() - interval '40 days' WHERE host=$1::uuid AND kennung <= $2`, id, bis); err != nil {
			t.Fatal(err)
		}
		if n, err := a.hostAufraeumen(t.Context(), id); err != nil || n == 0 {
			t.Fatalf("Aufräumen: %d %v", n, err)
		}
		if p := a.pruefeKette(t.Context(), id, "alt"); !p.OK {
			t.Errorf("nach dem Aufräumen gebrochen: %s", p.Grund)
		}
	}
	if c := liefern(t, a, "alt", probe("d", "befehl", "d", true)); c != 200 {
		t.Fatalf("Lieferung: %d", c)
	}
	if p := a.pruefeKette(t.Context(), id, "alt"); !p.OK {
		t.Errorf("Lieferung nach leerer Kette: %s", p.Grund)
	}
}
