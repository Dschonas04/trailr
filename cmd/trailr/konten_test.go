package main

import (
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trailr/internal/ereignis"
)

func TestJedesKontoBleibtSichtbar(t *testing.T) {
	a := pruefApp(t)
	if _, err := a.db.Exec(t.Context(), `DELETE FROM alarme`); err != nil {
		t.Fatal(err)
	}
	a.alarme = &Alarme{seit: time.Now().Add(-time.Hour)}
	nr := 0
	an := func(wer string, vor time.Duration) ereignis.Ereignis {
		nr++
		e := probe(fmt.Sprint("k", nr), "anmeldung", "SSH", true)
		e.Benutzer, e.Quelle, e.Zeit = wer, fmt.Sprintf("2001:db8:1::%x", nr), time.Now().Add(-vor)
		return e
	}
	zaehl := func(muster string) (n int) {
		if err := a.db.QueryRow(t.Context(), `SELECT count(*) FROM alarme WHERE regel='quelle' AND text LIKE $1`, muster).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	liefern(t, a, "falschroot", an("anna", time.Hour))
	for p := range 3 {
		var l []ereignis.Ereignis
		for i := range 48 {
			l = append(l, an(fmt.Sprintf("root:%d-%d", p, i), 0))
		}
		liefern(t, a, "falschroot", l...)
	}
	liefern(t, a, "falschroot", an("root", 0))
	if zaehl("%von root aus%") != 1 {
		t.Error("Konten namens root:x verbrauchen den Anteil von root")
	}

	liefern(t, a, "voll", an("anna", time.Hour))
	for k := range 6 {
		var l []ereignis.Ereignis
		for range 50 {
			l = append(l, an(fmt.Sprint("laut", k), 0))
		}
		liefern(t, a, "voll", l...)
	}
	liefern(t, a, "voll", an("berta", 0))
	if zaehl("%von berta aus%") != 1 {
		t.Error("laute Konten verdecken ein weiteres")
	}

	if _, err := a.db.Exec(t.Context(), `INSERT INTO alarme (host, regel, schluessel, text)
		SELECT 'seite', 'quelle', 's' || i, CASE WHEN i = 1 THEN 'DER-ERSTE' ELSE 'später ' || i END FROM generate_series(1, 180) i`); err != nil {
		t.Fatal(err)
	}
	a.v = ladeVorlagen()
	a.sso = NeuesSSO("Trailr", filepath.Join(t.TempDir(), "sso.json"), "TRAILR_TEST_SSO_AUS")
	hol := func(adresse string) string {
		w := httptest.NewRecorder()
		a.alarmeSeite(w, httptest.NewRequest("GET", adresse, nil))
		return w.Body.String()
	}
	if !strings.Contains(hol("/alarme"), "regel=quelle") {
		t.Error("die Übersicht verschweigt, dass es mehr gibt")
	}
	b := hol("/alarme?host=seite&regel=quelle")
	i := strings.Index(b, `id="aeltere" href="`)
	if i < 0 {
		t.Error("kein Blättern")
		return
	}
	b = b[i+len(`id="aeltere" href="`):]
	if !strings.Contains(hol(strings.ReplaceAll(b[:strings.Index(b, `"`)], "&amp;", "&")), "DER-ERSTE") {
		t.Error("der älteste ist unerreichbar")
	}
}
