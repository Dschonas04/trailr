package main

import (
	"context"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trailr/internal/ereignis"
)

func TestAlarmGrenzenJeHost(t *testing.T) {
	a := pruefApp(t)
	if _, err := a.db.Exec(t.Context(), `DELETE FROM alarme`); err != nil {
		t.Fatal(err)
	}
	a.alarme = &Alarme{seit: time.Now().Add(-time.Hour)}
	a.v = ladeVorlagen()
	a.sso = NeuesSSO("Trailr", filepath.Join(t.TempDir(), "sso.json"), "TRAILR_TEST_SSO_AUS")
	nr := 0
	an := func(wer string, vor time.Duration) ereignis.Ereignis {
		nr++
		e := probe(fmt.Sprint("g", nr), "anmeldung", "SSH", true)
		e.Benutzer, e.Quelle, e.Zeit = wer, fmt.Sprintf("2001:db8::%x", nr), time.Now().Add(-vor)
		return e
	}
	liefern(t, a, "laut", an("anna", time.Hour))
	for runde := range 12 {
		var l []ereignis.Ereignis
		for konto := range 8 {
			for range 52 {
				l = append(l, an(fmt.Sprintf("konto%d-%d", runde, konto), time.Minute))
			}
		}
		liefern(t, a, "laut", l...)
	}
	zaehl := func(regel, muster string) (n int) {
		if err := a.db.QueryRow(t.Context(), `SELECT count(*) FROM alarme WHERE regel=$1 AND text LIKE $2`, regel, muster).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := zaehl("quelle", "%"); n > 300 {
		t.Errorf("%d Quellen-Alarme von einem Host", n)
	}
	if n := zaehl("flut", "%"); n == 0 || n > 7 {
		t.Errorf("%d Flut-Alarme von einem Host", n)
	}

	var l []ereignis.Ereignis
	for range 150 {
		l = append(l, an("root", 0))
	}
	liefern(t, a, "laut", l...)
	if n := zaehl("quelle", "%von root %"); n == 0 || n > 100 {
		t.Errorf("root: %d, soll einen eigenen, begrenzten Anteil haben", n)
	}

	if _, err := a.db.Exec(t.Context(), `INSERT INTO alarme (host, regel, schluessel, text) VALUES ('leise', 'kette', 'k', 'KETTE-GEBROCHEN')`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(t.Context(), `INSERT INTO alarme (host, regel, schluessel, text)
		SELECT 'laut' || (i % 30), 'flut', 'f' || i, 'Flut ' || i FROM generate_series(1, 400) i`); err != nil {
		t.Fatal(err)
	}
	var an1 []string
	a.alarme.melder = []melder{{"Telegram", func(_ context.Context, text string) error { an1 = append(an1, text); return nil }}}
	a.alarmeSenden(t.Context())
	if len(an1) == 0 || !strings.HasPrefix(an1[0], "Trailr\nleise: KETTE-GEBROCHEN") {
		t.Error("eine Flut steht vor der gebrochenen Kette")
	}
	if _, err := a.db.Exec(t.Context(), `INSERT INTO alarme (host, regel, schluessel, text)
		SELECT 'laut', 'quelle', 's' || i, 'später ' || i FROM generate_series(1, 400) i`); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.alarmeSeite(w, httptest.NewRequest("GET", "/alarme", nil))
	if !strings.Contains(w.Body.String(), "KETTE-GEBROCHEN") {
		t.Error("ein Host schiebt die anderen von der Seite")
	}
}
