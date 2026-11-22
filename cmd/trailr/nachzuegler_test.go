package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"trailr/internal/ereignis"
)

func TestGescheitertesVerhungertNicht(t *testing.T) {
	for _, host := range []string{"anderer", "laut"} {
		a := pruefApp(t)
		if _, err := a.db.Exec(t.Context(), `DELETE FROM alarme`); err != nil {
			t.Fatal(err)
		}
		if _, err := a.db.Exec(t.Context(), `INSERT INTO alarme (host, regel, schluessel, text, versucht_je)
			VALUES ($1, 'quelle', 'alt', 'NACHZUEGLER', '{"Telegram": 1}')`, host); err != nil {
			t.Fatal(err)
		}
		if _, err := a.db.Exec(t.Context(), `INSERT INTO alarme (host, regel, schluessel, text)
			SELECT 'laut', 'quelle', 'n' || i, 'neu ' || i FROM generate_series(1, 300) i`); err != nil {
			t.Fatal(err)
		}
		var an []string
		a.alarme = &Alarme{seit: time.Now().Add(-time.Hour), melder: []melder{{"Telegram", func(_ context.Context, text string) error {
			an = append(an, text)
			return nil
		}}}}
		a.alarmeSenden(t.Context())
		if !strings.Contains(strings.Join(an, "\n"), "NACHZUEGLER") {
			t.Errorf("Gescheitertes von %s wartet hinter der Flut", host)
		}
	}
}

func TestHaengenderSammelversand(t *testing.T) {
	a := pruefApp(t)
	if _, err := a.db.Exec(t.Context(), `DELETE FROM alarme`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(t.Context(), `INSERT INTO alarme (host, regel, schluessel, text)
		VALUES ('a', 'quelle', 'k', 'eins'), ('b', 'quelle', 'k', 'zwei')`); err != nil {
		t.Fatal(err)
	}
	einzeln := 0
	a.alarme = &Alarme{seit: time.Now().Add(-time.Hour), melder: []melder{{"Mail", func(ctx context.Context, text string) error {
		if strings.Count(text, "\n") > 1 {
			<-ctx.Done()
			return ctx.Err()
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		einzeln++
		return nil
	}}}}
	a.alarmeSenden(t.Context())
	if einzeln != 2 {
		t.Errorf("nach dem Hänger kommen %d von 2 einzeln durch", einzeln)
	}
}

func TestQuellenFlut(t *testing.T) {
	a := pruefApp(t)
	if _, err := a.db.Exec(t.Context(), `DELETE FROM alarme`); err != nil {
		t.Fatal(err)
	}
	a.alarme = &Alarme{seit: time.Now().Add(-time.Hour)}
	an := func(k, quelle string, vor time.Duration) ereignis.Ereignis {
		e := probe(k, "anmeldung", "SSH", true)
		e.Quelle, e.Zeit = quelle, time.Now().Add(-vor)
		return e
	}
	liefern(t, a, "viele", an("basis", "192.0.2.1", time.Hour))
	var l []ereignis.Ereignis
	for i := range 120 {
		l = append(l, an(fmt.Sprint("q", i), fmt.Sprint("198.51.100.", i), 0))
	}
	liefern(t, a, "viele", l...)
	var einzelne, flut int
	if err := a.db.QueryRow(t.Context(), `SELECT count(*) FILTER (WHERE regel='quelle'), count(*) FILTER (WHERE regel='flut') FROM alarme`).Scan(&einzelne, &flut); err != nil {
		t.Fatal(err)
	}
	if einzelne > 50 || flut != 1 {
		t.Errorf("Quellen %d, Flut %d", einzelne, flut)
	}
}
