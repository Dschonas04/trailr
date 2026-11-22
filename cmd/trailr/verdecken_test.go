package main

import (
	"fmt"
	"testing"
	"time"

	"trailr/internal/ereignis"
)

func TestKeinKontoVerdecktEinAnderes(t *testing.T) {
	a := pruefApp(t)
	if _, err := a.db.Exec(t.Context(), `DELETE FROM alarme`); err != nil {
		t.Fatal(err)
	}
	a.alarme = &Alarme{seit: time.Now().Add(-time.Hour)}
	an := func(k, wer, quelle string, vor time.Duration) ereignis.Ereignis {
		e := probe(k, "anmeldung", "SSH", true)
		e.Benutzer, e.Quelle, e.Zeit = wer, quelle, time.Now().Add(-vor)
		return e
	}
	liefern(t, a, "deckung", an("basis", "anna", "192.0.2.1", time.Hour))
	var l []ereignis.Ereignis
	for i := range 80 {
		l = append(l, an(fmt.Sprint("a", i), "anna", fmt.Sprint("198.51.100.", i), time.Minute))
	}
	// root danach, einmal von eigener Adresse, einmal von einer, die unterging.
	l = append(l, an("r1", "root", "203.0.113.9", 0), an("r2", "root", "198.51.100.79", 0))
	liefern(t, a, "deckung", l...)
	zaehl := func(regel, text string) (n int) {
		if err := a.db.QueryRow(t.Context(), `SELECT count(*) FROM alarme WHERE regel=$1 AND text LIKE '%' || $2 || '%'`, regel, text).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := zaehl("quelle", "von root"); n != 2 {
		t.Errorf("root hinter anna versteckt: %d von 2", n)
	}
	if n := zaehl("flut", "anna"); n != 1 {
		t.Errorf("Flut ohne Konto: %d", n)
	}
	var m []ereignis.Ereignis
	for i := range 60 {
		m = append(m, an(fmt.Sprint("b", i), "anna", fmt.Sprint("203.0.113.", 100+i), 0))
	}
	liefern(t, a, "deckung", m...)
	if n := zaehl("flut", "anna"); n != 2 {
		t.Errorf("zweite Flut in derselben Stunde unsichtbar: %d", n)
	}
}
