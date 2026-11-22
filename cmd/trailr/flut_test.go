package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"trailr/internal/ereignis"
)

func TestCSVAusbruch(t *testing.T) {
	for _, s := range []string{` =1+1`, `"=1+1`, "\t@SUM(1)", "x,=1+1", "x; +1", "＝1+1"} {
		if !strings.Contains(csv(s), "'") {
			t.Errorf("Formel bleibt: %q wird %q", s, csv(s))
		}
	}
}

func TestFlutVerdecktNichts(t *testing.T) {
	a := pruefApp(t)
	a.alarme = &Alarme{seit: time.Now().Add(-time.Hour)}
	if _, err := a.db.Exec(t.Context(), `DELETE FROM alarme`); err != nil {
		t.Fatal(err)
	}
	an := func(k, quelle string, erfolg bool, vor time.Duration) ereignis.Ereignis {
		e := probe(k, "anmeldung", "SSH", erfolg)
		e.Quelle, e.Zeit = quelle, time.Now().Add(-vor)
		return e
	}
	liefern(t, a, "flut", an("basis", "192.0.2.1", true, time.Hour))
	var l []ereignis.Ereignis
	for i := range 250 {
		l = append(l, an(fmt.Sprint("f", i), fmt.Sprint("198.51.100.", i), false, time.Minute))
	}
	liefern(t, a, "flut", append(l, an("drin", "203.0.113.9", true, 0))...)
	for _, regel := range []string{"quelle", "flut"} {
		var n int
		if err := a.db.QueryRow(t.Context(), `SELECT count(*) FROM alarme WHERE regel=$1`, regel).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s: %d %v", regel, n, err)
		}
	}

	if _, err := a.db.Exec(t.Context(), `DELETE FROM alarme`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(t.Context(), `INSERT INTO alarme (host, regel, schluessel, text)
		SELECT 'laut', 'quelle', 'k' || i, repeat('ä', 140) FROM generate_series(1, 200) i`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(t.Context(), `INSERT INTO alarme (host, regel, schluessel, text) VALUES ('leise', 'kette', 'k', 'gebrochen')`); err != nil {
		t.Fatal(err)
	}
	var telegram, mail []string
	kaputt := true
	a.alarme.melder = []melder{
		{"Telegram", func(_ context.Context, text string) error {
			if kaputt {
				return errors.New("aus")
			}
			telegram = append(telegram, text)
			return nil
		}},
		{"Mail", func(_ context.Context, text string) error { mail = append(mail, text); return nil }},
	}
	a.alarmeSenden(t.Context())
	if len(mail) != 1 || !strings.Contains(mail[0], "leise") || len(mail[0]) > 4000 {
		t.Errorf("Mail: lauter Host zuerst oder zu lang")
	}
	kaputt = false
	a.alarmeSenden(t.Context())
	if len(telegram) != 1 || !strings.Contains(telegram[0], "leise") {
		t.Error("was einem Weg fehlte, kommt dort nicht nach")
	}
}
