package main

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestKeineZelleBeginntMitFormel(t *testing.T) {
	formel := regexp.MustCompile(`^[\s\p{Z}"]*[=+\-@\x{ff1d}]`)
	for _, s := range []string{"x,\t=1", "x,\n=1", "x;\r\n+1", "x,\v=1", "x\t=1", "a,,=1", "x,\t\"=1", "=1"} {
		feld := strings.Trim(csv(s), `"`)
		for _, trenner := range []string{",", ";", "\t"} {
			for _, zelle := range strings.Split(feld, trenner) {
				if formel.MatchString(zelle) {
					t.Errorf("%q an %q getrennt: %q", s, trenner, zelle)
				}
			}
		}
	}
}

func TestGiftHaeltDieSchlangeNichtAuf(t *testing.T) {
	a := pruefApp(t)
	if _, err := a.db.Exec(t.Context(), `DELETE FROM alarme`); err != nil {
		t.Fatal(err)
	}
	if _, err := a.db.Exec(t.Context(), `INSERT INTO alarme (host, regel, schluessel, text)
		SELECT 'laut', 'quelle', 'g' || i, 'GIFT ' || i FROM generate_series(1, 30) i
		UNION ALL SELECT 'gut', 'quelle', 'k', 'harmlos'
		UNION ALL SELECT 'wichtig', 'kette', 'k', 'gebrochen'`); err != nil {
		t.Fatal(err)
	}
	var an []string
	a.alarme = &Alarme{seit: time.Now().Add(-time.Hour), melder: []melder{{"Telegram", func(_ context.Context, text string) error {
		if strings.Contains(text, "GIFT") {
			return errors.New("abgelehnt")
		}
		an = append(an, text)
		return nil
	}}}}
	a.alarmeSenden(t.Context())
	alle := strings.Join(an, "\n")
	if !strings.Contains(alle, "harmlos") || !strings.Contains(alle, "gebrochen") {
		t.Errorf("ein Schub mit Gift hält andere auf: %q", an)
	}
	if _, err := a.db.Exec(t.Context(), `INSERT INTO alarme (host, regel, schluessel, text) VALUES ('spaet', 'still', 'k', 'verstummt')`); err != nil {
		t.Fatal(err)
	}
	a.alarmeSenden(t.Context())
	if !strings.Contains(strings.Join(an, "\n"), "verstummt") {
		t.Error("Wichtiges wartet hinter Abgelehntem")
	}
}
