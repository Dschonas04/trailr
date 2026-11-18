package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSeitenRendern(t *testing.T) {
	v := ladeVorlagen()
	jetzt := time.Now()
	z := []Zeile{{ID: 1, Host: "vm-debian-docker", Zeit: jetzt, Art: "sudo", Benutzer: "jonas", Als: "root", Sitzung: "3", Quelle: "pts/0", Erfolg: false, Text: "/usr/bin/apt update"}}
	h := []Host{{ID: "h1", Name: "vm-debian-docker", Zuletzt: &jetzt, Heute: 3, Fehl: 1, Benutzer: 1, Agent: "v0.1"}}
	faelle := map[string]map[string]any{
		"start":      {"Hosts": h, "Letzte": z, "Fehl": z},
		"ereignisse": {"Liste": z, "F": Filter{Sitzung: "3"}, "Hosts": h, "Arten": []string{"sudo"}, "Benutzer": []string{"jonas"}, "Voll": true, "Abfrage": "host=x"},
		"pruefen":    {"Ergebnis": []Pruefung{{Host: "a", Anzahl: 3, OK: true}, {Host: "b", Anzahl: 2, Grund: "geändert", Bruch: &z[0]}}, "Gelaufen": true},
		"einrichten": {"Server": "https://10.0.2.7:8400", "Tage": 365},
	}
	for name, d := range faelle {
		rec := httptest.NewRecorder()
		v.zeigen(rec, httptest.NewRequest("GET", "/", nil), name, Daten{App: "Trailr", D: d})
		if b := rec.Body.String(); !strings.Contains(b, "</html>") {
			t.Errorf("%s bricht ab: %s", name, b[max(0, len(b)-300):])
		}
	}
}

func TestCSV(t *testing.T) {
	if csv("=HYPERLINK(1);x\ny") != "'=HYPERLINK(1),x y" {
		t.Error(csv("=HYPERLINK(1);x\ny"))
	}
}
