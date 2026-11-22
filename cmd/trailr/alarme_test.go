package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"trailr/internal/ereignis"
)

func TestAlarme(t *testing.T) {
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
	zaehl := func(regel string) (n int) {
		if err := a.db.QueryRow(t.Context(), `SELECT count(*) FROM alarme WHERE regel=$1`, regel).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	var l []ereignis.Ereignis
	for i := range 4 {
		e := an("f"+strconv.Itoa(i), "192.0.2.9", false, time.Minute)
		e.Benutzer = "geraten" + strconv.Itoa(i) // der Name wechselt, die Quelle nicht
		l = append(l, e)
	}
	liefern(t, a, "wache", append(l, an("ok1", "192.0.2.1", true, time.Hour))...)
	if zaehl("fehlschlaege") != 0 || zaehl("quelle") != 0 {
		t.Error("zu früh gemeldet")
	}
	geheim := an("ok2", "192.0.2.2", true, 0)
	geheim.Text = "BEFEHL-MIT-GEHEIMNIS"
	liefern(t, a, "wache", an("f4", "192.0.2.9", false, 0), geheim)
	if zaehl("fehlschlaege") != 1 || zaehl("quelle") != 1 {
		t.Errorf("Fehlschläge %d, Quelle %d", zaehl("fehlschlaege"), zaehl("quelle"))
	}
	liefern(t, a, "wache", an("f5", "192.0.2.9", false, 0))
	if zaehl("fehlschlaege") > 2 { // höchstens je Stunde einer
		t.Error("jeder Versuch ein eigener Alarm")
	}

	var gemeldet []string
	a.alarme.melder = []melder{{"Test", func(_ context.Context, text string) error { gemeldet = append(gemeldet, text); return nil }}}
	a.alarmeSenden(t.Context())
	a.alarmeSenden(t.Context())
	if len(gemeldet) != 1 || !strings.Contains(gemeldet[0], "192.0.2.2") || strings.Contains(gemeldet[0], "GEHEIMNIS") {
		t.Errorf("gemeldet: %q", gemeldet)
	}

	w := httptest.NewRecorder()
	a.export(w, httptest.NewRequest("GET", "/ereignisse?format=json", nil), Filter{Host: "wache"}, "json")
	var raus []Zeile
	if err := json.Unmarshal(w.Body.Bytes(), &raus); err != nil || len(raus) != 8 {
		t.Errorf("JSON-Export: %d %v", len(raus), err)
	}
	if f, err := a.suchen(t.Context(), Filter{Suche: `ssh\`}, 5); err != nil || len(f) != 0 {
		t.Errorf("Suche nach Backslash: %v", err)
	}
}

func TestArbeitszeit(t *testing.T) {
	if v, b, ok := arbeitszeit("7-20"); !ok || v != 7 || b != 20 {
		t.Error("7-20")
	}
	for _, s := range []string{"20-7", "x", "0-25"} {
		if _, _, ok := arbeitszeit(s); ok {
			t.Error(s)
		}
	}
}

func TestTelegramVerraetDasTokenNicht(t *testing.T) {
	if err := telegram("http://127.0.0.1:1", "TESTTOKEN", "1")(t.Context(), "x"); err == nil || strings.Contains(err.Error(), "TESTTOKEN") {
		t.Errorf("%v", err)
	}
}

func TestZertifikatGehoertZumHost(t *testing.T) {
	r := httptest.NewRequest("POST", "/api/lieferung", nil)
	if zertifikatPasst(r, "h1") {
		t.Error("ohne Zertifikat")
	}
	c := &x509.Certificate{Subject: pkix.Name{CommonName: "h1"}, DNSNames: []string{"h1", "h1.example"}}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}}
	if zertifikatPasst(r, "h1") {
		t.Error("ungeprüftes Zertifikat")
	}
	r.TLS.VerifiedChains = [][]*x509.Certificate{{c}}
	if !zertifikatPasst(r, "h1") || zertifikatPasst(r, "h2") {
		t.Error("Name nicht geprüft")
	}
}
