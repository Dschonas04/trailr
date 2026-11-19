package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"trailr/internal/ereignis"
)

func TestOrdnerKette(t *testing.T) {
	dir := t.TempDir()
	o, err := neueAblage(dir, "test", 0)
	if err != nil {
		t.Fatal(err)
	}
	e := func(k, wer, text string) ereignis.Ereignis {
		return ereignis.Ereignis{Kennung: k, Zeit: time.Now(), Art: "befehl", Benutzer: wer, Als: "root", Erfolg: true, Text: text}
	}
	if err := o.ablegen([]ereignis.Ereignis{e("a:1", "jonas", "id"), e("a:2", "jonas", "ls /root")}); err != nil {
		t.Fatal(err)
	}
	// Neustart: Kette läuft weiter, Doppeltes wird verworfen.
	o2, _ := neueAblage(dir, "test", 0)
	o2.ablegen([]ereignis.Ereignis{e("a:2", "jonas", "ls /root"), e("a:3", "gast", "rm -rf /tmp/x")})
	p := kettePruefen(dir)
	if p.Bruch != "" || p.Zeilen != 3 {
		t.Fatalf("Prüfung: %+v", p)
	}
	var aus bytes.Buffer
	befehlZeigen([]string{"-ordner", dir, "-benutzer", "gast"}, &aus)
	if !strings.Contains(aus.String(), "rm -rf /tmp/x") || strings.Contains(aus.String(), "ls /root") {
		t.Fatalf("zeigen: %s", aus.String())
	}
	// Eine Zeile ändern: muss auffallen.
	d := trailDateien(dir)[0]
	b, _ := os.ReadFile(d)
	os.WriteFile(d, bytes.Replace(b, []byte("ls /root"), []byte("ls /tmp"), 1), 0o600)
	if p := kettePruefen(dir); p.Bruch == "" || !strings.Contains(p.Bruch, "Zeile 2") {
		t.Fatalf("Änderung nicht erkannt: %+v", p)
	}
	// Eine Zeile löschen: muss auch auffallen.
	os.WriteFile(d, b, 0o600)
	zeilen := strings.SplitAfter(string(b), "\n")
	os.WriteFile(d, []byte(zeilen[0]+zeilen[2]), 0o600)
	if p := kettePruefen(dir); p.Bruch == "" {
		t.Fatal("Löschen nicht erkannt")
	}
}

func TestOrdnerAufraeumen(t *testing.T) {
	dir := t.TempDir()
	alt := filepath.Join(dir, "trail-2020-01-01.jsonl")
	os.WriteFile(alt, nil, 0o600)
	o, _ := neueAblage(dir, "test", 30)
	o.ablegen([]ereignis.Ereignis{{Kennung: "x", Zeit: time.Now(), Art: "su", Benutzer: "a"}})
	if _, err := os.Stat(alt); err == nil {
		t.Fatal("alte Datei nicht aufgeräumt")
	}
}
