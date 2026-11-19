package main

// Ordner-Modus: der Agent legt die Ereignisse selbst ab, ohne Server. Eine
// Datei je Tag (trail-2026-11-19.jsonl), eine Zeile je Ereignis, verkettet
// über denselben Hash wie auf dem Server. Die Kette läuft über die Tage
// hinweg weiter; „trailr-agent pruefen“ rechnet sie nach, „trailr-agent
// zeigen“ gibt sie lesbar aus.

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"trailr/internal/ereignis"
)

type Zeile struct {
	ereignis.Ereignis
	Host   string `json:"host"`
	Vorher string `json:"vorher"`
	Hash   string `json:"hash"`
}

type ablage struct {
	dir     string
	host    string
	tage    int
	letzter string
	tag     string
	gesehen map[string]bool // Kennungen des laufenden Tages: nach einem Neustart liest der Agent manches doppelt
}

func trailDateien(dir string) []string {
	l, _ := filepath.Glob(filepath.Join(dir, "trail-*.jsonl"))
	sort.Strings(l)
	return l
}

func neueAblage(dir, host string, tage int) (*ablage, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	o := &ablage{dir: dir, host: host, tage: tage, gesehen: map[string]bool{}}
	// Den letzten Hash und die Kennungen von heute aus den Dateien selbst.
	if l := trailDateien(dir); len(l) > 0 {
		neueste := l[len(l)-1]
		o.tag = strings.TrimSuffix(strings.TrimPrefix(filepath.Base(neueste), "trail-"), ".jsonl")
		err := zeilenLesen(neueste, func(z Zeile) error {
			o.letzter = z.Hash
			o.gesehen[z.Kennung] = true
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", neueste, err)
		}
	}
	return o, nil
}

func zeilenLesen(pfad string, f func(Zeile) error) error {
	d, err := os.Open(pfad)
	if err != nil {
		return err
	}
	defer d.Close()
	sc := bufio.NewScanner(d)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		if len(strings.TrimSpace(sc.Text())) == 0 {
			continue
		}
		var z Zeile
		if err := json.Unmarshal(sc.Bytes(), &z); err != nil {
			return fmt.Errorf("Zeile %d unlesbar", n)
		}
		if err := f(z); err != nil {
			return err
		}
	}
	return sc.Err()
}

// ablegen hängt Ereignisse an die Datei des Tages an und gibt erst zurück,
// wenn sie auf der Platte sind.
func (o *ablage) ablegen(l []ereignis.Ereignis) error {
	if len(l) == 0 {
		return nil
	}
	heute := time.Now().Format("2006-01-02")
	if heute != o.tag {
		o.tag = heute
		o.gesehen = map[string]bool{}
		o.aufraeumen()
	}
	f, err := os.OpenFile(filepath.Join(o.dir, "trail-"+heute+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	letzter := o.letzter
	var neu []string
	for _, e := range l {
		if o.gesehen[e.Kennung] {
			continue
		}
		// Wie auf dem Server: Zeit in Mikrosekunden, damit der Hash stimmt.
		e.Zeit = e.Zeit.Truncate(time.Microsecond)
		z := Zeile{Ereignis: e, Host: o.host, Vorher: letzter}
		z.Hash = ereignis.Hash(letzter, e)
		if err := enc.Encode(z); err != nil {
			f.Close()
			return err
		}
		letzter = z.Hash
		neu = append(neu, e.Kennung)
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	o.letzter = letzter
	for _, k := range neu {
		o.gesehen[k] = true
	}
	return nil
}

// aufraeumen löscht Tagesdateien, die älter sind als die Aufbewahrung.
func (o *ablage) aufraeumen() {
	if o.tage <= 0 {
		return
	}
	grenze := time.Now().AddDate(0, 0, -o.tage).Format("2006-01-02")
	for _, p := range trailDateien(o.dir) {
		tag := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(p), "trail-"), ".jsonl")
		if tag < grenze {
			os.Remove(p)
		}
	}
}

// ---------- Befehle: pruefen und zeigen ----------

type pruefung struct {
	Dateien, Zeilen int
	Bruch           string
}

// kettePruefen rechnet alle Dateien in Reihenfolge nach. Die erste Datei
// darf mit einem fremden Vorgänger beginnen (ältere wurden aufgeräumt), danach
// muss jede Zeile genau an die vorige anschließen.
func kettePruefen(dir string) pruefung {
	var p pruefung
	letzter := ""
	erste := true
	for _, d := range trailDateien(dir) {
		p.Dateien++
		n := 0
		err := zeilenLesen(d, func(z Zeile) error {
			n++
			p.Zeilen++
			if !erste && z.Vorher != letzter {
				return fmt.Errorf("Zeile %d schließt nicht an (Eintrag davor fehlt oder wurde geändert)", n)
			}
			erste = false
			if ereignis.Hash(z.Vorher, z.Ereignis) != z.Hash {
				return fmt.Errorf("Zeile %d wurde geändert (%s %s, %s)", n, z.Art, z.Benutzer, z.Zeit.Local().Format("02.01. 15:04:05"))
			}
			letzter = z.Hash
			return nil
		})
		if err != nil {
			p.Bruch = filepath.Base(d) + ": " + err.Error()
			return p
		}
	}
	return p
}

func ordnerAusUmgebung() string { return umgebung("TRAILR_ORDNER", "/var/log/trailr") }

func befehlPruefen(args []string, aus io.Writer) int {
	fs := flag.NewFlagSet("pruefen", flag.ExitOnError)
	dir := fs.String("ordner", ordnerAusUmgebung(), "Ordner mit den Tagesdateien")
	fs.Parse(args)
	if len(trailDateien(*dir)) == 0 {
		fmt.Fprintf(aus, "Keine Trails in %s\n", *dir)
		return 1
	}
	p := kettePruefen(*dir)
	if p.Bruch != "" {
		fmt.Fprintf(aus, "KETTE GEBROCHEN nach %d Einträgen: %s\n", p.Zeilen, p.Bruch)
		return 2
	}
	fmt.Fprintf(aus, "Kette unverändert: %d Einträge in %d Dateien\n", p.Zeilen, p.Dateien)
	return 0
}

func befehlZeigen(args []string, aus io.Writer) int {
	fs := flag.NewFlagSet("zeigen", flag.ExitOnError)
	dir := fs.String("ordner", ordnerAusUmgebung(), "Ordner mit den Tagesdateien")
	n := fs.Int("n", 50, "so viele der neuesten Einträge")
	benutzer := fs.String("benutzer", "", "nur dieser Benutzer")
	art := fs.String("art", "", "nur diese Art: "+strings.Join(ereignis.Arten, ", "))
	tag := fs.String("tag", "", "nur dieser Tag (2026-11-19)")
	fs.Parse(args)
	dateien := trailDateien(*dir)
	if *tag != "" {
		dateien = []string{filepath.Join(*dir, "trail-"+*tag+".jsonl")}
	}
	var l []Zeile
	for _, d := range dateien {
		err := zeilenLesen(d, func(z Zeile) error {
			if (*benutzer == "" || z.Benutzer == *benutzer) && (*art == "" || z.Art == *art) {
				l = append(l, z)
				if *n > 0 && len(l) > *n*4 {
					l = l[len(l)-*n:]
				}
			}
			return nil
		})
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(aus, "%s: %v\n", d, err)
		}
	}
	if *n > 0 && len(l) > *n {
		l = l[len(l)-*n:]
	}
	tw := tabwriter.NewWriter(aus, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ZEIT\tART\tBENUTZER\tALS\tQUELLE\tOK\tWAS")
	for _, z := range l {
		ok := "ja"
		if !z.Erfolg {
			ok = "NEIN"
		}
		text := strings.ReplaceAll(z.Text, "\n", " ")
		if len(text) > 120 {
			text = text[:120] + "…"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", z.Zeit.Local().Format("02.01. 15:04:05"), z.Art, z.Benutzer, z.Als, z.Quelle, ok, text)
	}
	tw.Flush()
	return 0
}
