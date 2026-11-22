// trailr-agent läuft auf jedem Linux-Host und hält Benutzeraktionen fest,
// im eigenen Ordner (TRAILR_ORDNER), beim Trailr-Server oder beides: Anmeldungen (SSH), sudo, su, Sitzungen aus dem Journal und,
// wenn auditd läuft, ausgeführte Befehle und Änderungen an überwachten Pfaden.
//
// Nichts geht verloren, wenn der Server fehlt: jedes Paket landet zuerst in
// einem Puffer auf der Platte, erst dann rücken die Lesemarken vor; geleert
// wird der Puffer, wenn der Server den Empfang bestätigt.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"trailr/internal/ereignis"
)

var version = "entwicklung"

type agent struct {
	server, schluessel, host string
	dir                      string
	client                   *http.Client
	ordner                   *ablage

	mu       sync.Mutex
	warte    []ereignis.Ereignis
	journal  string // Lesemarke Journal (Cursor)
	auditPos auditStand
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "pruefen":
			os.Exit(befehlPruefen(os.Args[2:], os.Stdout))
		case "zeigen":
			os.Exit(befehlZeigen(os.Args[2:], os.Stdout))
		case "version":
			fmt.Println(version)
			return
		}
	}
	server := flag.String("server", os.Getenv("TRAILR_SERVER"), "Adresse des Servers, z. B. https://10.0.2.7:8400")
	dir := flag.String("stand", umgebung("TRAILR_STAND", "/var/lib/trailr"), "Verzeichnis für Puffer und Lesemarken")
	audit := flag.String("audit", umgebung("TRAILR_AUDIT_LOG", "/var/log/audit/audit.log"), "auditd-Protokoll")
	ordner := flag.String("ordner", os.Getenv("TRAILR_ORDNER"), "Trails selbst in diesem Ordner ablegen, z. B. /var/log/trailr")
	tage := flag.Int("tage", 0, "Tagesdateien im Ordner so viele Tage behalten (0: alle)")
	flag.Parse()
	if *tage == 0 {
		fmt.Sscan(os.Getenv("TRAILR_ORDNER_TAGE"), tage)
	}
	schluessel := os.Getenv("TRAILR_SCHLUESSEL")
	if *server == "" && *ordner == "" {
		log.Fatal("TRAILR_ORDNER (ohne Server) oder TRAILR_SERVER mit TRAILR_SCHLUESSEL setzen")
	}
	if *server != "" {
		if schluessel == "" {
			log.Fatal("Zu TRAILR_SERVER gehört TRAILR_SCHLUESSEL")
		}
		// Der Schlüssel geht nie unverschlüsselt über das Netz.
		if !strings.HasPrefix(*server, "https://") && os.Getenv("TRAILR_UNSICHER") != "1" {
			log.Fatal("TRAILR_SERVER muss mit https:// beginnen")
		}
	}
	host, _ := os.Hostname()
	if h := os.Getenv("TRAILR_HOST"); h != "" {
		host = h
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		log.Fatal(err)
	}
	client, err := neuerClient(os.Getenv("TRAILR_ZERTIFIKAT"), os.Getenv("TRAILR_ZERTIFIKAT_SCHLUESSEL"), os.Getenv("TRAILR_CA"))
	if err != nil {
		log.Fatalf("TLS: %v", err)
	}
	a := &agent{server: strings.TrimRight(*server, "/"), schluessel: schluessel, host: host, dir: *dir,
		client: client}
	if *ordner != "" {
		o, err := neueAblage(*ordner, host, *tage)
		if err != nil {
			log.Fatalf("Ordner: %v", err)
		}
		a.ordner = o
	}
	a.journal = a.lesen("journal.cursor")
	json.Unmarshal([]byte(a.lesen("audit.stand")), &a.auditPos)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ziele := []string{}
	if a.ordner != nil {
		ziele = append(ziele, "Ordner "+a.ordner.dir)
	}
	if a.server != "" {
		ziele = append(ziele, "Server "+a.server)
	}
	log.Printf("trailr-agent %s auf %s, %s", version, host, strings.Join(ziele, " und "))

	go a.journalLesen(ctx)
	go a.auditLesen(ctx, *audit)
	a.senden(ctx)
}

func umgebung(n, v string) string {
	if x := os.Getenv(n); x != "" {
		return x
	}
	return v
}

func (a *agent) lesen(name string) string {
	b, _ := os.ReadFile(filepath.Join(a.dir, name))
	return strings.TrimSpace(string(b))
}

func (a *agent) schreiben(name, inhalt string) {
	p := filepath.Join(a.dir, name)
	t := p + ".neu"
	if err := os.WriteFile(t, []byte(inhalt), 0o600); err == nil {
		os.Rename(t, p)
	}
}

// melden nimmt ein Ereignis aus einer Quelle auf und merkt sich deren Stand.
func (a *agent) melden(e ereignis.Ereignis, journal string, audit *auditStand) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.warte = append(a.warte, e)
	if journal != "" {
		a.journal = journal
	}
	if audit != nil {
		a.auditPos = *audit
	}
}

// senden: alle drei Sekunden in den Puffer, Lesemarken sichern, Puffer
// verschicken. Beim Beenden noch einmal.
func (a *agent) senden(ctx context.Context) {
	takt := time.NewTicker(3 * time.Second)
	defer takt.Stop()
	fehler := 0
	for {
		select {
		case <-ctx.Done():
			a.puffern()
			a.verschicken()
			return
		case <-takt.C:
		}
		a.puffern()
		if err := a.verschicken(); err != nil {
			fehler++
			if fehler == 1 || fehler%100 == 0 {
				log.Printf("Server nicht erreichbar, puffere: %v", err)
			}
		} else {
			if fehler > 0 {
				log.Printf("Server wieder erreichbar")
			}
			fehler = 0
		}
	}
}

func (a *agent) puffer() string { return filepath.Join(a.dir, "puffer.jsonl") }

func (a *agent) puffern() {
	a.mu.Lock()
	l := a.warte
	a.warte = nil
	journal, audit := a.journal, a.auditPos
	a.mu.Unlock()
	if a.ordner != nil {
		if err := a.ordner.ablegen(l); err != nil {
			log.Printf("Ordner: %v", err)
			a.mu.Lock()
			a.warte = append(l, a.warte...)
			a.mu.Unlock()
			return
		}
	}
	if len(l) > 0 && a.server != "" {
		f, err := os.OpenFile(a.puffer(), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			log.Printf("Puffer: %v", err)
			a.mu.Lock()
			a.warte = append(l, a.warte...)
			a.mu.Unlock()
			return
		}
		enc := json.NewEncoder(f)
		for _, e := range l {
			enc.Encode(e)
		}
		f.Sync()
		f.Close()
	}
	// Erst wenn die Ereignisse sicher im Puffer stehen, rücken die Marken vor.
	if journal != "" {
		a.schreiben("journal.cursor", journal)
	}
	if b, err := json.Marshal(audit); err == nil {
		a.schreiben("audit.stand", string(b))
	}
}

func (a *agent) verschicken() error {
	if a.server == "" {
		return nil
	}
	f, err := os.Open(a.puffer())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var l []ereignis.Ereignis
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e ereignis.Ereignis
		if json.Unmarshal(sc.Bytes(), &e) == nil {
			l = append(l, e)
		}
	}
	f.Close()
	if len(l) == 0 {
		os.Remove(a.puffer())
		return nil
	}
	for i := 0; i < len(l); i += 2000 {
		j := min(i+2000, len(l))
		if err := a.post(l[i:j]); err != nil {
			// Was schon angekommen ist, nicht noch einmal: der Server verwirft
			// Doppeltes ohnehin, aber der Puffer soll schrumpfen.
			if i > 0 {
				a.pufferErsetzen(l[i:])
			}
			return err
		}
	}
	os.Remove(a.puffer())
	return nil
}

func (a *agent) pufferErsetzen(rest []ereignis.Ereignis) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, e := range rest {
		enc.Encode(e)
	}
	a.schreiben("puffer.jsonl", b.String())
}

func (a *agent) post(l []ereignis.Ereignis) error {
	b, _ := json.Marshal(ereignis.Lieferung{Host: a.host, Agent: version, Ereignisse: l})
	req, err := http.NewRequest(http.MethodPost, a.server+"/api/lieferung", bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+a.schluessel)
	req.Header.Set("X-Trailr-Host", a.host)
	req.Header.Set("Content-Type", "application/json")
	res, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("Server antwortet %d", res.StatusCode)
	}
	return nil
}
