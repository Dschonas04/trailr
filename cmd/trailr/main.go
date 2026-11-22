// Trailr: protokolliert, was Benutzer auf Linux-Systemen tun. Agenten auf den
// Hosts liefern Anmeldungen, sudo, su, Sitzungen, Befehle und Dateiänderungen;
// der Server speichert sie je Host in einer Hash-Kette und zeigt sie an.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type App struct {
	// verwaltung: Änderungen an Konten, Rollen und Anmeldung laufen nacheinander.
	verwaltung Sperre
	admins     []string // Vorgabe des Betreibers
	db         *pgxpool.Pool
	sso        *SSO
	v          Vorlagen
	schluessel string // Agent-Schlüssel
	tage       int    // Aufbewahrung
	agentDatei string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	a := &App{
		db:         datenbank(ctx, umgebung("TRAILR_DB", "postgres://trailr:trailr@localhost:5432/trailr?sslmode=disable")),
		sso:        NeuesSSO("Trailr", umgebung("TRAILR_SSO_DATEI", "./einstellungen/sso.json"), "TRAILR_SSO_AUS"),
		v:          ladeVorlagen(),
		schluessel: umgebung("TRAILR_AGENT_SCHLUESSEL", ""),
		tage:       zahl(umgebung("TRAILR_AUFBEWAHRUNG_TAGE", "365")),
		agentDatei: umgebung("TRAILR_AGENT_DATEI", "/usr/local/share/trailr/trailr-agent"),
	}
	if len(a.schluessel) < 24 {
		log.Fatal("TRAILR_AGENT_SCHLUESSEL fehlt oder ist kürzer als 24 Zeichen")
	}
	// Agenten liefern mit eigenem Schlüssel, ohne Sitzung; das Programm des
	// Agenten ist kein Geheimnis.
	a.admins = adminListe(umgebung("TRAILR_ADMIN", ""))
	a.sso.ErstesKonto = a.ersterAdmin
	a.sso.KontoWeg = a.adminEntziehen
	a.sso.Frei = []string{"/statisch/", "/healthz", "/api/lieferung", "/agent/"}
	go a.aufraeumen(ctx)

	adresse := ":" + umgebung("TRAILR_PORT", "8400")
	srv := &http.Server{Addr: adresse, Handler: a.wege(), ReadHeaderTimeout: 10 * time.Second}
	go func() {
		log.Printf("Trailr %s lauscht auf %s", version, adresse)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	<-ctx.Done()
	ende, abbruch := context.WithTimeout(context.Background(), 10*time.Second)
	defer abbruch()
	srv.Shutdown(ende)
}

func (a *App) wege() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /healthz", gesund)
	m.HandleFunc("GET /favicon.svg", logo)
	m.HandleFunc("GET /favicon.ico", logo)
	m.Handle("GET /statisch/", statisch())
	a.sso.Wege(m, a.angemeldet)
	m.HandleFunc("POST /api/lieferung", a.agentPruefen(a.lieferung))
	m.HandleFunc("GET /agent/trailr-agent", a.agentProgramm)
	m.HandleFunc("GET /agent/trailr-agent.sha256", a.agentPruefsumme)
	m.HandleFunc("GET /{$}", a.start)
	m.HandleFunc("GET /ereignisse", a.ereignisse)
	m.HandleFunc("GET /pruefen", a.pruefenSeite)
	m.HandleFunc("GET /einrichten", a.nurAdmin(a.einrichten))
	return sicherheitskopf(nurAngemeldet(a.sso, m))
}

func (a *App) angemeldet(h http.HandlerFunc) http.HandlerFunc {
	// Anmeldung und Konten verwalten nur Admins; vor der Einrichtung, wer den
	// Code aus dem Log hat.
	darf := func(w http.ResponseWriter, r *http.Request) bool {
		if !a.sso.Geschuetzt() && a.sso.EinrichtungErlaubt(w, r) {
			return true
		}
		if _, ok := a.sso.Wer(r); !ok {
			http.Error(w, "Bitte anmelden", http.StatusUnauthorized)
			return false
		}
		if !a.istAdmin(r) {
			http.Error(w, "Nur für Admins", http.StatusForbidden)
			return false
		}
		return true
	}
	return func(w http.ResponseWriter, r *http.Request) {
		if !inhaltZuerst(w, r) {
			return
		}
		// Lesen und Testen ändern nichts und brauchen keine Sperre.
		if r.Method == http.MethodGet || r.Method == http.MethodHead || r.URL.Path == "/api/sso/testen" {
			if darf(w, r) {
				h(w, r)
			}
			return
		}
		// Der Anbieter wird vor der Sperre gefragt, und nur von Admins.
		if r.URL.Path == "/api/sso/einstellungen" {
			if !darf(w, r) {
				return
			}
			roh, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Die Anfrage ist unvollständig", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(roh))
			var ok bool
			if r, ok = a.sso.ausstellerVorab(w, r, roh); !ok {
				return
			}
		}
		// Erst sperren, dann prüfen: bis zum Speichern kann niemand die Rechte
		// entziehen, auf die sich die Prüfung stützt.
		a.verwaltung.fuehreAus(w, r, func(w http.ResponseWriter, r *http.Request) {
			if darf(w, r) {
				h(w, r)
			}
		})
	}
}

// hostSchluessel: jeder Host liefert mit einem eigenen Schlüssel, abgeleitet
// aus dem Hauptschlüssel und seinem Namen. Wer einen Host übernimmt, kann
// damit nur in dessen Namen schreiben, nicht für andere.
func hostSchluessel(haupt, host string) string {
	h := sha256.Sum256([]byte(haupt + ":" + host))
	return hex.EncodeToString(h[:])
}

func (a *App) agentPruefen(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Trailr-Host")
		k := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !hostMuster.MatchString(host) || subtle.ConstantTimeCompare([]byte(k), []byte(hostSchluessel(a.schluessel, host))) != 1 {
			alsJSON(w, http.StatusUnauthorized, map[string]string{"fehler": "Agent-Schlüssel falsch"})
			return
		}
		h(w, r, host)
	}
}

func (a *App) daten(r *http.Request, titel, nav string, d any) Daten {
	n, _ := a.sso.Wer(r)
	return Daten{App: "Trailr", Titel: titel, Nav: nav, Nutzer: n, Admin: a.istAdmin(r), D: d}
}

func zahl(s string) int {
	n := 0
	for _, c := range strings.TrimSpace(s) {
		if c < '0' || c > '9' {
			return n
		}
		n = n*10 + int(c-'0')
	}
	return n
}
