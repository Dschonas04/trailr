// Trailr: protokolliert, was Benutzer auf Linux-Systemen tun. Agenten auf den
// Hosts liefern Anmeldungen, sudo, su, Sitzungen, Befehle und Dateiänderungen;
// der Server speichert sie je Host in einer Hash-Kette und zeigt sie an.
package main

import (
	"context"
	"crypto/subtle"
	"errors"
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
	m.Handle("GET /statisch/", statisch())
	a.sso.Wege(m, a.angemeldet)
	m.HandleFunc("POST /api/lieferung", a.agentPruefen(a.lieferung))
	m.HandleFunc("GET /agent/trailr-agent", a.agentProgramm)
	m.HandleFunc("GET /{$}", a.start)
	m.HandleFunc("GET /ereignisse", a.ereignisse)
	m.HandleFunc("GET /pruefen", a.pruefenSeite)
	m.HandleFunc("GET /einrichten", a.einrichten)
	return sicherheitskopf(nurAngemeldet(a.sso, m))
}

func (a *App) angemeldet(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := a.sso.Wer(r); ok || (!a.sso.Geschuetzt() && a.sso.EinrichtungErlaubt(w, r)) {
			h(w, r)
			return
		}
		http.Error(w, "Bitte anmelden", http.StatusUnauthorized)
	}
}

func (a *App) agentPruefen(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		k := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(k), []byte(a.schluessel)) != 1 {
			alsJSON(w, http.StatusUnauthorized, map[string]string{"fehler": "Agent-Schlüssel falsch"})
			return
		}
		h(w, r)
	}
}

func (a *App) daten(r *http.Request, titel, nav string, d any) Daten {
	n, _ := a.sso.Wer(r)
	return Daten{App: "Trailr", Titel: titel, Nav: nav, Nutzer: n, D: d}
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
