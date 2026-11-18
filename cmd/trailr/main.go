// Trailr: Protokolliert, was Benutzer auf Linux-Systemen tun: Anmeldungen, Befehle, sudo, Änderungen. Zentral und manipulationssicher.
//
// Grundgerüst: der Server startet, liefert die Startseite aus und antwortet auf
// /healthz und /api/version. Was als Nächstes kommt, steht in der README.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

//go:embed web
var webDateien embed.FS

// version wird beim Bau gesetzt: -ldflags "-X main.version=v0.1.0".
var version = "entwicklung"

func main() {
	adresse := ":" + umgebung("TRAILR_PORT", "8400")
	srv := &http.Server{
		Addr:              adresse,
		Handler:           neuerMux(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		log.Printf("Trailr %s lauscht auf %s", version, adresse)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
	}()
	<-ctx.Done()

	ende, abbruch := context.WithTimeout(context.Background(), 10*time.Second)
	defer abbruch()
	if err := srv.Shutdown(ende); err != nil {
		log.Printf("Beenden: %v", err)
	}
}

func neuerMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /api/version", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"name": "trailr", "version": version})
	})
	web, err := fs.Sub(webDateien, "web")
	if err != nil {
		log.Fatal(err)
	}
	mux.Handle("GET /", http.FileServerFS(web))
	return sicherheitskopf(mux)
}

// sicherheitskopf setzt die Kopfzeilen, die jede Antwort tragen soll.
func sicherheitskopf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k := w.Header()
		k.Set("X-Content-Type-Options", "nosniff")
		k.Set("Referrer-Policy", "no-referrer")
		k.Set("X-Frame-Options", "DENY")
		k.Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
		next.ServeHTTP(w, r)
	})
}

func umgebung(name, vorgabe string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return vorgabe
}
