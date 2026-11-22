// Baukasten, in allen eigenen Apps derselbe: Datenbank, Seitenvorlagen,
// Formularschutz, Kopfzeilen. Die Anmeldung steckt in sso.go.
package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed web
var webDateien embed.FS

//go:embed schema.sql
var schemaSQL string

// version wird beim Bau gesetzt: -ldflags "-X main.version=v0.1.0".
var version = "entwicklung"

func umgebung(name, vorgabe string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return vorgabe
}

// datenbank verbindet sich und spielt das Schema ein. Das Schema ist
// idempotent (IF NOT EXISTS), ein Neustart ändert nichts.
func datenbank(ctx context.Context, adresse string) *pgxpool.Pool {
	var pool *pgxpool.Pool
	var err error
	// Beim gemeinsamen Start mit Compose ist Postgres manchmal noch nicht da.
	for versuch := 0; versuch < 30; versuch++ {
		pool, err = pgxpool.New(ctx, adresse)
		if err == nil {
			if err = pool.Ping(ctx); err == nil {
				break
			}
			pool.Close()
		}
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatalf("Datenbank: %v", err)
	}
	if _, err := pool.Exec(ctx, schemaSQL); err != nil {
		log.Fatalf("Schema: %v", err)
	}
	return pool
}

// ---------- Seiten ----------

// Vorlagen hält je Seite ein Template aus layout.html und der Seite selbst.
type Vorlagen map[string]*template.Template

var vorlagenFunktionen = template.FuncMap{
	"datum": func(t any) string {
		switch v := t.(type) {
		case time.Time:
			if v.IsZero() {
				return ""
			}
			return v.Local().Format("02.01.2006 15:04")
		case *time.Time:
			if v == nil {
				return ""
			}
			return v.Local().Format("02.01.2006 15:04")
		}
		return ""
	},
	"tag": func(t time.Time) string { return t.Local().Format("02.01.2006") },
	// feld: Wert für ein datetime-local-Feld.
	"feld": func(t *time.Time) string {
		if t == nil {
			return ""
		}
		return t.Local().Format("2006-01-02T15:04")
	},
	"seit": func(t time.Time) string {
		d := time.Since(t)
		switch {
		case d < time.Minute:
			return "gerade eben"
		case d < time.Hour:
			return "vor " + itoa(int(d.Minutes())) + " min"
		case d < 24*time.Hour:
			return "vor " + itoa(int(d.Hours())) + " h"
		}
		if tage := int(d.Hours() / 24); tage > 1 {
			return "vor " + itoa(tage) + " Tagen"
		}
		return "vor 1 Tag"
	},
	"gleich": func(a, b any) bool { return a == b },
	"mehrzahl": func(n int, eins, viele string) string {
		if n == 1 {
			return "1 " + eins
		}
		return itoa(n) + " " + viele
	},
	"kuerzel": kuerzel,
	"json": func(v any) template.JS {
		b, _ := json.Marshal(v)
		return template.JS(b)
	},
	"mehrzeilig": func(s string) template.HTML {
		return template.HTML(strings.ReplaceAll(template.HTMLEscapeString(s), "\n", "<br>"))
	},
}

// kuerzel: bis zu zwei Anfangsbuchstaben für das runde Namenszeichen.
func kuerzel(name string) string {
	var k []rune
	for _, wort := range strings.Fields(name) {
		if len(k) < 2 {
			k = append(k, []rune(wort)[0])
		}
	}
	return strings.ToUpper(string(k))
}

func itoa(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func ladeVorlagen() Vorlagen {
	v := Vorlagen{}
	seiten, err := fs.Glob(webDateien, "web/seiten/*.html")
	if err != nil {
		log.Fatal(err)
	}
	for _, s := range seiten {
		name := strings.TrimSuffix(strings.TrimPrefix(s, "web/seiten/"), ".html")
		v[name] = template.Must(template.New("layout.html").Funcs(vorlagenFunktionen).
			ParseFS(webDateien, "web/layout.html", "web/nav.html", s))
	}
	return v
}

// Daten ist, was jede Seite bekommt.
type Daten struct {
	App     string
	Titel   string
	Nav     string
	Nutzer  SSONutzer
	Token   string
	Hinweis string
	Fehler  string
	D       any
}

func (v Vorlagen) zeigen(w http.ResponseWriter, r *http.Request, seite string, d Daten) {
	t, ok := v[seite]
	if !ok {
		http.Error(w, "Seite fehlt: "+seite, http.StatusInternalServerError)
		return
	}
	if d.Hinweis == "" {
		d.Hinweis = r.URL.Query().Get("hinweis")
	}
	d.Token = formToken(w, r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, d); err != nil {
		log.Printf("Vorlage %s: %v", seite, err)
	}
}

// ---------- Formularschutz ----------

// formToken: Double-Submit-Keks. Jedes Formular trägt den Wert als verstecktes
// Feld, pruefeFormular vergleicht. Dazu prüft es die Herkunft.
func formToken(w http.ResponseWriter, r *http.Request) string {
	if k, err := r.Cookie("formular"); err == nil && len(k.Value) == 32 {
		return k.Value
	}
	b := make([]byte, 16)
	rand.Read(b)
	t := hex.EncodeToString(b)
	http.SetCookie(w, &http.Cookie{Name: "formular", Value: t, Path: "/", HttpOnly: true,
		Secure: ssoSicher(r), SameSite: http.SameSiteLaxMode})
	return t
}

func pruefeFormular(w http.ResponseWriter, r *http.Request) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<20)
	k, err := r.Cookie("formular")
	if !ssoGleicheHerkunft(r) || err != nil || k.Value == "" || r.FormValue("token") != k.Value {
		http.Error(w, "Das Formular ist abgelaufen. Bitte die Seite neu laden.", http.StatusForbidden)
		return false
	}
	return true
}

// zurueck leitet nach einem Formular weiter, mit kurzer Meldung.
func zurueck(w http.ResponseWriter, r *http.Request, ziel, hinweis string) {
	if hinweis != "" {
		if strings.Contains(ziel, "?") {
			ziel += "&"
		} else {
			ziel += "?"
		}
		ziel += "hinweis=" + urlEscape(hinweis)
	}
	http.Redirect(w, r, ziel, http.StatusSeeOther)
}

func urlEscape(s string) string { return url.QueryEscape(s) }

func alsJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// ---------- Kopfzeilen ----------

func sicherheitskopf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k := w.Header()
		k.Set("X-Content-Type-Options", "nosniff")
		k.Set("Referrer-Policy", "same-origin")
		if k.Get("X-Frame-Options") == "" {
			k.Set("X-Frame-Options", "SAMEORIGIN")
		}
		if k.Get("Content-Security-Policy") == "" {
			k.Set("Content-Security-Policy", cspStandard)
		}
		next.ServeHTTP(w, r)
	})
}

var cspStandard = "default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'self'"

// nurAngemeldet schützt die App. Solange weder SSO noch ein Konto
// eingerichtet ist, führt jeder Weg zur Einrichtung des ersten Kontos: eine
// frisch gestartete App ist nie offen.
func nurAngemeldet(s *SSO, n http.Handler) http.Handler {
	geschuetzt := s.Schutz(n)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.Geschuetzt() && !s.notaus && !s.frei(r.URL.Path) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				alsJSON(w, http.StatusUnauthorized, map[string]string{"fehler": "Anmeldung noch nicht eingerichtet"})
				return
			}
			http.Redirect(w, r, "/sso/konten?"+r.URL.RawQuery, http.StatusFound)
			return
		}
		geschuetzt.ServeHTTP(w, r)
	})
}

// statisch liefert web/statisch aus (CSS, JS, Bilder).
func statisch() http.Handler {
	sub, err := fs.Sub(webDateien, "web/statisch")
	if err != nil {
		log.Fatal(err)
	}
	fsrv := http.StripPrefix("/statisch/", http.FileServerFS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		fsrv.ServeHTTP(w, r)
	})
}

// logo liefert das Zeichen der App unter den Adressen, die Anmeldeseite und Browser erwarten.
func logo(w http.ResponseWriter, _ *http.Request) {
	b, err := webDateien.ReadFile("web/statisch/zeichen.svg")
	if err != nil {
		http.Error(w, "Zeichen fehlt", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "no-cache")
	w.Write(b)
}

func gesund(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) }
