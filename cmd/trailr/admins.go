package main

import (
	"log"
	"net/http"
)

// istAdmin: Die erste Person, die sich anmeldet, verwaltet die App (wie in
// Ticketr). Anmeldung, Konten und Verwaltung sind für alle anderen zu. Im
// Notaus ist die Sperre ohnehin offen.
func (a *App) istAdmin(r *http.Request) bool {
	if a.sso.notaus {
		return true
	}
	n, ok := a.sso.Wer(r)
	if !ok {
		return false
	}
	kennung := n.Kennung
	if kennung == "" {
		kennung = "lokal:" + n.Nutzer
	}
	// erster ist eindeutig: melden sich zwei zugleich an, gewinnt eine Person.
	if _, err := a.db.Exec(r.Context(), `INSERT INTO admins (kennung, erster)
		SELECT $1, true WHERE NOT EXISTS (SELECT 1 FROM admins)
		ON CONFLICT DO NOTHING`, kennung); err != nil {
		log.Printf("admins: %v", err)
		return false
	}
	var ja bool
	if err := a.db.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM admins WHERE kennung = $1)`, kennung).Scan(&ja); err != nil {
		log.Printf("admins: %v", err)
		return false
	}
	return ja
}

// nurAdmin schützt die Verwaltung der App.
func (a *App) nurAdmin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.istAdmin(r) {
			http.Error(w, "Nur für Admins", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}
