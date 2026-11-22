package main

import (
	"context"
	"log"
	"net/http"
	"slices"
	"strings"
)

// adminListe liest die Vorgabe des Betreibers: Kennungen mit Komma getrennt,
// konto:<name> oder oidc:<Aussteller>|<sub>.
func adminListe(s string) []string {
	var l []string
	for _, e := range strings.Split(s, ",") {
		if e = strings.TrimSpace(e); e != "" {
			l = append(l, e)
		}
	}
	return l
}

// istAdmin liest nur. Admin ist, wen der Betreiber vorgibt oder wer die App mit
// dem Code aus dem Log eingerichtet hat. Im Notaus ist die Sperre ohnehin offen.
func (a *App) istAdmin(r *http.Request) bool {
	if a.sso.notaus {
		return true
	}
	n, ok := a.sso.Wer(r)
	if !ok {
		return false
	}
	if slices.Contains(a.admins, n.Kennung) {
		return true
	}
	var ja bool
	if err := a.db.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM admins WHERE kennung = $1)`, n.Kennung).Scan(&ja); err != nil {
		log.Printf("admins: %v", err)
		return false
	}
	return ja
}

// ersterAdmin läuft, wenn mit dem Einrichtungscode das erste Konto entsteht.
func (a *App) ersterAdmin(ctx context.Context, kennung, _ string) error {
	_, err := a.db.Exec(ctx, `INSERT INTO admins (kennung) VALUES ($1) ON CONFLICT DO NOTHING`, kennung)
	return err
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

// adminEntziehen läuft vor dem Löschen eines Kontos und vor dem Anlegen eines
// neuen mit demselben Namen: ein Name erbt keine Rechte.
func (a *App) adminEntziehen(ctx context.Context, kennung string) error {
	_, err := a.db.Exec(ctx, `DELETE FROM admins WHERE kennung = $1`, kennung)
	return err
}
