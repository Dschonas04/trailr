package main

import (
	"net/http"
	"time"
)

// Sitzungsnummern beginnen nach jedem Neustart von vorn. Eine Zeitleiste zeigt
// deshalb nur die Tage um das Ereignis, von dem aus man sie öffnet.
const sitzungFenster = 3 * 24 * time.Hour

func (a *App) sitzung(w http.ResponseWriter, r *http.Request) {
	var host, nummer string
	var um time.Time
	if err := a.db.QueryRow(r.Context(), `SELECT h.name, e.sitzung, e.zeit FROM ereignisse e JOIN hosts h ON h.id = e.host
		WHERE e.id::text = $1 AND e.sitzung <> ''`, r.PathValue("id")).Scan(&host, &nummer, &um); err != nil {
		http.NotFound(w, r)
		return
	}
	var l []Zeile
	f := Filter{Host: host, Sitzung: nummer, ab: um.Add(-sitzungFenster), vor: um.Add(sitzungFenster)}
	if err := a.durchgehen(r.Context(), f, 5000, true, func(z Zeile) error { l = append(l, z); return nil }); err != nil {
		http.Error(w, "Datenbank", http.StatusInternalServerError)
		return
	}
	d := map[string]any{"Host": host, "Nummer": nummer, "Liste": l, "Voll": len(l) == 5000}
	if len(l) > 0 {
		d["Von"], d["Bis"] = l[0].Zeit, l[len(l)-1].Zeit
		d["Dauer"] = l[len(l)-1].Zeit.Sub(l[0].Zeit).Round(time.Second).String()
	}
	a.v.zeigen(w, r, "sitzung", a.daten(r, "Sitzung "+nummer+" auf "+host, "ereignisse", d))
}
