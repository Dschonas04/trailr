package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

const exportGrenze = 100000

// export streamt die Treffer, statt sie vorher zu sammeln.
func (a *App) export(w http.ResponseWriter, r *http.Request, f Filter, format string) {
	typ, kopf, fuss := "text/csv; charset=utf-8", "zeit;host;art;benutzer;als;sitzung;quelle;erfolg;text\n", ""
	if format == "json" {
		typ, kopf, fuss = "application/json", "[", "]\n"
	}
	n := 0
	beginn := func() error {
		w.Header().Set("Content-Type", typ)
		w.Header().Set("Content-Disposition", `attachment; filename="trailr.`+format+`"`)
		_, err := w.Write([]byte(kopf))
		return err
	}
	err := a.durchgehen(r.Context(), f, exportGrenze, false, func(z Zeile) error {
		if n == 0 {
			if err := beginn(); err != nil {
				return err
			}
		}
		n++
		if format == "json" {
			if n > 1 {
				if _, err := w.Write([]byte(",")); err != nil {
					return err
				}
			}
			return json.NewEncoder(w).Encode(z)
		}
		_, err := fmt.Fprintf(w, "%s;%s;%s;%s;%s;%s;%s;%t;%s\n", z.Zeit.Format(time.RFC3339), csv(z.Host), csv(z.Art), csv(z.Benutzer),
			csv(z.Als), csv(z.Sitzung), csv(z.Quelle), z.Erfolg, csv(z.Text))
		return err
	})
	if err != nil {
		log.Printf("Export: %v", err)
		if n == 0 {
			http.Error(w, "Der Export ging nicht", http.StatusInternalServerError)
		}
		// Mittendrin bleibt die Datei ohne Schluss, statt vollständig auszusehen.
		return
	}
	if n == 0 {
		if err := beginn(); err != nil {
			return
		}
	}
	if _, err := w.Write([]byte(fuss)); err != nil {
		log.Printf("Export: %v", err)
	}
}
