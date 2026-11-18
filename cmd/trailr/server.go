package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trailr/internal/ereignis"
)

var hostMuster = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.\-]{0,62}$`)

// lieferung nimmt ein Paket des Agenten an. Je Host wird in einer
// Transaktion verkettet, die Zeile des Hosts ist dabei gesperrt: zwei
// gleichzeitige Pakete eines Hosts können die Kette nicht verzweigen.
func (a *App) lieferung(w http.ResponseWriter, r *http.Request, host string) {
	var l ereignis.Lieferung
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&l); err != nil {
		alsJSON(w, 400, map[string]string{"fehler": "unlesbar"})
		return
	}
	// Der Host kommt aus dem Schlüssel, nicht aus dem Paket.
	if l.Host != host || len(l.Ereignisse) > 5000 {
		alsJSON(w, 400, map[string]string{"fehler": "Host oder Menge ungültig"})
		return
	}
	ctx := r.Context()
	tx, err := a.db.Begin(ctx)
	if err != nil {
		alsJSON(w, 500, map[string]string{"fehler": err.Error()})
		return
	}
	defer tx.Rollback(ctx)
	var hostID, vorher string
	if err := tx.QueryRow(ctx, `INSERT INTO hosts (name, zuletzt, agent) VALUES ($1, now(), $2)
		ON CONFLICT (name) DO UPDATE SET zuletzt = now(), agent = $2 RETURNING id::text`, l.Host, kuerzen(l.Agent, 40)).Scan(&hostID); err != nil {
		alsJSON(w, 500, map[string]string{"fehler": err.Error()})
		return
	}
	if err := tx.QueryRow(ctx, `SELECT letzter_hash FROM hosts WHERE id = $1::uuid FOR UPDATE`, hostID).Scan(&vorher); err != nil {
		alsJSON(w, 500, map[string]string{"fehler": err.Error()})
		return
	}
	neu := 0
	for _, e := range l.Ereignisse {
		// Zeiten aus der Zukunft würden das Aufräumen unterlaufen.
		if e.Kennung == "" || e.Zeit.IsZero() || !gueltigeArt(e.Art) || e.Zeit.After(time.Now().Add(time.Hour)) {
			continue
		}
		e.Zeit = e.Zeit.Truncate(time.Microsecond)
		e.Benutzer, e.Als, e.Sitzung, e.Quelle = kuerzen(e.Benutzer, 64), kuerzen(e.Als, 64), kuerzen(e.Sitzung, 64), kuerzen(e.Quelle, 128)
		e.Text, e.Kennung = kuerzen(e.Text, 4000), kuerzen(e.Kennung, 200)
		if len(e.Daten) > 20 {
			e.Daten = nil
		}
		h := ereignis.Hash(vorher, e)
		daten, _ := json.Marshal(e.Daten)
		if len(e.Daten) == 0 {
			daten = []byte("{}")
		}
		tag, err := tx.Exec(ctx, `INSERT INTO ereignisse (host, kennung, zeit, art, benutzer, als, sitzung, quelle, erfolg, text, daten, vorher, hash)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) ON CONFLICT (host, kennung) DO NOTHING`,
			hostID, e.Kennung, e.Zeit, e.Art, e.Benutzer, e.Als, e.Sitzung, e.Quelle, e.Erfolg, e.Text, daten, vorher, h)
		if err != nil {
			alsJSON(w, 500, map[string]string{"fehler": err.Error()})
			return
		}
		if tag.RowsAffected() == 1 {
			vorher = h
			neu++
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE hosts SET letzter_hash = $2 WHERE id = $1::uuid`, hostID, vorher); err != nil {
		alsJSON(w, 500, map[string]string{"fehler": err.Error()})
		return
	}
	if err := tx.Commit(ctx); err != nil {
		alsJSON(w, 500, map[string]string{"fehler": err.Error()})
		return
	}
	alsJSON(w, 200, map[string]int{"angenommen": neu})
}

func gueltigeArt(a string) bool {
	for _, x := range ereignis.Arten {
		if x == a {
			return true
		}
	}
	return false
}

func kuerzen(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && (s[n]&0xC0) == 0x80 {
		n--
	}
	return s[:n]
}

// agentPruefsumme: SHA-256 des Agenten, für die Prüfung beim Herunterladen.
func (a *App) agentPruefsumme(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open(a.agentDatei)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "%x  trailr-agent\n", h.Sum(nil))
}

func (a *App) agentProgramm(w http.ResponseWriter, r *http.Request) {
	f, err := os.Open(a.agentDatei)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, _ := f.Stat()
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="trailr-agent"`)
	http.ServeContent(w, r, "trailr-agent", st.ModTime(), f)
}

// aufraeumen löscht einmal am Tag, was älter als die Aufbewahrung ist. Die
// Prüfung der Kette beginnt danach beim ältesten verbliebenen Eintrag.
func (a *App) aufraeumen(ctx context.Context) {
	if a.tage <= 0 {
		return
	}
	for {
		tag, err := a.db.Exec(ctx, `DELETE FROM ereignisse WHERE empfangen < now() - make_interval(days => $1)`, a.tage)
		if err != nil {
			log.Printf("Aufräumen: %v", err)
		} else if tag.RowsAffected() > 0 {
			log.Printf("Aufräumen: %d Ereignisse älter als %d Tage gelöscht", tag.RowsAffected(), a.tage)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(24 * time.Hour):
		}
	}
}

// ---------- Oberfläche ----------

type Host struct {
	ID, Name, Agent string
	Zuletzt         *time.Time
	Heute, Fehl     int
	Benutzer        int
}

func (h Host) Still() bool { return h.Zuletzt == nil || time.Since(*h.Zuletzt) > 10*time.Minute }

type Zeile struct {
	ID       int64
	Host     string
	Zeit     time.Time
	Art      string
	Benutzer string
	Als      string
	Sitzung  string
	Quelle   string
	Erfolg   bool
	Text     string
}

func (z Zeile) ArtName() string {
	switch z.Art {
	case "anmeldung":
		return "Anmeldung"
	case "abmeldung":
		return "Abmeldung"
	case "sitzung":
		return "Sitzung"
	case "befehl":
		return "Befehl"
	case "sudo":
		return "sudo"
	case "su":
		return "su"
	case "datei":
		return "Datei"
	}
	return z.Art
}

func (z Zeile) Klasse() string {
	switch {
	case !z.Erfolg:
		return "schlecht"
	case z.Art == "sudo" || z.Art == "su":
		return "warn"
	case z.Art == "anmeldung":
		return "info"
	}
	return ""
}

func (a *App) hosts(ctx context.Context) []Host {
	rows, err := a.db.Query(ctx, `SELECT h.id::text, h.name, h.agent, h.zuletzt,
		(SELECT count(*) FROM ereignisse e WHERE e.host = h.id AND e.zeit > now() - interval '24 hours'),
		(SELECT count(*) FROM ereignisse e WHERE e.host = h.id AND e.zeit > now() - interval '24 hours' AND NOT e.erfolg),
		(SELECT count(DISTINCT e.benutzer) FROM ereignisse e WHERE e.host = h.id AND e.zeit > now() - interval '24 hours')
		FROM hosts h ORDER BY h.name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var l []Host
	for rows.Next() {
		var h Host
		if rows.Scan(&h.ID, &h.Name, &h.Agent, &h.Zuletzt, &h.Heute, &h.Fehl, &h.Benutzer) == nil {
			l = append(l, h)
		}
	}
	return l
}

type Filter struct {
	Host, Benutzer, Art, Suche, Sitzung, Von, Bis string
	Fehl                                          bool
}

func (a *App) suchen(ctx context.Context, f Filter, grenze int) ([]Zeile, error) {
	var wo []string
	var args []any
	arg := func(v any) string { args = append(args, v); return "$" + strconv.Itoa(len(args)) }
	if f.Host != "" {
		wo = append(wo, "h.name = "+arg(f.Host))
	}
	if f.Benutzer != "" {
		wo = append(wo, "(e.benutzer = "+arg(f.Benutzer)+" OR e.als = "+arg(f.Benutzer)+")")
	}
	if f.Art != "" {
		wo = append(wo, "e.art = "+arg(f.Art))
	}
	if f.Sitzung != "" {
		wo = append(wo, "e.sitzung = "+arg(f.Sitzung))
	}
	if f.Fehl {
		wo = append(wo, "NOT e.erfolg")
	}
	if q := strings.TrimSpace(f.Suche); q != "" {
		p := arg("%" + q + "%")
		wo = append(wo, "(e.text ILIKE "+p+" OR e.quelle ILIKE "+p+")")
	}
	if t, err := time.ParseInLocation("2006-01-02T15:04", f.Von, time.Local); err == nil {
		wo = append(wo, "e.zeit >= "+arg(t))
	}
	if t, err := time.ParseInLocation("2006-01-02T15:04", f.Bis, time.Local); err == nil {
		wo = append(wo, "e.zeit <= "+arg(t))
	}
	sql := `SELECT e.id, h.name, e.zeit, e.art, e.benutzer, e.als, e.sitzung, e.quelle, e.erfolg, e.text
		FROM ereignisse e JOIN hosts h ON h.id = e.host`
	if len(wo) > 0 {
		sql += " WHERE " + strings.Join(wo, " AND ")
	}
	sql += " ORDER BY e.zeit DESC, e.id DESC LIMIT " + strconv.Itoa(grenze)
	rows, err := a.db.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var l []Zeile
	for rows.Next() {
		var z Zeile
		if err := rows.Scan(&z.ID, &z.Host, &z.Zeit, &z.Art, &z.Benutzer, &z.Als, &z.Sitzung, &z.Quelle, &z.Erfolg, &z.Text); err != nil {
			return nil, err
		}
		l = append(l, z)
	}
	return l, rows.Err()
}

func (a *App) start(w http.ResponseWriter, r *http.Request) {
	letzte, _ := a.suchen(r.Context(), Filter{}, 25)
	fehl, _ := a.suchen(r.Context(), Filter{Fehl: true}, 10)
	a.v.zeigen(w, r, "start", a.daten(r, "Übersicht", "start", map[string]any{
		"Hosts": a.hosts(r.Context()), "Letzte": letzte, "Fehl": fehl,
	}))
}

func (a *App) ereignisse(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := Filter{Host: q.Get("host"), Benutzer: q.Get("benutzer"), Art: q.Get("art"), Suche: q.Get("q"),
		Sitzung: q.Get("sitzung"), Von: q.Get("von"), Bis: q.Get("bis"), Fehl: q.Get("fehl") == "ja"}
	l, err := a.suchen(r.Context(), f, 1000)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if q.Get("format") == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="trailr.csv"`)
		fmt.Fprintln(w, "zeit;host;art;benutzer;als;sitzung;quelle;erfolg;text")
		for _, z := range l {
			fmt.Fprintf(w, "%s;%s;%s;%s;%s;%s;%s;%t;%s\n", z.Zeit.Format(time.RFC3339), csv(z.Host), z.Art, csv(z.Benutzer),
				csv(z.Als), csv(z.Sitzung), csv(z.Quelle), z.Erfolg, csv(z.Text))
		}
		return
	}
	benutzer := []string{}
	rows, err := a.db.Query(r.Context(), `SELECT DISTINCT benutzer FROM ereignisse WHERE zeit > now() - interval '30 days' ORDER BY 1 LIMIT 200`)
	if err == nil {
		for rows.Next() {
			var b string
			if rows.Scan(&b) == nil {
				benutzer = append(benutzer, b)
			}
		}
		rows.Close()
	}
	a.v.zeigen(w, r, "ereignisse", a.daten(r, "Ereignisse", "ereignisse", map[string]any{
		"Liste": l, "F": f, "Hosts": a.hosts(r.Context()), "Arten": ereignis.Arten, "Benutzer": benutzer,
		"Voll": len(l) == 1000, "Abfrage": r.URL.RawQuery,
	}))
}

// csv entschärft ein Feld: kein Trenner, kein Zeilenumbruch, keine Formel.
func csv(s string) string {
	s = strings.NewReplacer(";", ",", "\n", " ", "\r", " ").Replace(s)
	if s != "" && strings.ContainsRune("=+-@", rune(s[0])) {
		s = "'" + s
	}
	return s
}

// Pruefung ist das Ergebnis der Kettenprüfung eines Hosts.
type Pruefung struct {
	Host   string
	Anzahl int
	OK     bool
	Bruch  *Zeile
	Grund  string
	Dauer  time.Duration
}

func (a *App) pruefeKette(ctx context.Context, hostID, name string) Pruefung {
	beginn := time.Now()
	p := Pruefung{Host: name, OK: true}
	rows, err := a.db.Query(ctx, `SELECT id, kennung, zeit, art, benutzer, als, sitzung, quelle, erfolg, text, daten, vorher, hash
		FROM ereignisse WHERE host = $1::uuid ORDER BY id`, hostID)
	if err != nil {
		p.OK, p.Grund = false, err.Error()
		return p
	}
	defer rows.Close()
	var erwartet string
	erste := true
	for rows.Next() {
		var e ereignis.Ereignis
		var z Zeile
		var daten []byte
		var vorher, hash string
		if err := rows.Scan(&z.ID, &e.Kennung, &e.Zeit, &e.Art, &e.Benutzer, &e.Als, &e.Sitzung, &e.Quelle, &e.Erfolg, &e.Text, &daten, &vorher, &hash); err != nil {
			p.OK, p.Grund = false, err.Error()
			return p
		}
		json.Unmarshal(daten, &e.Daten)
		p.Anzahl++
		z.Zeit, z.Art, z.Benutzer, z.Text = e.Zeit, e.Art, e.Benutzer, e.Text
		// Nach dem Aufräumen beginnt die Kette beim ältesten verbliebenen Eintrag.
		if !erste && vorher != erwartet {
			p.OK, p.Bruch, p.Grund = false, &z, "Eintrag davor fehlt oder wurde geändert"
			return p
		}
		if ereignis.Hash(vorher, e) != hash {
			p.OK, p.Bruch, p.Grund = false, &z, "Inhalt passt nicht zum Hash: geändert"
			return p
		}
		erwartet, erste = hash, false
	}
	var ende string
	a.db.QueryRow(ctx, `SELECT letzter_hash FROM hosts WHERE id = $1::uuid`, hostID).Scan(&ende)
	if p.Anzahl > 0 && ende != erwartet {
		p.OK, p.Grund = false, "Die neuesten Einträge fehlen"
	}
	p.Dauer = time.Since(beginn)
	return p
}

func (a *App) pruefenSeite(w http.ResponseWriter, r *http.Request) {
	var l []Pruefung
	if r.URL.Query().Get("los") == "ja" {
		for _, h := range a.hosts(r.Context()) {
			l = append(l, a.pruefeKette(r.Context(), h.ID, h.Name))
		}
	}
	a.v.zeigen(w, r, "pruefen", a.daten(r, "Kette prüfen", "pruefen", map[string]any{"Ergebnis": l, "Gelaufen": r.URL.Query().Get("los") == "ja"}))
}

func (a *App) einrichten(w http.ResponseWriter, r *http.Request) {
	schema := "http"
	if ssoSicher(r) {
		schema = "https"
	}
	a.v.zeigen(w, r, "einrichten", a.daten(r, "Agent einrichten", "einrichten", map[string]any{
		"Server": schema + "://" + r.Host, "Tage": a.tage,
	}))
}

var _ = pgx.ErrNoRows
