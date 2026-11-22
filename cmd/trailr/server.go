package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

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
	if err := tx.QueryRow(ctx, `INSERT INTO hosts (name, zuletzt, agent, kette_anfang) VALUES ($1, now(), $2, '')
		ON CONFLICT (name) DO UPDATE SET zuletzt = now(), agent = $2 RETURNING id::text`, l.Host, feldWert(l.Agent, 40)).Scan(&hostID); err != nil {
		alsJSON(w, 500, map[string]string{"fehler": err.Error()})
		return
	}
	if err := tx.QueryRow(ctx, `SELECT letzter_hash FROM hosts WHERE id = $1::uuid FOR UPDATE`, hostID).Scan(&vorher); err != nil {
		alsJSON(w, 500, map[string]string{"fehler": err.Error()})
		return
	}
	neu := 0
	var angenommen []ereignis.Ereignis
	for _, e := range l.Ereignisse {
		// Zeiten aus der Zukunft würden das Aufräumen unterlaufen.
		if e.Kennung == "" || e.Zeit.IsZero() || !gueltigeArt(e.Art) || e.Zeit.After(time.Now().Add(time.Hour)) {
			continue
		}
		e.Zeit = e.Zeit.Truncate(time.Microsecond)
		e.Benutzer, e.Als, e.Sitzung, e.Quelle = feldWert(e.Benutzer, 64), feldWert(e.Als, 64), feldWert(e.Sitzung, 64), feldWert(e.Quelle, 128)
		e.Text, e.Kennung = feldWert(e.Text, 4000), feldWert(e.Kennung, 200)
		if e.Kennung == "" {
			continue
		}
		if len(e.Daten) > 20 {
			e.Daten = nil
		} else if len(e.Daten) > 0 {
			d := map[string]string{}
			for k, v := range e.Daten {
				d[feldWert(k, 64)] = feldWert(v, 4000)
			}
			e.Daten = d
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
			angenommen = append(angenommen, e)
		}
	}
	if a.alarme != nil && len(angenommen) > 0 {
		if err := a.alarme.bewerten(ctx, tx, hostID, l.Host, angenommen); err != nil {
			log.Printf("Lieferung von %s, Alarme: %v", l.Host, err)
			alsJSON(w, 500, map[string]string{"fehler": "Datenbank"})
			return
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

// feldWert: Postgres nimmt kein Nullbyte, und 0x1f trennt im Hash die Felder.
func feldWert(s string, n int) string {
	return kuerzen(strings.NewReplacer("\x00", " ", "\x1f", " ").Replace(s), n)
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

// aufraeumen löscht einmal am Tag, was älter als die Aufbewahrung ist, und
// rückt den Anfang der Kette dorthin vor. Das geschieht unter der Sperre des
// Hosts und immer als Stück vom Anfang.
func (a *App) aufraeumen(ctx context.Context) {
	if a.tage <= 0 {
		return
	}
	for {
		for _, h := range a.hosts(ctx) {
			if n, err := a.hostAufraeumen(ctx, h.ID); err != nil {
				log.Printf("Aufräumen %s: %v", h.Name, err)
			} else if n > 0 {
				log.Printf("Aufräumen %s: %d Ereignisse älter als %d Tage gelöscht", h.Name, n, a.tage)
			}
		}
		if _, err := a.db.Exec(ctx, `DELETE FROM alarme WHERE zeit < now() - make_interval(days => $1)`, a.tage); err != nil {
			log.Printf("Aufräumen: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(24 * time.Hour):
		}
	}
}

func (a *App) hostAufraeumen(ctx context.Context, id string) (int64, error) {
	tx, err := a.db.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	var ende string
	if err := tx.QueryRow(ctx, `SELECT letzter_hash FROM hosts WHERE id=$1::uuid FOR UPDATE`, id).Scan(&ende); err != nil {
		return 0, err
	}
	var bis *int64
	if err := tx.QueryRow(ctx, `SELECT max(id) FROM ereignisse WHERE host=$1::uuid AND empfangen < now() - make_interval(days => $2)`, id, a.tage).Scan(&bis); err != nil {
		return 0, err
	}
	if bis == nil {
		return 0, nil
	}
	// Vor dem Löschen: der Hash des letzten, der geht, ist der neue Anfang.
	var anfang string
	if err := tx.QueryRow(ctx, `SELECT hash FROM ereignisse WHERE id=$1`, *bis).Scan(&anfang); err != nil {
		return 0, err
	}
	weg, err := tx.Exec(ctx, `DELETE FROM ereignisse WHERE host=$1::uuid AND id <= $2`, id, *bis)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE hosts SET kette_anfang=$2 WHERE id=$1::uuid`, id, anfang); err != nil {
		return 0, err
	}
	return weg.RowsAffected(), tx.Commit(ctx)
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
	ID       int64     `json:"id"`
	Host     string    `json:"host"`
	Zeit     time.Time `json:"zeit"`
	Art      string    `json:"art"`
	Benutzer string    `json:"benutzer"`
	Als      string    `json:"als"`
	Sitzung  string    `json:"sitzung"`
	Quelle   string    `json:"quelle"`
	Erfolg   bool      `json:"erfolg"`
	Text     string    `json:"text"`
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
	ab, vor                                       time.Time // genau, nicht aus dem Formular
}

func (a *App) suchen(ctx context.Context, f Filter, grenze int) ([]Zeile, error) {
	var l []Zeile
	err := a.durchgehen(ctx, f, grenze, false, func(z Zeile) error { l = append(l, z); return nil })
	return l, err
}

func (a *App) durchgehen(ctx context.Context, f Filter, grenze int, aelteste bool, je func(Zeile) error) error {
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
		// Wörtlich: in Befehlen sind %, _ und \\ keine Platzhalter.
		p := arg(strings.ReplaceAll(q, "\x00", ""))
		wo = append(wo, "(strpos(lower(e.text), lower("+p+")) > 0 OR strpos(lower(e.quelle), lower("+p+")) > 0)")
	}
	if !f.ab.IsZero() {
		wo = append(wo, "e.zeit >= "+arg(f.ab))
	}
	if !f.vor.IsZero() {
		wo = append(wo, "e.zeit <= "+arg(f.vor))
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
	richtung := "DESC"
	if aelteste {
		richtung = "ASC"
	}
	sql += " ORDER BY e.zeit " + richtung + ", e.id " + richtung + " LIMIT " + strconv.Itoa(grenze)
	rows, err := a.db.Query(ctx, sql, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var z Zeile
		if err := rows.Scan(&z.ID, &z.Host, &z.Zeit, &z.Art, &z.Benutzer, &z.Als, &z.Sitzung, &z.Quelle, &z.Erfolg, &z.Text); err != nil {
			return err
		}
		if err := je(z); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (a *App) start(w http.ResponseWriter, r *http.Request) {
	letzte, err1 := a.suchen(r.Context(), Filter{}, 25)
	fehl, err2 := a.suchen(r.Context(), Filter{Fehl: true}, 10)
	var alarme int
	err3 := a.db.QueryRow(r.Context(), `SELECT count(*) FROM alarme WHERE zeit > now() - interval '24 hours'`).Scan(&alarme)
	if err1 != nil || err2 != nil || err3 != nil {
		http.Error(w, "Datenbank", http.StatusInternalServerError)
		return
	}
	hosts := a.hosts(r.Context())
	liefern, heute, fehler := 0, 0, 0
	for _, h := range hosts {
		if !h.Still() {
			liefern++
		}
		heute, fehler = heute+h.Heute, fehler+h.Fehl
	}
	a.v.zeigen(w, r, "start", a.daten(r, "Übersicht", "start", map[string]any{
		"Hosts": hosts, "Letzte": letzte, "Fehl": fehl,
		"Liefern": liefern, "Heute": heute, "Fehler": fehler, "Alarme": alarme,
	}))
}

func (a *App) ereignisse(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := Filter{Host: q.Get("host"), Benutzer: q.Get("benutzer"), Art: q.Get("art"), Suche: q.Get("q"),
		Sitzung: q.Get("sitzung"), Von: q.Get("von"), Bis: q.Get("bis"), Fehl: q.Get("fehl") == "ja"}
	if format := q.Get("format"); format == "csv" || format == "json" {
		a.export(w, r, f, format)
		return
	}
	l, err := a.suchen(r.Context(), f, 1000)
	if err != nil {
		http.Error(w, err.Error(), 500)
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
		"Voll": len(l) == 1000, "CSV": exportAdresse(q, "csv"), "JSON": exportAdresse(q, "json"),
	}))
}

func exportAdresse(q url.Values, format string) string {
	n := url.Values{}
	for k, v := range q {
		n[k] = v
	}
	n.Set("format", format)
	return "/ereignisse?" + n.Encode()
}

// formelAnfang: eine Formel am Anfang des Werts, auch hinter Leerraum und
// Anführung, oder hinter einem Komma oder Semikolon.
var formelAnfang = regexp.MustCompile(`(^|[,;])([\p{Z}"]*[=+\-@\x{ff1d}\x{ff0b}\x{ff0d}\x{ff20}])`)

// csv macht aus einem Wert ein Feld: immer in Anführung und nie eine Formel.
// Den unveränderten Wert gibt der Export als JSON.
func csv(s string) string {
	// Erst die Steuerzeichen weg: dann kann zwischen dem Apostroph und der
	// Formel nichts mehr stehen, woran jemand trennt.
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	s = formelAnfang.ReplaceAllString(s, "${1}'${2}")
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// Pruefung ist das Ergebnis der Kettenprüfung eines Hosts.
type Pruefung struct {
	Host   string
	Anzahl int
	OK     bool
	Bruch  *Zeile
	Grund  string
	Dauer  time.Duration
	// Stoerung: nicht prüfbar, kein Befund.
	Stoerung bool
}

func (a *App) pruefeKette(ctx context.Context, hostID, name string) (p Pruefung) {
	beginn := time.Now()
	p = Pruefung{Host: name, OK: true}
	defer func() { p.Dauer = time.Since(beginn).Round(time.Millisecond) }()
	stoerung := func(err error) Pruefung {
		log.Printf("Kette %s: %v", name, err)
		p.OK, p.Stoerung, p.Grund = false, true, "Nicht prüfbar: Datenbank"
		return p
	}
	// Ein Schnappschuss: sonst gilt als Bruch, was währenddessen geliefert wird.
	tx, err := a.db.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return stoerung(err)
	}
	defer tx.Rollback(ctx)
	var erwartet, ende string
	if err := tx.QueryRow(ctx, `SELECT COALESCE(kette_anfang, ''), letzter_hash FROM hosts WHERE id = $1::uuid`, hostID).Scan(&erwartet, &ende); err != nil {
		return stoerung(err)
	}
	rows, err := tx.Query(ctx, `SELECT id, kennung, zeit, art, benutzer, als, sitzung, quelle, erfolg, text, daten, vorher, hash
		FROM ereignisse WHERE host = $1::uuid ORDER BY id`, hostID)
	if err != nil {
		return stoerung(err)
	}
	defer rows.Close()
	for rows.Next() {
		var e ereignis.Ereignis
		var z Zeile
		var daten []byte
		var vorher, hash string
		if err := rows.Scan(&z.ID, &e.Kennung, &e.Zeit, &e.Art, &e.Benutzer, &e.Als, &e.Sitzung, &e.Quelle, &e.Erfolg, &e.Text, &daten, &vorher, &hash); err != nil {
			return stoerung(err)
		}
		p.Anzahl++
		z.Zeit, z.Art, z.Benutzer, z.Text = e.Zeit, e.Art, e.Benutzer, e.Text
		if vorher != erwartet {
			p.OK, p.Bruch, p.Grund = false, &z, "Eintrag davor fehlt oder wurde geändert"
			if p.Anzahl == 1 {
				p.Grund = "Die ältesten Einträge fehlen"
			}
			return p
		}
		if json.Unmarshal(daten, &e.Daten) != nil || ereignis.Hash(vorher, e) != hash {
			p.OK, p.Bruch, p.Grund = false, &z, "Inhalt passt nicht zum Hash: geändert"
			return p
		}
		erwartet = hash
	}
	if err := rows.Err(); err != nil {
		return stoerung(err)
	}
	if ende != erwartet {
		p.OK, p.Grund = false, "Die neuesten Einträge fehlen"
		if p.Anzahl == 0 {
			p.Grund = "Alle Einträge fehlen"
		}
	}
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
	// Der Schlüssel eines Hosts wird hier ausgerechnet: der Hauptschlüssel
	// bleibt auf dem Server und muss nie auf einem Host getippt werden.
	host := strings.TrimSpace(r.URL.Query().Get("host"))
	d := map[string]any{"Server": schema + "://" + r.Host, "Tage": a.tage, "Host": host}
	if host != "" {
		if hostMuster.MatchString(host) {
			d["Schluessel"] = hostSchluessel(a.schluessel, host)
		} else {
			d["Fehler"] = "Hostname ungültig: Buchstaben, Ziffern, Punkt und Strich"
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	a.v.zeigen(w, r, "einrichten", a.daten(r, "Agent einrichten", "einrichten", d))
}
