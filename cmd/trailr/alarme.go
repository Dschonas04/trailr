package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"trailr/internal/ereignis"
)

// Alarme entstehen immer und stehen in der Oberfläche. Nach draußen gehen sie
// erst, wenn Telegram oder Mail eingerichtet ist, und dann ohne Befehlszeilen:
// in denen stehen gelegentlich Geheimnisse.

const (
	vieleFehlschlaege = 5
	fehlMuster        = 100  // so viele Muster von Fehlschlägen je Lieferung werden gezählt
	meldungMax        = 3500 // Telegram nimmt 4096 Zeichen
	wegPause          = 5 * time.Minute
	quellenKontoMax   = 30  // je Konto und Stunde
	quellenHostMax    = 200 // je Host und Stunde, der erste Alarm eines Kontos geht darüber hinaus
	quellenKontenMax  = 500 // so viele Konten je Host und Stunde bekommen ihren ersten Alarm sicher
	quellenRootMax    = 100 // je Host und Stunde, nur root: den Anteil nimmt ihm keiner
	flutMax           = 5   // je Host und Stunde, danach ein Sammelalarm
	sammelFrist       = 15 * time.Second
	einzelFrist       = 10 * time.Second
	schubFrist        = 2 * time.Minute
	stilleNach        = 30 * time.Minute
)

type Alarme struct {
	von, bis  int // Arbeitszeit in Stunden, beide 0: keine Regel
	melder    []melder
	seit      time.Time            // älteres wird nicht nachgeschickt
	aussetzer map[string]aussetzer // Wege, die gerade gar nicht gehen
}

type aussetzer struct {
	mal int
	bis time.Time
}

type melder struct {
	name   string
	senden func(ctx context.Context, text string) error
}

func neueAlarme() *Alarme {
	al := &Alarme{seit: time.Now().Add(-time.Hour)}
	if s := umgebung("TRAILR_ARBEITSZEIT", ""); s != "" {
		var ok bool
		if al.von, al.bis, ok = arbeitszeit(s); !ok {
			log.Fatal("TRAILR_ARBEITSZEIT erwartet Stunden wie 7-20")
		}
	}
	if token, chat := umgebung("TRAILR_TELEGRAM_TOKEN", ""), umgebung("TRAILR_TELEGRAM_CHAT", ""); token != "" && chat != "" {
		al.melder = append(al.melder, melder{"Telegram", telegram("https://api.telegram.org", token, chat)})
	}
	if m, an := neuerMailer(), umgebung("TRAILR_ALARM_AN", ""); m != nil && an != "" {
		al.melder = append(al.melder, melder{"Mail", func(ctx context.Context, text string) error {
			return m.senden(ctx, an, "Trailr: Alarm", text)
		}})
	}
	return al
}

func arbeitszeit(s string) (von, bis int, ok bool) {
	a, b, da := strings.Cut(s, "-")
	v, err1 := strconv.Atoi(strings.TrimSpace(a))
	n, err2 := strconv.Atoi(strings.TrimSpace(b))
	if !da || err1 != nil || err2 != nil || v < 0 || n > 24 || v >= n {
		return 0, 0, false
	}
	return v, n, true
}

func telegram(basis, token, chat string) func(context.Context, string) error {
	k := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return func(ctx context.Context, text string) error {
		b, err := json.Marshal(map[string]string{"chat_id": chat, "text": text})
		if err != nil {
			return err
		}
		r, err := http.NewRequestWithContext(ctx, http.MethodPost, basis+"/bot"+url.PathEscape(token)+"/sendMessage", bytes.NewReader(b))
		if err != nil {
			return errors.New("Adresse ungültig")
		}
		r.Header.Set("Content-Type", "application/json")
		res, err := k.Do(r)
		if err != nil {
			return errors.New("nicht erreichbar") // die Adresse enthält das Token
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("Antwort %d", res.StatusCode)
		}
		return nil
	}
}

func alarmAnlegen(ctx context.Context, tx pgx.Tx, host, regel, schluessel, text string) error {
	_, err := tx.Exec(ctx, `INSERT INTO alarme (host, regel, schluessel, text) VALUES ($1, $2, $3, $4) ON CONFLICT (host, schluessel) DO NOTHING`,
		host, regel, kuerzen(schluessel, 300), eineZeile(text, 300))
	return err
}

// eineZeile: Namen und Quellen wählt auch ein Angreifer, sie dürfen keine
// zweite Meldung vortäuschen.
func eineZeile(s string, n int) string {
	return kuerzen(strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || r == 0x2028 || r == 0x2029 {
			return ' '
		}
		return r
	}, s), n)
}

// bewerten läuft in der Transaktion der Lieferung: kein Ereignis wird
// übergangen, auch wenn der Server gleich danach stehen bleibt.
func (al *Alarme) bewerten(ctx context.Context, tx pgx.Tx, hostID, host string, l []ereignis.Ereignis) error {
	erledigt := map[string]bool{}
	gezaehlt, geflutet := 0, false
	jeKonto := map[string]int{}
	gemeldetesKonto := map[string]bool{}
	var andere, konten int
	gelesen := false
	for _, e := range l {
		if time.Since(e.Zeit) > 24*time.Hour {
			continue // Nachlieferungen von gestern alarmieren nicht mehr
		}
		anmelden := e.Art == "anmeldung" || e.Art == "sudo" || e.Art == "su"
		switch {
		case !e.Erfolg && anmelden:
			spalte, wert := "benutzer", e.Benutzer
			if e.Art == "anmeldung" && e.Quelle != "" {
				spalte, wert = "quelle", e.Quelle // wer rät, wechselt den Namen
			}
			k := "fehl:" + e.Art + ":" + spalte + ":" + wert + ":" + strconv.FormatInt(e.Zeit.Unix()/3600, 10)
			if erledigt[k] {
				continue
			}
			erledigt[k] = true
			// Nur das Zählen ist begrenzt. Die anderen Regeln sehen jedes Ereignis,
			// und dass gekürzt wurde, ist selbst ein Alarm.
			if gezaehlt++; gezaehlt > fehlMuster {
				if !geflutet {
					geflutet = true
					if err := alarmAnlegen(ctx, tx, host, "flut", "flut:"+strconv.FormatInt(time.Now().Unix()/3600, 10),
						fmt.Sprintf("Mehr als %d verschiedene Quellen oder Konten mit Fehlschlägen auf einmal", fehlMuster)); err != nil {
						return err
					}
				}
				continue
			}
			// Das engste Fenster von fünf Fehlschlägen in der Stunde um das Ereignis.
			var viele bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM (
					SELECT zeit - lag(zeit, $5) OVER (ORDER BY zeit) AS spanne FROM ereignisse
					WHERE host=$1::uuid AND art=$2 AND `+spalte+`=$3 AND NOT erfolg
					  AND zeit BETWEEN $4::timestamptz - interval '1 hour' AND $4::timestamptz + interval '1 hour'
				) x WHERE spanne <= interval '10 minutes')`, hostID, e.Art, wert, e.Zeit, vieleFehlschlaege-1).Scan(&viele); err != nil {
				return err
			}
			if viele {
				if err := alarmAnlegen(ctx, tx, host, "fehlschlaege", k, fmt.Sprintf("Mindestens %d Fehlschläge (%s) in 10 Minuten von %s", vieleFehlschlaege, e.Art, wert)); err != nil {
					return err
				}
			}
		case e.Erfolg && e.Art == "anmeldung" && e.Quelle != "":
			// Mit Länge: Namen und IPv6-Adressen enthalten Doppelpunkte.
			k := fmt.Sprintf("quelle:%d:%s:%s", len(e.Benutzer), e.Benutzer, e.Quelle)
			if erledigt[k] {
				continue
			}
			erledigt[k] = true
			// Neu heißt: es gab früher Anmeldungen, aber keine dieses Kontos von dort.
			// Was bei einem Konto unterging, macht die Quelle für andere nicht bekannt.
			var frueher, bekannt bool
			if err := tx.QueryRow(ctx, `SELECT
				EXISTS (SELECT 1 FROM ereignisse WHERE host=$1::uuid AND art='anmeldung' AND erfolg AND zeit < $3),
				EXISTS (SELECT 1 FROM ereignisse WHERE host=$1::uuid AND art='anmeldung' AND erfolg AND zeit < $3 AND quelle=$2 AND benutzer=$4)`,
				hostID, e.Quelle, e.Zeit, e.Benutzer).Scan(&frueher, &bekannt); err != nil {
				return err
			}
			if frueher && !bekannt {
				// Gezählt wird nach der Uhr des Servers und dem genauen Namen: Zeiten
				// und Namen im Paket wählt der Absender.
				if !gelesen {
					gelesen = true
					if err := tx.QueryRow(ctx, `SELECT count(*), count(DISTINCT konto) FROM alarme
						WHERE host=$1 AND regel='quelle' AND konto <> 'root' AND zeit > now() - interval '1 hour'`, host).Scan(&andere, &konten); err != nil {
						return err
					}
				}
				bisher, da := jeKonto[e.Benutzer]
				if !da {
					if err := tx.QueryRow(ctx, `SELECT count(*) FROM alarme
						WHERE host=$1 AND regel='quelle' AND konto=$2 AND zeit > now() - interval '1 hour'`, host, e.Benutzer).Scan(&bisher); err != nil {
						return err
					}
				}
				var zuViele bool
				switch {
				case e.Benutzer == "root":
					zuViele = bisher >= quellenRootMax
				case bisher == 0:
					if zuViele = konten >= quellenKontenMax; !zuViele {
						konten++
						andere++
					}
				default:
					if zuViele = bisher >= quellenKontoMax || andere >= quellenHostMax; !zuViele {
						andere++
					}
				}
				if !zuViele {
					bisher++
				}
				jeKonto[e.Benutzer] = bisher
				if zuViele {
					if !gemeldetesKonto[e.Benutzer] {
						gemeldetesKonto[e.Benutzer] = true
						if err := quellenFlut(ctx, tx, host, e.Benutzer); err != nil {
							return err
						}
					}
					continue
				}
				if _, err := tx.Exec(ctx, `INSERT INTO alarme (host, regel, schluessel, text, konto) VALUES ($1, 'quelle', $2, $3, $4)
					ON CONFLICT (host, schluessel) DO NOTHING`,
					host, kuerzen(k, 300), eineZeile("Anmeldung von "+e.Benutzer+" aus neuer Quelle "+e.Quelle, 300), e.Benutzer); err != nil {
					return err
				}
			}
		}
		if al.bis > 0 && e.Erfolg && (e.Art == "sudo" || e.Art == "su") {
			if z := e.Zeit.Local(); z.Hour() < al.von || z.Hour() >= al.bis {
				k := "zeit:" + e.Benutzer + ":" + z.Format("2006-01-02T15")
				if erledigt[k] {
					continue
				}
				erledigt[k] = true
				if err := alarmAnlegen(ctx, tx, host, "arbeitszeit", k, fmt.Sprintf("%s von %s um %s, außerhalb von %d bis %d Uhr", e.Art, e.Benutzer, z.Format("15:04"), al.von, al.bis)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// quellenFlut: auch eine zweite Flut fällt auf, aber den Schlüssel zählt der
// Server, und nach flutMax steht nur noch ein Sammelalarm für die Stunde.
func quellenFlut(ctx context.Context, tx pgx.Tx, host, konto string) error {
	if konto == "root" {
		// Eigener Schlüssel: den nimmt ihm kein anderes Konto.
		return alarmAnlegen(ctx, tx, host, "flut", "root-quellen:"+strconv.FormatInt(time.Now().Unix()/3600, 10),
			fmt.Sprintf("Anmeldungen von root aus mehr als %d neuen Quellen in einer Stunde", quellenRootMax))
	}
	var n int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM alarme
		WHERE host=$1 AND schluessel LIKE 'quellen:%' AND zeit > now() - interval '1 hour'`, host).Scan(&n); err != nil {
		return err
	}
	stunde := strconv.FormatInt(time.Now().Unix()/3600, 10)
	if n >= flutMax {
		return alarmAnlegen(ctx, tx, host, "flut", "quellen:"+stunde+":weitere",
			"Weitere Fluten von Anmeldungen aus neuen Quellen in dieser Stunde, bitte die Ereignisse ansehen")
	}
	// Die laufende Nummer aus der Folge, nicht aus dem Paket.
	var folge int64
	if err := tx.QueryRow(ctx, `SELECT nextval(pg_get_serial_sequence('alarme', 'id'))`).Scan(&folge); err != nil {
		return err
	}
	return alarmAnlegen(ctx, tx, host, "flut", "quellen:"+stunde+":"+strconv.FormatInt(folge, 10),
		fmt.Sprintf("Anmeldungen von %s aus zu vielen neuen Quellen, nicht mehr einzeln gemeldet", konto))
}

func (a *App) alarmLauf(ctx context.Context) {
	takt := time.NewTicker(30 * time.Second)
	defer takt.Stop()
	kette := time.Now().Add(5 * time.Minute) // nicht mitten in den Start
	for {
		select {
		case <-ctx.Done():
			return
		case <-takt.C:
		}
		if _, err := a.db.Exec(ctx, `INSERT INTO alarme (host, regel, schluessel, text)
			SELECT name, 'still', 'still:' || extract(epoch FROM zuletzt)::bigint, 'Der Agent liefert seit über 30 Minuten nicht'
			FROM hosts WHERE zuletzt < now() - make_interval(secs => $1) AND zuletzt > now() - interval '7 days'
			ON CONFLICT (host, schluessel) DO NOTHING`, int(stilleNach.Seconds())); err != nil {
			log.Printf("Alarme: %v", err)
		}
		if time.Now().After(kette) {
			kette = time.Now().Add(24 * time.Hour)
			a.ketteWache(ctx)
		}
		a.alarmeSenden(ctx)
	}
}

func (a *App) ketteWache(ctx context.Context) {
	for _, h := range a.hosts(ctx) {
		p := a.pruefeKette(ctx, h.ID, h.Name)
		// Nur ein Befund ist ein Alarm, keine Störung der Datenbank.
		if p.OK || p.Stoerung {
			continue
		}
		if _, err := a.db.Exec(ctx, `INSERT INTO alarme (host, regel, schluessel, text) VALUES ($1, 'kette', $2, $3) ON CONFLICT (host, schluessel) DO NOTHING`,
			h.Name, "kette:"+time.Now().Format("2006-01-02"), "Die Kette ist gebrochen: "+p.Grund); err != nil {
			log.Printf("Alarme: %v", err)
		}
	}
}

func (a *App) alarmeSenden(ctx context.Context) {
	if a.alarme == nil {
		return
	}
	// Jeder Weg für sich: fällt einer aus, hält er die anderen nicht auf und
	// bekommt nach, was ihm fehlt.
	for _, m := range a.alarme.melder {
		if err := a.alarmeUeber(ctx, m); err != nil {
			log.Printf("Alarme per %s: %v", m.name, err)
		}
	}
}

// alarmeUeber schickt einen Schub. Drei Klassen wechseln sich ab, in dieser
// Folge: Kette und Stille, Flut, übriges. Jede hat so immer Plätze. Darin geht es
// reihum je Host, für Neues und für Gescheitertes getrennt: eine Flut nimmt
// einem Nachzügler so weder bei anderen Hosts noch beim eigenen den Platz.
func (a *App) alarmeUeber(ctx context.Context, m melder) error {
	pause := a.alarme.aussetzer[m.name]
	if time.Now().Before(pause.bis) {
		return nil
	}
	rows, err := a.db.Query(ctx, `WITH offen AS (
			SELECT id, host, text, CASE WHEN regel IN ('kette', 'still') THEN 0 WHEN regel = 'flut' THEN 1 ELSE 2 END AS rang,
			       (versucht_je ->> $2)::float8 AS versucht
			FROM alarme WHERE zeit > $1 AND NOT ($2 = ANY(gesendet_an))
		), zuletzt AS (
			SELECT host, max(gesendet) AS wann FROM alarme WHERE zeit > $1 GROUP BY host
		), gereiht AS (
			SELECT o.*, z.wann,
			       row_number() OVER (PARTITION BY o.rang, o.host, o.versucht IS NULL ORDER BY o.versucht, o.id) AS reihum
			FROM offen o JOIN zuletzt z USING (host)
		)
		SELECT id, host, text FROM (
			SELECT *, row_number() OVER (PARTITION BY rang ORDER BY reihum, versucht NULLS FIRST, wann NULLS FIRST, id) AS platz
			FROM gereiht
		) x ORDER BY platz, rang LIMIT 20`, a.alarme.seit, m.name)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ids []int64
	var zeilen []string
	laenge := 0
	for rows.Next() {
		var id int64
		var host, text string
		if err := rows.Scan(&id, &host, &text); err != nil {
			return err
		}
		z := eineZeile(host+": "+text, 400)
		// In Byte gemessen, das ist nie weniger als Telegrams Zeichen.
		if laenge += len(z) + 1; laenge > meldungMax && len(ids) > 0 {
			break
		}
		ids = append(ids, id)
		zeilen = append(zeilen, z)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(ids) == 0 {
		return err
	}

	frist, ende := context.WithTimeout(ctx, schubFrist)
	defer ende()
	// Jeder Versuch mit eigener Frist: ein Hänger lässt Zeit für die übrigen.
	senden := func(z ...string) error {
		dauer := sammelFrist
		if len(z) == 1 {
			dauer = einzelFrist
		}
		einmal, ab := context.WithTimeout(frist, dauer)
		defer ab()
		return m.senden(einmal, "Trailr\n"+strings.Join(z, "\n"))
	}
	raus, gescheitert := ids, []int64(nil)
	fehler := senden(zeilen...)
	if fehler != nil {
		raus = nil
		if len(ids) == 1 {
			gescheitert = ids
		} else {
			// Liegt es an einzelnen Meldungen, kommen alle anderen einzeln durch.
			for i, id := range ids {
				if frist.Err() != nil {
					break
				}
				if e := senden(zeilen[i]); e != nil {
					gescheitert = append(gescheitert, id)
				} else {
					raus = append(raus, id)
				}
			}
		}
	}
	if a.alarme.aussetzer == nil {
		a.alarme.aussetzer = map[string]aussetzer{}
	}
	if len(raus) > 0 {
		delete(a.alarme.aussetzer, m.name)
	} else if pause.mal++; pause.mal >= 3 {
		// Geht der ganze Weg nicht, klopft Trailr nicht alle 30 Sekunden zwanzigmal.
		a.alarme.aussetzer[m.name] = aussetzer{mal: pause.mal, bis: time.Now().Add(wegPause)}
	} else {
		a.alarme.aussetzer[m.name] = pause
	}
	if len(gescheitert) > 0 {
		if _, err := a.db.Exec(ctx, `UPDATE alarme SET versucht_je = versucht_je || jsonb_build_object($2::text, extract(epoch FROM clock_timestamp()))
			WHERE id = ANY($1)`, gescheitert, m.name); err != nil {
			return err
		}
	}
	if len(raus) > 0 {
		if _, err := a.db.Exec(ctx, `UPDATE alarme SET gesendet = COALESCE(gesendet, now()), gesendet_an = array_append(gesendet_an, $2)
			WHERE id = ANY($1)`, raus, m.name); err != nil {
			return err
		}
	}
	return fehler
}

type Alarm struct {
	Host, Regel, Text string
	Zeit              time.Time
	Gesendet          *time.Time
}

func (x Alarm) RegelName() string {
	switch x.Regel {
	case "fehlschlaege":
		return "Fehlschläge"
	case "flut":
		return "Flut"
	case "quelle":
		return "neue Quelle"
	case "arbeitszeit":
		return "Arbeitszeit"
	case "still":
		return "still"
	case "kette":
		return "Kette"
	}
	return x.Regel
}

func (x Alarm) Klasse() string {
	if x.Regel == "kette" || x.Regel == "fehlschlaege" || x.Regel == "flut" {
		return "schlecht"
	}
	return "warn"
}

type alarmGruppe struct {
	Host, Regel, Adresse string
	Weitere              int
}

func (g alarmGruppe) RegelName() string { return Alarm{Regel: g.Regel}.RegelName() }

const alarmSeite = 100

func (a *App) alarmeSeite(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	host, regel := q.Get("host"), q.Get("regel")
	vor := int64(math.MaxInt64)
	if v, err := strconv.ParseInt(q.Get("vor"), 10, 64); err == nil && v > 0 {
		vor = v
	}
	// Übersicht: je Host und Regel die neuesten, root für sich, und was darüber
	// hinaus da ist als Verweis. Gefiltert: alles, zum Blättern.
	gefiltert := host != "" || regel != "" || q.Get("vor") != ""
	frage := `SELECT id, host, regel, text, zeit, gesendet FROM (
			SELECT * FROM (
				SELECT *, row_number() OVER (PARTITION BY host, regel, konto = 'root' ORDER BY id DESC) AS n FROM alarme
			) x WHERE n <= 50 ORDER BY n, id DESC LIMIT 5000
		) y ORDER BY id DESC`
	var args []any
	if gefiltert {
		frage = `SELECT id, host, regel, text, zeit, gesendet FROM alarme
			WHERE ($1 = '' OR host = $1) AND ($2 = '' OR regel = $2) AND id < $3 ORDER BY id DESC LIMIT $4`
		args = []any{host, regel, vor, alarmSeite + 1}
	}
	rows, err := a.db.Query(r.Context(), frage, args...)
	if err != nil {
		http.Error(w, "Datenbank", http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	var l []Alarm
	var ids []int64
	gezeigt := map[[2]string]int{}
	for rows.Next() {
		var x Alarm
		var id int64
		if err := rows.Scan(&id, &x.Host, &x.Regel, &x.Text, &x.Zeit, &x.Gesendet); err != nil {
			http.Error(w, "Datenbank", http.StatusInternalServerError)
			return
		}
		l, ids = append(l, x), append(ids, id)
		gezeigt[[2]string{x.Host, x.Regel}]++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		http.Error(w, "Datenbank", http.StatusInternalServerError)
		return
	}
	aeltere := ""
	var mehr []alarmGruppe
	if gefiltert {
		if len(l) > alarmSeite {
			l = l[:alarmSeite]
			aeltere = "/alarme?" + url.Values{"host": {host}, "regel": {regel}, "vor": {strconv.FormatInt(ids[alarmSeite-1], 10)}}.Encode()
		}
	} else {
		alle, err := a.db.Query(r.Context(), `SELECT host, regel, count(*) FROM alarme GROUP BY host, regel ORDER BY host, regel`)
		if err != nil {
			http.Error(w, "Datenbank", http.StatusInternalServerError)
			return
		}
		defer alle.Close()
		for alle.Next() {
			var g alarmGruppe
			var n int
			if err := alle.Scan(&g.Host, &g.Regel, &n); err != nil {
				http.Error(w, "Datenbank", http.StatusInternalServerError)
				return
			}
			if g.Weitere = n - gezeigt[[2]string{g.Host, g.Regel}]; g.Weitere > 0 {
				g.Adresse = "/alarme?" + url.Values{"host": {g.Host}, "regel": {g.Regel}}.Encode()
				mehr = append(mehr, g)
			}
		}
		if err := alle.Err(); err != nil {
			http.Error(w, "Datenbank", http.StatusInternalServerError)
			return
		}
	}
	var wege []string
	zeit := ""
	if a.alarme != nil {
		for _, m := range a.alarme.melder {
			wege = append(wege, m.name)
		}
		if a.alarme.bis > 0 {
			zeit = fmt.Sprintf("%d bis %d Uhr", a.alarme.von, a.alarme.bis)
		}
	}
	a.v.zeigen(w, r, "alarme", a.daten(r, "Alarme", "alarme", map[string]any{"Liste": l, "Mehr": mehr, "Aeltere": aeltere, "Gefiltert": gefiltert, "Host": host, "Regel": Alarm{Regel: regel}.RegelName(), "Wege": strings.Join(wege, " und "), "Arbeitszeit": zeit}))
}
