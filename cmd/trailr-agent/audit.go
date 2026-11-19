package main

import (
	"bufio"
	"context"
	"encoding/hex"
	"io"
	"log"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"trailr/internal/ereignis"
)

// Aus dem auditd-Protokoll kommen Befehle (Schlüssel trailr_befehl) und
// Dateiänderungen (trailr_datei), siehe agent/ansible/trailr_agent/files/audit.rules. Ein Audit-Ereignis
// besteht aus mehreren Zeilen mit derselben Nummer (SYSCALL, EXECVE, PATH,
// PROCTITLE, EOE); gesammelt wird bis EOE oder bis eine neue Nummer kommt.

type auditStand struct {
	Inode  uint64 `json:"inode"`
	Offset int64  `json:"offset"`
}

var (
	auditKopf = regexp.MustCompile(`^type=(\S+) msg=audit\((\d+)\.(\d+):(\d+)\):\s?(.*)$`)
	auditFeld = regexp.MustCompile(`(\w+)=("(?:[^"]*)"|\S+)`)
)

func (a *agent) auditLesen(ctx context.Context, pfad string) {
	gemeldet := false
	for ctx.Err() == nil {
		f, err := os.Open(pfad)
		if err != nil {
			if !gemeldet {
				log.Printf("auditd-Protokoll %s nicht lesbar (%v): Befehle und Dateien fehlen, Anmeldungen und sudo kommen trotzdem", pfad, err)
				gemeldet = true
			}
			time.Sleep(30 * time.Second)
			continue
		}
		gemeldet = false
		a.auditDatei(ctx, f, pfad)
		f.Close()
	}
}

func inode(f *os.File) uint64 {
	st, err := f.Stat()
	if err != nil {
		return 0
	}
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return s.Ino
	}
	return 0
}

// auditDatei liest eine Datei bis zur Rotation (neue Inode unter dem Pfad).
func (a *agent) auditDatei(ctx context.Context, f *os.File, pfad string) {
	ino := inode(f)
	a.mu.Lock()
	stand := a.auditPos
	a.mu.Unlock()
	pos := int64(0)
	if stand.Inode == ino {
		pos = stand.Offset
	} else if stand.Inode == 0 {
		// Erster Start: nicht die ganze Vergangenheit, ab jetzt.
		pos, _ = f.Seek(0, io.SeekEnd)
	}
	if st, err := f.Stat(); err == nil && pos > st.Size() {
		pos = 0
	}
	f.Seek(pos, io.SeekStart)
	r := bufio.NewReaderSize(f, 1<<16)
	s := neuerAuditSammler()
	rest := ""
	for ctx.Err() == nil {
		zeile, err := r.ReadString('\n')
		if err == io.EOF {
			rest += zeile
			// Rotation? Dann die alte Datei zu Ende lesen und wechseln.
			if neu, e := os.Stat(pfad); e == nil {
				if s2, ok := neu.Sys().(*syscall.Stat_t); ok && s2.Ino != ino {
					for _, ev := range s.alles() {
						a.melden(ev, "", &auditStand{Inode: ino, Offset: pos})
					}
					a.mu.Lock()
					a.auditPos = auditStand{Inode: s2.Ino, Offset: 0}
					a.mu.Unlock()
					return
				}
			}
			for _, ev := range s.alteAbschliessen() {
				a.melden(ev, "", &auditStand{Inode: ino, Offset: pos})
			}
			time.Sleep(500 * time.Millisecond)
			continue
		}
		if err != nil {
			return
		}
		zeile = rest + zeile
		rest = ""
		pos += int64(len(zeile))
		for _, ev := range s.zeile(strings.TrimRight(zeile, "\n")) {
			a.melden(ev, "", &auditStand{Inode: ino, Offset: pos})
		}
	}
}

type auditSatz struct {
	zeit    time.Time
	nummer  string
	syscall map[string]string
	args    []string
	pfade   []map[string]string
	cwd     string
	zuletzt time.Time
}

type auditSammler struct {
	offen map[string]*auditSatz
	namen *namen
	// sudo meldet erst den Befehl (USER_CMD), dann für wen er läuft
	// (USER_START); beides kommt vom selben Prozess.
	sudo map[string]*sudoOffen
}

type sudoOffen struct {
	e    ereignis.Ereignis
	seit time.Time
}

func neuerAuditSammler() *auditSammler {
	return &auditSammler{offen: map[string]*auditSatz{}, namen: &namen{m: map[string]string{}}, sudo: map[string]*sudoOffen{}}
}

// sudo und su kommen aus auditd, nicht aus dem Journal: USER_*-Sätze darf nur
// schreiben, wer CAP_AUDIT_WRITE hat (sudo, su, sshd), und uid/auid setzt der
// Kern. Ins Journal dagegen kann jeder unter dem Namen sudo schreiben.
var vertrauteProgramme = map[string]string{"/usr/bin/sudo": "sudo", "/bin/sudo": "sudo", "/usr/bin/su": "su", "/bin/su": "su"}

func (s *auditSammler) benutzerSatz(typ, nummer string, zeit time.Time, rest string) []ereignis.Ereignis {
	f := felder(strings.ReplaceAll(rest, "'", " "))
	prog := vertrauteProgramme[wert(f["exe"])]
	if prog == "" {
		return nil
	}
	auid := f["auid"]
	if auid == "" || auid == "4294967295" {
		auid = f["uid"]
	}
	quelle := wert(f["terminal"])
	if quelle == "?" {
		quelle = ""
	}
	e := ereignis.Ereignis{Kennung: "a:" + nummer, Zeit: zeit, Benutzer: s.namen.von(auid), Sitzung: f["ses"],
		Quelle: quelle, Erfolg: f["res"] == "success", Art: prog, Daten: map[string]string{"programm": wert(f["exe"])}}
	if e.Sitzung == "4294967295" {
		e.Sitzung = ""
	}
	pid := f["pid"]
	switch {
	case prog == "sudo" && typ == "USER_CMD":
		e.Text = wert(f["cmd"])
		if c := wert(f["cwd"]); c != "" {
			e.Daten["verzeichnis"] = c
		}
		s.sudo[pid] = &sudoOffen{e: e, seit: time.Now()}
	case prog == "sudo" && typ == "USER_START":
		if o := s.sudo[pid]; o != nil {
			delete(s.sudo, pid)
			o.e.Als = wert(f["acct"])
			return []ereignis.Ereignis{o.e}
		}
	case prog == "sudo" && typ == "USER_AUTH" && !e.Erfolg:
		e.Text = "sudo: Kennwort falsch"
		return []ereignis.Ereignis{e}
	case prog == "su" && typ == "USER_START":
		e.Als = wert(f["acct"])
		e.Text = "su zu " + e.Als
		return []ereignis.Ereignis{e}
	case prog == "su" && typ == "USER_AUTH" && !e.Erfolg:
		e.Als = wert(f["acct"])
		e.Text = "su zu " + e.Als + " (Kennwort falsch)"
		return []ereignis.Ereignis{e}
	}
	return nil
}

func felder(s string) map[string]string {
	m := map[string]string{}
	// Angereichertes Format: hinter \x1d stehen aufgelöste Namen, nicht nötig.
	if i := strings.IndexByte(s, 0x1d); i >= 0 {
		s = s[:i]
	}
	for _, f := range auditFeld.FindAllStringSubmatch(s, -1) {
		m[f[1]] = f[2]
	}
	return m
}

// wert entschlüsselt einen Audit-Wert: "text" oder hexkodiert.
func wert(v string) string {
	if strings.HasPrefix(v, `"`) && strings.HasSuffix(v, `"`) && len(v) >= 2 {
		return v[1 : len(v)-1]
	}
	if v == "(null)" {
		return ""
	}
	if b, err := hex.DecodeString(v); err == nil && len(v)%2 == 0 {
		return strings.ToValidUTF8(strings.ReplaceAll(string(b), "\x00", " "), "?")
	}
	return v
}

func (s *auditSammler) zeile(z string) []ereignis.Ereignis {
	m := auditKopf.FindStringSubmatch(z)
	if m == nil {
		return nil
	}
	typ, sek, ms, nummer, rest := m[1], m[2], m[3], m[4], m[5]
	schl := sek + "." + ms + ":" + nummer
	sz := s.offen[schl]
	if sz == nil {
		sk, _ := strconv.ParseInt(sek, 10, 64)
		mz, _ := strconv.ParseInt(ms, 10, 64)
		sz = &auditSatz{zeit: time.Unix(sk, mz*int64(time.Millisecond)), nummer: schl}
		s.offen[schl] = sz
	}
	sz.zuletzt = time.Now()
	if strings.HasPrefix(typ, "USER_") {
		delete(s.offen, schl)
		return s.benutzerSatz(typ, schl, sz.zeit, rest)
	}
	f := felder(rest)
	switch typ {
	case "SYSCALL":
		sz.syscall = f
	case "EXECVE":
		n, _ := strconv.Atoi(f["argc"])
		for i := 0; i < n && i < 64; i++ {
			sz.args = append(sz.args, wert(f["a"+strconv.Itoa(i)]))
		}
	case "CWD":
		sz.cwd = wert(f["cwd"])
	case "PATH":
		sz.pfade = append(sz.pfade, f)
	case "EOE":
		delete(s.offen, schl)
		if e, ok := s.ereignis(sz); ok {
			return []ereignis.Ereignis{e}
		}
	}
	return nil
}

// alteAbschliessen: Sätze ohne EOE, die seit zwei Sekunden ruhen.
func (s *auditSammler) alteAbschliessen() []ereignis.Ereignis {
	var l []ereignis.Ereignis
	// sudo ohne USER_START (etwa abgelehnt): nach zwei Sekunden so melden.
	for pid, o := range s.sudo {
		if time.Since(o.seit) > 2*time.Second {
			delete(s.sudo, pid)
			l = append(l, o.e)
		}
	}
	for k, sz := range s.offen {
		if time.Since(sz.zuletzt) > 2*time.Second {
			delete(s.offen, k)
			if e, ok := s.ereignis(sz); ok {
				l = append(l, e)
			}
		}
	}
	return l
}

func (s *auditSammler) alles() []ereignis.Ereignis {
	var l []ereignis.Ereignis
	for k, sz := range s.offen {
		delete(s.offen, k)
		if e, ok := s.ereignis(sz); ok {
			l = append(l, e)
		}
	}
	return l
}

func (s *auditSammler) ereignis(sz *auditSatz) (ereignis.Ereignis, bool) {
	sc := sz.syscall
	if sc == nil {
		return ereignis.Ereignis{}, false
	}
	key := wert(sc["key"])
	auid := sc["auid"]
	if auid == "" || auid == "4294967295" || auid == "-1" {
		return ereignis.Ereignis{}, false
	}
	e := ereignis.Ereignis{Kennung: "a:" + sz.nummer, Zeit: sz.zeit, Benutzer: s.namen.von(auid),
		Als: s.namen.von(sc["euid"]), Sitzung: sc["ses"], Quelle: sc["tty"], Erfolg: sc["success"] != "no",
		Daten: map[string]string{"programm": wert(sc["exe"])}}
	if sz.cwd != "" {
		e.Daten["verzeichnis"] = sz.cwd
	}
	if e.Quelle == "(none)" {
		e.Quelle = ""
	}
	switch key {
	case "trailr_befehl":
		if len(sz.args) == 0 {
			return ereignis.Ereignis{}, false
		}
		e.Art, e.Text = "befehl", strings.Join(sz.args, " ")
	case "trailr_datei":
		var namen []string
		for _, p := range sz.pfade {
			n := wert(p["name"])
			if n == "" {
				continue
			}
			if t := p["nametype"]; t == "DELETE" || t == "CREATE" {
				n += " (" + map[string]string{"DELETE": "gelöscht", "CREATE": "neu"}[t] + ")"
			}
			namen = append(namen, n)
		}
		if len(namen) == 0 {
			return ereignis.Ereignis{}, false
		}
		e.Art, e.Text = "datei", strings.Join(namen, ", ")
	default:
		return ereignis.Ereignis{}, false
	}
	if len(e.Text) > 4000 {
		e.Text = e.Text[:4000]
	}
	return e, true
}

// namen löst UIDs auf und merkt sich das Ergebnis.
type namen struct {
	mu sync.Mutex
	m  map[string]string
}

func (n *namen) von(uid string) string {
	if uid == "" {
		return ""
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if x, ok := n.m[uid]; ok {
		return x
	}
	name := uid
	if u, err := user.LookupId(uid); err == nil {
		name = u.Username
	}
	n.m[uid] = name
	return name
}
