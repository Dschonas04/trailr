package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"trailr/internal/ereignis"
)

// Aus dem Journal kommen Anmeldungen, sudo, su und Sitzungen. journalctl
// läuft als Kindprozess und liefert JSON; bricht er ab, startet er neu und
// macht bei der letzten Lesemarke weiter.
var quellen = []string{"sshd", "sshd-session", "sudo", "su", "systemd-logind"}

func (a *agent) journalLesen(ctx context.Context) {
	for ctx.Err() == nil {
		args := []string{"-f", "-o", "json", "--no-pager", "--no-tail"}
		a.mu.Lock()
		cursor := a.journal
		a.mu.Unlock()
		if cursor != "" {
			args = append(args, "--after-cursor="+cursor)
		} else {
			args = append(args, "--since=now")
		}
		for i, q := range quellen {
			if i > 0 {
				args = append(args, "+")
			}
			args = append(args, "SYSLOG_IDENTIFIER="+q)
		}
		cmd := exec.CommandContext(ctx, "journalctl", args...)
		aus, err := cmd.StdoutPipe()
		if err == nil {
			err = cmd.Start()
		}
		if err != nil {
			log.Printf("journalctl: %v", err)
			time.Sleep(10 * time.Second)
			continue
		}
		z := neuerJournalLeser()
		sc := bufio.NewScanner(aus)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			e, cur, ok := z.zeile(sc.Bytes())
			if ok {
				a.melden(e, cur, nil)
			} else if cur != "" {
				a.mu.Lock()
				a.journal = cur
				a.mu.Unlock()
			}
		}
		cmd.Wait()
		if ctx.Err() == nil {
			log.Printf("journalctl beendet, starte neu")
			time.Sleep(5 * time.Second)
		}
	}
}

type journalLeser struct {
	mu      sync.Mutex
	sitzung map[string]string // logind-Sitzung -> Benutzer
}

func neuerJournalLeser() *journalLeser { return &journalLeser{sitzung: map[string]string{}} }

var (
	// Angelegt am Zeilenende: ein Benutzername mit " from 1.2.3.4 port"
	// darin verschiebt die Quelle nicht.
	sshAngenommen = regexp.MustCompile(`^Accepted (\S+) for (\S+) from (\S+) port \d+ ssh2(?:: .*)?$`)
	sshFehl       = regexp.MustCompile(`^Failed (\S+) for (?:invalid user )?(.*) from (\S+) port \d+ ssh2$`)
	sshUnbekannt  = regexp.MustCompile(`^Invalid user (.*) from (\S+) port \d+$`)
	sshWeg        = regexp.MustCompile(`^Disconnected from (?:authenticating )?user (\S+) (\S+) port \d+(?: \[preauth\])?$`)
	sudoZeile     = regexp.MustCompile(`^\s*(\S+) : (.*?)(?:TTY=(\S+) ; )?PWD=(\S+) ; USER=(\S+) ;(?: [A-Z]+=\S+ ;)* COMMAND=(.*)$`)
	suZeile       = regexp.MustCompile(`^(FAILED SU )?\(to (\S+)\) (\S+) on (\S+)`)
	logindNeu     = regexp.MustCompile(`^New session (\S+) of user (\S+)\.`)
	logindWeg     = regexp.MustCompile(`^Removed session (\S+)\.`)
)

// nachricht liest MESSAGE: im Journal ein Text oder, bei Bytes außerhalb von
// UTF-8, eine Liste von Zahlen.
func nachricht(roh json.RawMessage) string {
	var s string
	if json.Unmarshal(roh, &s) == nil {
		return s
	}
	var b []byte
	var zahlen []int
	if json.Unmarshal(roh, &zahlen) == nil {
		for _, z := range zahlen {
			b = append(b, byte(z))
		}
		return strings.ToValidUTF8(string(b), "?")
	}
	return ""
}

// su und sudo laufen mit der echten UID dessen, der sie aufruft; das Journal
// trägt dann dessen UID ein. Echt ist die Zeile trotzdem, wenn sie vom
// installierten Programm kommt: _EXE stammt wie _UID vom Journal, nicht vom
// Absender, und nach /usr/bin schreibt nur root.
var vertraut = map[string]map[string]bool{
	"su":   {"/usr/bin/su": true, "/bin/su": true},
	"sudo": {"/usr/bin/sudo": true, "/bin/sudo": true},
}

func (z *journalLeser) zeile(roh []byte) (ereignis.Ereignis, string, bool) {
	var f map[string]json.RawMessage
	if json.Unmarshal(roh, &f) != nil {
		return ereignis.Ereignis{}, "", false
	}
	var cursor, ident, zeit, uid, exe string
	json.Unmarshal(f["__CURSOR"], &cursor)
	// _UID setzt das Journal selbst, nicht der Absender: nur Zeilen von root
	// zählen. Sonst könnte jeder mit logger -t sudo etwas vortäuschen.
	json.Unmarshal(f["_UID"], &uid)
	json.Unmarshal(f["_EXE"], &exe)
	json.Unmarshal(f["SYSLOG_IDENTIFIER"], &ident)
	json.Unmarshal(f["__REALTIME_TIMESTAMP"], &zeit)
	us, _ := strconv.ParseInt(zeit, 10, 64)
	msg := nachricht(f["MESSAGE"])
	h := sha256.Sum256([]byte(cursor))
	e := ereignis.Ereignis{Kennung: "j:" + hex.EncodeToString(h[:12]), Zeit: time.UnixMicro(us), Erfolg: true}
	if uid != "0" && !vertraut[ident][exe] {
		return e, cursor, false
	}
	ok := z.deuten(ident, msg, &e)
	return e, cursor, ok
}

// deuten macht aus einer Journalzeile ein Ereignis, wenn sie eine
// Benutzeraktion beschreibt.
func (z *journalLeser) deuten(ident, msg string, e *ereignis.Ereignis) bool {
	switch ident {
	case "sshd", "sshd-session":
		defer func() {
			if net.ParseIP(e.Quelle) == nil {
				e.Quelle = "ungültig: " + e.Quelle
			}
		}()
		if m := sshAngenommen.FindStringSubmatch(msg); m != nil {
			e.Art, e.Benutzer, e.Quelle, e.Text = "anmeldung", m[2], m[3], "SSH mit "+m[1]
			return true
		}
		if m := sshFehl.FindStringSubmatch(msg); m != nil {
			e.Art, e.Benutzer, e.Quelle, e.Erfolg, e.Text = "anmeldung", m[2], m[3], false, "SSH mit "+m[1]
			return true
		}
		if m := sshUnbekannt.FindStringSubmatch(msg); m != nil {
			e.Art, e.Benutzer, e.Quelle, e.Erfolg, e.Text = "anmeldung", m[1], m[2], false, "SSH, unbekannter Benutzer"
			if e.Benutzer == "" {
				e.Benutzer = "(leer)"
			}
			return true
		}
		if m := sshWeg.FindStringSubmatch(msg); m != nil {
			e.Art, e.Benutzer, e.Quelle, e.Text = "abmeldung", m[1], m[2], "SSH getrennt"
			return true
		}
	case "sudo":
		if m := sudoZeile.FindStringSubmatch(msg); m != nil {
			e.Art, e.Benutzer, e.Als, e.Quelle, e.Text = "sudo", m[1], m[5], m[3], m[6]
			e.Daten = map[string]string{"verzeichnis": m[4]}
			if grund := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(m[2]), ";")); grund != "" {
				e.Erfolg = false
				e.Daten["grund"] = grund
			}
			return true
		}
	case "su":
		if m := suZeile.FindStringSubmatch(msg); m != nil {
			e.Art, e.Benutzer, e.Als, e.Quelle, e.Erfolg = "su", m[3], m[2], m[4], m[1] == ""
			e.Text = "su zu " + m[2]
			return true
		}
	case "systemd-logind":
		z.mu.Lock()
		defer z.mu.Unlock()
		if m := logindNeu.FindStringSubmatch(msg); m != nil {
			z.sitzung[m[1]] = m[2]
			e.Art, e.Benutzer, e.Sitzung, e.Text = "sitzung", m[2], m[1], "Sitzung beginnt"
			return true
		}
		if m := logindWeg.FindStringSubmatch(msg); m != nil {
			b := z.sitzung[m[1]]
			delete(z.sitzung, m[1])
			if b == "" {
				b = "(unbekannt)"
			}
			e.Art, e.Benutzer, e.Sitzung, e.Text = "sitzung", b, m[1], "Sitzung endet"
			return true
		}
	}
	return false
}
