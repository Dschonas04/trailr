package main

import (
	"strings"
	"testing"

	"trailr/internal/ereignis"
)

func TestJournalDeuten(t *testing.T) {
	z := neuerJournalLeser()
	faelle := []struct {
		ident, msg string
		art, wer   string
		ok         bool
	}{
		{"sshd", "Accepted publickey for jonas from 10.0.0.5 port 50122 ssh2: ED25519 SHA256:abc", "anmeldung", "jonas", true},
		{"sshd-session", "Failed password for invalid user admin from 1.2.3.4 port 22 ssh2", "anmeldung", "admin", false},
		{"sshd", "Invalid user  from 1.2.3.4 port 22", "anmeldung", "(leer)", false},
		{"sshd", "Disconnected from user jonas 10.0.0.5 port 50122", "abmeldung", "jonas", true},
		{"sudo", "   jonas : TTY=pts/0 ; PWD=/home/jonas ; USER=root ; COMMAND=/usr/bin/apt update", "sudo", "jonas", true},
		{"sudo", "   gast : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/ ; USER=root ; COMMAND=/bin/bash", "sudo", "gast", false},
		{"sudo", "jonas : TTY=pts/0 ; PWD=/root ; USER=root ; ENV=A=1 ; COMMAND=/usr/bin/id", "sudo", "jonas", true},
		{"sudo", "  debian : PWD=/home/debian ; USER=root ; COMMAND=/usr/bin/id", "sudo", "debian", true},
		{"su", "(to root) jonas on pts/2", "su", "jonas", true},
		{"su", "FAILED SU (to root) gast on pts/3", "su", "gast", false},
		{"systemd-logind", "New session 42 of user jonas.", "sitzung", "jonas", true},
		{"systemd-logind", "Removed session 42.", "sitzung", "jonas", true},
	}
	for _, f := range faelle {
		var e ereignis.Ereignis
		e.Erfolg = true
		if !z.deuten(f.ident, f.msg, &e) {
			t.Errorf("nicht erkannt: %s", f.msg)
			continue
		}
		if e.Art != f.art || e.Benutzer != f.wer || e.Erfolg != f.ok {
			t.Errorf("%s: %+v", f.msg, e)
		}
	}
	var e ereignis.Ereignis
	if z.deuten("sshd", "Server listening on 0.0.0.0 port 22.", &e) {
		t.Error("Rauschen erkannt")
	}
}

func TestAuditSammeln(t *testing.T) {
	s := neuerAuditSammler()
	zeilen := []string{
		`type=SYSCALL msg=audit(1731940000.123:4567): arch=c000003e syscall=59 success=yes exit=0 a0=55 ppid=100 pid=101 auid=0 uid=0 gid=0 euid=0 ses=3 tty=pts0 comm="ls" exe="/usr/bin/ls" key="trailr_befehl"` + "\x1d" + `AUID="root"`,
		`type=EXECVE msg=audit(1731940000.123:4567): argc=3 a0="ls" a1="-la" a2=2F746D702F6D69742053706163652F`,
		`type=CWD msg=audit(1731940000.123:4567): cwd="/root"`,
		`type=PROCTITLE msg=audit(1731940000.123:4567): proctitle=6C73`,
		`type=EOE msg=audit(1731940000.123:4567): `,
	}
	var l []ereignis.Ereignis
	for _, z := range zeilen {
		l = append(l, s.zeile(z)...)
	}
	if len(l) != 1 {
		t.Fatalf("%d Ereignisse", len(l))
	}
	e := l[0]
	if e.Art != "befehl" || e.Text != "ls -la /tmp/mit Space/" || e.Benutzer != "root" || e.Quelle != "pts0" || e.Daten["verzeichnis"] != "/root" {
		t.Fatalf("%+v", e)
	}
	// Ohne Login-UID (Dienste) kein Ereignis.
	s.zeile(`type=SYSCALL msg=audit(1731940001.000:4568): syscall=59 success=yes auid=4294967295 uid=0 euid=0 ses=4294967295 tty=(none) exe="/usr/bin/cron" key="trailr_befehl"`)
	s.zeile(`type=EXECVE msg=audit(1731940001.000:4568): argc=1 a0="cron"`)
	if l := s.zeile(`type=EOE msg=audit(1731940001.000:4568): `); len(l) != 0 {
		t.Fatal("Dienst gemeldet")
	}
	// Datei
	s.zeile(`type=SYSCALL msg=audit(1731940002.000:4569): syscall=257 success=yes auid=0 uid=0 euid=0 ses=3 tty=pts0 exe="/usr/bin/vim.basic" key="trailr_datei"`)
	s.zeile(`type=PATH msg=audit(1731940002.000:4569): item=0 name="/etc/" nametype=PARENT`)
	s.zeile(`type=PATH msg=audit(1731940002.000:4569): item=1 name="/etc/hosts" nametype=CREATE`)
	l = s.zeile(`type=EOE msg=audit(1731940002.000:4569): `)
	if len(l) != 1 || l[0].Art != "datei" || !strings.Contains(l[0].Text, "/etc/hosts (neu)") {
		t.Fatalf("Datei: %+v", l)
	}
}

func TestKette(t *testing.T) {
	e := ereignis.Ereignis{Kennung: "x", Art: "sudo", Benutzer: "jonas", Erfolg: true}
	a := ereignis.Hash("", e)
	e.Daten = map[string]string{}
	if ereignis.Hash("", e) != a {
		t.Fatal("leere Daten ändern den Hash")
	}
	e.Text = "anders"
	if ereignis.Hash("", e) == a || ereignis.Hash("v", e) == ereignis.Hash("", e) {
		t.Fatal("Hash unempfindlich")
	}
}
