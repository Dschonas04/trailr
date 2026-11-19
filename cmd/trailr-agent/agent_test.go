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
		{"sshd", "Invalid user x from 9.9.9.9 port 1 from 1.2.3.4 port 22", "anmeldung", "x from 9.9.9.9 port 1", false},
		{"sshd", "Disconnected from user jonas 10.0.0.5 port 50122", "abmeldung", "jonas", true},
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

func TestJournalOhneSudo(t *testing.T) {
	z := neuerJournalLeser()
	// Ins Journal kann jeder als "sudo" schreiben; auch von root zählt es nicht.
	for _, uid := range []string{"0", "1000"} {
		z1 := []byte(`{"__CURSOR":"c1","SYSLOG_IDENTIFIER":"sudo","_UID":"` + uid + `","_EXE":"/usr/bin/sudo","__REALTIME_TIMESTAMP":"1","MESSAGE":"root : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/true"}`)
		if _, _, ok := z.zeile(z1); ok {
			t.Fatal("sudo aus dem Journal angenommen")
		}
	}
	gefaelscht := []byte(`{"__CURSOR":"c2","SYSLOG_IDENTIFIER":"sshd","_UID":"1000","__REALTIME_TIMESTAMP":"1","MESSAGE":"Accepted publickey for root from 10.0.0.5 port 1 ssh2"}`)
	if _, _, ok := z.zeile(gefaelscht); ok {
		t.Fatal("sshd-Zeile eines Benutzers angenommen")
	}
}

func TestAuditSudoSu(t *testing.T) {
	s := neuerAuditSammler()
	s.namen.m["1000"] = "debian"
	cmd := "646F636B6572207073" // "docker ps"
	l := s.zeile(`type=USER_CMD msg=audit(1795067527.074:1): pid=7 uid=1000 auid=1000 ses=850 subj=unconfined msg='cwd="/home/debian" cmd=` + cmd + ` exe="/usr/bin/sudo" terminal=pts/0 res=success'` + "\x1d" + `UID="debian"`)
	if len(l) != 0 {
		t.Fatal("sudo zu früh gemeldet")
	}
	l = s.zeile(`type=USER_START msg=audit(1795067527.078:2): pid=7 uid=1000 auid=1000 ses=850 subj=unconfined msg='op=PAM:session_open grantors=pam_unix acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=pts/0 res=success'`)
	if len(l) != 1 || l[0].Art != "sudo" || l[0].Benutzer != "debian" || l[0].Als != "root" || l[0].Text != "docker ps" || !l[0].Erfolg {
		t.Fatalf("sudo: %+v", l)
	}
	l = s.zeile(`type=USER_START msg=audit(1795067600.000:3): pid=9 uid=1000 auid=1000 ses=851 subj=unconfined msg='op=PAM:session_open grantors=pam_unix acct="root" exe="/usr/bin/su" hostname=? addr=? terminal=pts/1 res=success'`)
	if len(l) != 1 || l[0].Art != "su" || l[0].Als != "root" || l[0].Benutzer != "debian" {
		t.Fatalf("su: %+v", l)
	}
	l = s.zeile(`type=USER_AUTH msg=audit(1795067600.100:4): pid=10 uid=1000 auid=1000 ses=851 subj=unconfined msg='op=PAM:authentication grantors=? acct="root" exe="/usr/bin/su" hostname=? addr=? terminal=pts/1 res=failed'`)
	if len(l) != 1 || l[0].Erfolg {
		t.Fatalf("su falsch: %+v", l)
	}
	// Anderes Programm mit USER_START (etwa cron) zählt nicht.
	if l = s.zeile(`type=USER_START msg=audit(1795067600.200:5): pid=11 uid=0 auid=0 ses=1 msg='op=PAM:session_open acct="root" exe="/usr/sbin/cron" res=success'`); len(l) != 0 {
		t.Fatalf("cron gemeldet: %+v", l)
	}
}
