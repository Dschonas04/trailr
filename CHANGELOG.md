# Änderungen

## Unveröffentlicht

- Oberfläche überarbeitet: Kopfzeile, Tabellen und Felder am Handy, Anmeldeseite in den Farben der App.
- Logo auf der Anmeldeseite wird wieder ausgeliefert, der Hinweis zur Ersteinrichtung stimmt.
- Sicherheit: Anmeldung, Konten und Verwaltung nur noch für Admins. Admin ist, wer sich zuerst anmeldet.
- Sicherheit: Agent-Schlüssel sehen nur noch Admins.
- Agent: liest das Journal (sshd, sudo, su, systemd-logind) und das auditd-Protokoll (Befehle mit Login-UID, Änderungen unter /etc, /root/.ssh, /usr/local/bin), puffert auf der Platte, Lesemarken rücken erst nach dem Puffern vor.
- Server: nimmt Pakete mit Agent-Schlüssel an, verkettet je Host per SHA-256 (Zeile des Hosts gesperrt), verwirft Doppeltes.
- Oberfläche: Übersicht je Host, Ereignisse mit Filtern (Host, Benutzer, Art, Text, Zeitraum, Fehlschläge, Sitzung), CSV-Export, Kettenprüfung, Einrichtungsanleitung; der Server liefert den Agenten unter /agent/trailr-agent aus.
- Ansible-Rolle unter agent/ansible/trailr_agent.
- Grundgerüst: Server mit Startseite, /healthz und /api/version, Schemaentwurf, Docker, Prüfung in GitHub Actions.
