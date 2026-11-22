# Änderungen

## Unveröffentlicht

- Doppelte id im Seitengerüst behoben.
- Sicherheit: Die Sperre der Verwaltung wartet weder auf den Browser noch auf den Anbieter und hat eine Zeitgrenze.
- Sicherheit: Änderungen an Konten, Rollen und Anmeldung laufen nacheinander, Prüfung und Schreiben unter einer Sperre.
- Sicherheit: Mit einem Konto enden seine Rechte; geprüft wird erst, wenn die Anfrage vollständig da ist.
- Sicherheit: Admin wird man nur mit dem Einrichtungscode oder über `TRAILR_ADMIN`, nicht durch die erste Anmeldung. Kennungen von eigenen Konten und SSO sind getrennt.
- Oberfläche überarbeitet: Kopfzeile, Tabellen und Felder am Handy, Anmeldeseite in den Farben der App.
- Logo auf der Anmeldeseite wird wieder ausgeliefert, der Hinweis zur Ersteinrichtung stimmt.
- Sicherheit: Anmeldung, Konten und Verwaltung nur noch für Admins.
- Sicherheit: Agent-Schlüssel sehen nur noch Admins.
- Agent: liest das Journal (sshd, sudo, su, systemd-logind) und das auditd-Protokoll (Befehle mit Login-UID, Änderungen unter /etc, /root/.ssh, /usr/local/bin), puffert auf der Platte, Lesemarken rücken erst nach dem Puffern vor.
- Server: nimmt Pakete mit Agent-Schlüssel an, verkettet je Host per SHA-256 (Zeile des Hosts gesperrt), verwirft Doppeltes.
- Oberfläche: Übersicht je Host, Ereignisse mit Filtern (Host, Benutzer, Art, Text, Zeitraum, Fehlschläge, Sitzung), CSV-Export, Kettenprüfung, Einrichtungsanleitung; der Server liefert den Agenten unter /agent/trailr-agent aus.
- Ansible-Rolle unter agent/ansible/trailr_agent.
- Grundgerüst: Server mit Startseite, /healthz und /api/version, Schemaentwurf, Docker, Prüfung in GitHub Actions.
