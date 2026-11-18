# Trailr

Protokolliert, was Benutzer auf Linux-Systemen tun: Anmeldungen, Befehle, sudo, Änderungen. Zentral und manipulationssicher.

**Stand: 0.1.** Agent und Server laufen: Anmeldungen (SSH), sudo, su,
Sitzungen aus dem Journal, Befehle und Dateiänderungen über auditd, Puffer
auf dem Host, Hash-Kette je Host mit Prüfung, Übersicht, Filter, Sitzungen,
CSV-Export, Aufbewahrungsfrist. Alarme kommen noch.

## Geplant

* **Agent auf jedem Host** (ein statisches Go-Programm, systemd-Dienst), verteilt per Ansible-Rolle
* **Anmeldungen**: SSH, Konsole, su, sudo, mit Quelle, Schlüssel oder Kennwort, Erfolg und Fehlschlag
* **Ausgeführte Befehle** über auditd (execve mit Login-UID): auch nach sudo bleibt sichtbar, wer es war
* **Änderungen** an überwachten Pfaden (/etc, Schlüssel, Cron, systemd-Units)
* **Pakete und Dienste**: apt/dnf-Installationen, systemctl start/stop/enable
* **Zentraler Server** mit Suche nach Benutzer, Host, Zeitraum und Befehl, Sitzungen als Zeitleiste
* **Manipulationssicher**: Ereignisse in einer Hash-Kette je Host, Lücken und Änderungen fallen auf
* **Alarme** per Telegram oder Mail (z. B. sudo außerhalb der Arbeitszeit, unbekannte Quelle)
* **Übertragung mit mTLS** über die Homelab-CA, Puffer auf dem Host, wenn der Server fehlt
* **Aufbewahrungsfristen** und Export (JSON, CSV)

## Aufbau

```
cmd/trailr         Server: nimmt Ereignisse an, speichert, Weboberfläche
cmd/trailr-agent   Agent: läuft auf jedem Linux-Host als systemd-Dienst
```

Der Agent braucht Leserechte auf das Journal (Gruppe `systemd-journal`) und,
für Befehle und Dateien, auditd mit den Regeln aus `agent/ansible/trailr_agent/files/audit.rules`.

## Schritte

1. Agent liest das Journal (sshd, sudo, su, systemd-logind) und schickt Ereignisse
2. Server nimmt per mTLS an, speichert mit Hash-Kette
3. Weboberfläche: Suche und Zeitleiste je Sitzung
4. auditd-Regeln für Befehle und überwachte Pfade
5. Ansible-Rolle zum Verteilen
6. Alarme, Aufbewahrung, Export

## Starten

```bash
cp .env.beispiel .env            # Kennwort für die Datenbank eintragen
docker compose up -d --build
```

Danach unter `http://<host>:8400`. Im Homelab kommt TLS über Caddy mit
der Homelab-CA davor, der Dienst selbst lauscht dann auf `127.0.0.1:28400`.

## Entwickeln

```bash
go run ./cmd/trailr            # braucht TRAILR_AGENT_SCHLUESSEL
TRAILR_SERVER=http://localhost:8400 TRAILR_SCHLUESSEL=... go run ./cmd/trailr-agent -stand /tmp/trailr
go test ./...
```

Go 1.27.4, Datenbank PostgreSQL. Das Schema steht in `schema.sql`.

## Lizenz

MIT, siehe [LICENSE](LICENSE).
