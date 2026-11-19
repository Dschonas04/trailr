# Trailr

Protokolliert, was Benutzer auf Linux-Systemen tun: Anmeldungen, Befehle, sudo, Änderungen. Zentral und manipulationssicher.

**Stand: 0.1.** Agent und Server laufen: Anmeldungen (SSH), sudo, su,
Sitzungen aus dem Journal, Befehle und Dateiänderungen über auditd, Puffer
auf dem Host, Hash-Kette je Host mit Prüfung, Übersicht, Filter, Sitzungen,
CSV-Export, Aufbewahrungsfrist. Alarme kommen noch.

## Nur der Agent, ohne Server

Der Agent kann die Trails selbst in einem Ordner ablegen. Dann braucht es
keinen Server, keine Datenbank und kein Docker: ein Programm, ein
systemd-Dienst.

```bash
# /etc/trailr/agent.env
TRAILR_ORDNER=/var/log/trailr
TRAILR_ORDNER_TAGE=365          # optional, sonst bleibt alles
```

Je Tag eine Datei `trail-2026-11-19.jsonl`, eine Zeile je Ereignis, mit
derselben Hash-Kette wie auf dem Server, über die Tage hinweg verkettet.

```bash
sudo trailr-agent zeigen                       # die letzten 50
sudo trailr-agent zeigen -benutzer jonas -art sudo -n 200
sudo trailr-agent zeigen -tag 2026-11-19
sudo trailr-agent pruefen                      # Kette nachrechnen
```

`pruefen` findet geänderte, gelöschte und eingeschobene Einträge. Grenze:
Wer auf dem Host root ist, kann die ganze Kette neu schreiben. Dagegen hilft
nur ein zweiter Ort, also der Server; beides zugleich geht auch
(`TRAILR_ORDNER` und `TRAILR_SERVER` setzen). In der Ansible-Rolle:
`trailr_ordner: /var/log/trailr`, für ohne Server `trailr_server: ""`.

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

1. Agent liest das Journal (sshd, systemd-logind) und auditd (sudo, su, Befehle, Dateien; dort kann nur schreiben, wer CAP_AUDIT_WRITE hat) und schickt Ereignisse
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
