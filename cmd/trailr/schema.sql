-- Datenbankschema von Trailr. Idempotent: wird bei jedem Start eingespielt.
CREATE TABLE IF NOT EXISTS hosts (
	id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	name         text NOT NULL UNIQUE,
	zuletzt      timestamptz,
	agent        text NOT NULL DEFAULT '',          -- Version des Agenten
	letzter_hash text NOT NULL DEFAULT ''           -- Ende der Hash-Kette
);

-- Ein Ereignis ist eine Benutzeraktion. hash = sha256(vorher | Inhalt): wird
-- ein Eintrag geändert oder gelöscht, passt die Kette ab dort nicht mehr.
CREATE TABLE IF NOT EXISTS ereignisse (
	id        bigserial PRIMARY KEY,
	host      uuid NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
	kennung   text NOT NULL,                       -- vom Agenten, gegen doppelte Lieferung
	zeit      timestamptz NOT NULL,
	art       text NOT NULL,                       -- anmeldung | abmeldung | sitzung | befehl | sudo | su | datei
	benutzer  text NOT NULL,                       -- wer es ausgelöst hat (Login-UID)
	als       text NOT NULL DEFAULT '',            -- unter welchem Konto es lief
	sitzung   text NOT NULL DEFAULT '',
	quelle    text NOT NULL DEFAULT '',            -- IP bei SSH, tty bei Konsole
	erfolg    boolean NOT NULL DEFAULT true,
	text      text NOT NULL DEFAULT '',            -- Befehl, Pfad, Meldung
	daten     jsonb NOT NULL DEFAULT '{}',
	vorher    text NOT NULL,
	hash      text NOT NULL UNIQUE,
	empfangen timestamptz NOT NULL DEFAULT now(),
	UNIQUE (host, kennung)
);
CREATE INDEX IF NOT EXISTS ereignisse_host_zeit ON ereignisse(host, zeit DESC);
CREATE INDEX IF NOT EXISTS ereignisse_benutzer_zeit ON ereignisse(benutzer, zeit DESC);
CREATE INDEX IF NOT EXISTS ereignisse_zeit ON ereignisse(zeit DESC);

-- Wer die App verwaltet. Die erste angemeldete Person trägt sich ein.
CREATE TABLE IF NOT EXISTS admins (
	kennung text PRIMARY KEY,
	erster  boolean UNIQUE,
	seit    timestamptz NOT NULL DEFAULT now()
);
