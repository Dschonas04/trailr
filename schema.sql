-- Datenbankschema von Trailr (Entwurf).
CREATE TABLE IF NOT EXISTS hosts (
	id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
	name       text NOT NULL UNIQUE,             -- aus dem Client-Zertifikat (CN)
	zuletzt    timestamptz,
	letzter_hash text NOT NULL DEFAULT ''        -- Ende der Hash-Kette
);

-- Ein Ereignis ist eine Benutzeraktion. hash = sha256(vorher || inhalt): wird
-- ein Eintrag geändert oder gelöscht, passt die Kette ab dort nicht mehr.
CREATE TABLE IF NOT EXISTS ereignisse (
	id        bigserial PRIMARY KEY,
	host      uuid NOT NULL REFERENCES hosts(id),
	zeit      timestamptz NOT NULL,
	art       text NOT NULL,                     -- anmeldung | abmeldung | befehl | sudo | su | datei | paket | dienst
	benutzer  text NOT NULL,                     -- wer es ausgelöst hat (Login-UID)
	als       text NOT NULL DEFAULT '',          -- unter welchem Konto es lief (root nach sudo)
	sitzung   text NOT NULL DEFAULT '',
	quelle    text NOT NULL DEFAULT '',          -- IP bei SSH, tty bei Konsole
	erfolg    boolean NOT NULL DEFAULT true,
	daten     jsonb NOT NULL DEFAULT '{}',       -- Befehl, Pfad, Paket ...
	vorher    text NOT NULL,
	hash      text NOT NULL UNIQUE
);
CREATE INDEX IF NOT EXISTS ereignisse_host_zeit ON ereignisse(host, zeit DESC);
CREATE INDEX IF NOT EXISTS ereignisse_benutzer_zeit ON ereignisse(benutzer, zeit DESC);
