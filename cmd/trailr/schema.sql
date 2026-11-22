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

-- Wer die App eingerichtet hat und verwaltet. Dazu kommt TRAILR_ADMIN.
CREATE TABLE IF NOT EXISTS admins (
	kennung text PRIMARY KEY,
	seit    timestamptz NOT NULL DEFAULT now()
);

-- Wo die Kette beginnt. Nach dem Aufräumen rückt er vor, sonst nie: fehlt der
-- älteste Eintrag, fällt es auf.
ALTER TABLE hosts ADD COLUMN IF NOT EXISTS kette_anfang text;
UPDATE hosts h SET kette_anfang = COALESCE(
	(SELECT e.vorher FROM ereignisse e WHERE e.host = h.id ORDER BY e.id LIMIT 1), h.letzter_hash)
	WHERE h.kette_anfang IS NULL;

CREATE TABLE IF NOT EXISTS alarme (
	id         bigserial PRIMARY KEY,
	zeit       timestamptz NOT NULL DEFAULT now(),
	host       text NOT NULL,
	regel      text NOT NULL,     -- fehlschlaege | quelle | arbeitszeit | still | kette
	schluessel text NOT NULL,     -- gegen Wiederholung
	text       text NOT NULL,
	gesendet   timestamptz,
	UNIQUE (host, schluessel)
);
CREATE INDEX IF NOT EXISTS alarme_zeit ON alarme(zeit DESC);
CREATE INDEX IF NOT EXISTS ereignisse_sitzung ON ereignisse(host, sitzung, zeit) WHERE sitzung <> '';
ALTER TABLE alarme ADD COLUMN IF NOT EXISTS gesendet_an text[] NOT NULL DEFAULT '{}';
ALTER TABLE alarme ADD COLUMN IF NOT EXISTS versucht_an text[] NOT NULL DEFAULT '{}';
ALTER TABLE alarme ADD COLUMN IF NOT EXISTS versucht timestamptz;
