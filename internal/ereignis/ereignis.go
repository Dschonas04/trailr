// Package ereignis beschreibt, was Agent und Server austauschen, und wie die
// Hash-Kette gebildet wird. Beide Seiten nutzen denselben Code, damit der
// Server eine Kette prüfen kann, die er selbst geschrieben hat.
package ereignis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Ereignis ist eine Benutzeraktion auf einem Host.
type Ereignis struct {
	Kennung  string            `json:"kennung"`
	Zeit     time.Time         `json:"zeit"`
	Art      string            `json:"art"`
	Benutzer string            `json:"benutzer"`
	Als      string            `json:"als,omitempty"`
	Sitzung  string            `json:"sitzung,omitempty"`
	Quelle   string            `json:"quelle,omitempty"`
	Erfolg   bool              `json:"erfolg"`
	Text     string            `json:"text,omitempty"`
	Daten    map[string]string `json:"daten,omitempty"`
}

// Lieferung ist ein Paket vom Agenten.
type Lieferung struct {
	Host       string     `json:"host"`
	Agent      string     `json:"agent"`
	Ereignisse []Ereignis `json:"ereignisse"`
}

// Arten, die der Agent kennt.
var Arten = []string{"anmeldung", "abmeldung", "sitzung", "befehl", "sudo", "su", "datei"}

// Hash verkettet ein Ereignis mit dem vorigen. Die Zeit geht in
// Mikrosekunden ein: Postgres speichert nicht genauer.
func Hash(vorher string, e Ereignis) string {
	daten := []byte("{}")
	if len(e.Daten) > 0 {
		daten, _ = json.Marshal(e.Daten) // Schlüssel sortiert
	}
	teile := []string{vorher, e.Kennung, strconv.FormatInt(e.Zeit.UnixMicro(), 10), e.Art, e.Benutzer, e.Als,
		e.Sitzung, e.Quelle, strconv.FormatBool(e.Erfolg), e.Text, string(daten)}
	h := sha256.Sum256([]byte(strings.Join(teile, "\x1f")))
	return hex.EncodeToString(h[:])
}
