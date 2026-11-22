package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Sperre lässt Änderungen an Konten, Rollen und Anmeldung nacheinander laufen.
// Anders als bei sync.Mutex hat das Warten ein Ende.
type Sperre struct {
	einmal sync.Once
	platz  chan struct{}
}

func (s *Sperre) bereit() chan struct{} {
	s.einmal.Do(func() { s.platz = make(chan struct{}, 1) })
	return s.platz
}

func (s *Sperre) Lock()   { s.bereit() <- struct{}{} }
func (s *Sperre) Unlock() { <-s.bereit() }

func (s *Sperre) TryLock() bool {
	select {
	case s.bereit() <- struct{}{}:
		return true
	default:
		return false
	}
}

const sperreWarten = 10 * time.Second

func (s *Sperre) nehmen(ctx context.Context) bool {
	uhr := time.NewTimer(sperreWarten)
	defer uhr.Stop()
	select {
	case s.bereit() <- struct{}{}:
		return true
	case <-ctx.Done():
	case <-uhr.C:
	}
	return false
}

// antwortPuffer hält die Antwort fest, bis die Sperre frei ist.
type antwortPuffer struct {
	kopf   http.Header
	code   int
	inhalt bytes.Buffer
}

func (p *antwortPuffer) Header() http.Header { return p.kopf }

func (p *antwortPuffer) WriteHeader(code int) {
	if p.code == 0 {
		p.code = code
	}
}

func (p *antwortPuffer) Write(b []byte) (int, error) {
	p.WriteHeader(http.StatusOK)
	return p.inhalt.Write(b)
}

// fuehreAus prüft und schreibt unter der Sperre. An den Browser geht die
// Antwort erst danach: wer langsam liest, hält niemanden auf.
func (s *Sperre) fuehreAus(w http.ResponseWriter, r *http.Request, h http.HandlerFunc) {
	if !s.nehmen(r.Context()) {
		http.Error(w, "Es läuft gerade eine andere Änderung. Bitte noch einmal versuchen.", http.StatusServiceUnavailable)
		return
	}
	p := &antwortPuffer{kopf: w.Header().Clone()}
	func() {
		defer s.Unlock()
		h(p, r)
	}()
	maps.Copy(w.Header(), p.kopf)
	if p.code == 0 {
		p.code = http.StatusOK
	}
	w.WriteHeader(p.code)
	if p.inhalt.Len() > 0 {
		w.Write(p.inhalt.Bytes())
	}
}

type ausstellerGeprueft struct{}

type ssoEingabe struct {
	SSOKonfig
	GeheimnisBehalten bool `json:"geheimnisBehalten"`
}

// ssoEingabeLesen ist der einzige Leser der SSO-Einstellung, vor der Sperre
// wie beim Speichern: genau ein JSON-Wert, danach nichts.
func ssoEingabeLesen(r io.Reader) (ssoEingabe, error) {
	var e ssoEingabe
	d := json.NewDecoder(io.LimitReader(r, 1<<16))
	if err := d.Decode(&e); err != nil {
		return e, err
	}
	var rest json.RawMessage
	if err := d.Decode(&rest); !errors.Is(err, io.EOF) {
		return e, errors.New("hinter dem JSON steht noch etwas")
	}
	e.Aussteller = strings.TrimSuffix(strings.TrimSpace(e.Aussteller), "/")
	return e, nil
}

// ausstellerVorab fragt den Anbieter, bevor die Sperre gilt. Ab hier steht im
// Kontext, was geprüft ist (leer: SSO aus), und nur das darf gespeichert werden.
func (s *SSO) ausstellerVorab(w http.ResponseWriter, r *http.Request, roh []byte) (*http.Request, bool) {
	e, err := ssoEingabeLesen(bytes.NewReader(roh))
	if err != nil {
		ssoJSON(w, http.StatusBadRequest, map[string]string{"fehler": "Ungültige Angaben"})
		return r, false
	}
	geprueft := ""
	if e.Aktiv {
		if _, err := s.anbieter(r.Context(), e.Aussteller); err != nil {
			ssoJSON(w, http.StatusBadRequest, map[string]string{"fehler": err.Error()})
			return r, false
		}
		geprueft = e.Aussteller
	}
	return r.WithContext(context.WithValue(r.Context(), ausstellerGeprueft{}, geprueft)), true
}
