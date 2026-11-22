package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// langsam ist ein Browser, der seine Antwort nicht abholt.
type langsam struct {
	*httptest.ResponseRecorder
	drin, weiter chan struct{}
}

func (l langsam) Write(b []byte) (int, error) {
	close(l.drin)
	<-l.weiter
	return len(b), nil
}

func TestLangsamerBrowserHaeltDieSperreNicht(t *testing.T) {
	a := &App{sso: NeuesSSO("Trailr", filepath.Join(t.TempDir(), "sso.json"), "TRAILR_TEST_SSO_AUS")}
	h := a.angemeldet(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	r := httptest.NewRequest("POST", "/sso/konten?code="+a.sso.einrichtcode, http.NoBody)
	w := langsam{httptest.NewRecorder(), make(chan struct{}), make(chan struct{})}
	fertig := make(chan struct{})
	go func() {
		defer close(fertig)
		h(w, r)
	}()
	defer func() {
		close(w.weiter)
		<-fertig
	}()
	select {
	case <-w.drin:
	case <-time.After(5 * time.Second):
		t.Fatal("keine Antwort")
	}
	if !a.verwaltung.TryLock() {
		t.Fatal("die Sperre hängt am Browser")
	}
	a.verwaltung.Unlock()
}
