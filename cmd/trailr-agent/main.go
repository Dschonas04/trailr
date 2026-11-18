// trailr-agent läuft auf jedem Linux-Host und schickt Benutzeraktionen an den
// Trailr-Server: Anmeldungen, sudo, su, Befehle (auditd), Dateiänderungen.
//
// Grundgerüst: liest die Einstellungen und meldet sich. Das Lesen des Journals
// kommt im ersten Schritt, siehe README.
package main

import (
	"flag"
	"log"
	"os"
)

var version = "entwicklung"

func main() {
	server := flag.String("server", os.Getenv("TRAILR_SERVER"), "Adresse des Servers, z. B. https://10.0.2.7:8400")
	zert := flag.String("zertifikat", "/etc/trailr/client.crt", "Client-Zertifikat (Homelab-CA)")
	schluessel := flag.String("schluessel", "/etc/trailr/client.key", "Schlüssel zum Client-Zertifikat")
	puffer := flag.String("puffer", "/var/lib/trailr/puffer", "Ereignisse, die noch nicht beim Server sind")
	flag.Parse()

	if *server == "" {
		log.Fatal("kein Server angegeben (-server oder TRAILR_SERVER)")
	}
	host, _ := os.Hostname()
	log.Printf("trailr-agent %s auf %s, Server %s, Zertifikat %s, Schlüssel %s, Puffer %s",
		version, host, *server, *zert, *schluessel, *puffer)
}
