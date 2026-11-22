package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
	netmail "net/mail"
	"net/smtp"
	"strings"
	"time"
)

// Mailer schickt Alarme. Ohne TRAILR_SMTP gibt es keinen.
type Mailer struct {
	server, nutzer, kennwort, absender string
}

func neuerMailer() *Mailer {
	s := umgebung("TRAILR_SMTP", "")
	if s == "" {
		return nil
	}
	m := &Mailer{server: s, nutzer: umgebung("TRAILR_SMTP_NUTZER", ""),
		kennwort: umgebung("TRAILR_SMTP_KENNWORT", ""), absender: umgebung("TRAILR_ABSENDER", "")}
	if m.absender == "" {
		m.absender = m.nutzer
	}
	return m
}

func (m *Mailer) senden(ctx context.Context, an, betreff, text string) error {
	if strings.ContainsAny(an, "\r\n") || strings.ContainsAny(betreff, "\r\n") {
		return fmt.Errorf("ungültige Adresse oder Betreff")
	}
	host, _, err := net.SplitHostPort(m.server)
	if err != nil {
		return err
	}
	var auth smtp.Auth
	if m.nutzer != "" {
		auth = smtp.PlainAuth("", m.nutzer, m.kennwort, host)
	}
	nachricht := "From: " + m.absender + "\r\n" +
		"To: " + an + "\r\n" +
		"Subject: " + mime.QEncoding.Encode("utf-8", betreff) + "\r\n" +
		"Date: " + time.Now().Format(time.RFC1123Z) + "\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" +
		strings.ReplaceAll(text, "\n", "\r\n") + "\r\n"
	// Von Hand statt smtp.SendMail: das hat keine Zeitgrenze.
	verbindung, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", m.server)
	if err != nil {
		return err
	}
	defer verbindung.Close()
	bis := time.Now().Add(time.Minute)
	if d, ok := ctx.Deadline(); ok && d.Before(bis) {
		bis = d
	}
	if err := verbindung.SetDeadline(bis); err != nil {
		return err
	}
	c, err := smtp.NewClient(verbindung, host)
	if err != nil {
		return err
	}
	defer c.Close()
	// Alarme nennen Hosts und Konten: über das Netz nur verschlüsselt.
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return err
		}
	} else if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return fmt.Errorf("der Mailserver bietet kein STARTTLS")
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(m.adresse()); err != nil {
		return err
	}
	if err := c.Rcpt(an); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write([]byte(nachricht)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// adresse ist der Absender ohne Anzeigenamen.
func (m *Mailer) adresse() string {
	if a, err := netmail.ParseAddress(m.absender); err == nil {
		return a.Address
	}
	return m.absender
}
