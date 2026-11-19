# Prüfsumme des Agenten, wie ihn das Docker-Abbild baut (reproduzierbar).
VERSION ?= entwicklung

agent-pruefsumme:
	@CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$(VERSION)" -o /tmp/trailr-agent-pruefen ./cmd/trailr-agent
	@sha256sum /tmp/trailr-agent-pruefen | cut -d' ' -f1
	@rm -f /tmp/trailr-agent-pruefen

.PHONY: agent-pruefsumme
