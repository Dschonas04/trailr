FROM golang:1.27.4-alpine AS bau
WORKDIR /quelle
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=entwicklung
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$VERSION" -o /trailr ./cmd/trailr \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "-s -w -X main.version=$VERSION" -o /trailr-agent ./cmd/trailr-agent

FROM alpine:3.24
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 10001 trailr \
 && mkdir /einstellungen && chown trailr /einstellungen
ENV TZ=Europe/Berlin TRAILR_SSO_DATEI=/einstellungen/sso.json
USER trailr
COPY --from=bau /trailr /usr/local/bin/trailr
# Den Agenten liefert der Server selbst aus: GET /agent/trailr-agent
COPY --from=bau /trailr-agent /usr/local/share/trailr/trailr-agent
EXPOSE 8400
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://127.0.0.1:8400/healthz || exit 1
ENTRYPOINT ["/usr/local/bin/trailr"]
