# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.25-alpine AS builder

RUN apk add --no-cache git gcc musl-dev

WORKDIR /src

# Cache dependency downloads separately from the build.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ouroboros ./cmd/ouroboros

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.21

LABEL maintainer="Ouroboros Project"
LABEL description="AI-powered security scanner with Red/Blue adversarial loop"
LABEL org.opencontainers.image.source="https://github.com/borntobeyours/ouroboros"

# ca-certificates is required for HTTPS targets.
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /out/ouroboros /usr/local/bin/ouroboros

# Scan results and the SQLite database are written to /data.
WORKDIR /data

ENTRYPOINT ["ouroboros"]
CMD ["--help"]
