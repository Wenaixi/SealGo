# Multi-stage build: smallest possible image
FROM golang:1.25-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# Build static binary (no libc)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -trimpath \
    -o /SealGo ./cmd/cli/

# Distroless static (no shell, no distro)
FROM gcr.io/distroless/static:nonroot

COPY --from=builder /SealGo /SealGo
ENTRYPOINT ["/SealGo"]
