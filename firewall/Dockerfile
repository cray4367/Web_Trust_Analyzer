# Build stage
# Switching to Debian-based image to avoid musl/sqlite3 compatibility issues
FROM golang:1.21 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
# CGO_ENABLED=1 is default on Debian images
RUN go build -o firewall .

# Final stage
FROM debian:bookworm-slim

WORKDIR /app

# Install CA certificates for HTTPS and sqlite3 libraries
RUN apt-get update && apt-get install -y ca-certificates sqlite3 libsqlite3-0 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/firewall .
# Try to copy .env if it exists, but don't fail if it doesn't (handled by wildcard or separate command usually, but strict copy fails if missing)
# For safety, we rely on the builder copy. 
COPY --from=builder /app/.env .

EXPOSE 8080

CMD ["./firewall"]
