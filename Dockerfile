# Build stage
FROM golang:1.23-bookworm AS builder

# Install build dependencies for CGO and SQLite
RUN apt-get update && apt-get install -y gcc libc6-dev sqlite3 libsqlite3-dev

WORKDIR /app

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with CGO enabled
RUN CGO_ENABLED=1 GOOS=linux go build -o stockex main.go

# Run stage
FROM debian:bookworm-slim

# Install runtime dependencies for SQLite
RUN apt-get update && apt-get install -y sqlite3 libsqlite3-0 ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/stockex .
# Copy assets
COPY --from=builder /app/static ./static
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/config.json .

# Expose the default port
EXPOSE 8080

# Command to run the application
CMD ["./stockex"]
