# Build stage
FROM golang:1.25-alpine AS builder

# Build arguments
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_DATE=unknown

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application with version information
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildDate=${BUILD_DATE}" \
    -o s3-gateway ./cmd/gateway

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata aws-cli curl

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/s3-gateway .

# Copy example config
COPY config.example.yaml ./config.example.yaml

# Expose port
EXPOSE 9000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:9000/health || exit 1

# Run the application
ENTRYPOINT ["./s3-gateway"]
CMD ["-config", "/app/config.yaml"]
