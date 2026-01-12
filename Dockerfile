# Build stage
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache gcc musl-dev

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -o dropper .

# Runtime stage
FROM alpine:latest

WORKDIR /app

# Copy binary and BPF object
COPY --from=builder /app/dropper .
COPY --from=builder /app/bpf/drop_port.bpf.o ./bpf/

ENTRYPOINT ["./dropper"]
