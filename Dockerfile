# Build stage
FROM golang:1.23.2-alpine3.20 AS builder

# Installing build dependencies
RUN apk --no-cache add build-base

# Setting up the working directory and copying dependencies
WORKDIR /sso
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and build
COPY . .

# Building the application
RUN go build -o sso ./cmd/main.go

# Final stage
FROM alpine:3.20

# Create a non-root user
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Set the working directory
WORKDIR /sso

# Copying the binary
COPY --from=builder /sso/sso .

# Setting permissions
RUN chmod +x ./sso \
    && chown -R appuser:appgroup /sso

# Specifying a port for a container
EXPOSE 8001

# Switch to non-root user
USER appuser

# Launch command
ENTRYPOINT ["./sso", "serve", "--config=/sso/config.yaml"]