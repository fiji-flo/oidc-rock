# Use official Rust image as builder
FROM rust:1.91 AS builder

# Set working directory
WORKDIR /usr/src/app

# Copy Cargo.toml and Cargo.lock
COPY Cargo.toml Cargo.lock ./

# Copy source code
COPY src ./src

# Build the application
RUN cargo build --release

# Use a minimal runtime image
FROM debian:trixie-slim

# Install CA certificates for HTTPS requests
RUN apt-get update && \
    apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user
RUN useradd -r -u 1000 -m -d /app -s /bin/bash oidc && \
    mkdir -p /app && \
    chown -R oidc:oidc /app

# Set working directory
WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /usr/src/app/target/release/oidc-rock .

# Copy configuration file
COPY config.yaml .

# Change ownership
RUN chown -R oidc:oidc /app

# Switch to non-root user
USER oidc

# Expose port
EXPOSE 3080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3080/ || exit 1

# Run the application
CMD ["./oidc-rock", "config.yaml"]
