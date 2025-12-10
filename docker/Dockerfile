# Build stage
FROM rust:1-alpine AS builder

# Install build dependencies
RUN apk add --no-cache musl-dev

# Create app directory
WORKDIR /usr/src/mdns-dns-proxy

# Copy manifests
COPY Cargo.toml Cargo.lock* ./

# Copy source tree
COPY src ./src

# Build for release with static linking
RUN cargo build --release --target x86_64-unknown-linux-musl && \
    strip target/x86_64-unknown-linux-musl/release/mdns-dns-proxy

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates

# Create a non-root user
RUN addgroup -g 1000 mdns && \
    adduser -D -u 1000 -G mdns mdns

# Copy the binary from builder
COPY --from=builder /usr/src/mdns-dns-proxy/target/x86_64-unknown-linux-musl/release/mdns-dns-proxy /usr/local/bin/mdns-dns-proxy

# Create directory for runtime files
RUN mkdir -p /var/lib/mdns-dns-proxy && \
    chown -R mdns:mdns /var/lib/mdns-dns-proxy

# Switch to non-root user
USER mdns

# Set default port
ARG MDNS_DNS_PROXY_PORT=5335
ENV MDNS_DNS_PROXY_PORT=${MDNS_DNS_PROXY_PORT}

# Expose DNS port
EXPOSE ${MDNS_DNS_PROXY_PORT}/udp
EXPOSE ${MDNS_DNS_PROXY_PORT}/tcp

# Run the binary
CMD ["mdns-dns-proxy"]
