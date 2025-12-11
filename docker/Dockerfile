FROM debian:trixie-slim

# Target architecture is provided by buildx; defaults aid local builds
ARG TARGETARCH=amd64

# Copy in the prebuilt static binary produced by CI (musl to avoid glibc drift)
COPY dist/mdns-dns-proxy-${TARGETARCH} /usr/local/bin/mdns-dns-proxy

# Create a non-root user
RUN groupadd -g 1000 mdns && \
    useradd -m -u 1000 -g mdns mdns

# Ensure binary is executable (tarballs sometimes lose the bit)
RUN chmod +x /usr/local/bin/mdns-dns-proxy

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