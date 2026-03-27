# ==========================================
# STAGE 1: The Builder (Heavy)
# ==========================================
FROM golang:1.26-alpine AS builder

RUN apk add --no-cache upx
WORKDIR /app
COPY config config
COPY rudp rudp
COPY worker worker
COPY go.mod go.mod

# Compile statically, strip debug symbols, and heavily compress
RUN cd worker && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o proxy-worker proxy-worker.go
RUN cd worker && upx --best --lzma proxy-worker && cp proxy-worker .. && cp config.ini .. && cp entrypoint.sh ..

# ==========================================
# STAGE 2: The Final Image (Ultra-Lightweight & Secure)
# ==========================================
FROM alpine:latest

COPY --from=builder /app/proxy-worker /app/config.ini /app/entrypoint.sh /

# Install ONLY the absolute bare minimum networking tools + su-exec
RUN apk add --no-cache wireguard-tools iptables iproute2 su-exec && \
    echo -e '#!/bin/sh\nexit 0' > /usr/local/bin/sysctl && \
    chmod +x /usr/local/bin/sysctl && \
    adduser -D -S -H proxyuser && \
    mv /proxy-worker /usr/local/bin/proxy-worker && \
    mv /config.ini /usr/local/bin/config.ini && \
    mv /entrypoint.sh /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/bin/proxy-worker /usr/local/bin/entrypoint.sh

# The container starts as root to run the entrypoint, 
# then the script safely drops privileges to 'proxyuser'
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
