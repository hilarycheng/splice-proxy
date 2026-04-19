# Splice-Proxy

A lightweight, single-binary proxy system that routes browser traffic through a remote WireGuard VPN without affecting the host system's network. Only proxied traffic goes through the tunnel.

```
Browser ──TCP──▶ Proxy Server ──▶  Wireguard Go ──TCP──▶ Internet
```

## Why

Running WireGuard system-wide isn't always possible or desirable — especially on managed corporate machines with endpoint protection software. Splice-Proxy lets you selectively route browser traffic through a VPN while everything else on the host stays untouched.

Browser VPN extensions solve a similar problem (browser-only routing without touching the system network), but they only work inside the browser. Any other application that needs the same VPN path — CLI tools, API clients, desktop apps — is out of luck. Splice-Proxy exposes a standard HTTP/SOCKS5 proxy on localhost, so anything that supports proxy settings can use it, not just the browser.

The server and worker communicate over UDP using a custom Reliable UDP (RUDP) protocol, which avoids the TCP-over-TCP issues and WSL networking limitations that make a pure TCP approach unreliable at scale.

## Components

| File              | Role                                                                                         |
| ----------------- | -------------------------------------------------------------------------------------------- |
| `rudp/rudp.go`    | Reliable UDP library — multiplexed streams over a single UDP socket                          |
| `proxy-server.go` | HTTP & SOCKS5 proxy + RUDP listener + WireGuard UDP forwarder (runs on host)                 |
| `proxy-worker.go` | Accepts RUDP streams, dials remote targets via TCP through WireGuard (runs in WSL/container) |

## Ports

| Port  | Protocol | Purpose                    |
| ----- | -------- | -------------------------- |
| 12346 | TCP      | HTTP proxy                 |
| 12348 | TCP      | SOCKS5 proxy               |

## RUDP Protocol

The custom RUDP layer provides reliable, ordered delivery over UDP with stream multiplexing.

- **Wire format:** 11-byte header — `reqID[4] + frameID[4] + type[1] + payloadLen[2]`
- **Message types:** Data, EOF, ACK
- **Chunk size:** 1200 bytes per frame
- **Window:** 128 in-flight packets
- **Retransmit:** RTT-based timeout (RFC 6298 SRTT/RTTVAR) with exponential backoff
- **Karn's algorithm:** skips RTT samples from retransmitted packets
- **Out-of-order handling:** reorder buffer with guaranteed-delivery queue
- **Buffer pooling:** reusable payload and copy buffers to reduce GC pressure

Each RUDP stream implements `Read()` / `Write()` / `Close()` and behaves like a standard `net.Conn`.

## Limitations

- Single worker only — no multi-worker support
- No HTTP keep-alive for plain HTTP requests (HTTPS tunnels handle it internally)
- No automatic reconnection if the server restarts
- Worker must be restarted manually after a server restart

## Build

Needs Go **1.21+** (1.22 recommended).

```bash
# One-time: fetch deps
go mod tidy

# Linux
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags "-s -w" -o splice-proxy      splice-proxy.go

# Windows
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -o splice-proxy.exe  splice-proxy.go
```

`-ldflags "-s -w"` strips debug info (~30% smaller binary). `CGO_ENABLED=0`
makes the binary fully static — no glibc / musl runtime dependency.

## Acknowledgments

This project was coded with the help of [Claude](https://claude.ai) (Anthropic) and [Gemini](https://gemini.google.com) (Google). The author designed the architecture and directed the implementation; the AI did the typing.

## License

MIT License. See [LICENSE](LICENSE).

**This software is provided "as is", without warranty of any kind.** The author is not responsible for any loss, damage, or consequence resulting from the use of this software. Use it at your own risk.
