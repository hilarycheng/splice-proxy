# Splice-Proxy

A lightweight, single-binary proxy system that routes browser traffic through a remote WireGuard VPN without affecting the host system's network. Only proxied traffic goes through the tunnel.

```
Browser ──TCP──▶ Proxy Server ──▶  Wireguard Go ──TCP──▶ Internet
```

## Why

Running WireGuard system-wide isn't always possible or desirable — especially on managed corporate machines with endpoint protection software. Splice-Proxy lets you selectively route browser traffic through a VPN while everything else on the host stays untouched.

Browser VPN extensions solve a similar problem (browser-only routing without touching the system network), but they only work inside the browser. Any other application that needs the same VPN path — CLI tools, API clients, desktop apps — is out of luck. Splice-Proxy exposes a standard HTTP/SOCKS5 proxy on localhost, so anything that supports proxy settings can use it, not just the browser.

The server and worker communicate over UDP using a custom Reliable UDP (RUDP) protocol, which avoids the TCP-over-TCP issues and WSL networking limitations that make a pure TCP approach unreliable at scale.

## Selective Routing

Splice-Proxy supports both direct and WireGuard host rules in the same
application. This lets tools without proxy-exception support continue using
Splice-Proxy for every request while the proxy selects the outbound route.

```ini
[routing]
default = wireguard
reload_interval_seconds = 0

[routes]
example.com         = direct
secure.example.com  = wireguard
192.0.2.10          = direct
```

Routing behavior:

- An explicit hostname rule in `[routes]` has the highest priority.
- Hostnames listed in the operating system hosts file are automatically routed
  `direct`. Linux uses `/etc/hosts`; Windows uses
  `%SystemRoot%\System32\drivers\etc\hosts`.
- `localhost`, subdomains of `localhost`, `127.0.0.0/8`, and `::1` are also
  automatically routed `direct` unless an explicit hostname or IP rule overrides
  them.
- A domain rule matches the domain itself and all of its subdomains. For
  example, `example.com` also matches `a.example.com` and `a.b.example.com`.
- The longest matching domain wins; otherwise `routing.default` is used.
- `direct` uses a matching `[hosts]` static IP or the operating system DNS, then
  connects through the normal local network, completely bypassing WireGuard.
- `wireguard` resolves with the configured tunnel DNS servers and connects
  through the embedded WireGuard stack.
- Domain matching respects label boundaries, so `example.com` does not match
  `notexample.com`.
- A literal IP rule matches only that exact IP. CIDR and netmask route rules,
  such as `192.168.0.0/16`, are not supported.
- Host rules require the client to send a hostname. If a SOCKS5 client sends a
  literal IP address, only an exact IP rule can match because the proxy cannot
  recover the original hostname.

The system hosts file is read at startup and periodically reloaded for route
classification. Each valid line may contain one IP followed by multiple
hostname aliases; blank lines, comments, and malformed entries are ignored. The
proxy then uses the operating system resolver for the direct connection,
preserving native handling of duplicate names, multiple addresses, and address
ordering.

### Static Host Overrides

The `[hosts]` section only maps a hostname to a static IP address. Route
selection follows this order:

1. Match the requested hostname in `[routes]`.
2. If unmatched and the hostname is in the operating system hosts file, use
   `direct`.
3. If unmatched and `[hosts]` supplies a static IP, match that exact IP in
   `[routes]`.
4. If still unmatched, use `routing.default`, which is `wireguard` when omitted.

The static IP is used for the connection regardless of the selected route.
Hosts not defined in `[hosts]` skip step 3; the proxy does not perform DNS merely
to choose a route.

An HTTP or SOCKS5 proxy cannot send a standard response that tells a client to
retry one request directly. A rejected request is normally just a failure.
Therefore, the proxy must make the selected direct connection itself. Client-side
PAC, proxy bypass lists, and `NO_PROXY` remain alternatives for clients that
support them.

### Dynamic Route and Hosts Reload

`routing.reload_interval_seconds` controls periodic route and system hosts file
reloads. `0` disables reload. When enabled, Splice-Proxy rereads `[routing]`,
`[routes]`, and the operating system hosts file, then atomically activates valid
updates. Read or validation failures are logged while the last valid data
remains active. Changed content must be identical on two consecutive polls
before activation, which prevents a temporary partial write from becoming live.

Reloaded rules will apply to new connections only. Existing HTTP CONNECT and
SOCKS5 tunnels will keep their selected route until they disconnect. WireGuard
settings, DNS servers, proxy listen addresses, and `[hosts]` static overrides
will remain startup-only settings.

Changing the interval to `0` during reload stops the watcher. Restart is needed
to enable it again because a disabled watcher cannot observe later file changes.

### Connection Diagnostics

An ICMP ping only proves that the WireGuard/netstack ICMP path is alive. It does
not prove that DNS, TCP connection setup, proxy handlers, or relay throughput are
healthy. Splice-Proxy logs per-request timing for DNS, outbound TCP connect,
first response byte, transferred bytes, and relay speed.

Every five minutes, and once immediately after startup, independent health checks
probe WireGuard ICMP, tunnel DNS, TCP connection setup, and a small HTTPS
response. A successful layer does not hide a failure in another layer.

The diagnostic summary also reports active HTTP/SOCKS handlers, outbound
dials, relays, memory, garbage collection, and goroutine counts. A single
snapshot command will capture this information before restart so slow or stuck
behavior can be compared with the fresh process.

Run with `--debug-console` and enter `x` to write a timestamped
`diagnostic-*.txt` snapshot containing runtime counters, health results, tracked
routines, and goroutine stacks. Request logs and snapshots never include traffic
payloads, credentials, WireGuard private keys, or proxy authorization values.

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
