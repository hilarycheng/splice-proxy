# RUDP Proxy System — Project Summary

## Architecture

```
Browser ←TCP→ Proxy Server ←RUDP/UDP→ Proxy Worker ←TCP→ Internet (via VPN)
                  ↕ UDP
                VPN Client ←UDP forwarded→ Any UDP VPN Server
```

**Purpose:** Route browser traffic through a remote VPN without passing the entire system through VPN. Only proxied traffic goes through the VPN tunnel. Company local PC traffic remains unaffected.

**Constraint:** Due to Symantec Endpoint Protection on Windows, the container/WSL worker can only connect to the host on localhost/local IPs. TCP connections at scale break WSL networking, so UDP is used between server and worker with a custom Reliable UDP (RUDP) protocol.

## Components (3 files)

### rudp.go — Reliable UDP Library
- **Package:** `rudp` (imported by both server and worker)
- **Wire format:** 11-byte header: `reqID[4] + frameID[4] + type[1] + payloadLen[2]`
- **Message types:** MsgData=0, MsgEOF=1, MsgACK=2
- **Chunk size:** 1200 bytes per frame
- **Window:** Fixed 128 in-flight packets
- **Mux:** Multiplexes many streams over a single UDP socket
- **Stream:** Implements `Read()` / `Write()` / `Close()` — behaves like `net.Conn`

Key features:
- RTT-based retransmit timeout (RFC 6298 SRTT/RTTVAR)
- Karn's algorithm (skip RTT samples from retransmitted packets)
- Exponential backoff on retransmits (prevents retransmit storms)
- OOO frame reordering with `s.ready` guaranteed-delivery queue
- ACK sent only after successful channel queue (prevents permanent frame loss)
- Payload buffer pooling (payloadPool, sendPool, CopyBufPool)
- Dedicated stack-allocated ACK path (sendACK)
- Write idle timeout (30 seconds, resets on progress)
- Reusable timers in Write() (no time.After allocation per chunk)
- Mux.Close() for clean shutdown of readLoop/retransmitLoop
- Channel size 4096 for backpressure absorption

### proxy-server.go — Runs on Windows or Linux (host)
- **HTTP proxy:** port 12346
- **SOCKS5 proxy:** port 12348
- **RUDP mux:** port 12347 (UDP, listens for worker connection)
- **UDP forwarder:** port 12349 → VPN Server (via VPN UDP Mode)

Features:
- HTTP CONNECT tunnel for HTTPS
- Plain HTTP forwarding (non-CONNECT)
- Full SOCKS5 implementation (no-auth, IPv4/IPv6/domain, CONNECT only)
- SOCKS5 bridges to worker via synthetic HTTP CONNECT
- UDP session tracking with 5-minute timeout for VPN
- Relay goroutines don't prematurely close connections (SSE/streaming safe)
- Pooled 32KB copy buffers via rudp.CopyBufPool

### proxy-worker.go — Runs on Linux only (container/WSL)
- Connects to proxy-server via UDP (DialUDP)
- Receives requests as RUDP streams
- Dials remote targets via TCP (through VPN)
- Hello keepalive every 5 seconds
- Relay goroutines don't prematurely close connections (SSE/streaming safe)
- cleanRequest() strips proxy headers and absolutizes URLs for plain HTTP

## Listen Ports

| Port  | Protocol | Purpose                        |
|-------|----------|--------------------------------|
| 12346 | TCP      | HTTP proxy (browser connects)  |
| 12347 | UDP      | RUDP mux (server ↔ worker)     |
| 12348 | TCP      | SOCKS5 proxy (browser connects)|
| 12349 | UDP      | UDP forwarder                  |

## Static Build

```bash
make linux     # CGO_ENABLED=0, static, runs on Alpine/minimal/WSL/any Linux
make windows   # CGO_ENABLED=0, static .exe
make all       # both
```

`-ldflags "-s -w"` strips symbols/debug info (~30% smaller binary).
No external dependencies. Go standard library only. Go 1.21+.

## Bugs Fixed (from original code)

### Critical
1. **ACK before queue** — ACK was sent before channel push. If channel full, frame dropped but sender thought it was delivered. Permanent stream hang.
2. **OOO frame drop in popNext** — Consecutive OOO frames were re-queued to channel via `select { default: drop }`. If channel full, frames silently lost while nextRx already advanced. Caused TLS MAC errors (SSL_ERROR_MAC_ALERT) during uploads.

### High
3. **OOO stall** — After consuming a frame from channel, popNext didn't re-check OOO map for consecutive frames. Caused 120-second stalls on any packet reorder.
4. **Retransmit storm** — Fixed retransmit interval with no backoff. Under backpressure, 128 packets retransmitted every 20ms = 6400 packets/sec, starving writeMu for ACKs and response data.

### Medium
5. **EOF teardown** — Unconditional 2-second AfterFunc destroyed stream regardless of ACK state. Now waits for inFlight drain (5s deadline).
6. **Relay premature close** — CONNECT tunnel goroutines called remote.Close()/s.Close() when their direction ended. For SSE/streaming, the idle direction's 120s timeout killed the active response stream.
7. **time.After in Write hot loop** — Thousands of timer allocations during bulk transfer caused GC pressure.

### Low
8. **closeStream leaked pooled payloads** — inFlight, OOO, and channel payloads not returned to pool on teardown.
9. **SOCKS5 variable shadowing** — `m` in methods loop shadowed Mux parameter.

## Current Known Limitations

- **Single worker only** — Mux.peerAddr is a single atomic pointer. Multiple workers would overwrite each other's address.
- **No HTTP keep-alive for plain HTTP** — Each non-CONNECT request opens a new stream. HTTPS (CONNECT tunnel) handles keep-alive internally via the tunnel.
- **120-second popNext timeout** — Long-idle CONNECT tunnels eventually time out on the idle direction. Active direction continues until remote closes.
- **No Mux reconnection logic** — Worker's inner hello loop never breaks. If server restarts, worker must be manually restarted.
- **retransmitLoop is O(all_inflight) per tick** — Acceptable at current scale but would benefit from per-stream timers at 500+ concurrent streams.

## For New Chat Sessions

Upload these files to start working on this project:
- `config/config.go` — config.ini library
- `rudp/rudp.go` — the RUDP library
- `server/proxy-server.go` — the proxy server (Windows/Linux)
- `worker/proxy-worker.go` — the proxy worker (Linux only)
- `go.mod` — module definition

Include this summary document for context on architecture, decisions made, and bugs already fixed.

## [Latest Release / Changelog] - Network Stability & Burst Recovery Update

### Added
* **Explicit OS Error Handling:** Added `syscall.EMSGSIZE` detection to `sendRaw` and `sendRawHeadroom` to catch and log silent MTU drops at the OS level instead of blindly retransmitting.

### Fixed
* **MTU Blackhole:** Reduced `ChunkSize` from 1400 to 1200 to safely clear VPN's 1420-byte MTU limit, preventing 100% packet loss on large HTTP POSTs and file uploads.
* **Stream Teardown Panic:** Replaced `close(s.ch)` in `closeStream()` with a safe, non-blocking `drainLoop`. This eliminates fatal Go panics caused by race conditions when delayed network packets hit a closing stream.
* **Out-of-Order Stream Killer:** Removed the hard `io.EOF` connection kill when the `s.ooo` buffer exceeds `chanSize`. The receiver now safely drops excess packets during massive downstream bursts (like LLM text generation) without severing the inner TCP connection.
* **Out-of-Order Memory Leak:** Fixed a silent memory leak in `popNext()` by explicitly returning orphaned payload arrays to the `sync.Pool` before overwriting them with duplicate frames.

### Changed
* **Burst Recovery Speed:** Increased `maxRetransmitsPerTick` from 8 to 64, radically speeding up the congestion window's ability to recover from massive packet loss events.
* **Timeout Tolerance:** Increased `writeIdleTimeout` from 30 seconds to 120 seconds to give the RUDP layer enough time to process and retransmit heavy downstream bursts.
* **Congestion Control Smoothing:** Lowered `cwndFloor` to 4.0 and added an RTT-based cooldown timer to `lastLossTime`. This ensures the congestion window halves at most once per RTT during loss events, mirroring true TCP behavior.
