// splice-proxy.go — Single-binary HTTP + SOCKS5 proxy with embedded WireGuard.
//
// Runs on Windows and Linux. No TUN driver. No admin rights. No kernel modules.
// All traffic (including DNS) is routed through an embedded userspace WireGuard
// tunnel via gVisor netstack.
//
// Build:   go build -ldflags "-s -w" -o splice-proxy splice-proxy.go
// Config:  config.ini (see README.md)

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
)

// ─── Logging ──────────────────────────────────────────────────────────────────

var lg = log.New(os.Stdout, "", 0)

func logf(format string, args ...interface{}) {
	lg.Printf(time.Now().Format("2006-01-02 15:04:05.000")+" | "+format, args...)
}

// wgLogger adapts our logf into the WireGuard device.Logger interface.
type wgLogger struct{ prefix string }

func (l *wgLogger) Verbosef(format string, args ...interface{}) {
	// Silenced by default — WG is very chatty at verbose level.
	// Uncomment for handshake debugging:
	// logf("WG | TRACE | "+format, args...)
}
func (l *wgLogger) Errorf(format string, args ...interface{}) {
	logf("WG | ERROR | "+format, args...)
}

// ─── Config loading ───────────────────────────────────────────────────────────

type Config struct {
	HTTPListen   string
	SOCKS5Listen string

	WGPrivateKey       string
	WGPeerPublicKey    string
	WGPeerPresharedKey string
	WGPeerEndpoint     string
	WGLocalIPs         []netip.Addr
	WGAllowedIPs       string
	WGKeepalive        int
	WGMTU              int

	DNSServers  []string
	DNSCacheTTL time.Duration

	// HostOverrides maps "host" or "*.suffix" to an IP string.
	// Exact matches are checked first, then suffix wildcards (longest first).
	HostOverrides map[string]string
}

func loadIni(path string) map[string]string {
	m := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return m
	}
	defer f.Close()

	section := ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' && line[len(line)-1] == ']' {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if i := strings.IndexByte(line, '='); i >= 0 {
			k := strings.TrimSpace(line[:i])
			v := strings.TrimSpace(line[i+1:])
			if section != "" {
				k = section + "." + k
			}
			m[k] = v
		}
	}
	return m
}

func iniGet(m map[string]string, key, fallback string) string {
	if v, ok := m[key]; ok && v != "" {
		return v
	}
	return fallback
}

func iniGetInt(m map[string]string, key string, fallback int) int {
	if v, ok := m[key]; ok && v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return fallback
}

func loadConfig(path string) (*Config, error) {
	m := loadIni(path)

	c := &Config{
		HTTPListen:   iniGet(m, "proxy.http_listen", "127.0.0.1:12346"),
		SOCKS5Listen: iniGet(m, "proxy.socks5_listen", "127.0.0.1:12348"),

		WGPrivateKey:       iniGet(m, "wireguard.private_key", ""),
		WGPeerPublicKey:    iniGet(m, "wireguard.peer_public_key", ""),
		WGPeerPresharedKey: iniGet(m, "wireguard.preshared_key", ""),
		WGPeerEndpoint:     iniGet(m, "wireguard.peer_endpoint", ""),
		WGAllowedIPs:       iniGet(m, "wireguard.allowed_ips", "0.0.0.0/0"),
		WGKeepalive:        iniGetInt(m, "wireguard.persistent_keepalive", 25),
		WGMTU:              iniGetInt(m, "wireguard.mtu", 1420),

		DNSCacheTTL: time.Duration(iniGetInt(m, "dns.cache_ttl_seconds", 300)) * time.Second,
	}

	// Local IPs (can be comma-separated for IPv4+IPv6 dual-stack)
	localStr := iniGet(m, "wireguard.local_ip", "")
	if localStr == "" {
		return nil, errors.New("config: wireguard.local_ip is required")
	}
	for _, s := range strings.Split(localStr, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// Strip CIDR suffix if present
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[:i]
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("config: bad local_ip %q: %v", s, err)
		}
		c.WGLocalIPs = append(c.WGLocalIPs, a)
	}

	// DNS servers — default to Cloudflare
	dnsStr := iniGet(m, "dns.servers", "1.1.1.1:53,1.0.0.1:53")
	for _, s := range strings.Split(dnsStr, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, ":") {
			s += ":53"
		}
		c.DNSServers = append(c.DNSServers, s)
	}

	// Host overrides from [hosts] section — exact and wildcard (*.suffix).
	// Any key under "hosts." in the flat map becomes an override.
	c.HostOverrides = make(map[string]string)
	for k, v := range m {
		if !strings.HasPrefix(k, "hosts.") {
			continue
		}
		host := strings.TrimPrefix(k, "hosts.")
		v = strings.TrimSpace(v)
		if host == "" || v == "" {
			continue
		}
		// Validate the value is a parseable IP
		if net.ParseIP(v) == nil {
			return nil, fmt.Errorf("config: [hosts] %q = %q is not a valid IP", host, v)
		}
		c.HostOverrides[strings.ToLower(host)] = v
	}

	// Validate WG required fields
	if c.WGPrivateKey == "" {
		return nil, errors.New("config: wireguard.private_key is required")
	}
	if c.WGPeerPublicKey == "" {
		return nil, errors.New("config: wireguard.peer_public_key is required")
	}
	if c.WGPeerEndpoint == "" {
		return nil, errors.New("config: wireguard.peer_endpoint is required")
	}

	return c, nil
}

// ─── WireGuard setup ──────────────────────────────────────────────────────────

// base64ToHex converts a base64 WG key (as shown by `wg genkey` / `wg pubkey`)
// to the hex format expected by the device IPC interface.
func base64ToHex(b64 string) (string, error) {
	b64 = strings.TrimSpace(b64)
	// Pad to a multiple of 4
	for len(b64)%4 != 0 {
		b64 += "="
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", err
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key must be 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}

// setupWireGuard builds and brings up a userspace WG device with netstack.
// Returns the virtual network (for Dial) and the device (for shutdown).
func setupWireGuard(c *Config) (*netstack.Net, *device.Device, error) {
	// 1. Create netstack TUN + Net
	tun, tnet, err := netstack.CreateNetTUN(
		c.WGLocalIPs,
		dnsAddrs(c.DNSServers), // netstack's internal DNS; we override via custom resolver anyway
		c.WGMTU,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("netstack create: %w", err)
	}

	// 1b. Tune gVisor TCP buffers BEFORE any connections are made.
	// Default 32KB receive buffer causes zero-window stalls on fast bursts
	// (e.g. Gemini fast mode). See Cloudflare slirpnetstack for precedent.
	tuneNetstack(tnet)

	// 2. Build the WG device
	dev := device.NewDevice(tun, conn.NewDefaultBind(), &device.Logger{
		Verbosef: (&wgLogger{}).Verbosef,
		Errorf:   (&wgLogger{}).Errorf,
	})

	// 3. Configure via IPC. Format is documented at:
	//    https://www.wireguard.com/xplatform/#configuration-protocol
	// The device section comes first (private_key, listen_port), then each
	// peer section starts with a public_key line and is followed by that
	// peer's settings (endpoint, allowed_ip, etc.)
	privHex, err := base64ToHex(c.WGPrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("private_key decode: %w", err)
	}
	pubHex, err := base64ToHex(c.WGPeerPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("peer_public_key decode: %w", err)
	}

	var ipcCfg strings.Builder
	// Device section
	fmt.Fprintf(&ipcCfg, "private_key=%s\n", privHex)
	// Peer section — public_key line begins it
	fmt.Fprintf(&ipcCfg, "public_key=%s\n", pubHex)
	fmt.Fprintf(&ipcCfg, "endpoint=%s\n", c.WGPeerEndpoint)
	fmt.Fprintf(&ipcCfg, "persistent_keepalive_interval=%d\n", c.WGKeepalive)
	if c.WGPeerPresharedKey != "" {
		pskHex, err := base64ToHex(c.WGPeerPresharedKey)
		if err != nil {
			return nil, nil, fmt.Errorf("preshared_key decode: %w", err)
		}
		fmt.Fprintf(&ipcCfg, "preshared_key=%s\n", pskHex)
	}
	for _, cidr := range strings.Split(c.WGAllowedIPs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		fmt.Fprintf(&ipcCfg, "allowed_ip=%s\n", cidr)
	}

	if err := dev.IpcSet(ipcCfg.String()); err != nil {
		return nil, nil, fmt.Errorf("ipc_set: %w", err)
	}

	if err := dev.Up(); err != nil {
		return nil, nil, fmt.Errorf("device up: %w", err)
	}

	_ = tun // returned implicitly via the device; keep reference silent
	return tnet, dev, nil
}

// ─── Netstack TCP tuning ─────────────────────────────────────────────────────
//
// gVisor netstack defaults to ~32KB TCP receive buffers with no auto-tuning.
// Under fast downstream bursts (Gemini fast mode, LLM streaming), the receive
// buffer fills instantly, gVisor advertises zero window, and the remote server
// resets or times out. The Linux kernel defaults to 128-256KB with auto-tuning
// up to several MB — we replicate that here.
//
// netstack.Net hides the *stack.Stack in an unexported field. We extract it
// via reflect+unsafe to call SetTransportProtocolOption. The field layout is:
//
//   type netTun struct {
//       ep    *channel.Endpoint  // field 0
//       stack *stack.Stack       // field 1
//       ...
//   }
//   type Net = netTun  (type alias)
//
// If wireguard-go ever reorders these fields, getNetstackStack will panic at
// startup — a clear signal to update the offset, not a silent corruption.

func getNetstackStack(tnet *netstack.Net) *stack.Stack {
	v := reflect.ValueOf(tnet).Elem()
	f := v.Field(1) // netTun.stack is field index 1
	return (*stack.Stack)(unsafe.Pointer(f.Pointer()))
}

func tuneNetstack(tnet *netstack.Net) {
	s := getNetstackStack(tnet)

	// Receive buffer: 4KB min, 256KB default, 4MB max
	rcv := tcpip.TCPReceiveBufferSizeRangeOption{Min: 4096, Default: 262144, Max: 4 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcv)

	// Send buffer: 4KB min, 256KB default, 4MB max
	snd := tcpip.TCPSendBufferSizeRangeOption{Min: 4096, Default: 262144, Max: 4 << 20}
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &snd)

	// Enable receive buffer auto-tuning — gVisor dynamically grows buffers
	// under load, matching Linux kernel tcp_moderate_rcvbuf behavior.
	mod := tcpip.TCPModerateReceiveBufferOption(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &mod)

  // Enable SACK for better packet loss recovery through WG tunnel.
	sack := tcpip.TCPSACKEnabled(true)
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)

	var cc tcpip.CongestionControlOption = "cubic"
	s.SetTransportProtocolOption(tcp.ProtocolNumber, &cc)

	logf("SYS | INFO  | netstack tuned: rcv=256KB snd=256KB max=4MB auto-tune=on sack=on cc=cubic")
}

func dnsAddrs(servers []string) []netip.Addr {
	var out []netip.Addr
	for _, s := range servers {
		host, _, err := net.SplitHostPort(s)
		if err != nil {
			host = s
		}
		if a, err := netip.ParseAddr(host); err == nil {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		// Fallback so netstack doesn't choke
		out = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
	return out
}

// ─── DNS resolver (through tunnel, with cache) ───────────────────────────────

type dnsCache struct {
	mu    sync.Mutex
	items map[string]dnsEntry
	ttl   time.Duration
}

type dnsEntry struct {
	addrs   []string
	expires time.Time
}

func newDNSCache(ttl time.Duration) *dnsCache {
	return &dnsCache{items: make(map[string]dnsEntry), ttl: ttl}
}

func (c *dnsCache) get(host string) ([]string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.items[host]
	if !ok || time.Now().After(e.expires) {
		return nil, false
	}
	return e.addrs, true
}

func (c *dnsCache) put(host string, addrs []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items[host] = dnsEntry{addrs: addrs, expires: time.Now().Add(c.ttl)}
}

// size returns the current number of cached entries (including expired ones
// not yet evicted). Used for diagnostics only.
func (c *dnsCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

// Resolver resolves hostnames through the WG tunnel.
type Resolver struct {
	tnet    *netstack.Net
	servers []string
	cache   *dnsCache
	nextSrv atomic.Uint32

	// Host overrides: exact match takes priority over wildcard.
	// Wildcards are stored as "suffix" (e.g. ".example.com") and matched longest-first.
	exactHosts    map[string]string // "gemini.google.com" -> "142.250.80.110"
	wildcardHosts []wildcardEntry   // sorted by suffix length, descending
}

type wildcardEntry struct {
	suffix string // ".example.com"
	ip     string // "1.2.3.4"
}

func newResolver(tnet *netstack.Net, servers []string, ttl time.Duration, overrides map[string]string) *Resolver {
	r := &Resolver{
		tnet:       tnet,
		servers:    servers,
		cache:      newDNSCache(ttl),
		exactHosts: make(map[string]string),
	}
	for host, ip := range overrides {
		host = strings.ToLower(host)
		if strings.HasPrefix(host, "*.") {
			// "*.foo.com" → suffix ".foo.com" (matches a.foo.com, b.c.foo.com, but NOT foo.com itself)
			r.wildcardHosts = append(r.wildcardHosts, wildcardEntry{
				suffix: host[1:], // drop the '*'
				ip:     ip,
			})
		} else {
			r.exactHosts[host] = ip
		}
	}
	// Longest suffix wins: sort descending by length
	sortWildcardsLongestFirst(r.wildcardHosts)
	return r
}

func sortWildcardsLongestFirst(ws []wildcardEntry) {
	// Simple insertion sort; override lists are tiny.
	for i := 1; i < len(ws); i++ {
		for j := i; j > 0 && len(ws[j].suffix) > len(ws[j-1].suffix); j-- {
			ws[j], ws[j-1] = ws[j-1], ws[j]
		}
	}
}

// matchOverride returns the overridden IP for host, or "" if no match.
func (r *Resolver) matchOverride(host string) string {
	host = strings.ToLower(host)
	if ip, ok := r.exactHosts[host]; ok {
		return ip
	}
	for _, w := range r.wildcardHosts {
		if strings.HasSuffix(host, w.suffix) {
			return w.ip
		}
	}
	return ""
}

// resolverForGo builds a *net.Resolver that dials through WG.
// This is what we use for LookupHost — clean, stdlib-based.
func (r *Resolver) resolverForGo() *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Round-robin across configured DNS servers
			idx := int(r.nextSrv.Add(1)) % len(r.servers)
			srv := r.servers[idx]

			// netstack only supports udp/tcp — normalize
			if strings.HasPrefix(network, "udp") {
				network = "udp"
			} else {
				network = "tcp"
			}
			return r.tnet.DialContext(ctx, network, srv)
		},
	}
}

// Resolve returns at least one IP for host, using cache when possible.
func (r *Resolver) Resolve(ctx context.Context, host string) ([]string, error) {
	// If already an IP, pass through
	if ip := net.ParseIP(host); ip != nil {
		return []string{host}, nil
	}

	// Host override takes priority over cache and DNS
	if ip := r.matchOverride(host); ip != "" {
		return []string{ip}, nil
	}

	if cached, ok := r.cache.get(host); ok {
		return cached, nil
	}

	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	addrs, err := r.resolverForGo().LookupHost(rctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses for %s", host)
	}
	r.cache.put(host, addrs)
	return addrs, nil
}

// DialHostPort resolves host via WG DNS and dials through WG.
func (r *Resolver) DialHostPort(ctx context.Context, hostport string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	ips, err := r.Resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}

	// Happy-eyeballs-lite: try each IP in order, 3s timeout each
	var lastErr error
	for _, ip := range ips {
		addr := net.JoinHostPort(ip, port)
		dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		c, err := r.tnet.DialContext(dctx, "tcp", addr)
		cancel()
		if err == nil {
			return c, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("dial %s: %w", hostport, lastErr)
}

// ─── Request ID counter ──────────────────────────────────────────────────────

var reqIDCt atomic.Uint32

func nextReqID() uint32 {
	for {
		id := reqIDCt.Add(1)
		if id != 0 {
			return id
		}
	}
}

// activeRelays tracks how many relay() goroutines are currently running.
// Used by diagLoop for observability; zero behavior impact.
var activeRelays atomic.Int64

// ─── Copy buffer pool ────────────────────────────────────────────────────────

var copyBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

func copyBuffered(dst io.Writer, src io.Reader) (int64, error) {
	bp := copyBufPool.Get().(*[]byte)
	n, err := io.CopyBuffer(dst, src, *bp)
	copyBufPool.Put(bp)
	return n, err
}

// closeWrite safely attempts a TCP Half-Close.
// It signals that we are done sending data, but keeps the receive channel open.
func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// ─── Tunnel relay (bidirectional copy) ───────────────────────────────────────
//
// SSE-safe: uses a small copy buffer (4 KB) so that tiny streaming chunks are
// forwarded immediately instead of being batched into a 32 KB flush. Does NOT
// half-close on one-direction completion — some servers (notably Google SSE
// endpoints) treat the client's half-close as an end-of-stream signal and will
// tear down the response. Instead we let both goroutines finish naturally and
// close everything at the end.
type relayResult struct {
	direction string
	bytes     int64
	duration  time.Duration
	err       error
}

func (r relayResult) reason() string {
	if r.err == nil {
		return "clean EOF"
	}
	if ne, ok := r.err.(net.Error); ok && ne.Timeout() {
		return "idle timeout"
	}
	if errors.Is(r.err, io.EOF) {
		return "EOF"
	}
	return r.err.Error()
}

// relay copies a CONNECT/SOCKS5 tunnel in both directions.
//
// Gemini/Google AI traffic is very sensitive to premature TCP half-closes:
// if the proxy sends FIN on the upload side while the model is still streaming
// down, some upstream endpoints treat it as an end-of-stream signal and stop the
// response. For that reason this relay does NOT CloseWrite() when one direction
// finishes. It waits for both directions, with long sliding idle deadlines, and
// then closes both sockets together.
func relay(id uint32, label, host string, client net.Conn, clientReader io.Reader, remote net.Conn) {
	activeRelays.Add(1)
	defer activeRelays.Add(-1)

	started := time.Now()
	logf("REQ-%05d | TUNNEL | open %s %s", id, label, host)

	results := make(chan relayResult, 2)

	go func() {
		results <- copyStreaming(remote, clientReader, remote, client, id, label, host, "browser->remote")
	}()

	go func() {
		results <- copyStreaming(client, remote, client, remote, id, label, host, "remote->browser")
	}()

	// Wait for both directions. We intentionally do not half-close either side
	// after the first direction exits; this is safer for Google/Gemini streaming.
	r1 := <-results
	logf("REQ-%05d | TUNNEL | lane done %s %s bytes=%d dur=%s reason=%s",
		id, label, r1.direction, r1.bytes, r1.duration.Truncate(time.Millisecond), r1.reason())

	r2 := <-results
	logf("REQ-%05d | TUNNEL | lane done %s %s bytes=%d dur=%s reason=%s",
		id, label, r2.direction, r2.bytes, r2.duration.Truncate(time.Millisecond), r2.reason())

	_ = client.Close()
	_ = remote.Close()

	logf("REQ-%05d | TUNNEL | closed %s %s total=%s up=%d down=%d",
		id, label, host, time.Since(started).Truncate(time.Millisecond),
		bytesForDirection(r1, r2, "browser->remote"),
		bytesForDirection(r1, r2, "remote->browser"))
}

func bytesForDirection(a, b relayResult, direction string) int64 {
	if a.direction == direction {
		return a.bytes
	}
	if b.direction == direction {
		return b.bytes
	}
	return 0
}
	
// copyStreaming implements a long sliding idle timeout for AI/web streaming.
// Every successful read pushes the deadline forward. Write failures are treated
// as real tunnel failures and are logged/returned instead of being silently
// ignored, which prevents hidden truncated TLS streams and JetBrains/Gemini EOFs.
func copyStreaming(dst io.Writer, src io.Reader, rawDst net.Conn, rawSrc net.Conn, id uint32, label, host string, direction string) relayResult {
	const idleTimeout = 30 * time.Minute

	started := time.Now()
	buf := make([]byte, 4096)
	var total int64

	for {
		deadline := time.Now().Add(idleTimeout)
		_ = rawSrc.SetReadDeadline(deadline)
		_ = rawDst.SetWriteDeadline(deadline)

	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			written := 0
			for written < nr {
				nw, werr := dst.Write(buf[written:nr])
				if nw > 0 {
					written += nw
					total += int64(nw)
				}
				if werr != nil {
					return relayResult{direction: direction, bytes: total, duration: time.Since(started), err: fmt.Errorf("write after %d/%d bytes of chunk: %w", written, nr, werr)}
				}
				if nw == 0 {
					return relayResult{direction: direction, bytes: total, duration: time.Since(started), err: io.ErrShortWrite}
				}
			}
			
			// Only push the dead man's switch forward periodically
			// This prevents gVisor timer-mutex thrashing during fast bursts
			if time.Since(lastDeadlineUpdate) > 10*time.Second {
				_ = rawSrc.SetReadDeadline(time.Now().Add(timeout))
				_ = rawDst.SetWriteDeadline(time.Now().Add(timeout))
				lastDeadlineUpdate = time.Now()
			}
		}
		if rerr != nil {
			return relayResult{direction: direction, bytes: total, duration: time.Since(started), err: rerr}
		}
	}
}

// tuneTCP configures TCP connections for low-latency streaming and Keep-Alives.
// It uses interface assertion to handle both standard net.TCPConn and gVisor's gonet.TCPConn.
func tuneTCP(c net.Conn) {
	type keepAliveConn interface {
		SetKeepAlive(bool) error
		SetKeepAlivePeriod(time.Duration) error
		SetNoDelay(bool) error
	}
	if kc, ok := c.(keepAliveConn); ok {
		_ = kc.SetNoDelay(true)
		_ = kc.SetKeepAlive(true)
		_ = kc.SetKeepAlivePeriod(15 * time.Second)
	} else if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(15 * time.Second)
	}
}

// ─── HTTP request parsing ────────────────────────────────────────────────────
func readRequest(rd io.Reader) ([]byte, []byte, error) {
	br := bufio.NewReaderSize(rd, 4096)
	var buf []byte
	var cLen int
	for {
		line, err := br.ReadString('\n')
		buf = append(buf, line...)
		if err != nil {
			return nil, nil, err
		}
		lo := strings.ToLower(line)
		if strings.HasPrefix(lo, "content-length:") {
			fmt.Sscanf(strings.TrimSpace(line[15:]), "%d", &cLen)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	if cLen > 0 {
		body := make([]byte, cLen)
		if _, err := io.ReadFull(br, body); err != nil {
			return nil, nil, err
		}
		buf = append(buf, body...)
	}

	// Capture the TLS ClientHello swallowed by bufio
	leftover := make([]byte, br.Buffered())
	io.ReadFull(br, leftover)

	return buf, leftover, nil
}

func parseMethodHost(raw []byte) (method, host string) {
	nl := strings.IndexByte(string(raw), '\n')
	if nl < 0 {
		return "?", "?"
	}
	f := strings.Fields(strings.TrimSpace(string(raw[:nl])))
	if len(f) < 2 {
		return "?", "?"
	}
	method, target := f[0], f[1]
	if method == "CONNECT" {
		host = target
		if !strings.Contains(host, ":") {
			host += ":443"
		}
		return
	}
	if i := strings.Index(target, "://"); i >= 0 {
		target = target[i+3:]
		if j := strings.IndexAny(target, "/?"); j >= 0 {
			target = target[:j]
		}
		host = target
	} else {
		for _, l := range strings.Split(string(raw), "\n") {
			if strings.HasPrefix(strings.ToLower(l), "host:") {
				host = strings.TrimRight(strings.TrimSpace(l[5:]), "\r")
				break
			}
		}
	}
	if !strings.Contains(host, ":") {
		host += ":80"
	}
	return
}

// cleanRequest strips proxy-specific headers and absolutizes URL to origin-form.
func cleanRequest(raw []byte) []byte {
	headerEnd := strings.Index(string(raw), "\r\n\r\n")
	var body []byte
	if headerEnd >= 0 {
		body = raw[headerEnd+4:]
		raw = raw[:headerEnd+4]
	}
	lines := strings.Split(string(raw), "\r\n")
	if len(lines) == 0 {
		out := append([]byte{}, raw...)
		return append(out, body...)
	}
	parts := strings.Fields(lines[0])
	if len(parts) == 3 {
		target := parts[1]
		if i := strings.Index(target, "://"); i >= 0 {
			after := target[i+3:]
			if slash := strings.IndexByte(after, '/'); slash >= 0 {
				parts[1] = after[slash:]
			} else {
				parts[1] = "/"
			}
		}
		lines[0] = strings.Join(parts, " ")
	}
	var out []string
	out = append(out, lines[0])
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		lo := strings.ToLower(line)
		if strings.HasPrefix(lo, "proxy-connection:") || strings.HasPrefix(lo, "proxy-authorization:") {
			continue
		}
		out = append(out, line)
	}
	result := strings.Join(out, "\r\n") + "\r\n\r\n"
	if len(body) > 0 {
		return append([]byte(result), body...)
	}
	return []byte(result)
}

// ─── HTTP proxy handler ───────────────────────────────────────────────────────
func handleHTTP(r *Resolver, client net.Conn) {
	defer client.Close()
	id := nextReqID()

	// FIX: Prevent speculative pre-connections from freezing the proxy
	_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
	raw, leftover, err := readRequest(client)
	_ = client.SetReadDeadline(time.Time{}) // Disable deadline so the tunnel takes over
	if err != nil {
		return
	}

	method, host := parseMethodHost(raw)
	logf("REQ-%05d | HTTP   | %s %s", id, method, host)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	remote, err := r.DialHostPort(ctx, host)
	cancel()
	if err != nil {
		logf("REQ-%05d | ERR    | dial %s: %v", id, host, err)
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}

	// Apply Keep-Alives to BOTH ends
	tuneTCP(client)
	tuneTCP(remote)

	if method == "CONNECT" {
		if _, err := client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			remote.Close()
			return
		}

		// Stitch the swallowed handshake bytes back to the front of the socket
		var clientReader io.Reader = client
		if len(leftover) > 0 {
			clientReader = io.MultiReader(bytes.NewReader(leftover), client)
		}

		relay(id, "HTTP", host, client, clientReader, remote)
	} else {
		if _, err := remote.Write(cleanRequest(raw)); err != nil {
			remote.Close()
			return
		}
		copyBuffered(client, remote)
		remote.Close()
		logf("REQ-%05d | DONE   | %s", id, host)
	}
}

// ─── SOCKS5 handler ───────────────────────────────────────────────────────────

func readFull(c net.Conn, buf []byte) error {
	_, err := io.ReadFull(c, buf)
	return err
}

func handleSOCKS5(r *Resolver, client net.Conn) {
	defer client.Close()
	id := nextReqID()

	// FIX: Prevent speculative pre-connections from freezing the proxy
	_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
	// Apply Keep-Alives to the client side
	tuneTCP(client)

	// Greeting
	hdr := make([]byte, 2)
	if err := readFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	methods := make([]byte, int(hdr[1]))
	if err := readFull(client, methods); err != nil {
		return
	}
	ok := false
	for _, m := range methods {
		if m == 0x00 {
			ok = true
			break
		}
	}
	if !ok {
		client.Write([]byte{0x05, 0xFF})
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	// Request
	req := make([]byte, 4)
	if err := readFull(client, req); err != nil {
		return
	}
	if req[0] != 0x05 {
		return
	}
	cmd := req[1]
	atyp := req[3]

	if cmd != 0x01 { // CONNECT only
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch atyp {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if err := readFull(client, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 0x03: // domain
		lenBuf := make([]byte, 1)
		if err := readFull(client, lenBuf); err != nil {
			return
		}
		domain := make([]byte, int(lenBuf[0]))
		if err := readFull(client, domain); err != nil {
			return
		}
		host = string(domain)
	case 0x04: // IPv6
		addr := make([]byte, 16)
		if err := readFull(client, addr); err != nil {
			return
		}
		host = "[" + net.IP(addr).String() + "]"
	default:
		client.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	portBuf := make([]byte, 2)
	if err := readFull(client, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	logf("REQ-%05d | SOCKS5 | CONNECT %s", id, target)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	remote, err := r.DialHostPort(ctx, target)
	cancel()
	if err != nil {
		logf("REQ-%05d | ERR    | dial %s: %v", id, target, err)
		client.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	// Apply Keep-Alives to the remote side
	tuneTCP(remote)

	// Success reply (bind addr/port = 0)
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		remote.Close()
		return
	}

	// Disable deadline right before handing off to the relay
	_ = client.SetReadDeadline(time.Time{})
	// SOCKS5 doesn't swallow bytes, so we pass the `client` socket twice
	// (once as the raw socket, once as the io.Reader)
	relay(id, "SOCKS5", target, client, client, remote)
}

// ─── Listeners ────────────────────────────────────────────────────────────────

func serveHTTP(ln net.Listener, r *Resolver) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logf("SYS | WARN  | http accept: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go handleHTTP(r, c)
	}
}

func serveSOCKS5(ln net.Listener, r *Resolver) {
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			logf("SYS | WARN  | socks5 accept: %v", err)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		go handleSOCKS5(r, c)
	}
}

// ─── Diagnostics ──────────────────────────────────────────────────────────────
//
// Two loops, both observation-only (zero impact on request paths):
//
//   diagLoop         — every 60s, logs goroutine count, active relays,
//                      DNS cache size, WG last-handshake age, WG rx/tx delta.
//   tunnelHealthLoop — every 5 min, does a TCP handshake to 1.1.1.1:443
//                      through the tunnel and logs RTT. After 3 consecutive
//                      failures, emits a loud ALERT line. No auto-rebuild.
//
// Purpose: when the proxy goes stale after hours/days of uptime, the log
// should show which subsystem died (goroutine leak, WG handshake wedge, or
// netstack tcp stall) so a real fix can be designed.

// wgStats holds a parsed snapshot of the peer section of `IpcGet()`.
type wgStats struct {
	lastHandshakeUnix int64 // seconds; 0 if never
	rxBytes           uint64
	txBytes           uint64
}

// readWGStats parses the first peer's stats from the WG device IPC dump.
// Returns a zero-value struct on any parse failure — observability should
// never be able to panic the process.
func readWGStats(dev *device.Device) wgStats {
	var s wgStats
	raw, err := dev.IpcGet()
	if err != nil {
		return s
	}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		k, v := line[:eq], line[eq+1:]
		switch k {
		case "last_handshake_time_sec":
			var n int64
			fmt.Sscanf(v, "%d", &n)
			s.lastHandshakeUnix = n
		case "rx_bytes":
			var n uint64
			fmt.Sscanf(v, "%d", &n)
			s.rxBytes = n
		case "tx_bytes":
			var n uint64
			fmt.Sscanf(v, "%d", &n)
			s.txBytes = n
		}
	}
	return s
}

func diagLoop(dev *device.Device, resolver *Resolver) {
	t := time.NewTicker(60 * time.Second)
	defer t.Stop()

	var lastRx, lastTx uint64
	first := true

	for range t.C {
		s := readWGStats(dev)

		var dRx, dTx uint64
		if !first {
			if s.rxBytes >= lastRx {
				dRx = s.rxBytes - lastRx
			}
			if s.txBytes >= lastTx {
				dTx = s.txBytes - lastTx
			}
		}
		lastRx, lastTx = s.rxBytes, s.txBytes
		first = false

		var hsAge string
		if s.lastHandshakeUnix == 0 {
			hsAge = "never"
		} else {
			age := time.Since(time.Unix(s.lastHandshakeUnix, 0))
			hsAge = age.Truncate(time.Second).String()
		}

		logf("SYS | DIAG  | goroutines=%d relays=%d dns_cache=%d wg_hs_age=%s wg_rx_delta=%d wg_tx_delta=%d",
			runtime.NumGoroutine(),
			activeRelays.Load(),
			resolver.cache.size(),
			hsAge,
			dRx, dTx,
		)
	}
}

// tunnelHealthLoop probes the tunnel every 5 minutes by opening a TCP
// connection to 1.1.1.1:443 through gVisor+WG, then immediately closing it.
// Cheap, honest liveness signal. Logs RTT on success; on 3 consecutive
// failures emits a loud ALERT line (but does NOT attempt to rebuild WG —
// that decision waits until we've seen a real failure in the log).
func tunnelHealthLoop(tnet *netstack.Net) {
	const (
		interval    = 5 * time.Minute
		probeTarget = "1.1.1.1:443"
		dialTimeout = 8 * time.Second
		alertAfter  = 3
	)

	t := time.NewTicker(interval)
	defer t.Stop()

	failStreak := 0
	for range t.C {
		ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
		start := time.Now()
		c, err := tnet.DialContext(ctx, "tcp", probeTarget)
		rtt := time.Since(start)
		cancel()

		if err != nil {
			failStreak++
			logf("SYS | HEALTH| probe %s FAIL (streak=%d) after %v: %v",
				probeTarget, failStreak, rtt.Truncate(time.Millisecond), err)
			if failStreak == alertAfter {
				logf("SYS | ALERT | tunnel appears unhealthy: %d consecutive probe failures — manual restart may be required",
					failStreak)
			}
			continue
		}
		_ = c.Close()

		if failStreak > 0 {
			logf("SYS | HEALTH| probe %s OK rtt=%v (recovered after %d failure(s))",
				probeTarget, rtt.Truncate(time.Millisecond), failStreak)
		} else {
			logf("SYS | HEALTH| probe %s OK rtt=%v",
				probeTarget, rtt.Truncate(time.Millisecond))
		}
		failStreak = 0
	}
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	cfgPath := "config.ini"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		logf("SYS | FATAL | config: %v", err)
		os.Exit(1)
	}

	logf("SYS | START | splice-proxy")
	logf("SYS | INFO  | config : %s", cfgPath)
	logf("SYS | INFO  | http   : %s", cfg.HTTPListen)
	logf("SYS | INFO  | socks5 : %s", cfg.SOCKS5Listen)
	logf("SYS | INFO  | wg peer: %s", cfg.WGPeerEndpoint)
	logf("SYS | INFO  | wg ip  : %v", cfg.WGLocalIPs)
	logf("SYS | INFO  | dns    : %v (cache=%v)", cfg.DNSServers, cfg.DNSCacheTTL)
	if len(cfg.HostOverrides) > 0 {
		logf("SYS | INFO  | hosts  : %d override(s) loaded", len(cfg.HostOverrides))
		for host, ip := range cfg.HostOverrides {
			logf("SYS | INFO  |         %s -> %s", host, ip)
		}
	}

	tnet, dev, err := setupWireGuard(cfg)
	if err != nil {
		logf("SYS | FATAL | wireguard: %v", err)
		os.Exit(1)
	}
	logf("SYS | READY | wireguard up")

	resolver := newResolver(tnet, cfg.DNSServers, cfg.DNSCacheTTL, cfg.HostOverrides)

	httpLn, err := net.Listen("tcp", cfg.HTTPListen)
	if err != nil {
		logf("SYS | FATAL | http listen: %v", err)
		dev.Close()
		os.Exit(1)
	}
	socksLn, err := net.Listen("tcp", cfg.SOCKS5Listen)
	if err != nil {
		logf("SYS | FATAL | socks5 listen: %v", err)
		httpLn.Close()
		dev.Close()
		os.Exit(1)
	}

	go serveHTTP(httpLn, resolver)
	go serveSOCKS5(socksLn, resolver)
	go diagLoop(dev, resolver)
	go tunnelHealthLoop(tnet)

	logf("SYS | READY | proxies listening")

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	logf("SYS | STOP  | shutdown signal received")

	httpLn.Close()
	socksLn.Close()
	dev.Close()
	logf("SYS | STOP  | goodbye")
}
