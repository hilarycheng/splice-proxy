// splice-proxy.go — Single-binary HTTP + SOCKS5 proxy with embedded WireGuard.
//
// Runs on Windows and Linux. No TUN driver. No admin rights. No kernel modules.
// Traffic is routed either through an embedded userspace WireGuard tunnel via
// gVisor netstack or directly through the system network, according to config.
//
// Build:   go build -ldflags "-s -w" -o splice-proxy splice-proxy.go
// Config:  config.ini (see README.md)

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
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
	"runtime/pprof"
	"sort"
	"strconv"
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

	DefaultRoute routeAction
	Routes       map[string]routeAction
	RouteReload  time.Duration

	// HostOverrides maps "host" or "*.suffix" to an IP string.
	// Exact matches are checked first, then suffix wildcards (longest first).
	HostOverrides map[string]string
}

type routeAction string

const (
	routeDirect    routeAction = "direct"
	routeWireGuard routeAction = "wireguard"
)

func parseRouteAction(value string) (routeAction, error) {
	switch routeAction(strings.ToLower(strings.TrimSpace(value))) {
	case routeDirect:
		return routeDirect, nil
	case routeWireGuard:
		return routeWireGuard, nil
	default:
		return "", fmt.Errorf("must be %q or %q", routeDirect, routeWireGuard)
	}
}

func normalizeRoutePattern(pattern string) (string, error) {
	pattern = strings.ToLower(strings.TrimSpace(pattern))
	pattern = strings.TrimSuffix(pattern, ".")
	if pattern == "" {
		return "", errors.New("hostname is empty")
	}
	if prefix, err := netip.ParsePrefix(pattern); err == nil {
		return prefix.Masked().String(), nil
	}
	if strings.Contains(pattern, "/") {
		return "", errors.New("invalid CIDR")
	}
	if ip, err := netip.ParseAddr(strings.Trim(pattern, "[]")); err == nil {
		return ip.Unmap().String(), nil
	}
	if strings.HasPrefix(pattern, "*.") {
		if len(pattern) == 2 || strings.Contains(pattern[2:], "*") {
			return "", errors.New("invalid wildcard hostname")
		}
		return pattern, nil
	}
	if strings.Contains(pattern, "*") {
		return "", errors.New("wildcard is only supported as a leading *.")
	}
	return pattern, nil
}

func parseRoutingConfig(m map[string]string) (routeAction, map[string]routeAction, time.Duration, error) {
	defaultValue, ok := m["routing.default"]
	if !ok {
		defaultValue = string(routeWireGuard)
	}
	defaultRoute, err := parseRouteAction(defaultValue)
	if err != nil {
		return "", nil, 0, fmt.Errorf("routing.default %s", err)
	}
	reloadSeconds := 0
	if raw, ok := m["routing.reload_interval_seconds"]; ok {
		reloadSeconds, err = strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return "", nil, 0, fmt.Errorf("routing.reload_interval_seconds must be an integer: %w", err)
		}
	}
	if reloadSeconds < 0 {
		return "", nil, 0, errors.New("routing.reload_interval_seconds must be 0 or greater")
	}

	routes := make(map[string]routeAction)
	for k, v := range m {
		if !strings.HasPrefix(k, "routes.") {
			continue
		}
		name := strings.TrimPrefix(k, "routes.")
		pattern, err := normalizeRoutePattern(name)
		if err != nil {
			return "", nil, 0, fmt.Errorf("[routes] %q: %w", name, err)
		}
		action, err := parseRouteAction(v)
		if err != nil {
			return "", nil, 0, fmt.Errorf("[routes] %q %s", pattern, err)
		}
		routes[pattern] = action
	}
	return defaultRoute, routes, time.Duration(reloadSeconds) * time.Second, nil
}

func loadIni(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return make(map[string]string)
	}
	return parseIniData(data)
}

func parseIniData(data []byte) map[string]string {
	m := make(map[string]string)
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(data))
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
	defaultRoute, routes, reloadInterval, err := parseRoutingConfig(m)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}

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

		DefaultRoute: defaultRoute,
		Routes:       routes,
		RouteReload:  reloadInterval,
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

	logf("SYS | INFO  | netstack tuned: rcv=256KB snd=256KB max=4MB auto-tune=on sack=on")
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
	tnet          *netstack.Net
	servers       []string
	cache         *dnsCache
	nextSrv       atomic.Uint32
	direct        net.Dialer
	routes        atomic.Pointer[routeRuleSet]
	systemHostsMu sync.RWMutex

	// Address-family mode comes from configured WG local IPs.
	// If the tunnel has only IPv4 local addresses, avoid using IPv6 DNS answers
	// for large Google sites. Some WG/netstack setups can appear to connect to an
	// IPv6 address and then fail during TLS, which Firefox reports as
	// PR_END_OF_FILE_ERROR.
	allowIPv4 bool
	allowIPv6 bool

	// Host overrides: exact match takes priority over wildcard.
	// Wildcards are stored as "suffix" (e.g. ".example.com") and matched longest-first.
	exactHosts    map[string]string // "gemini.google.com" -> "142.250.80.110"
	wildcardHosts []wildcardEntry   // sorted by suffix length, descending

	// systemHosts contains names declared in the operating system hosts file.
	// It is used only for route selection; direct resolution remains the OS's job.
	systemHosts map[string]struct{}
}

type wildcardEntry struct {
	suffix string // ".example.com"
	ip     string // "1.2.3.4"
}

type routeRuleSet struct {
	defaultAction routeAction
	exact         map[string]routeAction
	prefixes      []routePrefixEntry
	wildcards     []routeWildcardEntry
}

type routePrefixEntry struct {
	prefix  netip.Prefix
	pattern string
	action  routeAction
}

type routeWildcardEntry struct {
	suffix   string
	pattern  string
	action   routeAction
	explicit bool
}

func newRouteRuleSet(defaultAction routeAction, routes map[string]routeAction) routeRuleSet {
	r := routeRuleSet{
		defaultAction: defaultAction,
		exact:         make(map[string]routeAction),
	}
	for pattern, action := range routes {
		if prefix, err := netip.ParsePrefix(pattern); err == nil {
			r.prefixes = append(r.prefixes, routePrefixEntry{
				prefix:  prefix.Masked(),
				pattern: prefix.Masked().String(),
				action:  action,
			})
			continue
		}
		if strings.HasPrefix(pattern, "*.") {
			r.wildcards = append(r.wildcards, routeWildcardEntry{
				suffix:   pattern[1:],
				pattern:  pattern,
				action:   action,
				explicit: true,
			})
			continue
		}
		r.exact[pattern] = action
		if _, err := netip.ParseAddr(pattern); err == nil {
			continue
		}
		r.wildcards = append(r.wildcards, routeWildcardEntry{
			suffix:  "." + pattern,
			pattern: pattern,
			action:  action,
		})
	}
	sort.Slice(r.prefixes, func(i, j int) bool {
		return r.prefixes[i].prefix.Bits() > r.prefixes[j].prefix.Bits()
	})
	sort.Slice(r.wildcards, func(i, j int) bool {
		if len(r.wildcards[i].suffix) != len(r.wildcards[j].suffix) {
			return len(r.wildcards[i].suffix) > len(r.wildcards[j].suffix)
		}
		// Preserve the meaning of an explicitly configured wildcard when a
		// bare domain rule covers the same suffix.
		return r.wildcards[i].explicit && !r.wildcards[j].explicit
	})
	return r
}

func (r routeRuleSet) match(host string) routeAction {
	action, _ := r.matchDetail(host)
	return action
}

func (r routeRuleSet) matchDetail(host string) (routeAction, string) {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if action, ok := r.exact[host]; ok {
		return action, host
	}
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		ip = ip.Unmap()
		for _, rule := range r.prefixes {
			if rule.prefix.Contains(ip) {
				return rule.action, rule.pattern
			}
		}
	}
	for _, rule := range r.wildcards {
		if strings.HasSuffix(host, rule.suffix) {
			return rule.action, rule.pattern
		}
	}
	return r.defaultAction, "default"
}

func newResolver(tnet *netstack.Net, servers []string, ttl time.Duration, overrides map[string]string, systemHosts map[string]struct{}, localIPs []netip.Addr, defaultRoute routeAction, routes map[string]routeAction) *Resolver {
	allowIPv4, allowIPv6 := addressFamilyMode(localIPs)
	r := &Resolver{
		tnet:    tnet,
		servers: servers,
		cache:   newDNSCache(ttl),
		direct: net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
			Resolver:  net.DefaultResolver,
		},
		allowIPv4:  allowIPv4,
		allowIPv6:  allowIPv6,
		exactHosts: make(map[string]string),
	}
	r.replaceRoutes(defaultRoute, routes)
	r.replaceSystemHosts(systemHosts)
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

func (r *Resolver) replaceRoutes(defaultAction routeAction, routes map[string]routeAction) {
	rules := newRouteRuleSet(defaultAction, routes)
	r.routes.Store(&rules)
}

func (r *Resolver) replaceSystemHosts(hosts map[string]struct{}) {
	r.systemHostsMu.Lock()
	r.systemHosts = hosts
	r.systemHostsMu.Unlock()
}

func (r *Resolver) matchRoute(host string) (routeAction, string) {
	rules := r.routes.Load()
	if rules == nil {
		return routeWireGuard, "default"
	}
	return rules.matchDetail(host)
}

func normalizeHostname(host string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
}

func (r *Resolver) isSystemHost(host string) bool {
	host = normalizeHostname(host)
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return ip.IsLoopback()
	}
	r.systemHostsMu.RLock()
	_, ok := r.systemHosts[host]
	r.systemHostsMu.RUnlock()
	return ok
}

// selectRoute checks explicit routes first, then OS hosts-file membership,
// then a static [hosts] IP route before falling back to the configured default.
func (r *Resolver) selectRoute(host string) (routeAction, string, string) {
	action, rule := r.matchRoute(host)
	staticIP := r.matchOverride(host)
	if rule != "default" {
		return action, rule, staticIP
	}
	if r.isSystemHost(host) {
		return routeDirect, "system-hosts", staticIP
	}
	if staticIP == "" {
		return action, rule, staticIP
	}

	ipAction, ipRule := r.matchRoute(staticIP)
	if ipRule != "default" {
		return ipAction, ipRule, staticIP
	}
	return action, rule, staticIP
}

func systemHostsFilePath() string {
	if runtime.GOOS != "windows" {
		return "/etc/hosts"
	}
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = os.Getenv("windir")
	}
	if root == "" {
		root = `C:\Windows`
	}
	return strings.TrimRight(root, `\/`) + `\System32\drivers\etc\hosts`
}

// loadSystemHostnames reads hosts-file aliases for route classification only.
// The direct resolver still decides which address to use, preserving OS rules.
func loadSystemHostnames(path string) (map[string]struct{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseSystemHostnames(data)
}

func parseSystemHostnames(data []byte) (map[string]struct{}, error) {
	hosts := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line, _, _ := strings.Cut(scanner.Text(), "#")
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, err := netip.ParseAddr(fields[0]); err != nil {
			continue
		}
		for _, alias := range fields[1:] {
			alias = normalizeHostname(alias)
			if alias != "" {
				hosts[alias] = struct{}{}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return hosts, nil
}

func reloadLoop(configPath, systemHostsPath string, resolver *Resolver, initialInterval time.Duration) {
	interval := initialInterval
	timer := time.NewTimer(0)
	defer timer.Stop()

	var routeObservedHash, routeProcessedHash [sha256.Size]byte
	routeHaveObserved := false
	routeHaveProcessed := false
	routeStableReads := 0
	var hostsObservedHash, hostsProcessedHash [sha256.Size]byte
	hostsHaveObserved := false
	hostsHaveProcessed := false
	hostsStableReads := 0
	for {
		<-timer.C
		data, err := os.ReadFile(configPath)
		if err != nil {
			logf("SYS | ROUTE | reload read failed; keeping last valid routes: %v", err)
			routeHaveObserved = false
			routeStableReads = 0
		} else {
			hash := sha256.Sum256(data)
			if !routeHaveObserved || hash != routeObservedHash {
				routeHaveObserved = true
				routeObservedHash = hash
				routeStableReads = 1
			} else {
				routeStableReads++
			}
			if routeStableReads >= 2 && (!routeHaveProcessed || hash != routeProcessedHash) {
				routeHaveProcessed = true
				routeProcessedHash = hash
				defaultRoute, routes, nextInterval, parseErr := parseRoutingConfig(parseIniData(data))
				if parseErr != nil {
					logf("SYS | ROUTE | reload rejected; keeping last valid routes: %v", parseErr)
				} else {
					resolver.replaceRoutes(defaultRoute, routes)
					logf("SYS | ROUTE | reloaded default=%s rules=%d", defaultRoute, len(routes))
					if nextInterval != interval {
						interval = nextInterval
						logf("SYS | ROUTE | reload interval changed to %v", interval)
					}
				}
			}
		}

		hostsData, hostsErr := os.ReadFile(systemHostsPath)
		if hostsErr != nil {
			logf("SYS | HOSTS | reload read failed; keeping last valid hosts: %v", hostsErr)
			hostsHaveObserved = false
			hostsStableReads = 0
		} else {
			hash := sha256.Sum256(hostsData)
			if !hostsHaveObserved || hash != hostsObservedHash {
				hostsHaveObserved = true
				hostsObservedHash = hash
				hostsStableReads = 1
			} else {
				hostsStableReads++
			}
			if hostsStableReads >= 2 && (!hostsHaveProcessed || hash != hostsProcessedHash) {
				hostsHaveProcessed = true
				hostsProcessedHash = hash
				hosts, parseErr := parseSystemHostnames(hostsData)
				if parseErr != nil {
					logf("SYS | HOSTS | reload rejected; keeping last valid hosts: %v", parseErr)
				} else {
					resolver.replaceSystemHosts(hosts)
					logf("SYS | HOSTS | reloaded names=%d", len(hosts))
				}
			}
		}

		if interval <= 0 {
			logf("SYS | ROUTE | dynamic reload disabled; restart required to enable it again")
			return
		}
		timer.Reset(interval)
	}
}

func sortWildcardsLongestFirst(ws []wildcardEntry) {
	// Simple insertion sort; override lists are tiny.
	for i := 1; i < len(ws); i++ {
		for j := i; j > 0 && len(ws[j].suffix) > len(ws[j-1].suffix); j-- {
			ws[j], ws[j-1] = ws[j-1], ws[j]
		}
	}
}

func addressFamilyMode(localIPs []netip.Addr) (allowIPv4, allowIPv6 bool) {
	for _, ip := range localIPs {
		if ip.Is4() || ip.Is4In6() {
			allowIPv4 = true
			continue
		}
		if ip.Is6() {
			allowIPv6 = true
		}
	}
	// Be conservative if config parsing ever passes an empty slice here.
	if !allowIPv4 && !allowIPv6 {
		allowIPv4 = true
	}
	return allowIPv4, allowIPv6
}

// orderResolvedAddrs keeps DNS answers compatible with the tunnel address
// family. Prefer IPv4 whenever available because many splice-proxy deployments
// are IPv4-only WG tunnels with allowed_ips=0.0.0.0/0.
func (r *Resolver) orderResolvedAddrs(addrs []string) []string {
	var v4, v6, unknown []string
	for _, addr := range addrs {
		ip := net.ParseIP(addr)
		if ip == nil {
			unknown = append(unknown, addr)
			continue
		}
		if ip.To4() != nil {
			if r.allowIPv4 {
				v4 = append(v4, addr)
			}
			continue
		}
		if r.allowIPv6 {
			v6 = append(v6, addr)
		}
	}

	out := make([]string, 0, len(v4)+len(v6)+len(unknown))
	// IPv4-first is intentional for Google/Gmail compatibility through
	// IPv4-only WireGuard peers. IPv6 is still used when the tunnel is IPv6-only
	// or after IPv4 addresses fail.
	if r.allowIPv4 {
		out = append(out, v4...)
	}
	if r.allowIPv6 {
		out = append(out, v6...)
	}
	out = append(out, unknown...)
	if len(out) == 0 {
		return addrs
	}
	return out
}

func (r *Resolver) ipAllowedByTunnel(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.To4() != nil {
		return r.allowIPv4
	}
	return r.allowIPv6
}

func (r *Resolver) explainIPMode() string {
	return fmt.Sprintf("wireguard address family: ipv4=%v ipv6=%v", r.allowIPv4, r.allowIPv6)
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

// resolveWireGuard returns at least one IP plus the resolution source.
func (r *Resolver) resolveWireGuard(ctx context.Context, host string) ([]string, string, error) {
	// If already an IP, pass through only when the configured WireGuard
	// address family can actually route it. This matters for Firefox SOCKS5
	// when "Proxy DNS when using SOCKS v5" is disabled: Firefox may send a
	// literal IPv6 address for gmail.google.com even though the tunnel is IPv4-only.
	if ip := net.ParseIP(strings.Trim(host, "[]")); ip != nil {
		if !r.ipAllowedByTunnel(ip) {
			return nil, "literal", fmt.Errorf("direct IP target %s is not usable with %s; enable Firefox 'Proxy DNS when using SOCKS v5' or configure IPv6 in WireGuard", host, r.explainIPMode())
		}
		return []string{strings.Trim(host, "[]")}, "literal", nil
	}

	// Host override takes priority over cache and DNS
	if ip := r.matchOverride(host); ip != "" {
		return []string{ip}, "host-override", nil
	}

	if cached, ok := r.cache.get(host); ok {
		return cached, "cache", nil
	}

	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	addrs, err := r.resolverForGo().LookupHost(rctx, host)
	if err != nil {
		return nil, "tunnel-dns", err
	}
	if len(addrs) == 0 {
		return nil, "tunnel-dns", fmt.Errorf("no addresses for %s", host)
	}
	addrs = r.orderResolvedAddrs(addrs)
	r.cache.put(host, addrs)
	return addrs, "tunnel-dns", nil
}

// Resolve preserves the existing WireGuard-only resolver API.
func (r *Resolver) Resolve(ctx context.Context, host string) ([]string, error) {
	addrs, _, err := r.resolveWireGuard(ctx, host)
	return addrs, err
}

func resolveDirect(ctx context.Context, host string) ([]string, string, error) {
	host = strings.Trim(host, "[]")
	if net.ParseIP(host) != nil {
		return []string{host}, "literal", nil
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupHost(rctx, host)
	if err != nil {
		return nil, "system-dns", err
	}
	if len(addrs) == 0 {
		return nil, "system-dns", fmt.Errorf("no addresses for %s", host)
	}
	return addrs, "system-dns", nil
}

// DialHostPort selects the configured outbound route, then resolves and dials
// entirely through that path. Direct routing uses system DNS and networking;
// WireGuard routing uses the tunnel DNS and netstack.
func (r *Resolver) DialHostPort(ctx context.Context, reqID uint32, hostport string) (net.Conn, error) {
	activeDials.Add(1)
	defer activeDials.Add(-1)
	tr, done := registerRoutine("outbound-dial", reqID, hostport)
	defer done()
	if tr != nil {
		tr.setState("parse target")
	}

	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	// net.SplitHostPort normally removes IPv6 brackets, but be defensive because
	// older SOCKS5 code accidentally passed pre-bracketed IPv6 strings.
	host = strings.Trim(host, "[]")
	action, rule, staticIP := r.selectRoute(host)
	logf("REQ-%05d | ROUTE  | %s via=%s rule=%s", reqID, hostport, action, rule)
	if tr != nil {
		tr.setState("resolve " + string(action))
	}

	resolveStarted := time.Now()
	var ips []string
	var source string
	if staticIP != "" {
		ips, source = []string{staticIP}, "host-override"
	} else if action == routeDirect {
		ips, source, err = resolveDirect(ctx, host)
	} else {
		ips, source, err = r.resolveWireGuard(ctx, host)
	}
	resolveDuration := time.Since(resolveStarted)
	if err != nil {
		logf("REQ-%05d | DNS    | host=%s route=%s source=%s dur=%v error=%v",
			reqID, host, action, source, resolveDuration.Truncate(time.Millisecond), err)
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}
	logf("REQ-%05d | DNS    | host=%s route=%s source=%s dur=%v addrs=%v",
		reqID, host, action, source, resolveDuration.Truncate(time.Millisecond), ips)

	var lastErr error
	attempted := make([]string, 0, len(ips))
	for _, ip := range ips {
		addr := net.JoinHostPort(ip, port)
		attempted = append(attempted, addr)
		dialAction := action
		if rule == "default" {
			if ipAction, ipRule := r.matchRoute(ip); ipRule != "default" {
				dialAction = ipAction
				logf("REQ-%05d | ROUTE  | %s via=%s rule=%s", reqID, addr, dialAction, ipRule)
			}
		}
		if tr != nil {
			tr.setState("connect " + addr)
		}
		dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		started := time.Now()
		var c net.Conn
		if dialAction == routeDirect {
			c, err = r.direct.DialContext(dctx, "tcp", addr)
		} else {
			c, err = r.tnet.DialContext(dctx, "tcp", addr)
		}
		duration := time.Since(started)
		cancel()
		if err == nil {
			logf("REQ-%05d | DIAL   | route=%s addr=%s dur=%v result=connected",
				reqID, dialAction, addr, duration.Truncate(time.Millisecond))
			return c, nil
		}
		logf("REQ-%05d | DIAL   | route=%s addr=%s dur=%v result=failed error=%v",
			reqID, dialAction, addr, duration.Truncate(time.Millisecond), err)
		lastErr = err
	}
	return nil, fmt.Errorf("dial %s via %s %v: %w", hostport, action, attempted, lastErr)
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
var activeHTTPHandlers atomic.Int64
var activeSOCKSHandlers atomic.Int64
var activeDials atomic.Int64

// debugConsoleEnabled gates all foreground-only diagnostics. Normal/systemd
// startup leaves this false, so there is no stdin menu, routine registry table,
// or frequent ping loop unless --debug-console is explicitly passed.
var debugConsoleEnabled atomic.Bool

type trackedRoutine struct {
	id    uint64
	name  string
	reqID uint32
	host  atomic.Value // string
	state atomic.Value // string
	start time.Time
	last  atomic.Int64 // UnixNano
	bytes atomic.Int64
}

var routineTracker = struct {
	next atomic.Uint64
	mu   sync.Mutex
	m    map[uint64]*trackedRoutine
}{m: make(map[uint64]*trackedRoutine)}

func registerRoutine(name string, reqID uint32, host string) (*trackedRoutine, func()) {
	if !debugConsoleEnabled.Load() {
		return nil, func() {}
	}
	now := time.Now()
	tr := &trackedRoutine{id: routineTracker.next.Add(1), name: name, reqID: reqID, start: now}
	tr.host.Store(host)
	tr.state.Store("start")
	tr.last.Store(now.UnixNano())
	routineTracker.mu.Lock()
	routineTracker.m[tr.id] = tr
	routineTracker.mu.Unlock()
	return tr, func() {
		routineTracker.mu.Lock()
		delete(routineTracker.m, tr.id)
		routineTracker.mu.Unlock()
	}
}

func goTracked(name string, reqID uint32, host string, fn func(*trackedRoutine)) {
	if !debugConsoleEnabled.Load() {
		go fn(nil)
		return
	}
	go func() {
		tr, done := registerRoutine(name, reqID, host)
		defer done()
		fn(tr)
	}()
}

func (tr *trackedRoutine) setHost(host string) {
	if tr != nil {
		tr.host.Store(host)
	}
}

func (tr *trackedRoutine) setState(state string) {
	if tr != nil {
		tr.state.Store(state)
		tr.last.Store(time.Now().UnixNano())
	}
}

func (tr *trackedRoutine) addBytes(n int) {
	if tr != nil && n > 0 {
		tr.bytes.Add(int64(n))
		tr.last.Store(time.Now().UnixNano())
	}
}

type routineSnapshot struct {
	ID    uint64
	Name  string
	ReqID uint32
	Host  string
	State string
	Start time.Time
	Last  time.Time
	Bytes int64
}

func snapshotRoutines() []routineSnapshot {
	routineTracker.mu.Lock()
	defer routineTracker.mu.Unlock()
	out := make([]routineSnapshot, 0, len(routineTracker.m))
	for _, tr := range routineTracker.m {
		host, _ := tr.host.Load().(string)
		state, _ := tr.state.Load().(string)
		out = append(out, routineSnapshot{
			ID: tr.id, Name: tr.name, ReqID: tr.reqID, Host: host, State: state,
			Start: tr.start, Last: time.Unix(0, tr.last.Load()), Bytes: tr.bytes.Load(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Start.Before(out[j].Start) })
	return out
}

// ─── Copy buffer pool ────────────────────────────────────────────────────────

var copyBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

func copyBuffered(dst io.Writer, src io.Reader, onFirstData func()) (int64, error) {
	bp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bp)
	var total int64
	first := true
	for {
		n, readErr := src.Read(*bp)
		if n > 0 {
			if first {
				first = false
				if onFirstData != nil {
					onFirstData()
				}
			}
			if err := writeFull(dst, (*bp)[:n]); err != nil {
				return total, err
			}
			total += int64(n)
		}
		if readErr != nil {
			return total, readErr
		}
	}
}

// ─── Tunnel relay (bidirectional copy) ───────────────────────────────────────

const (
	// CONNECT tunnels are long-lived HTTPS/TLS pipes. Gmail/Google/AI sites can
	// keep one direction idle for a long time while the opposite direction remains
	// active, so the timeout must be shared by the whole tunnel, not enforced per
	// copy lane.
	tunnelIdleTimeout = 30 * time.Minute

	// Watchdog check interval. Relay goroutines block in Read() naturally; the
	// watchdog closes both sockets if the whole tunnel is idle too long.
	relayWatchdogInterval = 5 * time.Second
)

type relayActivity struct {
	last atomic.Int64 // UnixNano of last successful read/write in either lane
}

func newRelayActivity() *relayActivity {
	a := &relayActivity{}
	a.touch()
	return a
}

func (a *relayActivity) touch() {
	a.last.Store(time.Now().UnixNano())
}

func (a *relayActivity) idleFor() time.Duration {
	last := a.last.Load()
	if last == 0 {
		return 0
	}
	return time.Since(time.Unix(0, last))
}

type relayResult struct {
	direction string
	bytes     int64
	duration  time.Duration
	err       error
}

func (r relayResult) reason() string {
	if r.err == nil || errors.Is(r.err, io.EOF) {
		return "eof"
	}
	return r.err.Error()
}

func (r relayResult) cleanEOF() bool {
	return r.err == nil || errors.Is(r.err, io.EOF)
}

type closeWriteConn interface {
	CloseWrite() error
}

// closeWrite forwards a client-side TCP FIN to the remote peer without closing
// the still-active download lane. This is important for Java/IntelliJ HTTP
// CONNECT downloads: some clients finish the upload side first and still expect
// the response body to drain cleanly instead of seeing a premature EOF.
func closeWrite(c net.Conn) error {
	if cw, ok := c.(closeWriteConn); ok {
		return cw.CloseWrite()
	}
	return errors.New("CloseWrite unsupported")
}

// relay copies a CONNECT/SOCKS5 tunnel in both directions.
//
// Important behavior:
//   - No per-direction idle timeout is allowed to close the tunnel.
//   - A clean Browser->Remote EOF is treated as upload completion only; the
//     Remote->Browser lane is allowed to keep draining the download body.
//   - Remote->Browser completion/error, non-EOF upload errors, or shared tunnel
//     idle timeout still close both sockets to unblock the opposite lane.
func relay(id uint32, label, host string, client net.Conn, clientReader io.Reader, remote net.Conn, requestStarted time.Time) {
	tr, done := registerRoutine("relay", id, host)
	defer done()
	if tr != nil {
		tr.setState("open")
	}

	activeRelays.Add(1)
	defer activeRelays.Add(-1)

	start := time.Now()
	activity := newRelayActivity()
	doneCh := make(chan relayResult, 2)

	logf("REQ-%05d | TUNNEL | open %s %s", id, label, host)

	// Lane 1: Browser -> Remote (Upload). It may finish before the download lane
	// for Java/IntelliJ CONNECT downloads. A clean EOF must not hard-close the
	// remote-to-client response path.
	goTracked("relay-upload", id, host, func(lane *trackedRoutine) {
		doneCh <- copyStreaming(remote, clientReader, remote, client, activity, "Browser->Remote", lane, nil)
	})

	// Lane 2: Remote -> Browser (Download).
	goTracked("relay-download", id, host, func(lane *trackedRoutine) {
		doneCh <- copyStreaming(client, remote, client, remote, activity, "Remote->Browser", lane, func() {
			logf("REQ-%05d | FIRST  | %s %s dur=%v", id, label, host, time.Since(requestStarted).Truncate(time.Millisecond))
		})
	})

	if tr != nil {
		tr.setState("wait lanes")
	}

	doneCount := 0
	closed := false
	closeReason := "both-lanes-done"
	ticker := time.NewTicker(relayWatchdogInterval)
	defer ticker.Stop()

	closeBoth := func(reason string) {
		if closed {
			return
		}
		closed = true
		closeReason = reason
		if tr != nil {
			tr.setState("closing: " + reason)
		}
		_ = client.Close()
		_ = remote.Close()
	}

	for doneCount < 2 {
		select {
		case res := <-doneCh:
			doneCount++
			logf("REQ-%05d | TUNNEL | lane-done %s %s dir=%s bytes=%d dur=%v rate_bps=%d reason=%s",
				id, label, host, res.direction, res.bytes, res.duration.Truncate(time.Millisecond), bytesPerSecond(res.bytes, res.duration), res.reason())

			if res.direction == "Browser->Remote" && res.cleanEOF() && !closed {
				if tr != nil {
					tr.setState("upload eof; drain download")
				}
				if err := closeWrite(remote); err != nil {
					logf("REQ-%05d | TUNNEL | upload-eof %s %s closewrite=skip reason=%v",
						id, label, host, err)
				} else {
					logf("REQ-%05d | TUNNEL | upload-eof %s %s remote-write-closed; draining download",
						id, label, host)
				}
				continue
			}

			// Remote->Browser completion means the response body is done. A non-EOF
			// upload error means the client side is no longer reliable. In both cases,
			// close both sockets and drain the remaining lane result.
			closeBoth(res.reason())

		case <-ticker.C:
			idle := activity.idleFor()
			if idle >= tunnelIdleTimeout {
				logf("REQ-%05d | TUNNEL | idle-timeout %s %s idle=%v", id, label, host, idle.Truncate(time.Second))
				closeBoth("shared-idle-timeout")
			}
		}
	}

	logf("REQ-%05d | TUNNEL | closed %s %s dur=%v reason=%s",
		id, label, host, time.Since(start).Truncate(time.Millisecond), closeReason)
}

func writeFull(dst io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := dst.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// copyStreaming forwards bytes for one tunnel direction. It intentionally does
// not set per-lane read deadlines. Actual tunnel lifetime is controlled by
// relay() using shared activity across both lanes; the watchdog closes the raw
// sockets to unblock these reads.
func bytesPerSecond(bytes int64, duration time.Duration) int64 {
	if bytes <= 0 || duration <= 0 {
		return 0
	}
	return int64(float64(bytes) / duration.Seconds())
}

func copyStreaming(dst io.Writer, src io.Reader, rawDst net.Conn, rawSrc net.Conn, activity *relayActivity, direction string, tr *trackedRoutine, onFirstData func()) relayResult {
	buf := make([]byte, 4096)
	started := time.Now()
	var total int64
	firstData := true

	if tr != nil {
		tr.setState("read " + direction)
	}

	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			if firstData {
				firstData = false
				if onFirstData != nil {
					onFirstData()
				}
			}
			activity.touch()
			if tr != nil {
				tr.setState("write " + direction)
			}
			_ = rawDst.SetWriteDeadline(time.Now().Add(tunnelIdleTimeout))
			if err := writeFull(dst, buf[:nr]); err != nil {
				if tr != nil {
					tr.setState("write error: " + err.Error())
				}
				return relayResult{direction: direction, bytes: total, duration: time.Since(started), err: err}
			}
			total += int64(nr)
			activity.touch()
			if tr != nil {
				tr.addBytes(nr)
				tr.setState("read " + direction)
			}
		}

		if rerr != nil {
			if tr != nil {
				tr.setState("done: " + rerr.Error())
			}
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
		if strings.HasPrefix(lo, "proxy-connection:") ||
			strings.HasPrefix(lo, "proxy-authorization:") ||
			strings.HasPrefix(lo, "connection:") ||
			strings.HasPrefix(lo, "keep-alive:") {
			continue
		}
		out = append(out, line)
	}
	// Plain HTTP proxying is one-request-per-connection in splice-proxy. Force
	// origin close so copyBuffered() can finish deterministically instead of
	// waiting on server keep-alive behavior.
	out = append(out, "Connection: close")
	result := strings.Join(out, "\r\n") + "\r\n\r\n"
	if len(body) > 0 {
		return append([]byte(result), body...)
	}
	return []byte(result)
}

// ─── HTTP proxy handler ───────────────────────────────────────────────────────
func handleHTTP(r *Resolver, client net.Conn, id uint32, tr *trackedRoutine) {
	defer client.Close()
	activeHTTPHandlers.Add(1)
	defer activeHTTPHandlers.Add(-1)
	requestStarted := time.Now()
	if tr != nil {
		tr.setState("read request")
	}

	// FIX: Prevent speculative pre-connections from freezing the proxy
	_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
	raw, leftover, err := readRequest(client)
	_ = client.SetReadDeadline(time.Time{}) // Disable deadline so the tunnel takes over
	if err != nil {
		return
	}

	method, host := parseMethodHost(raw)
	if tr != nil {
		tr.setHost(host)
		tr.setState("outbound dial")
	}
	logf("REQ-%05d | HTTP   | %s %s", id, method, host)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	remote, err := r.DialHostPort(ctx, id, host)
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
		if tr != nil {
			tr.setState("relay")
		}
		if err := writeFull(client, []byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
			remote.Close()
			return
		}

		// Stitch the swallowed handshake bytes back to the front of the socket
		var clientReader io.Reader = client
		if len(leftover) > 0 {
			clientReader = io.MultiReader(bytes.NewReader(leftover), client)
		}

		relay(id, "HTTP", host, client, clientReader, remote, requestStarted)
	} else {
		if err := writeFull(remote, cleanRequest(raw)); err != nil {
			logf("REQ-%05d | ERR    | plain-http request write %s: %v", id, host, err)
			remote.Close()
			return
		}
		copyStarted := time.Now()
		n, err := copyBuffered(client, remote, func() {
			logf("REQ-%05d | FIRST  | HTTP %s dur=%v", id, host, time.Since(requestStarted).Truncate(time.Millisecond))
		})
		copyDuration := time.Since(copyStarted)
		remote.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			logf("REQ-%05d | ERR    | plain-http response copy %s bytes=%d dur=%v rate_bps=%d: %v",
				id, host, n, copyDuration.Truncate(time.Millisecond), bytesPerSecond(n, copyDuration), err)
			return
		}
		logf("REQ-%05d | DONE   | %s bytes=%d dur=%v rate_bps=%d",
			id, host, n, copyDuration.Truncate(time.Millisecond), bytesPerSecond(n, copyDuration))
	}
}

// ─── SOCKS5 handler ───────────────────────────────────────────────────────────

func readFull(c net.Conn, buf []byte) error {
	_, err := io.ReadFull(c, buf)
	return err
}

func writeSOCKS5Reply(client net.Conn, rep byte) error {
	// VER, REP, RSV, ATYP, BND.ADDR=0.0.0.0, BND.PORT=0
	return writeFull(client, []byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func handleSOCKS5(r *Resolver, client net.Conn, id uint32, tr *trackedRoutine) {
	defer client.Close()
	activeSOCKSHandlers.Add(1)
	defer activeSOCKSHandlers.Add(-1)
	requestStarted := time.Now()
	if tr != nil {
		tr.setState("SOCKS handshake")
	}

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
		_ = writeFull(client, []byte{0x05, 0xFF})
		return
	}
	if err := writeFull(client, []byte{0x05, 0x00}); err != nil {
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
		_ = writeSOCKS5Reply(client, 0x07)
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
		// Keep host unbracketed. net.JoinHostPort() adds brackets for IPv6.
		// The old code pre-bracketed IPv6 and produced invalid targets like
		// [[2607:f8b0:...]]:443, which breaks Firefox SOCKS5 when local DNS
		// returns an IPv6 address for Gmail.
		host = net.IP(addr).String()
	default:
		_ = writeSOCKS5Reply(client, 0x08)
		return
	}

	portBuf := make([]byte, 2)
	if err := readFull(client, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// The SOCKS request is fully read. Clear the handshake deadline before the
	// outbound WG/netstack dial, otherwise a slow dial can leave an expired client
	// read deadline behind for the TLS relay.
	_ = client.SetReadDeadline(time.Time{})

	logf("REQ-%05d | SOCKS5 | CONNECT %s", id, target)
	if tr != nil {
		tr.setHost(target)
		tr.setState("outbound dial")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	remote, err := r.DialHostPort(ctx, id, target)
	cancel()
	if err != nil {
		logf("REQ-%05d | ERR    | SOCKS5 dial %s: %v", id, target, err)
		_ = writeSOCKS5Reply(client, 0x05)
		return
	}

	// Apply Keep-Alives to the remote side
	tuneTCP(remote)

	// Success reply (bind addr/port = 0)
	if err := writeSOCKS5Reply(client, 0x00); err != nil {
		remote.Close()
		return
	}

	// Disable deadline right before handing off to the relay
	_ = client.SetReadDeadline(time.Time{})
	// SOCKS5 doesn't swallow bytes, so we pass the `client` socket twice
	// (once as the raw socket, once as the io.Reader)
	if tr != nil {
		tr.setState("relay")
	}
	relay(id, "SOCKS5", target, client, client, remote, requestStarted)
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
		id := nextReqID()
		goTracked("http-handler", id, c.RemoteAddr().String(), func(tr *trackedRoutine) { handleHTTP(r, c, id, tr) })
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
		id := nextReqID()
		goTracked("socks5-handler", id, c.RemoteAddr().String(), func(tr *trackedRoutine) { handleSOCKS5(r, c, id, tr) })
	}
}

// ─── Diagnostics ──────────────────────────────────────────────────────────────
//
// Two loops, both observation-only:
//
//   diagLoop         — every 60s, logs goroutine count, active relays,
//                      DNS cache size, WG last-handshake age, WG rx/tx delta.
//   tunnelHealthLoop — every 5 min, independently probes ICMP, tunnel DNS,
//                      TCP, and a small HTTPS response through WireGuard.
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
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)

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

		logf("SYS | DIAG  | goroutines=%d http=%d socks5=%d dials=%d relays=%d dns_cache=%d heap=%d heap_sys=%d gc=%d gc_pause_last_ns=%d wg_hs_age=%s wg_rx_delta=%d wg_tx_delta=%d",
			runtime.NumGoroutine(),
			activeHTTPHandlers.Load(),
			activeSOCKSHandlers.Load(),
			activeDials.Load(),
			activeRelays.Load(),
			resolver.cache.size(),
			mem.HeapAlloc,
			mem.HeapSys,
			mem.NumGC,
			latestGCPause(&mem),
			hsAge,
			dRx, dTx,
		)
	}
}

func latestGCPause(mem *runtime.MemStats) uint64 {
	if mem.NumGC == 0 {
		return 0
	}
	return mem.PauseNs[(mem.NumGC+255)%256]
}

type healthResult struct {
	At       time.Time
	OK       bool
	Duration time.Duration
	Detail   string
	Streak   int
}

var healthResults = struct {
	sync.Mutex
	items map[string]healthResult
}{items: make(map[string]healthResult)}

func recordHealth(layer string, started time.Time, err error, detail string) {
	result := healthResult{At: time.Now(), OK: err == nil, Duration: time.Since(started), Detail: detail}
	if err != nil {
		result.Detail = detail + " error=" + err.Error()
	}
	healthResults.Lock()
	if err != nil {
		result.Streak = healthResults.items[layer].Streak + 1
	}
	healthResults.items[layer] = result
	healthResults.Unlock()
	status := "OK"
	if err != nil {
		status = "FAIL"
	}
	logf("SYS | HEALTH| layer=%s result=%s streak=%d dur=%v detail=%s",
		layer, status, result.Streak, result.Duration.Truncate(time.Millisecond), result.Detail)
	if result.Streak == 3 {
		logf("SYS | ALERT | health layer %s failed 3 consecutive times", layer)
	}
}

func snapshotHealth() map[string]healthResult {
	healthResults.Lock()
	defer healthResults.Unlock()
	out := make(map[string]healthResult, len(healthResults.items))
	for k, v := range healthResults.items {
		out[k] = v
	}
	return out
}

// tunnelHealthLoop independently probes ICMP, tunnel DNS, TCP, and HTTPS once
// after startup and every 5 minutes. It reports failures but never rebuilds or
// restarts the tunnel automatically.
func tunnelHealthLoop(tnet *netstack.Net, resolver *Resolver) {
	const (
		interval  = 5 * time.Minute
		probeHost = "one.one.one.one"
		probePort = "443"
	)

	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		<-timer.C

		started := time.Now()
		_, pingErr := debugPingOnce(tnet, "1.1.1.1", 2*time.Second)
		recordHealth("wireguard-icmp", started, pingErr, "1.1.1.1")

		started = time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		addrs, dnsErr := resolver.resolverForGo().LookupHost(ctx, probeHost)
		cancel()
		if dnsErr == nil {
			addrs = resolver.orderResolvedAddrs(addrs)
		}
		recordHealth("wireguard-dns", started, dnsErr, fmt.Sprintf("%s -> %v", probeHost, addrs))

		if dnsErr == nil && len(addrs) > 0 {
			addr := net.JoinHostPort(addrs[0], probePort)
			started = time.Now()
			ctx, cancel = context.WithTimeout(context.Background(), 8*time.Second)
			conn, tcpErr := tnet.DialContext(ctx, "tcp", addr)
			cancel()
			if conn != nil {
				_ = conn.Close()
			}
			recordHealth("wireguard-tcp", started, tcpErr, addr)

			started = time.Now()
			httpsErr := probeHTTPS(tnet, addr, probeHost)
			recordHealth("wireguard-https", started, httpsErr, probeHost)
		} else {
			err := dnsErr
			if err == nil {
				err = errors.New("DNS returned no usable addresses")
			}
			recordHealth("wireguard-tcp", time.Now(), err, probeHost)
			recordHealth("wireguard-https", time.Now(), err, probeHost)
		}

		timer.Reset(interval)
	}
}

func probeHTTPS(tnet *netstack.Net, addr, serverName string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	raw, err := tnet.DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
	tlsConn := tls.Client(raw, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return err
	}
	if err := writeFull(tlsConn, []byte("HEAD / HTTP/1.1\r\nHost: "+serverName+"\r\nConnection: close\r\n\r\n")); err != nil {
		return err
	}
	line, err := bufio.NewReader(tlsConn).ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "HTTP/") {
		return fmt.Errorf("unexpected response %q", strings.TrimSpace(line))
	}
	return nil
}

// ─── Debug console and ICMP ping (opt-in) ────────────────────────────────────

var debugPingSeq atomic.Uint32

type debugPingResult struct {
	Target string
	Seq    uint16
	Bytes  int
	RTT    time.Duration
	TTL    int // -1 means unavailable from gVisor ping4 endpoint
}

func (r debugPingResult) StandardLine() string {
	ttl := ""
	if r.TTL >= 0 {
		ttl = fmt.Sprintf(" ttl=%d", r.TTL)
	}
	return fmt.Sprintf("%d bytes from %s: icmp_seq=%d%s time=%v",
		r.Bytes, r.Target, r.Seq, ttl, r.RTT.Truncate(time.Millisecond))
}

func icmpChecksum(b []byte) uint16 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b[:2]))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for (sum >> 16) != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildICMPEchoRequest(id, seq uint16, payload []byte) []byte {
	pkt := make([]byte, 8+len(payload))
	pkt[0] = 8 // ICMPv4 Echo Request
	pkt[1] = 0 // code
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], seq)
	copy(pkt[8:], payload)
	binary.BigEndian.PutUint16(pkt[2:4], icmpChecksum(pkt))
	return pkt
}

func parseICMPEchoReply(pkt []byte) (id, seq uint16, payload []byte, err error) {
	if len(pkt) < 8 {
		return 0, 0, nil, fmt.Errorf("short icmp reply: %d bytes", len(pkt))
	}
	if pkt[0] != 0 || pkt[1] != 0 {
		return 0, 0, nil, fmt.Errorf("unexpected icmp type=%d code=%d", pkt[0], pkt[1])
	}
	return binary.BigEndian.Uint16(pkt[4:6]), binary.BigEndian.Uint16(pkt[6:8]), pkt[8:], nil
}

// debugPingOnce sends one lightweight ICMP Echo Request through the embedded
// gVisor/WireGuard netstack. The ping4 endpoint expects a full ICMP packet,
// not an arbitrary payload.
func debugPingOnce(tnet *netstack.Net, target string, timeout time.Duration) (debugPingResult, error) {
	var zero debugPingResult
	c, err := tnet.Dial("ping4", target)
	if err != nil {
		return zero, err
	}
	defer c.Close()

	seq := uint16(debugPingSeq.Add(1))
	id := uint16(os.Getpid())
	payload := []byte(fmt.Sprintf("splice-proxy-%d", time.Now().UnixNano()))
	request := buildICMPEchoRequest(id, seq, payload)

	_ = c.SetReadDeadline(time.Now().Add(timeout))
	start := time.Now()
	if _, err := c.Write(request); err != nil {
		return zero, err
	}

	reply := make([]byte, 1500)
	n, err := c.Read(reply)
	if err != nil {
		return zero, err
	}
	rtt := time.Since(start)
	replyID, replySeq, replyPayload, err := parseICMPEchoReply(reply[:n])
	if err != nil {
		return zero, err
	}
	// gVisor's ping endpoint may own/rewrite the ICMP identifier internally,
	// so do not treat an identifier mismatch as failure. The sequence number plus
	// our unique timestamp payload is enough to prove this reply belongs to this
	// probe.
	if replySeq != seq || !bytes.Equal(replyPayload, payload) {
		return zero, fmt.Errorf("unexpected icmp reply id=%d seq=%d len=%d expected_seq=%d expected_len=%d",
			replyID, replySeq, len(replyPayload), seq, len(payload))
	}
	return debugPingResult{Target: target, Seq: replySeq, Bytes: len(replyPayload), RTT: rtt, TTL: -1}, nil
}

func debugPingLoop(tnet *netstack.Net) {
	const (
		interval = 5 * time.Second
		target   = "1.1.1.1"
		timeout  = 2 * time.Second
	)
	t := time.NewTicker(interval)
	defer t.Stop()
	failStreak := 0
	for range t.C {
		res, err := debugPingOnce(tnet, target, timeout)
		if err != nil {
			failStreak++
			logf("SYS | PING  | Request timeout for icmp_seq=%d target=%s streak=%d err=%v", debugPingSeq.Load(), target, failStreak, err)
			continue
		}
		if failStreak > 0 {
			logf("SYS | PING  | %s recovered_after=%d", res.StandardLine(), failStreak)
		} else {
			logf("SYS | PING  | %s", res.StandardLine())
		}
		failStreak = 0
	}
}

func printSummary(dev *device.Device, resolver *Resolver) {
	s := readWGStats(dev)
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	hsAge := "never"
	if s.lastHandshakeUnix != 0 {
		hsAge = time.Since(time.Unix(s.lastHandshakeUnix, 0)).Truncate(time.Second).String()
	}
	fmt.Printf("goroutines=%d http=%d socks5=%d dials=%d relays=%d tracked=%d dns_cache=%d heap=%d heap_sys=%d gc=%d gc_pause_last_ns=%d wg_hs_age=%s wg_rx=%d wg_tx=%d\n",
		runtime.NumGoroutine(), activeHTTPHandlers.Load(), activeSOCKSHandlers.Load(), activeDials.Load(),
		activeRelays.Load(), len(snapshotRoutines()), resolver.cache.size(), mem.HeapAlloc, mem.HeapSys,
		mem.NumGC, latestGCPause(&mem), hsAge, s.rxBytes, s.txBytes)
}

func printRoutines() {
	now := time.Now()
	items := snapshotRoutines()
	fmt.Printf("%-4s %-19s %-9s %-9s %-16s %-9s %-12s %-24s %s\n", "ID", "START", "AGE", "IDLE", "TYPE", "REQ", "BYTES", "STATE", "HOST")
	for _, it := range items {
		req := "-"
		if it.ReqID != 0 {
			req = fmt.Sprintf("REQ-%05d", it.ReqID)
		}
		fmt.Printf("%-4d %-19s %-9s %-9s %-16s %-9s %-12d %-24s %s\n",
			it.ID,
			it.Start.Format("2006-01-02 15:04:05"),
			now.Sub(it.Start).Truncate(time.Second),
			now.Sub(it.Last).Truncate(time.Second),
			it.Name,
			req,
			it.Bytes,
			it.State,
			it.Host,
		)
	}
}

func writeGoroutineDump() error {
	name := "goroutines-" + time.Now().Format("20060102-150405") + ".txt"
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := fmt.Fprintf(f, "splice-proxy goroutine dump at %s\n\n", time.Now().Format(time.RFC3339)); err != nil {
		return err
	}
	if err := pprof.Lookup("goroutine").WriteTo(f, 2); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", name)
	return nil
}

func writeDiagnosticSnapshot(dev *device.Device, resolver *Resolver) error {
	name := "diagnostic-" + time.Now().Format("20060102-150405") + ".txt"
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	defer f.Close()

	now := time.Now()
	s := readWGStats(dev)
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)
	hsAge := "never"
	if s.lastHandshakeUnix != 0 {
		hsAge = time.Since(time.Unix(s.lastHandshakeUnix, 0)).Truncate(time.Second).String()
	}
	fmt.Fprintf(f, "splice-proxy diagnostic snapshot at %s\n\n", now.Format(time.RFC3339))
	fmt.Fprintf(f, "runtime goroutines=%d http=%d socks5=%d dials=%d relays=%d tracked=%d\n",
		runtime.NumGoroutine(), activeHTTPHandlers.Load(), activeSOCKSHandlers.Load(), activeDials.Load(), activeRelays.Load(), len(snapshotRoutines()))
	fmt.Fprintf(f, "memory heap_alloc=%d heap_sys=%d stack_inuse=%d num_gc=%d gc_pause_last_ns=%d\n",
		mem.HeapAlloc, mem.HeapSys, mem.StackInuse, mem.NumGC, latestGCPause(&mem))
	fmt.Fprintf(f, "network dns_cache=%d wg_hs_age=%s wg_rx=%d wg_tx=%d\n\n",
		resolver.cache.size(), hsAge, s.rxBytes, s.txBytes)

	fmt.Fprintln(f, "health:")
	health := snapshotHealth()
	layers := make([]string, 0, len(health))
	for layer := range health {
		layers = append(layers, layer)
	}
	sort.Strings(layers)
	for _, layer := range layers {
		result := health[layer]
		fmt.Fprintf(f, "  %s at=%s ok=%v streak=%d dur=%v detail=%s\n",
			layer, result.At.Format(time.RFC3339), result.OK, result.Streak, result.Duration.Truncate(time.Millisecond), result.Detail)
	}

	fmt.Fprintln(f, "\nroutines:")
	for _, it := range snapshotRoutines() {
		fmt.Fprintf(f, "  id=%d req=%d type=%s host=%s start=%s age=%v idle=%v bytes=%d state=%s\n",
			it.ID, it.ReqID, it.Name, it.Host, it.Start.Format(time.RFC3339),
			now.Sub(it.Start).Truncate(time.Second), now.Sub(it.Last).Truncate(time.Second), it.Bytes, it.State)
	}

	fmt.Fprintln(f, "\ngoroutines:")
	if err := pprof.Lookup("goroutine").WriteTo(f, 2); err != nil {
		return err
	}
	fmt.Printf("wrote %s\n", name)
	return nil
}

func printRouteAndSystemHosts(resolver *Resolver) {
	rules := resolver.routes.Load()
	if rules == nil {
		fmt.Println("routes: unavailable")
	} else {
		entries := make([]string, 0, len(rules.exact)+len(rules.prefixes)+len(rules.wildcards))
		for pattern, action := range rules.exact {
			entries = append(entries, fmt.Sprintf("%s -> %s", pattern, action))
		}
		for _, rule := range rules.prefixes {
			entries = append(entries, fmt.Sprintf("%s -> %s", rule.pattern, rule.action))
		}
		for _, rule := range rules.wildcards {
			if rule.explicit {
				entries = append(entries, fmt.Sprintf("%s -> %s", rule.pattern, rule.action))
			}
		}
		sort.Strings(entries)
		fmt.Printf("routes: default -> %s, rules=%d\n", rules.defaultAction, len(entries))
		for _, entry := range entries {
			fmt.Printf("  %s\n", entry)
		}
	}

	resolver.systemHostsMu.RLock()
	hosts := make([]string, 0, len(resolver.systemHosts))
	for host := range resolver.systemHosts {
		hosts = append(hosts, host)
	}
	resolver.systemHostsMu.RUnlock()
	sort.Strings(hosts)
	fmt.Printf("system hosts: names=%d source=%s\n", len(hosts), systemHostsFilePath())
	for _, host := range hosts {
		fmt.Printf("  %s\n", host)
	}
}

func debugConsoleLoop(tnet *netstack.Net, dev *device.Device, resolver *Resolver) {
	fmt.Println("\nDebug console enabled. Commands: h=help, s=summary, l=route/hosts lists, r=routines, x=diagnostic snapshot, d=dump goroutines, p=ping now, q=exit now")
	sc := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("splice-proxy> ")
		if !sc.Scan() {
			return
		}
		cmd := strings.ToLower(strings.TrimSpace(sc.Text()))
		switch cmd {
		case "", "h", "help", "?":
			fmt.Println("Commands: s=summary, l=current route/system-host lists, r=routines with START/AGE/IDLE, x=diagnostic snapshot, d=write full goroutine dump, p=ICMP ping now, q=exit now")
		case "s", "summary":
			printSummary(dev, resolver)
		case "l", "lists":
			printRouteAndSystemHosts(resolver)
		case "r", "routines":
			printRoutines()
		case "d", "dump":
			if err := writeGoroutineDump(); err != nil {
				fmt.Printf("dump failed: %v\n", err)
			}
		case "x", "snapshot":
			if err := writeDiagnosticSnapshot(dev, resolver); err != nil {
				fmt.Printf("snapshot failed: %v\n", err)
			}
		case "p", "ping":
			res, err := debugPingOnce(tnet, "1.1.1.1", 2*time.Second)
			if err != nil {
				fmt.Printf("Request timeout for icmp_seq=%d target=1.1.1.1 err=%v\n", debugPingSeq.Load(), err)
			} else {
				fmt.Println(res.StandardLine())
			}
		case "q", "quit", "exit":
			logf("SYS | STOP  | debug console requested exit")
			os.Exit(0)
		default:
			fmt.Printf("unknown command %q; type h for help\n", cmd)
		}
	}
}

func parseArgs(args []string) bool {
	debugConsole := false
	for _, arg := range args {
		switch arg {
		case "--debug-console", "--console", "-debug-console":
			debugConsole = true
		case "--help", "-h":
			fmt.Println("usage: splice-proxy [--debug-console]")
			os.Exit(0)
		default:
			if strings.HasPrefix(arg, "-") {
				logf("SYS | WARN  | unknown option ignored: %s", arg)
			} else {
				logf("SYS | WARN  | positional config path ignored, using default config.ini: %s", arg)
			}
		}
	}
	return debugConsole
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	cfgPath := "config.ini"
	debugConsole := parseArgs(os.Args[1:])
	debugConsoleEnabled.Store(debugConsole)

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		logf("SYS | FATAL | config %s: %v", cfgPath, err)
		os.Exit(1)
	}

	logf("SYS | START | splice-proxy")
	logf("SYS | INFO  | config : %s", cfgPath)
	logf("SYS | INFO  | http   : %s", cfg.HTTPListen)
	logf("SYS | INFO  | socks5 : %s", cfg.SOCKS5Listen)
	logf("SYS | INFO  | wg peer: %s", cfg.WGPeerEndpoint)
	logf("SYS | INFO  | wg ip  : %v", cfg.WGLocalIPs)
	logf("SYS | INFO  | dns    : %v (cache=%v)", cfg.DNSServers, cfg.DNSCacheTTL)
	logf("SYS | INFO  | routing: default=%s rules=%d", cfg.DefaultRoute, len(cfg.Routes))
	logf("SYS | INFO  | route/hosts reload: %v", cfg.RouteReload)
	for host, action := range cfg.Routes {
		logf("SYS | INFO  |          %s -> %s", host, action)
	}
	if debugConsole {
		logf("SYS | INFO  | debug console enabled: stdin menu + tracked routine start times + 5s ICMP ping")
	}
	if len(cfg.HostOverrides) > 0 {
		logf("SYS | INFO  | hosts  : %d override(s) loaded", len(cfg.HostOverrides))
		for host, ip := range cfg.HostOverrides {
			logf("SYS | INFO  |         %s -> %s", host, ip)
		}
	}
	systemHostsPath := systemHostsFilePath()
	systemHosts, hostsErr := loadSystemHostnames(systemHostsPath)
	if hostsErr != nil {
		logf("SYS | WARN  | system hosts file unavailable (%s): %v", systemHostsPath, hostsErr)
	} else {
		logf("SYS | INFO  | system hosts: %d name(s) loaded from %s", len(systemHosts), systemHostsPath)
	}

	tnet, dev, err := setupWireGuard(cfg)
	if err != nil {
		logf("SYS | FATAL | wireguard: %v", err)
		os.Exit(1)
	}
	logf("SYS | READY | wireguard up")

	resolver := newResolver(tnet, cfg.DNSServers, cfg.DNSCacheTTL, cfg.HostOverrides, systemHosts, cfg.WGLocalIPs, cfg.DefaultRoute, cfg.Routes)
	logf("SYS | INFO  | ip mode: ipv4=%v ipv6=%v dns_order=ipv4-first", resolver.allowIPv4, resolver.allowIPv6)
	if cfg.RouteReload > 0 {
		goTracked("route-hosts-reload-loop", 0, cfgPath, func(tr *trackedRoutine) {
			reloadLoop(cfgPath, systemHostsPath, resolver, cfg.RouteReload)
		})
	}

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

	goTracked("http-accept", 0, cfg.HTTPListen, func(tr *trackedRoutine) { serveHTTP(httpLn, resolver) })
	goTracked("socks5-accept", 0, cfg.SOCKS5Listen, func(tr *trackedRoutine) { serveSOCKS5(socksLn, resolver) })
	goTracked("diag-loop", 0, "", func(tr *trackedRoutine) { diagLoop(dev, resolver) })
	goTracked("layered-health-loop", 0, "one.one.one.one:443", func(tr *trackedRoutine) { tunnelHealthLoop(tnet, resolver) })
	if debugConsole {
		goTracked("debug-ping-loop", 0, "1.1.1.1", func(tr *trackedRoutine) { debugPingLoop(tnet) })
		goTracked("debug-console", 0, "stdin", func(tr *trackedRoutine) { debugConsoleLoop(tnet, dev, resolver) })
	}

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
