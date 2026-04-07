package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"proxy/config"
	"proxy/rudp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const udpTimeout = 5 * time.Minute

var (
	proxyAddr     string
	socks5Addr    string
	muxAddr       string
	udpListenAddr string
	udpTargetAddr string
)

func loadConfig() {
	cfg := config.Load("config.ini")
	proxyAddr = config.Get(cfg, "server.http_proxy", "0.0.0.0:12346")
	socks5Addr = config.Get(cfg, "server.socks5_proxy", "0.0.0.0:12348")
	muxAddr = config.Get(cfg, "server.mux_listen", "0.0.0.0:12347")
	udpListenAddr = config.Get(cfg, "server.udp_listen", "0.0.0.0:12349")
	udpTargetAddr = config.Get(cfg, "server.udp_target", "")
}

var (
	lg      = log.New(os.Stdout, "", 0)
	reqIDCt atomic.Uint32
)

func logf(format string, args ...interface{}) {
	lg.Printf(time.Now().Format("2006-01-02 15:04:05.000")+" | "+format, args...)
}

func nextReqID() uint32 {
	for {
		id := reqIDCt.Add(1)
		if id != 0 {
			return id
		}
	}
}

// ─── HTTP proxy helpers ───────────────────────────────────────────────────────

func readRequest(rd io.Reader) ([]byte, error) {
	br := bufio.NewReaderSize(rd, 4096)
	var buf []byte
	var cLen int
	for {
		line, err := br.ReadString('\n')
		buf = append(buf, line...)
		if err != nil {
			return nil, err
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
			return nil, err
		}
		buf = append(buf, body...)
	}
	return buf, nil
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

// ─── Shared tunnel relay ──────────────────────────────────────────────────────

func copyBuffered(dst io.Writer, src io.Reader) (int64, error) {
	bp := rudp.CopyBufPool.Get().(*[]byte)
	n, err := io.CopyBuffer(dst, src, *bp)
	rudp.CopyBufPool.Put(bp)
	return n, err
}

func relay(id uint32, host string, client net.Conn, s *rudp.Stream) {
	logf("REQ-%05d | TUNNEL | open %s", id, host)

	go func() {
		<-s.Done()
		client.Close()
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		copyBuffered(client, s)
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		} else {
			client.Close()
		}
	}()

	go func() {
		defer wg.Done()
		copyBuffered(s, client)
		s.Close()
	}()

	wg.Wait()
	logf("REQ-%05d | TUNNEL | closed %s", id, host)
}

// ─── HTTP proxy handler ───────────────────────────────────────────────────────

func handleClient(m *rudp.Mux, client net.Conn) {
	defer client.Close()
	id := nextReqID()

	raw, err := readRequest(client)
	if err != nil {
		return
	}

	method, host := parseMethodHost(raw)
	logf("REQ-%05d | REQ    | %s %s", id, method, host)

	s := m.OpenStream(id)
	defer s.Close()

	if _, err := s.Write(raw); err != nil {
		client.Write([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
		return
	}

	if method == "CONNECT" {
		buf := make([]byte, 1024)
		nr, err := s.Read(buf)
		if err != nil {
			return
		}
		client.Write(buf[:nr])
		if !strings.Contains(string(buf[:nr]), "200") {
			return
		}
		relay(id, host, client, s)
	} else {
		copyBuffered(client, s)
		logf("REQ-%05d | DONE   | %s", id, host)
	}
}

// ─── SOCKS5 handler ───────────────────────────────────────────────────────────

func readFull(conn net.Conn, buf []byte) error {
	_, err := io.ReadFull(conn, buf)
	return err
}

func handleSocks5Client(m *rudp.Mux, client net.Conn) {
	defer client.Close()
	id := nextReqID()

	hdr := make([]byte, 2)
	if err := readFull(client, hdr); err != nil {
		return
	}
	if hdr[0] != 0x05 {
		return
	}
	nMethods := int(hdr[1])
	methods := make([]byte, nMethods)
	if err := readFull(client, methods); err != nil {
		return
	}
	hasNoAuth := false
	for _, mt := range methods {
		if mt == 0x00 {
			hasNoAuth = true
			break
		}
	}
	if !hasNoAuth {
		client.Write([]byte{0x05, 0xFF})
		return
	}
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	req := make([]byte, 4)
	if err := readFull(client, req); err != nil {
		return
	}
	if req[0] != 0x05 {
		return
	}
	cmd := req[1]
	atyp := req[3]

	if cmd != 0x01 {
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var host string
	switch atyp {
	case 0x01:
		addr := make([]byte, 4)
		if err := readFull(client, addr); err != nil {
			return
		}
		host = net.IP(addr).String()
	case 0x03:
		lenBuf := make([]byte, 1)
		if err := readFull(client, lenBuf); err != nil {
			return
		}
		domainBuf := make([]byte, int(lenBuf[0]))
		if err := readFull(client, domainBuf); err != nil {
			return
		}
		host = string(domainBuf)
	case 0x04:
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
	target := fmt.Sprintf("%s:%d", host, port)

	logf("REQ-%05d | SOCKS5 | CONNECT %s", id, target)

	syntheticReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)

	s := m.OpenStream(id)
	defer s.Close()

	if _, err := s.Write([]byte(syntheticReq)); err != nil {
		client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	buf := make([]byte, 1024)
	nr, err := s.Read(buf)
	if err != nil || !strings.Contains(string(buf[:nr]), "200") {
		client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	relay(id, target, client, s)
}

// ─── UDP WireGuard forwarder ──────────────────────────────────────────────────

func listenUDP() {
	laddr, _ := net.ResolveUDPAddr("udp", udpListenAddr)
	raddr, _ := net.ResolveUDPAddr("udp", udpTargetAddr)
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		logf("UDP-FWD   | FATAL  | listen: %v", err)
		return
	}
	conn.SetReadBuffer(4 * 1024 * 1024)
	conn.SetWriteBuffer(4 * 1024 * 1024)

	var sessions sync.Map
	type session struct {
		tConn    *net.UDPConn
		lastUsed atomic.Int64
	}

	go func() {
		for {
			time.Sleep(time.Minute)
			now := time.Now().Unix()
			sessions.Range(func(key, value interface{}) bool {
				sess := value.(*session)
				if now-sess.lastUsed.Load() > int64(udpTimeout.Seconds()) {
					sess.tConn.Close()
					sessions.Delete(key)
					logf("UDP-FWD   | CLOSE  | %s", key)
				}
				return true
			})
		}
	}()

	buf := make([]byte, 65507)
	for {
		nr, cAddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		cKey := cAddr.String()
		var sess *session
		if val, ok := sessions.Load(cKey); ok {
			sess = val.(*session)
		} else {
			tConn, err := net.DialUDP("udp", nil, raddr)
			if err != nil {
				continue
			}
			sess = &session{tConn: tConn}
			sess.lastUsed.Store(time.Now().Unix())
			sessions.Store(cKey, sess)
			go func(a *net.UDPAddr, s *session) {
				rb := make([]byte, 65507)
				for {
					rn, err := s.tConn.Read(rb)
					if err != nil {
						return
					}
					s.lastUsed.Store(time.Now().Unix())
					conn.WriteToUDP(rb[:rn], a)
				}
			}(cAddr, sess)
		}
		sess.lastUsed.Store(time.Now().Unix())
		sess.tConn.Write(buf[:nr])
	}
}

// ─── Diagnostics ──────────────────────────────────────────────────────────────

func diagnosticsLoop(m *rudp.Mux) {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		logf("SYS | DIAG  | active_streams=%d", m.StreamCount.Load())
	}
}

// ─── Main ─────────────────────────────────────────────────────────────────────

func main() {
	loadConfig()

	muxUDPAddr, _ := net.ResolveUDPAddr("udp", muxAddr)
	muxConn, err := net.ListenUDP("udp", muxUDPAddr)
	if err != nil {
		logf("SYS | FATAL | listen mux: %v", err)
		os.Exit(1)
	}
	muxConn.SetReadBuffer(8 * 1024 * 1024)
	muxConn.SetWriteBuffer(8 * 1024 * 1024)

	m := rudp.NewMux(muxConn, true)

	logf("SYS | START | proxy-server")
	logf("SYS | INFO  | http  : %s (browser HTTP proxy)", proxyAddr)
	logf("SYS | INFO  | socks5: %s (SOCKS5 proxy)", socks5Addr)
	logf("SYS | INFO  | mux   : %s (Reliable UDP)", muxAddr)

	if udpTargetAddr != "" {
		logf("SYS | INFO  | udp   : %s → %s", udpListenAddr, udpTargetAddr)
		go listenUDP()
	} else {
		logf("SYS | INFO  | udp   : disabled (udp_target not set)")
	}

	go diagnosticsLoop(m)

	httpLn, err := net.Listen("tcp", proxyAddr)
	if err != nil {
		logf("SYS | FATAL | listen http: %v", err)
		os.Exit(1)
	}
	go func() {
		for {
			conn, err := httpLn.Accept()
			if err == nil {
				go handleClient(m, conn)
			}
			// FIX: Prevent Symantec/Windows from dropping idle sessions during AI "thinking"
			if tc, ok := conn.(*net.TCPConn); ok {
				tc.SetKeepAlive(true)
				tc.SetKeepAlivePeriod(10 * time.Second)
			}
		}
	}()

	socks5Ln, err := net.Listen("tcp", socks5Addr)
	if err != nil {
		logf("SYS | FATAL | listen socks5: %v", err)
		os.Exit(1)
	}
	logf("SYS | READY | http=%s socks5=%s", proxyAddr, socks5Addr)
	for {
		conn, err := socks5Ln.Accept()
		if err == nil {
			go handleSocks5Client(m, conn)
		}
	}
}
