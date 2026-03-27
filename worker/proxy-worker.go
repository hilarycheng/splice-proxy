package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"proxy/config"
	"proxy/rudp"
	"strings"
	"sync"
	"time"
)

var serverMuxAddr string

func init() {
	cfg := config.Load("config.ini")
	serverMuxAddr = config.Get(cfg, "worker.server_addr", "127.0.0.1:12347")
}

var lg = log.New(os.Stdout, "", 0)

func logf(format string, args ...interface{}) {
	lg.Printf(time.Now().Format("2006-01-02 15:04:05.000")+" | "+format, args...)
}

func cleanRequest(raw []byte) []byte {
	headerEnd := bytes.Index(raw, []byte("\r\n\r\n"))
	var body []byte
	if headerEnd >= 0 {
		body = raw[headerEnd+4:]
		raw = raw[:headerEnd+4]
	}
	lines := strings.Split(string(raw), "\r\n")
	if len(lines) == 0 {
		return append(raw, body...)
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
		// Leave Keep-Alive alone so SSE works, only strip proxy-specific headers
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
	nl := bytes.IndexByte(raw, '\n')
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

func copyBuffered(dst io.Writer, src io.Reader) (int64, error) {
	bp := rudp.CopyBufPool.Get().(*[]byte)
	n, err := io.CopyBuffer(dst, src, *bp)
	rudp.CopyBufPool.Put(bp)
	return n, err
}

func handleWorkerRequest(id uint32, s *rudp.Stream) {
	defer s.Close()

	raw, err := readRequest(s)
	if err != nil {
		return
	}

	method, host := parseMethodHost(raw)
	logf("REQ-%05d | REQ    | %s %s", id, method, host)

	remote, err := net.DialTimeout("tcp", host, 15*time.Second)
	if err != nil {
		s.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer remote.Close()

	if tc, ok := remote.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
	}

	if method == "CONNECT" {
		s.Write([]byte("HTTP/1.1 200 Connection Established\r\nProxy-Agent: GoProxy/1.0\r\n\r\n"))
		logf("REQ-%05d | TUNNEL | open %s", id, host)

		go func() {
			<-s.Done()
			remote.Close()
		}()

		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			copyBuffered(remote, s)
			if tc, ok := remote.(*net.TCPConn); ok {
				tc.CloseWrite()
			} else {
				remote.Close()
			}
		}()

		go func() {
			defer wg.Done()
			copyBuffered(s, remote)
			s.Close()
		}()

		wg.Wait()
		logf("REQ-%05d | TUNNEL | closed %s", id, host)
	} else {
		remote.Write(cleanRequest(raw))
		copyBuffered(s, remote)
		logf("REQ-%05d | DONE   | %s", id, host)
	}
}

func main() {
	logf("SYS | START | proxy-worker (Linux) via RUDP")
	logf("SYS | INFO  | server mux: %s", serverMuxAddr)

	serverAddr, err := net.ResolveUDPAddr("udp", serverMuxAddr)
	if err != nil {
		logf("SYS | FATAL | resolve: %v", err)
		os.Exit(1)
	}

	for {
		conn, err := net.DialUDP("udp", nil, serverAddr)
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		conn.SetReadBuffer(8 * 1024 * 1024)
		conn.SetWriteBuffer(8 * 1024 * 1024)

		m := rudp.NewMux(conn, false)
		m.OnStream = handleWorkerRequest

		for {
			m.SendHello()
			time.Sleep(5 * time.Second)
		}
	}
}
