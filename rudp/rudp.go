package rudp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	ChunkSize = 1200
	HdrSize   = 11

	MsgData        = uint8(0)
	MsgEOF         = uint8(1)
	MsgACK         = uint8(2) // Wire: [hdr 11] + [rwnd 4] = 15 bytes total
	MsgKeepAlive   = uint8(3)
	MsgWindowProbe = uint8(4) // Zero-window probe: sender asks receiver for fresh rwnd

	WindowSize = 256

	initialRTO     = 150 * time.Millisecond
	minRTO         = 20 * time.Millisecond
	maxRTO         = 3 * time.Second
	retransmitTick = 25 * time.Millisecond

	writeIdleTimeout = 10 * time.Minute

	chanSize = 4096

	maxBackoffShift = 5

	// Congestion control
	initialCwnd     = 8.0   // Slow start begins here
	initialSsthresh = 256.0 // First slow-start runs until loss or cap
	cwndFloor       = 4.0   // FIX #4: was 8.0 (same as initial — MD was a no-op). 4 is enough for recovery.
	ssthreshFloor   = 4.0   // FIX #4: match cwndFloor

	// Retransmit budget: max retransmits per stream per tick.
	// Bounds writeMu hold time under congestion.
	maxRetransmitsPerTick = 64

	// StreamIdleTimeout: a stream with no Read/Write/ACK activity for
	// this long is reaped by the Mux GC. 5 minutes is well above the
	// popNext polling interval, so normal idle-direction timeouts won't
	// trigger GC. Only truly abandoned streams are reaped.
	StreamIdleTimeout = 5 * time.Minute

	// streamGCInterval: how often the Mux scans for idle streams.
	streamGCInterval = 15 * time.Second
)

// ─── Buffer pools ─────────────────────────────────────────────────────────────

var sendBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, HdrSize+ChunkSize)
		return &b
	},
}

var legacySendPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, HdrSize+ChunkSize)
		return &b
	},
}

var payloadPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, ChunkSize)
		return &b
	},
}

var CopyBufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 32*1024)
		return &b
	},
}

func getPayload(size int) []byte {
	if size <= ChunkSize {
		bp := payloadPool.Get().(*[]byte)
		return (*bp)[:size]
	}
	return make([]byte, size)
}

func putPayload(b []byte) {
	if cap(b) >= ChunkSize {
		bp := b[:ChunkSize]
		payloadPool.Put(&bp)
	}
}

func putSendBuf(buf []byte) {
	b := buf[:cap(buf)]
	sendBufPool.Put(&b)
}

// ─── Packet types ─────────────────────────────────────────────────────────────

type sentPacket struct {
	frameID     uint32
	typ         uint8
	data        []byte // nil for EOF; headroom buf [hdr|payload] for Data
	sentAt      time.Time
	retransmits uint8
}

type frame struct {
	frameID uint32
	isEOF   bool
	payload []byte
}

// ─── Stream ───────────────────────────────────────────────────────────────────

type Stream struct {
	id uint32
	m  *Mux

	ch     chan frame
	nextRx uint32
	ooo    map[uint32]frame
	ready  []frame
	rxMu   sync.Mutex

	txSeq    uint32
	inFlight map[uint32]*sentPacket
	flightMu sync.Mutex
	flightCh chan struct{}

	// ── Congestion control (protected by flightMu) ──
	cwnd         float64   // Congestion window: path capacity estimate
	ssthresh     float64   // Slow start threshold
	rwnd         uint32    // Receiver window: last advertised by peer
	lastLossTime time.Time // FIX #3: track last MD event, one reduction per RTT

	srtt   time.Duration
	rttVar time.Duration
	rto    time.Duration
	rttMu  sync.Mutex

	unread []byte
	closed atomic.Bool

	lastActivity atomic.Int64

	done     chan struct{}
	doneOnce sync.Once
}

func newStream(id uint32, m *Mux) *Stream {
	s := &Stream{
		id:       id,
		m:        m,
		ch:       make(chan frame, chanSize),
		nextRx:   1,
		ooo:      make(map[uint32]frame),
		txSeq:    1,
		inFlight: make(map[uint32]*sentPacket),
		flightCh: make(chan struct{}, WindowSize),
		cwnd:     initialCwnd,
		ssthresh: initialSsthresh,
		rwnd:     chanSize, // Assume full capacity until peer advertises
		rto:      initialRTO,
		done:     make(chan struct{}),
	}
	s.touch()
	return s
}

func (s *Stream) touch() {
	s.lastActivity.Store(time.Now().UnixNano())
}

func (s *Stream) Done() <-chan struct{} {
	return s.done
}

func (s *Stream) getRTO() time.Duration {
	s.rttMu.Lock()
	rto := s.rto
	s.rttMu.Unlock()
	return rto
}

func (s *Stream) updateRTT(sample time.Duration) {
	s.rttMu.Lock()
	defer s.rttMu.Unlock()

	if s.srtt == 0 {
		s.srtt = sample
		s.rttVar = sample / 2
	} else {
		diff := s.srtt - sample
		if diff < 0 {
			diff = -diff
		}
		s.rttVar = (3*s.rttVar + diff) / 4
		s.srtt = (7*s.srtt + sample) / 8
	}
	s.rto = s.srtt + 4*s.rttVar
	if s.rto < minRTO {
		s.rto = minRTO
	}
	if s.rto > maxRTO {
		s.rto = maxRTO
	}
}

// effectiveWindow returns the sending window: min(cwnd, rwnd).
// FIX #1: always returns at least 1 — TCP persist semantics.
// A zero window must never prevent the sender from having at least one
// packet in flight, otherwise the zero-window deadlock occurs: sender
// blocks, no data flows, receiver never drains, rwnd stays 0 forever.
// Caller must hold flightMu.
func (s *Stream) effectiveWindow() int {
	cw := int(s.cwnd)
	rw := int(s.rwnd)
	w := cw
	if rw < w {
		w = rw
	}
	if w < 1 {
		w = 1
	}
	return w
}

// calcRwnd computes the receiver window: how many more frames we can accept.
// Caller must hold rxMu (for ooo and ready) but ch length is a snapshot.
func (s *Stream) calcRwnd() uint32 {
	used := len(s.ch) + len(s.ooo) + len(s.ready)
	avail := chanSize - used
	if avail < 0 {
		avail = 0
	}
	return uint32(avail)
}

func (s *Stream) Read(p []byte) (int, error) {
	if len(s.unread) > 0 {
		n := copy(p, s.unread)
		s.unread = s.unread[n:]
		s.touch()
		return n, nil
	}
	f, ok := s.popNext(StreamIdleTimeout)
	if !ok || f.isEOF {
		return 0, io.EOF
	}
	n := copy(p, f.payload)
	if n < len(f.payload) {
		s.unread = f.payload[n:]
	} else {
		putPayload(f.payload)
	}
	s.touch()
	return n, nil
}

func (s *Stream) Write(p []byte) (int, error) {
	if s.closed.Load() {
		return 0, io.EOF
	}

	total := len(p)
	data := p

	idle := time.NewTimer(writeIdleTimeout)
	defer idle.Stop()

	wait := time.NewTimer(0)
	if !wait.Stop() {
		<-wait.C
	}
	defer wait.Stop()

	// FIX #2: window probe timer — if blocked on zero-window, actively
	// probe the receiver instead of relying on retransmit loop (which
	// only probes when there are expired inFlight packets).
	probe := time.NewTimer(0)
	if !probe.Stop() {
		<-probe.C
	}
	defer probe.Stop()
	probeArmed := false

	for len(data) > 0 {
		c := len(data)
		if c > ChunkSize {
			c = ChunkSize
		}

		bp := sendBufPool.Get().(*[]byte)
		buf := (*bp)[:HdrSize+c]
		copy(buf[HdrSize:], data[:c])

		s.flightMu.Lock()
		for len(s.inFlight) >= s.effectiveWindow() {
			// FIX #2: arm window probe if rwnd is zero
			if s.rwnd == 0 && !probeArmed {
				rto := s.getRTO()
				if rto < 200*time.Millisecond {
					rto = 200 * time.Millisecond
				}
				probe.Reset(rto)
				probeArmed = true
			}
			s.flightMu.Unlock()

			wait.Reset(5 * time.Second)

			select {
			case <-s.flightCh:
				if !wait.Stop() {
					select {
					case <-wait.C:
					default:
					}
				}
			case <-wait.C:
				// keep trying, idle catches true stalls
			case <-probe.C:
				// FIX #2: send window probe and re-arm
				probeArmed = false
				s.m.sendRaw(s.id, 0, MsgWindowProbe, nil)
				s.touch() // keep stream alive while probing
			case <-idle.C:
				putSendBuf(*bp)
				return 0, fmt.Errorf("write timeout: no progress for %v", writeIdleTimeout)
			case <-s.done:
				putSendBuf(*bp)
				return 0, io.EOF
			}

			s.flightMu.Lock()
		}

		// Window opened — disarm probe if armed
		if probeArmed {
			if !probe.Stop() {
				select {
				case <-probe.C:
				default:
				}
			}
			probeArmed = false
		}

		fid := s.txSeq
		s.txSeq++
		s.inFlight[fid] = &sentPacket{
			frameID: fid,
			typ:     MsgData,
			data:    buf,
			sentAt:  time.Now(),
		}
		s.flightMu.Unlock()

		s.m.sendRawHeadroom(s.id, fid, MsgData, buf)
		s.touch()

		// Packet pacing: yield briefly to OS to prevent WSL UDP buffer
		// overflow. On a localhost UDP path with sub-millisecond RTT,
		// the sender can blast packets faster than the kernel can flush
		// them, causing silent local drops. This is not a substitute for
		// cwnd — it's an OS-level workaround that cwnd cannot replace.
		time.Sleep(50 * time.Microsecond)

		if !idle.Stop() {
			select {
			case <-idle.C:
			default:
			}
		}
		idle.Reset(writeIdleTimeout)

		data = data[c:]
	}
	return total, nil
}

func (s *Stream) Close() error {
	if s.closed.CompareAndSwap(false, true) {
		s.flightMu.Lock()
		fid := s.txSeq
		s.txSeq++
		s.inFlight[fid] = &sentPacket{frameID: fid, typ: MsgEOF, data: nil, sentAt: time.Now()}
		s.flightMu.Unlock()
		s.m.sendRaw(s.id, fid, MsgEOF, nil)

		go func() {
			deadline := time.After(5 * time.Second)
			tick := time.NewTicker(100 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-tick.C:
					s.flightMu.Lock()
					empty := len(s.inFlight) == 0
					s.flightMu.Unlock()
					if empty {
						s.m.closeStream(s.id)
						return
					}
				case <-deadline:
					s.m.closeStream(s.id)
					return
				}
			}
		}()
	}
	return nil
}

func (s *Stream) drainOOO() {
	for {
		f, ok := s.ooo[s.nextRx]
		if !ok {
			break
		}
		delete(s.ooo, s.nextRx)
		s.nextRx++
		s.ready = append(s.ready, f)
	}
}

func (s *Stream) popNext(timeout time.Duration) (frame, bool) {
	s.rxMu.Lock()

	if len(s.ready) > 0 {
		f := s.ready[0]
		copy(s.ready, s.ready[1:])
		s.ready = s.ready[:len(s.ready)-1]
		s.rxMu.Unlock()
		return f, true
	}

	if f, ok := s.ooo[s.nextRx]; ok {
		delete(s.ooo, s.nextRx)
		s.nextRx++
		s.drainOOO()
		s.rxMu.Unlock()
		return f, true
	}
	s.rxMu.Unlock()

	checkInterval := 15 * time.Second
	timer := time.NewTimer(checkInterval)
	defer timer.Stop()

	for {
		select {
		case f, ok := <-s.ch:
			if !ok {
				return frame{}, false
			}

			s.rxMu.Lock()
			if f.frameID == s.nextRx {
				s.nextRx++
				s.drainOOO()
				s.rxMu.Unlock()
				return f, true
			}
			if f.frameID > s.nextRx {
				// Safely overwrite duplicates to prevent memory leaks
				if existing, exists := s.ooo[f.frameID]; exists {
					if existing.payload != nil {
						putPayload(existing.payload)
					}
				}

				// Only buffer if we have room. If full, drop it safely instead of killing the stream.
				if len(s.ooo) < chanSize {
					s.ooo[f.frameID] = f
				} else {
					if f.payload != nil {
						putPayload(f.payload)
					}
				}
			} else {
				// FIX #5: duplicate frame (frameID < nextRx) — free payload
				if f.payload != nil {
					putPayload(f.payload)
				}
			}
			s.rxMu.Unlock()

		case <-timer.C:
			lastAct := s.lastActivity.Load()
			if time.Now().UnixNano()-lastAct > int64(timeout) {
				return frame{}, false
			}
			timer.Reset(checkInterval)

		case <-s.done:
			return frame{}, false
		}
	}
}

// ─── Mux ──────────────────────────────────────────────────────────────────────

type Mux struct {
	conn     *net.UDPConn
	peerAddr atomic.Pointer[net.UDPAddr]
	streams  sync.Map
	writeMu  sync.Mutex
	isServer bool
	closed   chan struct{}
	OnStream func(id uint32, s *Stream)

	StreamCount atomic.Int64
}

func NewMux(conn *net.UDPConn, isServer bool) *Mux {
	m := &Mux{conn: conn, isServer: isServer, closed: make(chan struct{})}
	go m.retransmitLoop()
	go m.readLoop()
	go m.streamGCLoop()
	return m
}

func (m *Mux) Close() {
	select {
	case <-m.closed:
		return
	default:
	}
	close(m.closed)
	m.conn.Close()
	m.streams.Range(func(key, value interface{}) bool {
		m.closeStream(key.(uint32))
		return true
	})
}

// sendACK sends an ACK with receiver window advertisement.
// Wire: [reqID 4][frameID 4][type 1][payloadLen 2][rwnd 4] = 15 bytes
func (m *Mux) sendACK(reqID, frameID uint32, rwnd uint32) {
	var buf [HdrSize + 4]byte
	binary.BigEndian.PutUint32(buf[0:], reqID)
	binary.BigEndian.PutUint32(buf[4:], frameID)
	buf[8] = MsgACK
	binary.BigEndian.PutUint16(buf[9:], 4) // payloadLen = 4 (rwnd field)
	binary.BigEndian.PutUint32(buf[HdrSize:], rwnd)

	m.writeMu.Lock()
	if m.isServer {
		if addr := m.peerAddr.Load(); addr != nil {
			m.conn.WriteToUDP(buf[:], addr)
		}
	} else {
		m.conn.Write(buf[:])
	}
	m.writeMu.Unlock()
}

func (m *Mux) sendRaw(reqID, frameID uint32, typ uint8, payload []byte) {
	bp := legacySendPool.Get().(*[]byte)
	buf := (*bp)[:HdrSize+len(payload)]
	binary.BigEndian.PutUint32(buf[0:], reqID)
	binary.BigEndian.PutUint32(buf[4:], frameID)
	buf[8] = typ
	binary.BigEndian.PutUint16(buf[9:], uint16(len(payload)))
	if len(payload) > 0 {
		copy(buf[HdrSize:], payload)
	}

	var err error
	m.writeMu.Lock()
	if m.isServer {
		if addr := m.peerAddr.Load(); addr != nil {
			_, err = m.conn.WriteToUDP(buf, addr)
		}
	} else {
		_, err = m.conn.Write(buf)
	}
	m.writeMu.Unlock()

	// Evaluate the dropped packet
	if err != nil {
		if errors.Is(err, syscall.EMSGSIZE) {
			fmt.Printf("RUDP FATAL | MTU Drop! Packet too large (size=%d bytes). Lower ChunkSize.\n", len(buf))
		}
	}

	legacySendPool.Put(bp)
}

func (m *Mux) sendRawHeadroom(reqID, frameID uint32, typ uint8, buf []byte) {
	binary.BigEndian.PutUint32(buf[0:], reqID)
	binary.BigEndian.PutUint32(buf[4:], frameID)
	buf[8] = typ
	binary.BigEndian.PutUint16(buf[9:], uint16(len(buf)-HdrSize))

	var err error
	m.writeMu.Lock()
	if m.isServer {
		if addr := m.peerAddr.Load(); addr != nil {
			_, err = m.conn.WriteToUDP(buf, addr)
		}
	} else {
		_, err = m.conn.Write(buf)
	}
	m.writeMu.Unlock()

	// Evaluate the dropped packet
	if err != nil {
		if errors.Is(err, syscall.EMSGSIZE) {
			fmt.Printf("RUDP FATAL | MTU Drop! Packet too large (size=%d bytes). Lower ChunkSize.\n", len(buf))
		}
	}
}

func (m *Mux) sendRetransmit(reqID uint32, p *sentPacket) {
	if p.data != nil {
		m.sendRawHeadroom(reqID, p.frameID, p.typ, p.data)
	} else {
		m.sendRaw(reqID, p.frameID, p.typ, nil)
	}
}

func (m *Mux) OpenStream(id uint32) *Stream {
	s := newStream(id, m)
	m.streams.Store(id, s)
	m.StreamCount.Add(1)
	return s
}

func (m *Mux) closeStream(id uint32) {
	if v, ok := m.streams.LoadAndDelete(id); ok {
		m.StreamCount.Add(-1)
		s := v.(*Stream)

		s.doneOnce.Do(func() { close(s.done) })

		s.flightMu.Lock()
		for fid, p := range s.inFlight {
			if p.data != nil {
				putSendBuf(p.data)
			}
			delete(s.inFlight, fid)
		}
		s.flightMu.Unlock()
		s.rxMu.Lock()
		for k, f := range s.ooo {
			if f.payload != nil {
				putPayload(f.payload)
			}
			delete(s.ooo, k)
		}
		for _, f := range s.ready {
			if f.payload != nil {
				putPayload(f.payload)
			}
		}
		s.ready = nil
		s.rxMu.Unlock()
	drainLoop:
		for {
			select {
			case f := <-s.ch:
				if f.payload != nil {
					putPayload(f.payload)
				}
			default:
				break drainLoop
			}
		}
	}
}

func retransmitBackoff(baseRTO time.Duration, retransmits uint8) time.Duration {
	shift := retransmits
	if shift > maxBackoffShift {
		shift = maxBackoffShift
	}
	d := baseRTO << shift
	if d > maxRTO {
		d = maxRTO
	}
	return d
}

func (m *Mux) retransmitLoop() {
	ticker := time.NewTicker(retransmitTick)
	defer ticker.Stop()
	for {
		select {
		case <-m.closed:
			return
		case <-ticker.C:
		}
		m.streams.Range(func(key, value interface{}) bool {
			s := value.(*Stream)
			s.flightMu.Lock()
			if len(s.inFlight) == 0 {
				// FIX #2 (supplement): even with empty inFlight, if rwnd is
				// zero we should probe. The main probe logic is in Write(),
				// but this catches edge cases where Write isn't actively
				// looping (e.g., between Write calls in copyBuffered).
				if s.rwnd == 0 && !s.closed.Load() {
					s.flightMu.Unlock()
					m.sendRaw(s.id, 0, MsgWindowProbe, nil)
					return true
				}
				s.flightMu.Unlock()
				return true
			}

			baseRTO := s.getRTO()
			now := time.Now()

			// Collect overdue packets, sorted by frameID (lowest first)
			type overdue struct {
				fid uint32
				p   *sentPacket
			}
			var expired []overdue
			for fid, p := range s.inFlight {
				timeout := retransmitBackoff(baseRTO, p.retransmits)
				if now.Sub(p.sentAt) > timeout {
					expired = append(expired, overdue{fid, p})
				}
			}

			if len(expired) == 0 {
				s.flightMu.Unlock()
				return true
			}

			// Sort by frameID ascending — lowest first (head-of-line priority)
			sort.Slice(expired, func(i, j int) bool {
				return expired[i].fid < expired[j].fid
			})

			// FIX #3: Multiplicative decrease at most once per RTT.
			// Without this guard, MD fires every 25ms tick that has any
			// expired packet. A single loss event spanning 5 ticks would
			// collapse cwnd: 128→64→32→16→8→floor. TCP only halves once
			// per loss event (roughly per RTT). We use max(srtt, baseRTO)
			// as the cooldown period.
			cooldown := baseRTO
			s.rttMu.Lock()
			if s.srtt > cooldown {
				cooldown = s.srtt
			}
			s.rttMu.Unlock()
			if cooldown < 50*time.Millisecond {
				cooldown = 50 * time.Millisecond // sane minimum
			}

			if now.Sub(s.lastLossTime) >= cooldown {
				s.ssthresh = math.Max(s.cwnd/2.0, ssthreshFloor)
				s.cwnd = math.Max(s.cwnd/2.0, cwndFloor)
				s.lastLossTime = now
			}

			// Budget: retransmit at most maxRetransmitsPerTick packets
			budget := maxRetransmitsPerTick
			if budget > len(expired) {
				budget = len(expired)
			}

			for i := 0; i < budget; i++ {
				p := expired[i].p
				p.sentAt = time.Now()
				p.retransmits++
				m.sendRetransmit(s.id, p)
				time.Sleep(50 * time.Microsecond)
			}

			// If rwnd is zero, send a window probe
			if s.rwnd == 0 {
				m.sendRaw(s.id, 0, MsgWindowProbe, nil)
			}

			s.flightMu.Unlock()
			return true
		})
	}
}

func (m *Mux) streamGCLoop() {
	ticker := time.NewTicker(streamGCInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.closed:
			return
		case now := <-ticker.C:
			cutoffReap := now.UnixNano() - int64(StreamIdleTimeout)
			cutoffPing := now.UnixNano() - int64(15*time.Second)

			m.streams.Range(func(key, value interface{}) bool {
				s := value.(*Stream)
				lastAct := s.lastActivity.Load()
				if lastAct < cutoffReap {
					m.closeStream(key.(uint32))
				} else if lastAct < cutoffPing {
					// FIX #8: touch on sender side too, so the stream
					// that sent the keepalive also refreshes lastActivity.
					// Without this, only the receiver's lastActivity updates
					// (via the ACK reply), and the sender side can drift
					// toward the reap cutoff during long SSE idle periods.
					s.touch()
					m.sendRaw(s.id, 0, MsgKeepAlive, nil)
				}
				return true
			})
		}
	}
}

func (m *Mux) SendHello() {
	m.sendRaw(0, 0, MsgData, nil)
}

func (m *Mux) readLoop() {
	buf := make([]byte, HdrSize+ChunkSize+256)
	for {
		var (
			n    int
			addr *net.UDPAddr
			err  error
		)
		if m.isServer {
			n, addr, err = m.conn.ReadFromUDP(buf)
		} else {
			n, err = m.conn.Read(buf)
		}
		if err != nil {
			select {
			case <-m.closed:
				return
			default:
			}
			continue
		}
		if n < HdrSize {
			continue
		}

		reqID := binary.BigEndian.Uint32(buf[0:])
		frameID := binary.BigEndian.Uint32(buf[4:])
		typ := buf[8]
		plen := binary.BigEndian.Uint16(buf[9:])

		if int(plen) != n-HdrSize {
			continue
		}

		if m.isServer && addr != nil {
			known := m.peerAddr.Load()
			if known == nil || known.String() != addr.String() {
				newAddr := new(net.UDPAddr)
				*newAddr = *addr
				m.peerAddr.Store(newAddr)
			}
		}

		if reqID == 0 {
			continue
		}

		v, exists := m.streams.Load(reqID)

		// ── ACK with rwnd ──
		if typ == MsgACK {
			if exists {
				s := v.(*Stream)

				// Extract rwnd from ACK payload (4 bytes, big-endian)
				var peerRwnd uint32 = chanSize
				if plen >= 4 {
					peerRwnd = binary.BigEndian.Uint32(buf[HdrSize : HdrSize+4])
				}

				s.flightMu.Lock()
				prevRwnd := s.rwnd
				s.rwnd = peerRwnd

				if p, pending := s.inFlight[frameID]; pending {
					if p.retransmits == 0 {
						rtt := time.Since(p.sentAt)
						s.updateRTT(rtt)
					}

					// cwnd growth: only on non-retransmitted ACK
					if p.retransmits == 0 {
						if s.cwnd < s.ssthresh {
							// Slow start: +1 per ACK (~doubles per RTT)
							s.cwnd += 1.0
						} else {
							// Congestion avoidance: +1/cwnd per ACK (+1 per RTT)
							s.cwnd += 1.0 / math.Floor(s.cwnd)
						}
						if s.cwnd > float64(WindowSize) {
							s.cwnd = float64(WindowSize)
						}
					}

					if p.data != nil {
						putSendBuf(p.data)
					}
					delete(s.inFlight, frameID)
					select {
					case s.flightCh <- struct{}{}:
					default:
					}
				}

				// FIX #1 (supplement): if rwnd just opened from zero,
				// wake Write() even if no inFlight was deleted.
				// This handles the case where all inFlight was already
				// ACKed but Write was blocked on effectiveWindow() == 1
				// with 1 inFlight that just got ACKed in a previous tick.
				if prevRwnd == 0 && peerRwnd > 0 {
					select {
					case s.flightCh <- struct{}{}:
					default:
					}
				}

				s.flightMu.Unlock()
				s.touch()
			}
			continue
		}

		// ── KeepAlive ──
		if typ == MsgKeepAlive {
			if exists {
				s := v.(*Stream)
				s.touch()
				s.rxMu.Lock()
				rwnd := s.calcRwnd()
				s.rxMu.Unlock()
				m.sendACK(reqID, frameID, rwnd)
			}
			continue
		}

		// ── WindowProbe: respond with fresh rwnd ──
		if typ == MsgWindowProbe {
			if exists {
				s := v.(*Stream)
				s.touch()
				s.rxMu.Lock()
				rwnd := s.calcRwnd()
				s.rxMu.Unlock()
				m.sendACK(reqID, 0, rwnd)
			}
			continue
		}

		// ── Data or EOF: never block readLoop ──
		var payload []byte
		if plen > 0 {
			payload = getPayload(int(plen))
			copy(payload, buf[HdrSize:n])
		}

		f := frame{frameID: frameID, isEOF: typ == MsgEOF, payload: payload}

		if exists {
			s := v.(*Stream)
			select {
			case s.ch <- f:
				s.rxMu.Lock()
				rwnd := s.calcRwnd()
				s.rxMu.Unlock()
				m.sendACK(reqID, frameID, rwnd)
				s.touch()
			default:
				// Channel full — drop frame, BUT send ACK to update window (rwnd=0)
				s.rxMu.Lock()
				rwnd := s.calcRwnd()
				s.rxMu.Unlock()
				// ACK the last continuous good frame so sender pauses
				m.sendACK(reqID, s.nextRx-1, rwnd)

				if payload != nil {
					putPayload(payload)
				}
			}
			continue
		}

		if frameID != 1 {
			if payload != nil {
				putPayload(payload)
			}
			continue
		}

		// FIX #6: non-blocking send for new stream creation.
		// The old code used a blocking `s.ch <- f` which could stall
		// readLoop if the channel were somehow full (shouldn't happen
		// on a brand-new stream, but defensive code matters — one stuck
		// readLoop freezes ALL streams).
		if m.OnStream != nil {
			s := newStream(reqID, m)
			m.streams.Store(reqID, s)
			m.StreamCount.Add(1)
			select {
			case s.ch <- f:
				s.rxMu.Lock()
				rwnd := s.calcRwnd()
				s.rxMu.Unlock()
				m.sendACK(reqID, frameID, rwnd)
			default:
				// Should never happen on new stream, but don't block readLoop
				if payload != nil {
					putPayload(payload)
				}
			}
			go m.OnStream(reqID, s)
		} else {
			if payload != nil {
				putPayload(payload)
			}
		}
	}
}
