package tomtp

import (
	"crypto/ecdh"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

type BBRState int

const (
	BBRStateStartup BBRState = iota
	BBRStateNormal
)

type Connection struct {
	connId                uint64
	remoteAddr            netip.AddrPort
	streams               map[uint32]*Stream
	listener              *Listener
	pubKeyIdRcv           *ecdh.PublicKey
	prvKeyEpSnd           *ecdh.PrivateKey
	prvKeyEpSndRollover   *ecdh.PrivateKey
	pubKeyEpRcv           *ecdh.PublicKey
	pubKeyEpRcvRollover   *ecdh.PublicKey
	sharedSecret          []byte
	sharedSecretRollover1 []byte
	sharedSecretRollover2 []byte
	rbSnd                 *SendBuffer // Send buffer for outgoing dataToSend, handles the global sn
	rbRcv                 *ReceiveBuffer
	bytesWritten          uint64
	mtu                   int
	closed                bool
	sender                bool
	firstPaket            bool
	isRollover            bool
	isHandshake           bool
	snCrypto              uint64 //this is 48bit

	// Flow control
	rcvWndSize uint64 // Receive window Size

	BBR
	srtt   time.Duration // Smoothed RTT
	rttvar time.Duration // RTT variation
	mu     sync.Mutex
}

type BBR struct {
	// Core state
	state      BBRState      // Current state (Startup or Normal)
	pacingRate uint64        // Current pacing rate (bytes per second)
	cwnd       uint64        // Congestion window (bytes)
	rttMin     time.Duration // Minimum RTT observed
	maxBW      uint64        // Maximum bandwidth observed (bytes per second)

	// Bandwidth plateau detection for startup exit
	bwGrowthCount      int   // Counter for non-increasing bandwidth measurements
	lastBWUpdateMicros int64 // Last time bandwidth was updated

	// Gain factors
	pacingGainPct int // Current pacing gain multiplier
	cwndGainPct   int // Current cwnd gain multiplier

	// Probing
	lastProbeTimeMicros int64 // When we last initiated a probe
	inProbingPhase      bool  // Whether we're currently in a probing phase

	// Constants
	minRttWindowDuration time.Duration // How long min_rtt is valid
	probeInterval        time.Duration // How often to probe
}

func (c *Connection) IsHandshakeCompleted() bool {
	return c.sharedSecret != nil || c.sharedSecretRollover1 != nil || c.sharedSecretRollover2 != nil
}

// NewBBR creates a new BBR instance with default values
func NewBBR() BBR {
	return BBR{
		state:                BBRStateStartup,
		pacingRate:           12000,     // Initial conservative rate
		cwnd:                 startMtu,  // Start with 1 packet
		rttMin:               time.Hour, // Set to high value initially
		maxBW:                0,
		bwGrowthCount:        0,
		lastBWUpdateMicros:   0,
		pacingGainPct:        200, // Aggressive gain for startup
		cwndGainPct:          200,
		lastProbeTimeMicros:  0,
		inProbingPhase:       false,
		minRttWindowDuration: 3 * time.Second,
		probeInterval:        1 * time.Second,
	}
}

func (c *Connection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, stream := range c.streams {
		stream.conn.closed = true
	}
	c.closed = true
	clear(c.streams)
}

func (c *Connection) GetOrCreate(streamId uint32) (s *Stream, isNew bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.streams == nil {
		c.streams = make(map[uint32]*Stream)
	}

	if stream, ok := c.streams[streamId]; !ok {
		s := &Stream{
			streamId: streamId,
			conn:     c,
			mu:       sync.Mutex{},
		}
		c.streams[streamId] = s
		return s, true
	} else {
		return stream, false
	}
}

func (c *Connection) UpdateRTT(rttMeasurement time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.srtt == 0 {
		// First measurement
		c.srtt = rttMeasurement
		c.rttvar = rttMeasurement / 2
	} else {
		// Calculate absolute difference for RTT variation
		var delta time.Duration
		if rttMeasurement > c.srtt {
			delta = rttMeasurement - c.srtt
		} else {
			delta = c.srtt - rttMeasurement
		}

		// Integer-based RTT variation update using shifts
		// RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT-R'|
		// Using shift: 3/4 is ~= 6/8, and 1/4 is ~= 2/8
		c.rttvar = (c.rttvar*6)/8 + (delta*2)/8

		// Integer-based smoothed RTT update
		// SRTT = 7/8 * SRTT + 1/8 * R'
		// Using shift: 7/8 is ~= 7/8, and 1/8 is ~= 1/8
		c.srtt = (c.srtt*7)/8 + (rttMeasurement*1)/8
	}
}

func (c *Connection) UpdateBBR(rttMeasurement time.Duration, bytesAcked uint64, nowMicros int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.lastBWUpdateMicros == 0 {
		c.lastBWUpdateMicros = nowMicros
	}

	// Store whether we need to force an RTT reset
	needsRttReset := false

	// Check if minimum RTT window has expired
	slog.Debug("RTT window check vars",
		slog.Int64("nowMicros", nowMicros),
		slog.Int64("c.lastBWUpdateMicros", c.lastBWUpdateMicros),
		slog.Int64("c.minRttWindowDuration.Microseconds()", c.minRttWindowDuration.Microseconds()))

	if nowMicros-c.lastBWUpdateMicros > c.minRttWindowDuration.Microseconds() {
		c.rttMin = time.Hour // Reset to high value
		needsRttReset = true
	}

	// Always update minimum RTT if we have a valid measurement
	if rttMeasurement > 0 && rttMeasurement < c.rttMin {
		c.rttMin = rttMeasurement
		// If this was after a reset, update the timestamp
		if needsRttReset {
			c.lastBWUpdateMicros = nowMicros
		}
	}

	// 2. Update bandwidth estimate
	// Only if we got a valid RTT measurement and some bytes were acknowledged
	oldState := c.state
	if rttMeasurement > 0 && bytesAcked > 0 {
		// Calculate instantaneous bandwidth
		instantBw := uint64(float64(bytesAcked) / rttMeasurement.Seconds())

		// If bandwidth increased, update maxBW
		if instantBw > c.maxBW {
			if c.state == BBRStateStartup {
				// Reset growth counter when bandwidth increases
				c.bwGrowthCount = 0
			}
			c.maxBW = instantBw
			c.lastBWUpdateMicros = nowMicros
		} else if c.state == BBRStateStartup && nowMicros-c.lastBWUpdateMicros > 100*1000 { //100ms
			// In startup, track if bandwidth stops growing
			c.bwGrowthCount++
			c.lastBWUpdateMicros = nowMicros

			// If bandwidth hasn't grown for three consecutive samples, exit startup
			if c.bwGrowthCount >= 3 {
				c.state = BBRStateNormal
				c.pacingGainPct = 100 // Standard pacing in normal state
				c.cwndGainPct = 150   // Allow some queue build-up

				slog.Debug("BBR entering NORMAL state", slog.Uint64("cwnd", c.cwnd), slog.Uint64("max_bw", c.maxBW))
			}
		}
	}

	// 3. State-specific behavior
	switch oldState {
	case BBRStateStartup:
		// In Startup: Aggressive cwnd growth like classic slow start
		if c.cwnd > uint64(c.mtu) {
			// Add the number of bytes ACKed to cwnd (classic slow start)
			c.cwnd += bytesAcked
		} else {
			// Bootstrap initial cwnd
			c.cwnd = uint64(10 * c.mtu)
		}

		// Keep pacing rate proportional to cwnd and RTT
		if c.rttMin < time.Hour && c.rttMin > 0 {
			// pacingRate = cwnd / rtt * gain
			c.pacingRate = (c.cwnd * uint64(c.pacingGainPct) * 10000) / uint64(c.rttMin.Microseconds())
		}

	case BBRStateNormal:
		// Handle probing in normal state
		c.handleProbing(nowMicros)

		// In Normal state: BDP-based cwnd with gain factor
		if c.maxBW > 0 && c.rttMin > 0 && c.rttMin < time.Hour {
			// Calculate Bandwidth-Delay Product (BDP)
			rttMicros := c.rttMin.Microseconds()
			bdp := (c.maxBW * uint64(rttMicros)) / 1000000

			// Set cwnd based on BDP and gain factor (with minimum of 4 segments)
			targetCwnd := (bdp * uint64(c.cwndGainPct)) / 100
			minCwnd := uint64(4 * c.mtu)
			if targetCwnd < minCwnd {
				c.cwnd = minCwnd
			} else {
				c.cwnd = targetCwnd
			}

			// Set pacing rate based on estimated bandwidth
			c.pacingRate = (c.maxBW * uint64(c.pacingGainPct)) / 100
		}
	}

	slog.Debug("BBR update",
		slog.Any("state", c.state),
		slog.Uint64("cwnd", c.cwnd),
		slog.Uint64("pacing_rate", c.pacingRate),
		slog.Uint64("max_bw", c.maxBW),
		slog.Duration("rtt_min", c.rttMin))
}

func (c *Connection) handleProbing(nowMicros int64) {
	// Skip probing if we don't have a good BW estimate yet
	if c.maxBW == 0 {
		return
	}

	if c.lastProbeTimeMicros == 0 {
		c.lastProbeTimeMicros = nowMicros
	}

	if c.inProbingPhase {
		// Check if probe phase should end (after 200ms)
		if nowMicros-c.lastProbeTimeMicros > 200*1000 {
			// End probe phase
			c.inProbingPhase = false
			c.pacingGainPct = 100 // Restore normal pacing gain

			// Apply updated pacing rate
			c.pacingRate = (c.maxBW * uint64(c.pacingGainPct)) / 100

			slog.Debug("BBR probe phase ended",
				slog.Int("pacing_gain", c.pacingGainPct))
		}
	} else if nowMicros-c.lastProbeTimeMicros > c.probeInterval.Microseconds() {
		// Time to start a new probe
		c.pacingGainPct = 150
		c.inProbingPhase = true
		c.lastProbeTimeMicros = nowMicros

		// Apply the new pacing rate immediately
		c.pacingRate = (c.maxBW * uint64(c.pacingGainPct)) / 100

		slog.Debug("BBR starting probe phase", slog.Int("probe_pacing_gain", c.pacingGainPct))
	}
}

func (c *Connection) decode(decryptedData []byte, nowMicros int64) (s *Stream, isNew bool, err error) {
	p, _, payloadData, err := DecodePayload(decryptedData)
	if err != nil {
		slog.Info("error in decoding payload from new connection", slog.Any("error", err))
		return nil, false, err
	}

	if p.RcvWndSize > 0 {
		c.rcvWndSize = p.RcvWndSize
	}

	// Get or create stream using StreamId from Data
	s, isNew = c.GetOrCreate(p.StreamId)

	if p.Ack != nil {
		sentTimeMicros := c.rbSnd.AcknowledgeRange(p.Ack.StreamId, p.Ack.StreamOffset, p.Ack.Len)
		if nowMicros > sentTimeMicros {
			rtt := time.Duration(nowMicros-sentTimeMicros) * time.Millisecond
			c.UpdateRTT(rtt)
			c.UpdateBBR(rtt, uint64(p.Ack.Len), nowMicros)
		}
	}

	if len(payloadData) > 0 {
		s.conn.rbRcv.Insert(s.streamId, p.StreamOffset, payloadData)
	}

	switch p.CloseOp {
	case CloseStream:
		s.Close()
	case CloseConnection:
		c.Close()
	}

	return s, isNew, nil
}

// GetPacingDelay calculates how long to wait before sending the next packet
func (c *Connection) GetPacingDelay(packetSize int) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.pacingRate == 0 {
		return 0 // No pacing if rate is not set
	}

	// Calculate delay based on packet size and pacing rate
	delaySeconds := float64(packetSize) / float64(c.pacingRate)
	return time.Duration(delaySeconds * float64(time.Second))
}

func (c *Connection) RTO() time.Duration {
	// Standard formula from RFC 6298
	rto := c.srtt + 4*c.rttvar

	//the first packet
	if rto == 0 {
		return 250 * time.Millisecond //with backoff, max 2 sec
	} else if rto < 100*time.Millisecond { // Apply minimum and maximum bounds
		return 100 * time.Millisecond
	} else if rto > 1000*time.Millisecond {
		return 1000 * time.Millisecond //with backoff, max 8 sec
	}

	return rto
}

func (c *Connection) OnPacketLoss() {
	if c.BBR.inProbingPhase {
		return // Avoid further reduction during probing phase
	}
	c.BBR.pacingGainPct = 75
	c.BBR.inProbingPhase = false
	c.BBR.maxBW = uint64(float64(c.BBR.maxBW) * 0.95) // Reduce by 5%
	c.BBR.rttMin = time.Hour                          // Reset to high value
}
