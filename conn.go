package tomtp

import (
	"context"
	"crypto/ecdh"
	"log/slog"
	"math/rand"
	"net/netip"
	"sync"
	"time"
)

type ConnectionState uint8

const (
	ConnectionStarting ConnectionState = iota
	ConnectionEnding
	ConnectionEnded
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
	nextSleepMillis       uint64
	rbSnd                 *SendBuffer // Send buffer for outgoing dataToSend, handles the global sn
	rbRcv                 *ReceiveBuffer
	bytesWritten          uint64
	mtu                   int
	sender                bool
	firstPaket            bool
	isRollover            bool
	isHandshake           bool
	snCrypto              uint64 //this is 48bit

	// Flow control
	maxRcvWndSize uint64 // Receive window Size
	maxSndWndSize uint64 // Send window Size

	RTT
	BBR
	mu    sync.Mutex
	state ConnectionState
}

type RTT struct {
	// Smoothed RTT estimation
	srtt time.Duration

	// RTT variation
	rttvar time.Duration

	// RTO (Retransmission Timeout)
	rto time.Duration

	// Alpha and Beta are the smoothing factors
	// TCP typically uses alpha = 0.125 and beta = 0.25
	alpha float64
	beta  float64

	// Minimum and maximum RTO values
	minRTO time.Duration
	maxRTO time.Duration
}

func NewRTT() *RTT {
	return &RTT{
		alpha:  0.125, // TCP default
		beta:   0.25,  // TCP default
		minRTO: 500 * time.Millisecond,
		maxRTO: 60 * time.Second,
	}
}

// BBR states
type BBRState int

const (
	BBRStateStartup BBRState = iota
	BBRStateNormal
	// Super simplified: just startup and normal
)

// Enhanced BBR structure with additional fields for a simplified BBR implementation
type BBR struct {
	// Current state
	state          BBRState      // Current state of BBR
	pacingRate     uint64        // Bytes per second
	cwnd           uint64        // Congestion window in bytes
	rttMin         time.Duration // Minimum RTT observed
	roundTripCount uint64        // Counter for round trips

	// BW estimation
	maxBW            uint64    // Maximum bandwidth observed in bytes per second
	lastBWUpdateTime time.Time // Last time bandwidth was updated

	// BBR-specific parameters
	basePacingRate       uint64  // Starting pacing rate
	pacingGain           float64 // Current pacing gain multiplier
	cwndGain             float64 // Current cwnd gain multiplier
	pacingIncreaseFactor float64 // Multiplicative factor to increase pacing rate

	// Slow start related
	ssthresh  uint64 // Slow Start Threshold
	slowStart bool   // Whether we're in slow start

	// RTT measurement
	minRTTTimestamp time.Time     // When min_rtt was last updated
	rtPropExpiry    time.Duration // How long a min_rtt sample is valid

	// Random probing
	lastProbeTime time.Time     // When we last probed for bandwidth
	probeInterval time.Duration // How often to probe
	randomSeed    int64         // Seed for random number generation
}

// NewBBR creates a new BBR instance with default values
func NewBBR() BBR {
	return BBR{
		state:                BBRStateStartup,
		pacingRate:           uint64(12000), // Initial pacing rate
		cwnd:                 startMtu,      // Initial congestion window, 1 packet due to crypto handshake
		rttMin:               time.Hour,     // Initialize to a very large value
		basePacingRate:       uint64(12000),
		pacingGain:           2.0,  // Startup phase uses higher gain
		cwndGain:             2.0,  // Startup phase uses higher gain
		pacingIncreaseFactor: 0.01, // 1% increase
		ssthresh:             uint64(14000),
		slowStart:            true,                   // Start in slow start
		rtPropExpiry:         10 * time.Second,       // How long min_rtt sample is valid
		probeInterval:        200 * time.Millisecond, // How often to randomly probe
		randomSeed:           time.Now().UnixNano(),  // Random seed for probing
	}
}

func (c *Connection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, stream := range c.streams {
		//pick first stream, send close flag to close all streams
		if stream.conn.state == ConnectionStarting {
			stream.conn.state = ConnectionEnding
		}
	}

	clear(c.streams)
	return nil
}

func (c *Connection) GetOrNewStreamRcv(streamId uint32) (*Stream, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.streams == nil {
		c.streams = make(map[uint32]*Stream)
	}

	if stream, ok := c.streams[streamId]; !ok {
		ctx, cancel := context.WithCancel(context.Background())
		s := &Stream{
			streamId:      streamId,
			state:         StreamStarting,
			conn:          c,
			closeCtx:      ctx,
			closeCancelFn: cancel,
			mu:            sync.Mutex{},
		}
		c.streams[streamId] = s
		return s, true
	} else {
		return stream, false
	}
}

// UpdateRTT updates the RTT estimation based on a new measurement
func (c *Connection) UpdateRTT(rttMeasurement time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// For the first measurement, initialize values
	if c.srtt == 0 {
		c.srtt = rttMeasurement
		c.rttvar = rttMeasurement / 2
		c.rto = c.srtt + 4*c.rttvar

		// Bound RTO to Min and max values
		if c.rto < c.minRTO {
			c.rto = c.minRTO
		} else if c.rto > c.maxRTO {
			c.rto = c.maxRTO
		}
		return
	}

	// Calculate RTT variation (RFC 6298)
	// RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R'|
	difference := rttMeasurement - c.srtt
	if difference < 0 {
		difference = -difference
	}
	c.rttvar = time.Duration((1-c.beta)*float64(c.rttvar) + c.beta*float64(difference))

	// Update smoothed RTT
	// SRTT = (1 - alpha) * SRTT + alpha * R'
	c.srtt = time.Duration((1-c.alpha)*float64(c.srtt) + c.alpha*float64(rttMeasurement))

	// Update RTO (RFC 6298 suggests RTO = SRTT + 4 * RTTVAR)
	c.rto = c.srtt + 4*c.rttvar

	// Bound RTO to Min and max values
	if c.rto < c.minRTO {
		c.rto = c.minRTO
	} else if c.rto > c.maxRTO {
		c.rto = c.maxRTO
	}

}

// UpdateBBR updates BBR state based on new RTT measurement and acknowledgment
// This is a simplified version with just Startup and Normal states
func (c *Connection) UpdateBBR(rttMeasurement time.Duration, acked uint64, nowMicros int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Unix(0, nowMicros*1000)

	// Update minimum RTT
	if rttMeasurement < c.BBR.rttMin {
		c.BBR.rttMin = rttMeasurement
		c.BBR.minRTTTimestamp = now

		// Increase pacing rate based on decreased RTT in Startup mode
		if c.BBR.state == BBRStateStartup {
			c.BBR.pacingRate = uint64(float64(c.BBR.pacingRate) * (1 + c.BBR.pacingIncreaseFactor))
		}
	}

	// Periodically reset minRTT to force a fresh measurement
	if now.Sub(c.BBR.minRTTTimestamp) > c.BBR.rtPropExpiry {
		// Reset min RTT to cause a fresh measurement
		c.BBR.rttMin = time.Hour
		c.BBR.minRTTTimestamp = now

		// Temporarily reduce cwnd to get a cleaner RTT measurement
		// but don't reduce below 4 segments
		minCwnd := uint64(4 * c.mtu)
		if c.BBR.cwnd > minCwnd {
			// Reduce cwnd by 25%, but not below minimum
			reducedCwnd := c.BBR.cwnd - (c.BBR.cwnd / 4)
			if reducedCwnd > minCwnd {
				c.BBR.cwnd = reducedCwnd
			} else {
				c.BBR.cwnd = minCwnd
			}
		}

		slog.Debug("BBR RTT reset",
			slog.Uint64("cwnd", c.BBR.cwnd),
			slog.Duration("expired_rtt", c.BBR.rttMin))
	}

	// Handle the two BBR states
	switch c.BBR.state {
	case BBRStateStartup:
		// In Startup, we use slow start logic for cwnd
		if c.BBR.slowStart {
			// Double cwnd for each RTT in slow start
			if c.BBR.cwnd == startMtu {
				c.BBR.cwnd = startMtu * 10
			} else {
				c.BBR.cwnd += acked // Increase cwnd by the amount of data acked
			}

			// Check if we should exit slow start
			if c.BBR.cwnd >= c.BBR.ssthresh {
				c.BBR.slowStart = false
				c.enterNormal(now)
			}
		}

		// Check if we've found a bandwidth plateau
		if c.BBR.maxBW > 0 && c.BBR.pacingRate >= c.BBR.maxBW {
			// We've found a bandwidth plateau, exit startup directly to normal
			c.enterNormal(now)

			// Set pacing rate to 75% of maxBW initially to drain any queue
			c.BBR.pacingRate = uint64(float64(c.BBR.maxBW) * 0.75)
			slog.Debug("BBR draining queue", slog.Uint64("pacing_rate", c.BBR.pacingRate))
		}

	case BBRStateNormal:
		// In Normal state, we use a simple AIMD approach with random probing

		// Randomly probe for more bandwidth at regular intervals
		if c.BBR.lastProbeTime.IsZero() || now.Sub(c.BBR.lastProbeTime) > c.BBR.probeInterval {
			c.BBR.lastProbeTime = now

			// Generate a random number between -0.1 and +0.2
			// This gives us more upward probing than downward
			r := rand.New(rand.NewSource(c.BBR.randomSeed))
			c.BBR.randomSeed = r.Int63()
			randomFactor := r.Float64()*0.3 - 0.1 // [-0.1, 0.2]

			// Apply random adjustment to pacing rate
			if c.BBR.maxBW > 0 {
				// Adjust around our estimate of maxBW
				newPacingRate := uint64(float64(c.BBR.maxBW) * (1.0 + randomFactor))

				// Don't drop too far below maxBW
				if newPacingRate < uint64(float64(c.BBR.maxBW)*0.8) {
					newPacingRate = uint64(float64(c.BBR.maxBW) * 0.8)
				}

				c.BBR.pacingRate = newPacingRate

				slog.Debug("BBR random probe",
					slog.Float64("factor", randomFactor),
					slog.Uint64("new_rate", c.BBR.pacingRate),
					slog.Uint64("maxBW", c.BBR.maxBW))
			}
		}

		// Increase cwnd by a fraction of the newly acked data (like TCP Cubic)
		c.BBR.cwnd += uint64(float64(acked) * 0.1) // Increase by 10% of the acked data
	}

	// Update bandwidth estimate (very simplified)
	if acked > 0 {
		// Calculate instantaneous bandwidth: bytes_acked / time_delta
		if !c.BBR.lastBWUpdateTime.IsZero() {
			elapsed := now.Sub(c.BBR.lastBWUpdateTime)
			if elapsed > 0 {
				instantBW := uint64(float64(acked) / elapsed.Seconds())

				if instantBW > c.BBR.maxBW {
					c.BBR.maxBW = instantBW

					// If we found a new maximum bandwidth, adjust pacing rate
					// to be slightly above it
					if c.BBR.state == BBRStateNormal {
						c.BBR.pacingRate = uint64(float64(c.BBR.maxBW) * 1.05) // 5% above maxBW
					}
				}
			}
		}
		c.BBR.lastBWUpdateTime = now
	}

	// Apply CWND bounds
	c.applyBBRCwndBounds()

	slog.Debug("BBR update",
		slog.String("state", bbrStateString(c.BBR.state)),
		slog.Uint64("cwnd", c.BBR.cwnd),
		slog.Uint64("pacing_rate", c.BBR.pacingRate),
		slog.Duration("rtt_min", c.BBR.rttMin),
		slog.Uint64("maxBW", c.BBR.maxBW),
		slog.Bool("slow_start", c.BBR.slowStart))
}

// OnPacketLoss is called when a packet loss is detected
func (c *Connection) OnPacketLoss() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Reduce ssthresh on packet loss
	c.BBR.ssthresh = c.BBR.cwnd / 2
	if c.BBR.ssthresh < uint64(2*c.mtu) {
		c.BBR.ssthresh = uint64(2 * c.mtu)
	}

	// Exit slow start if we're still in it
	if c.BBR.slowStart {
		c.BBR.slowStart = false
		slog.Debug("BBR exited slow start due to packet loss",
			slog.Uint64("ssthresh", c.BBR.ssthresh))
	}

	// If we're in Startup state, move directly to Normal state
	if c.BBR.state == BBRStateStartup {
		c.enterNormal(time.Now())
	}

	// Reduce cwnd by 25% on packet loss, but never below minimum
	minCwnd := uint64(4 * c.mtu)
	reducedCwnd := c.BBR.cwnd - (c.BBR.cwnd / 4)
	if reducedCwnd > minCwnd {
		c.BBR.cwnd = reducedCwnd
	} else {
		c.BBR.cwnd = minCwnd
	}

	// Also reduce pacing rate proportionally
	if c.BBR.maxBW > 0 {
		c.BBR.pacingRate = uint64(float64(c.BBR.maxBW) * 0.75) // Down to 75% of maxBW
	}

	slog.Debug("BBR responded to packet loss",
		slog.Uint64("cwnd", c.BBR.cwnd),
		slog.Uint64("pacing_rate", c.BBR.pacingRate))
}

// enterNormal transitions directly to Normal state
func (c *Connection) enterNormal(now time.Time) {
	c.BBR.state = BBRStateNormal
	c.BBR.pacingGain = 1.0
	c.BBR.cwndGain = 1.0
	c.BBR.lastProbeTime = now

	slog.Debug("BBR entering NORMAL state")
}

// applyBBRCwndBounds applies bounds to the congestion window
func (c *Connection) applyBBRCwndBounds() {
	// Minimum CWND = 4 * MTU (typical value)
	minCwnd := uint64(4 * c.mtu)
	if c.BBR.cwnd < minCwnd {
		c.BBR.cwnd = minCwnd
	}

	// Maximum CWND capping - This is optional but can prevent bufferbloat
	// A typical approach is to cap based on BDP (Bandwidth-Delay Product)
	if c.BBR.maxBW > 0 && c.BBR.rttMin > 0 {
		// Calculate BDP: bandwidth * rtt
		bdp := uint64(float64(c.BBR.maxBW) * c.BBR.rttMin.Seconds())

		// Cap cwnd at 2 * BDP (allows for some queueing)
		maxCwnd := 2 * bdp
		if c.BBR.cwnd > maxCwnd {
			c.BBR.cwnd = maxCwnd
		}
	}
}

// Helper function to convert BBR state to string for logging
func bbrStateString(state BBRState) string {
	switch state {
	case BBRStateStartup:
		return "STARTUP"
	case BBRStateNormal:
		return "NORMAL"
	default:
		return "UNKNOWN"
	}
}

// IsCwndLimited checks if we're constrained by the congestion window
func (c *Connection) IsCwndLimited() bool {
	return c.rbSnd.Size() >= int(c.BBR.cwnd)
}

// GetPacingDelay returns the time to wait before sending the next packet
func (c *Connection) GetPacingDelay(packetSize uint64) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.BBR.pacingRate <= 0 {
		return 0
	}

	// Calculate delay: packet_size / pacing_rate
	return time.Duration(float64(packetSize) / float64(c.BBR.pacingRate) * float64(time.Second))
}

// GetRTO returns the current RTO value
func (c *Connection) GetRTO() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rto
}

// GetSRTT returns the current smoothed RTT estimate
func (c *Connection) GetSRTT() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.srtt
}

// SetAlphaBeta allows customizing the smoothing factors
func (c *Connection) SetAlphaBeta(alpha, beta float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.alpha = alpha
	c.beta = beta
}

func (c *Connection) decode(decryptedData []byte, nowMicros int64) (s *Stream, isNew bool, err error) {
	p, _, payloadData, err := DecodePayload(decryptedData)
	if err != nil {
		slog.Info("error in decoding payload from new connection", slog.Any("error", err))
		return nil, false, err
	}

	// Get or create stream using StreamId from Data
	s, isNew = c.GetOrNewStreamRcv(p.StreamId)

	if len(p.Acks) > 0 {
		for _, ack := range p.Acks {

			// Slow Start: Increment cwnd until ssthresh is reached
			if c.BBR.slowStart {
				if c.BBR.cwnd == startMtu {
					c.BBR.cwnd = startMtu * 10
				} else {
					c.BBR.cwnd *= 2
				}
				if c.BBR.cwnd >= c.BBR.ssthresh {
					c.BBR.slowStart = false // Exit slow start
				}
			} else {
				//Congestion avoidance: increase cwnd by 1 MTU per RTT
				c.BBR.cwnd += uint64(1400)
			}

			sentTime := c.rbSnd.AcknowledgeRange(ack.StreamId, ack.StreamOffset, ack.Len)
			if nowMicros > sentTime {
				rtt := time.Duration(nowMicros-sentTime) * time.Millisecond
				c.UpdateRTT(rtt)
			}

		}
	}

	//TODO: handle status, e.g., we may have duplicates
	s.receive(p.StreamOffset, payloadData)

	return s, isNew, nil
}
