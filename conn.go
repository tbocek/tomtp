package tomtp

import (
	"crypto/ecdh"
	"fmt"
	"log/slog"
	"net"
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
	remoteAddr            net.Addr
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
	rbSnd                 *SendBuffer // Send buffer for outgoing data, handles the global sn
	bytesWritten          uint64
	mtu                   int
	sender                bool
	firstPaket            bool
	isRollover            bool
	snCrypto              uint64 //this is 48bit
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

type BBR struct {
	pacingRate     uint64        // Bytes per second
	cwnd           uint64        // Congestion window in bytes
	rttMin         time.Duration // Minimum RTT observed
	roundTripCount uint64

	basePacingRate       uint64  // Starting pacing rate
	pacingIncreaseFactor float64 // Multiplicative factor to increase pacing rate
}

func NewBBR() BBR {
	initialPacingRate := uint64(12000) // Start with initial pacing rate, adjust later (bytes per second).
	return BBR{
		pacingRate:           initialPacingRate,        // Initial pacing rate
		cwnd:                 12000,                    // Initial congestion window.  QUIC's default is ~12KB.
		rttMin:               time.Duration(time.Hour), // Initialize to a very large value
		basePacingRate:       initialPacingRate,
		pacingIncreaseFactor: 0.01, //1% increase
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

func (c *Connection) NewStreamSnd(streamId uint32) (*Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.streams[streamId]; !ok {
		s := &Stream{
			streamId:         streamId,
			streamOffsetNext: 0,
			state:            StreamStarting,
			conn:             c,
			rbRcv:            NewReceiveBuffer(maxRingBuffer),
			mu:               sync.Mutex{},
		}
		c.streams = make(map[uint32]*Stream)
		c.streams[streamId] = s
		return s, nil
	} else {
		return nil, fmt.Errorf("stream %x already exists", streamId)
	}
}

func (c *Connection) GetOrNewStreamRcv(streamId uint32) (*Stream, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if stream, ok := c.streams[streamId]; !ok {
		s := &Stream{
			streamId:         streamId,
			streamOffsetNext: 0,
			state:            StreamStarting,
			conn:             c,
			rbRcv:            NewReceiveBuffer(maxRingBuffer),
			mu:               sync.Mutex{},
		}
		c.streams = make(map[uint32]*Stream)
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

		// Bound RTO to min and max values
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

	// Bound RTO to min and max values
	if c.rto < c.minRTO {
		c.rto = c.minRTO
	} else if c.rto > c.maxRTO {
		c.rto = c.maxRTO
	}

	// Update BBR
	if rttMeasurement < c.rttMin {
		c.rttMin = rttMeasurement
		// Increase pacing rate based on decreased RTT
		c.pacingRate = c.basePacingRate + uint64(float64(c.basePacingRate)*c.pacingIncreaseFactor)
	}
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

func (c *Connection) decode(decryptedData []byte, nowMillis uint64) (s *Stream, isNew bool, err error) {
	p, _, err := DecodePayload(decryptedData)
	if err != nil {
		slog.Info("error in decoding payload from new connection", slog.Any("error", err))
		return nil, false, err
	}

	// Get or create stream using StreamId from Data
	s, isNew = c.GetOrNewStreamRcv(p.StreamId)

	if len(p.Acks) > 0 {
		for _, ack := range p.Acks {
			sentTime := c.rbSnd.AcknowledgeRange(ack.StreamId, ack.StreamOffset, ack.Len)
			if nowMillis > sentTime {
				rtt := time.Duration(nowMillis-sentTime) * time.Millisecond
				c.UpdateRTT(rtt)
			}

		}
	}

	//TODO: handle status
	s.receive(p.Data, p.StreamOffset)

	return s, isNew, nil
}
