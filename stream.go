package tomtp

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

type StreamState uint8

const (
	StreamStarting StreamState = iota
	StreamOpen
	StreamEnding
	StreamEnded
)

var (
	ErrStreamClosed  = errors.New("stream closed")
	ErrWriteTooLarge = errors.New("write exceeds maximum size")
	ErrTimeout       = errors.New("operation timed out")
)

type Stream struct {
	// Connection info
	streamId     uint32
	streamSnNext uint64
	conn         *Connection
	state        StreamState
	isSender     bool // Whether this stream initiated the connection

	// Flow control
	rcvWndSize uint64 // Receive window size
	sndWndSize uint64 // Send window size

	// Reliable delivery buffers
	rbRcv *RingBufferRcv[[]byte] // Receive buffer for incoming data
	sn    uint64
	// Write buffering
	writeBuffer     []byte
	writeBufferSize int

	// Statistics
	bytesRead        uint64
	lastWindowUpdate uint64

	// Stream state
	lastActive     uint64 // Unix timestamp of last activity
	closeTimeout   uint64 // Unix timestamp for close timeout
	closeInitiated bool
	closePending   bool

	mu        sync.Mutex
	closeOnce sync.Once
	cond      *sync.Cond
}

func (s *Stream) Write(b []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	slog.Debug("Write", debugGoroutineID(), s.conn.listener.debug(s.conn.remoteAddr), slog.String("b...", string(b[:min(10, len(b))])))

	if s.state == StreamEnded || s.conn.state == ConnectionEnded {
		return 0, ErrStreamClosed
	}

	p := &Payload{
		StreamId:            s.streamId,
		StreamFlagClose:     s.state == StreamEnding,
		CloseConnectionFlag: s.conn.state == ConnectionEnding,
		IsRecipient:         !s.conn.sender,
		RcvWndSize:          uint32(s.rbRcv.Size()), //TODO: make it 32bit
		AckSns:              s.rbRcv.toAckSnConn,
		SnStream:            s.streamSnNext,
		Data:                []byte{},
		Filler:              nil,
	}

	var encodeFunc func(snConn uint64) ([]byte, int, error)

	switch {
	case s.conn.firstPaket && s.conn.sender:
		p.Filler = []byte{}
		overhead := CalcOverhead(p) + MsgInitSndSize
		// Calculate how much space we have left in the MTU
		remainingSpace := s.conn.mtu - (len(b) + overhead)
		// If we have space left, fill it
		if remainingSpace > 0 {
			p.Filler = make([]byte, remainingSpace)
			n = len(b)
		} else {
			n = s.conn.mtu - overhead
		}
		p.Data = b[:n]

		encodeFunc = func(snConn uint64) ([]byte, int, error) {
			payRaw, err := EncodePayload(p)
			if err != nil {
				return nil, 0, err
			}
			slog.Debug("EncodeWriteInitSnd", debugGoroutineID(), s.debugKeys(), s.conn.listener.debug(s.conn.remoteAddr), slog.Int("len(payRaw)", len(payRaw)))
			enc, err := EncodeWriteInitSnd(s.conn.pubKeyIdRcv, s.conn.listener.pubKeyId, s.conn.prvKeyEpSnd, payRaw)

			if err != nil {
				return nil, 0, err
			}

			return enc, len(enc), nil
		}

	case s.conn.firstPaket && !s.conn.sender:
		overhead := CalcOverhead(p)
		if overhead < 8 {
			p.Filler = make([]byte, 8-2-n)
			overhead += 8 - n
		}

		n = min(len(b), s.conn.mtu-(overhead+MinMsgInitRcvSize))
		p.Data = b[:n]

		encodeFunc = func(snConn uint64) ([]byte, int, error) {
			payRaw, err := EncodePayload(p)
			if err != nil {
				return nil, 0, err
			}
			slog.Debug("EncodeWriteInitRcv", debugGoroutineID(), s.debugKeys(), s.conn.listener.debug(s.conn.remoteAddr), slog.Int("len(payRaw)", len(payRaw)))
			enc, err := EncodeWriteInitRcv(s.conn.pubKeyIdRcv, s.conn.listener.pubKeyId, s.conn.pubKeyEpRcv, s.conn.prvKeyEpSnd, payRaw)

			if err != nil {
				return nil, 0, err
			}

			return enc, len(enc), nil
		}

	default:
		overhead := CalcOverhead(p)
		if overhead < 8 {
			p.Filler = make([]byte, 8-2-n)
			overhead += 8 - n
		}

		n = min(len(b), s.conn.mtu-(overhead+MinMsgSize))
		p.Data = b[:n]

		encodeFunc = func(snConn uint64) ([]byte, int, error) {
			payRaw, err := EncodePayload(p)
			if err != nil {
				return nil, 0, err
			}
			slog.Debug("EncodeWriteData", debugGoroutineID(), s.debugKeys(), s.conn.listener.debug(s.conn.remoteAddr), slog.Int("len(payRaw)", len(payRaw)))
			enc, err := EncodeWriteData(s.conn.prvKeyEpSnd.PublicKey(), s.conn.pubKeyIdRcv, s.conn.sender, s.conn.sharedSecret, snConn, payRaw)
			if err != nil {
				return nil, 0, err
			}

			return enc, len(enc), nil
		}
	}

	dataLen, status, err := s.conn.rbSnd.InsertProducerBlocking(encodeFunc)
	if err != nil {
		return 0, err
	}
	if status != SndInserted {
		return 0, nil
	}

	slog.Debug("EncodeWriteData done", debugGoroutineID(), s.debugKeys(), s.conn.listener.debug(s.conn.remoteAddr), slog.Int("dataLen", dataLen))

	if s.conn.firstPaket {
		s.conn.firstPaket = false
	}

	if s.state == StreamEnding {
		s.state = StreamEnded
	}

	if s.conn.state == ConnectionEnding {
		s.conn.state = ConnectionEnded
	}

	//only if we send data, increase the sequence number of the stream
	if len(p.Data) > 0 {
		s.streamSnNext = (s.streamSnNext + 1) % MaxUint48
	}

	return n, nil
}

func (s *Stream) Read(b []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	slog.Debug("Read", debugGoroutineID(), s.conn.listener.debug(s.conn.remoteAddr))

	segment := s.rbRcv.RemoveBlocking()
	if segment == nil {
		if s.state >= StreamEnded {
			return 0, io.EOF
		}
		return 0, nil
	}

	n = copy(b, segment.data)
	slog.Debug("Read Data", debugGoroutineID(), s.conn.listener.debug(s.conn.remoteAddr), slog.String("b...", string(b[:min(10, n)])))
	s.bytesRead += uint64(n)
	return n, nil
}

func (s *Stream) Update() error {
	if s.state == StreamEnding || s.conn.state == ConnectionEnding || len(s.rbRcv.toAckSnConn) > 0 {
		_, err := s.Write([]byte{})
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Stream) CloseAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.conn.state >= ConnectionEnding {
		return nil
	}

	s.conn.state = ConnectionEnding
	return nil
}

func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state >= StreamEnding {
		return nil
	}

	s.state = StreamEnding
	return nil
}

func (s *Stream) debugKeys() slog.Attr {

	formatBytes := func(b []byte) string {
		if len(b) <= 10 {
			return fmt.Sprintf("%v", b)
		}
		return fmt.Sprintf("%v...", b[:10])
	}

	var pubKeyEpRcvStr string
	if s.conn.pubKeyEpRcv != nil {
		pubKeyEpRcvStr = formatBytes(s.conn.pubKeyEpRcv.Bytes())
	} else {
		pubKeyEpRcvStr = "nil"
	}

	return slog.Group("keys",
		slog.String("pubKeyIdRcv", formatBytes(s.conn.pubKeyIdRcv.Bytes())),
		slog.String("pubKeyIdSnd", formatBytes(s.conn.listener.pubKeyId.Bytes())),
		slog.String("prvKeyEpSnd", formatBytes(s.conn.prvKeyEpSnd.Bytes())),
		slog.String("pubKeyEpSnd", formatBytes(s.conn.prvKeyEpSnd.PublicKey().Bytes())),
		slog.String("pubKeyEpRcv", pubKeyEpRcvStr),
	)
}
