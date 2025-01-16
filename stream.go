package tomtp

import (
	"errors"
	"io"
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

	var encodeFunc func(snConn uint64) ([]byte, error)

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

		encodeFunc = func(snConn uint64) ([]byte, error) {
			payRaw, err := EncodePayload(p)
			if err != nil {
				return nil, err
			}
			return EncodeWriteInitSnd(s.conn.pubKeyIdRcv, s.conn.listener.pubKeyId, s.conn.prvKeyEpSnd, payRaw)
		}

	case s.conn.firstPaket && !s.conn.sender:
		overhead := CalcOverhead(p)
		if overhead < 8 {
			p.Filler = make([]byte, 8-2-n)
			overhead += 8 - n
		}

		n = min(len(b), s.conn.mtu-(overhead+MinMsgInitRcvSize))
		p.Data = b[:n]

		encodeFunc = func(snConn uint64) ([]byte, error) {
			payRaw, err := EncodePayload(p)
			if err != nil {
				return nil, err
			}
			return EncodeWriteInitRcv(s.conn.pubKeyIdRcv, s.conn.listener.pubKeyId, s.conn.pubKeyEpRcv, s.conn.prvKeyEpSnd, payRaw)
		}

	default:
		overhead := CalcOverhead(p)
		if overhead < 8 {
			p.Filler = make([]byte, 8-2-n)
			overhead += 8 - n
		}

		n = min(len(b), s.conn.mtu-(overhead+MinMsgSize))
		p.Data = b[:n]

		encodeFunc = func(snConn uint64) ([]byte, error) {
			payRaw, err := EncodePayload(p)
			if err != nil {
				return nil, err
			}
			return EncodeWriteData(s.conn.pubKeyIdRcv, s.conn.listener.pubKeyId, s.conn.sharedSecret, snConn, payRaw)
		}
	}

	status, err := s.conn.rbSnd.InsertBlockingProducer(encodeFunc)
	if err != nil {
		return 0, err
	}
	if status != SndInserted {
		return 0, nil
	}

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

	segment := s.rbRcv.RemoveBlocking()
	if segment == nil {
		if s.state >= StreamEnded {
			return 0, io.EOF
		}
		return 0, nil
	}

	n = copy(b, segment.data)
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
