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
	streamId uint32
	streamSn uint64
	conn     *Connection
	state    StreamState
	isSender bool // Whether this stream initiated the connection

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
	sender    bool
}

func (s *Stream) Write(b []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state >= StreamEnding {
		return 0, ErrStreamClosed
	}

	/*p := Payload{
		StreamId:            s.streamId,
		StreamFlagClose:     false,
		CloseConnectionFlag: s.conn.rbSnd.req.requestConnClose,
		AckCount:            0,
		IsRecipient:         false,
		RcvWndSize:          0,
		AckSns:              nil,
		SnStream:            0,
		Data:                nil,
		Filler:              nil,
	}*/

	//s.conn.rbSnd.InsertBlocking()

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

// check request flags if they need to be pushed out
func (s *Stream) Update() {
	if s.conn.rbSnd.req.requestConnClose {

		//s.conn.rbSnd.InsertBlocking()
	}
}

func (s *Stream) CloseAll() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.conn.rbSnd.req.requestConnClose = true
	return nil
}

func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state >= StreamEnding {
		return nil
	}

	s.state = StreamEnding
	s.conn.rbSnd.req.requestStreamClone = append(s.conn.rbSnd.req.requestStreamClone, s.streamId)

	return nil
}
