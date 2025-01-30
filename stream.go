package tomtp

import (
	"errors"
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

	// Flow control
	rcvWndSize uint64 // Receive window size
	sndWndSize uint64 // Send window size

	// Reliable delivery buffers
	rbRcv *ReceiveBuffer // Receive buffer for incoming data

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

	slog.Debug("Write", debugGoroutineID(), s.debug(), slog.String("b...", string(b[:min(10, len(b))])))
	return s.encode(b, n)
}

func (s *Stream) Read(b []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	slog.Debug("read data start", debugGoroutineID(), s.debug())

	segment := s.rbRcv.RemoveOldestInOrder()
	if segment == nil {
		if s.state >= StreamEnded {
			return 0, io.EOF
		}
		return 0, nil
	}

	n = copy(b, segment.data)
	slog.Debug("read Data done", debugGoroutineID(), s.debug(), slog.String("b...", string(b[:min(10, n)])))
	s.bytesRead += uint64(n)
	return n, nil
}

func (s *Stream) Update() error {
	if s.state == StreamEnding || s.conn.state == ConnectionEnding || len(s.rbRcv.acks) > 0 {
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

func (s *Stream) debug() slog.Attr {
	return s.conn.listener.debug(s.conn.remoteAddr)
}
