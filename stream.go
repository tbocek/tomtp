package tomtp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"
)

type StreamState uint8

var (
	ErrStreamClosed = errors.New("stream closed")
)

type Stream struct {
	// Connection info
	streamId uint32
	conn     *Connection
	closed   bool

	// Reliable delivery buffers
	//rbRcv *ReceiveBuffer // Receive buffer for incoming dataToSend

	// Statistics
	bytesRead        uint64
	lastWindowUpdate uint64

	// Stream state
	lastActive     uint64 // Unix timestamp of last activity
	closeTimeout   uint64 // Unix timestamp for close timeout
	closeInitiated bool
	closePending   bool

	closeCtx      context.Context
	closeCancelFn context.CancelFunc

	mu sync.Mutex
}

func (s *Stream) WriteWithTime(b []byte, nowMicros int64) (nTot int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	slog.Debug("Write", debugGoroutineID(), s.debug(), slog.String("b...", string(b[:min(10, len(b))])))

	for len(b) > 0 {
		var n int
		n, err = s.conn.rbSnd.InsertBlocking(s.closeCtx, s.streamId, b)
		if err != nil {
			return nTot, err
		}
		nTot += n

		// Signal the listener that there is dataToSend to send

		err = s.conn.listener.localConn.CancelRead()
		if err != nil {
			return nTot, err
		}

		b = b[n:]
	}

	return nTot, nil
}

func (s *Stream) Write(b []byte) (nTot int, err error) {
	return s.WriteWithTime(b, time.Now().UnixMicro())
}

func (s *Stream) Read(b []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	slog.Debug("read dataToSend start", debugGoroutineID(), s.debug())

	_, data, err := s.conn.rbRcv.RemoveOldestInOrderBlocking(s.closeCtx, s.streamId)
	if err != nil {
		return 0, err
	}
	if data == nil {
		if s.closed {
			return 0, io.EOF
		}
		return 0, nil
	}

	n = copy(b, data)
	slog.Debug("read Data done", debugGoroutineID(), s.debug(), slog.String("b...", string(b[:min(10, n)])))
	s.bytesRead += uint64(n)
	return n, nil
}

func (s *Stream) ReadBytes() (b []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	slog.Debug("read dataToSend start", debugGoroutineID(), s.debug())

	_, data, err := s.conn.rbRcv.RemoveOldestInOrderBlocking(s.closeCtx, s.streamId)
	if err != nil {
		return nil, err
	}

	s.bytesRead += uint64(len(data))
	return data, nil
}

func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
	s.closeCancelFn()
	return nil
}

func (s *Stream) debug() slog.Attr {
	if s.conn == nil {
		return slog.Any("s.conn", "is null")
	} else if s.conn.listener == nil {
		return slog.Any("s.conn.listener", "is null")
	}
	return s.conn.listener.debug(s.conn.remoteAddr)
}

func (s *Stream) receive(offset uint64, decodedData []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(decodedData) > 0 {
		s.conn.rbRcv.Insert(s.streamId, offset, decodedData)
	}
}

func (s *Stream) calcLen(mtu int, ack bool) uint16 {
	return uint16(mtu - s.Overhead(ack))
}
