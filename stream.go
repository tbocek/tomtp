package tomtp

import (
	"errors"
	"log/slog"
	"sync"
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

	mu sync.Mutex
}

func (s *Stream) NotifyStreamChange() error {
	return s.conn.listener.localConn.CancelRead()
}

func (s *Stream) ReadWrite(writeData []byte, nowMicros int64) (readData []byte, remainingWriteData []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	slog.Debug("ReadWrite", debugGoroutineID(), s.debug(), slog.String("b...", string(writeData[:min(10, len(writeData))])))

	timeoutMicros := 100 * 1000 //default time to block in read
	if s.conn.rbSnd.HasCapacity() && len(writeData) > 0 {
		//if we have data to process do not block in read, just check if there is something
		timeoutMicros = 0
	}

	err = s.conn.listener.UpdateRcv(timeoutMicros, nowMicros)
	if err != nil {
		return nil, writeData, err
	}

	_, readData, err = s.conn.rbRcv.RemoveOldestInOrder(s.streamId)
	if err != nil {
		return nil, writeData, err
	}

	if len(writeData) > 0 {
		var n int
		n, err = s.conn.rbSnd.Insert(s.streamId, writeData)
		if err != nil {
			return nil, writeData, err
		}
		remainingWriteData = writeData[n:]
		err = s.conn.listener.UpdateSnd(nowMicros)
		if err != nil {
			return nil, writeData, err
		}
	}

	return readData, remainingWriteData, err
}

func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}

	s.closed = true
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
