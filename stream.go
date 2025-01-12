package tomtp

import (
	"errors"
	"io"
	"sync"
	"time"
)

type StreamState uint8

const (
	StreamStarting StreamState = iota
	StreamOpen
	StreamEnding
	StreamEnded
)

// Window management constants
const (
	defaultInitialWindow = 65536   // 64KB initial window
	maxWindowSize        = 1 << 48 // 48-bit max window
	windowUpdateThresh   = 0.25    // Update window when 25% remaining
	closeTimeout         = 3000    // 3 seconds timeout for closing
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
	rbSnd *RingBufferSnd[[]byte] // Send buffer for outgoing data.

	// Write buffering
	writeBuffer     []byte
	writeBufferSize int

	// Statistics
	bytesWritten     uint64
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

	if s.state == StreamStarting {
		s.cond.Wait()
	}

	remaining := s.writeBufferSize - len(s.writeBuffer)
	if remaining > 0 {
		n = copy(s.writeBuffer[len(s.writeBuffer):], b)
		s.writeBuffer = s.writeBuffer[:len(s.writeBuffer)+n]
		b = b[n:]
	}

	if len(s.writeBuffer) == s.writeBufferSize || len(b) > 0 {
		if err := s.flush(); err != nil {
			return n, err
		}

		for len(b) > 0 {
			chunk := b
			if len(chunk) > s.writeBufferSize {
				chunk = b[:s.writeBufferSize]
			}

			if err := s.writeChunk(chunk); err != nil {
				return n, err
			}

			n += len(chunk)
			b = b[len(chunk):]
		}
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
	s.updateReceiveWindow()

	return n, nil
}

func (s *Stream) CloseAll() error {
	//set flag close conn to be sent
	return nil
}

func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state >= StreamEnding {
		return nil
	}

	s.closeOnce.Do(func() {
		s.state = StreamEnding
		s.closePending = true
		s.flush()
		s.sendClose()
	})

	return nil
}

func (s *Stream) Update(nowMillis uint64) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state == StreamStarting && nowMillis-s.lastActive > 3000 {
		s.state = StreamEnded
		return 0
	}

	if s.state == StreamEnding && s.closeTimeout != 0 {
		if nowMillis > s.closeTimeout {
			s.state = StreamEnded
			return 0
		}
	}

	nextTimeout, segment := s.rbSnd.ReadyToSend(s.conn.rtoMillis, nowMillis)
	if segment != nil {
		_, err := s.conn.listener.handleOutgoingUDP(segment.data, s.conn.remoteAddr)
		if err != nil {
			s.state = StreamEnded
			return 0
		}
		s.lastActive = nowMillis
	}

	if s.shouldUpdateWindow() {
		s.sendWindowUpdate()
	}

	if s.closeTimeout != 0 {
		timeoutDelta := s.closeTimeout - nowMillis
		if timeoutDelta < nextTimeout {
			nextTimeout = timeoutDelta
		}
	}

	return nextTimeout
}

func (s *Stream) flush() error {
	if len(s.writeBuffer) == 0 {
		return nil
	}

	if err := s.writeChunk(s.writeBuffer); err != nil {
		return err
	}

	s.writeBuffer = s.writeBuffer[:0]
	return nil
}

func (s *Stream) doEncode(data []byte) (uint64, []byte, error) {
	//var buf bytes.Buffer

	/*buf, err := EncodePayload(
		s.streamId,
		s.state == StreamEnding, // closeFlag
		s.getReceiveWindow(),    // rcvWndSize
		s.rbRcv.NextAck(),       // ackSn
		data)

	if err != nil {
		return 0, nil, err
	}

	sn, status := s.rbSnd.Insert(buf.Bytes())
	if status == SndOverflow {
		return 0, nil, ErrWriteTooLarge
	}

	var msgBuf []byte

	if s.state == StreamStarting && s.isSender {
		msgBuf, err = EncodeWriteInitSnd(
			s.conn.pubKeyIdRcv,
			s.conn.listener.pubKeyId,
			s.conn.privKeyEpSnd,
			buf.Bytes())
	} else if s.state == StreamStarting && !s.isSender {
		msgBuf, err = EncodeWriteInitRcv(
			s.conn.pubKeyIdRcv,
			s.conn.listener.privKeyId,
			s.conn.pubKeyEpRcv,
			s.conn.privKeyEpSnd,
			buf.Bytes())
	} else {
		msgBuf, err = EncodeWriteData(
			s.conn.pubKeyIdRcv,
			s.conn.listener.pubKeyId,
			s.conn.sharedSecret,
			sn,
			buf.Bytes())
	}

	if err != nil {
		return 0, nil, err
	}

	*/

	return 0, nil, nil
}

func (s *Stream) writeChunk(data []byte) error {
	_, encoded, err := s.doEncode(data)
	if err != nil {
		return err
	}

	s.bytesWritten += uint64(len(data))
	_, err = s.conn.listener.handleOutgoingUDP(encoded, s.conn.remoteAddr)
	return err
}

func (s *Stream) sendInit() error {
	_, encoded, err := s.doEncode(nil)
	if err != nil {
		return err
	}

	_, err = s.conn.listener.handleOutgoingUDP(encoded, s.conn.remoteAddr)
	return err
}

func (s *Stream) handleInitReply() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state != StreamStarting {
		return errors.New("unexpected init reply in current state")
	}

	s.state = StreamOpen
	s.cond.Broadcast()
	return nil
}

func (s *Stream) sendWindowUpdate() error {
	_, encoded, err := s.doEncode(nil)
	if err != nil {
		return err
	}

	_, err = s.conn.listener.handleOutgoingUDP(encoded, s.conn.remoteAddr)
	return err
}

func (s *Stream) updateReceiveWindow() {
	consumed := s.bytesRead - s.lastWindowUpdate
	if consumed > uint64(float64(s.rcvWndSize)*windowUpdateThresh) {
		s.lastWindowUpdate = s.bytesRead
		s.sendWindowUpdate()
	}
}

func (s *Stream) shouldUpdateWindow() bool {
	if s.state >= StreamEnding {
		return false
	}
	availableWindow := s.rcvWndSize - uint64(s.rbRcv.Size())
	return availableWindow < uint64(float64(s.rcvWndSize)*windowUpdateThresh)
}

func (s *Stream) getReceiveWindow() uint64 {
	window := s.rcvWndSize - uint64(s.rbRcv.Size())
	if window > maxWindowSize {
		return maxWindowSize
	}
	return window
}

func (s *Stream) updateSendWindow(peerWindow uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.sndWndSize = min(peerWindow, maxWindowSize)
	if s.sndWndSize > 0 {
		s.cond.Broadcast()
	}
}

func (s *Stream) sendClose() error {
	_, encoded, err := s.doEncode(nil)
	if err != nil {
		return err
	}

	if _, err = s.conn.listener.handleOutgoingUDP(encoded, s.conn.remoteAddr); err != nil {
		return err
	}

	s.closeTimeout = uint64(time.Now().UnixMilli() + closeTimeout)
	return nil
}

func (s *Stream) handleClose() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.state >= StreamEnding {
		return
	}

	if s.closePending {
		s.state = StreamEnded
		return
	}

	s.state = StreamEnding
	s.sendClose()
}
