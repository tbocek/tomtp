package tomtp

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

type StreamState uint8

const (
	StreamStarting StreamState = iota
	StreamOpen                 //from here on, it does not matter who opened the stream
	StreamEnding
	StreamEnded
)

type Stream struct {
	streamId        uint32
	closing         bool
	sender          bool
	state           StreamState
	currentRcvSn    uint32
	conn            *Connection
	rbRcv           *RingBufferRcv[[]byte]
	rbSnd           *RingBufferSnd[[]byte]
	totalOutgoing   int
	totalIncoming   int
	bytesWritten    int //statistics
	writeBuffer     []byte
	writeBufferSize int
	mu              *sync.Mutex
}

func (c *Connection) NewMaintenance() (*Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var mu sync.Mutex
	if _, ok := c.streams[math.MaxUint32]; !ok {
		s := &Stream{
			streamId:        math.MaxUint32,
			sender:          true,
			state:           StreamOpen,
			conn:            c,
			rbRcv:           nil,
			rbSnd:           nil,
			writeBuffer:     []byte{},
			writeBufferSize: startMtu - (MinMsgSize + protoHeaderSize),
			mu:              &mu,
		}
		c.streams[math.MaxUint32] = s
		return s, nil
	} else {
		return nil, fmt.Errorf("maintenance stream %x already exists", math.MaxUint32)
	}
}

func (c *Connection) New(streamId uint32) (*Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var mu sync.Mutex
	if _, ok := c.streams[streamId]; !ok {
		s := &Stream{
			streamId:        streamId,
			sender:          true,
			state:           StreamStarting,
			conn:            c,
			rbRcv:           NewRingBufferRcv[[]byte](maxRingBuffer, maxRingBuffer),
			rbSnd:           NewRingBufferSnd[[]byte](maxRingBuffer, maxRingBuffer),
			writeBuffer:     []byte{},
			writeBufferSize: startMtu - (MinMsgInitSize + protoHeaderSize),
			mu:              &mu,
		}
		c.streams[streamId] = s
		return s, nil
	} else {
		return nil, fmt.Errorf("stream %x already exists", streamId)
	}
}

func (c *Connection) GetOrCreate(streamId uint32) (*Stream, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var mu sync.Mutex
	if stream, ok := c.streams[streamId]; !ok {
		s := &Stream{
			streamId:        streamId,
			sender:          false,
			state:           StreamStarting,
			conn:            c,
			rbRcv:           NewRingBufferRcv[[]byte](1, maxRingBuffer),
			rbSnd:           NewRingBufferSnd[[]byte](1, maxRingBuffer),
			writeBuffer:     []byte{},
			writeBufferSize: startMtu - (MinMsgInitReplySize + protoHeaderSize),
			mu:              &mu,
		}
		c.streams[streamId] = s
		return s, true
	} else {
		return stream, false
	}
}

func (s *Stream) Close() {
	slog.Debug("close stream", debugGoroutineID(), s.debug())
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = StreamEnding
	slog.Debug("close stream done", debugGoroutineID(), s.debug())
	//TODO: wait until StreamEnded
}

func (s *Stream) Update(nowMillis uint64) (sleepMillis uint64) {
	slog.Debug("Update", debugGoroutineID(), s.debug(), slog.Any("nowMillis", nowMillis))
	s.mu.Lock()
	defer s.mu.Unlock()

	//get those that are ready to send, and send them. Store the time when this happened
	var segment *SndSegment[[]byte]
	n := 0
	sleepMillis, segment = s.rbSnd.ReadyToSend(s.conn.rtoMillis, nowMillis)

	if segment == nil && s.rbRcv.HasPendingAck() {
		t, b, err := s.doEncode([]byte{})
		if err != nil {
			slog.Info("outgoing msg failed", slog.Any("error", err))
			s.Close()
		}
		s.bytesWritten += t
		segment = &SndSegment[[]byte]{
			sn:         0,
			data:       b,
			sentMillis: 0,
		}

		slog.Debug("SndUDP Ack/Ping", debugGoroutineID(), s.debug(), slog.Int("n", n), slog.Any("sn", segment.sn))
	}

	if segment != nil {
		n, err := s.conn.listener.handleOutgoingUDP(segment.data, s.conn.remoteAddr)
		s.conn.lastSentMillis = nowMillis
		if err != nil {
			slog.Info("outgoing msg failed", slog.Any("error", err))
			s.Close()
		}
		slog.Debug("SndUDP", debugGoroutineID(), s.debug(), slog.Int("n", n), slog.Any("sn", segment.sn))
	}

	sleepMillis, _ = s.rbSnd.ReadyToSend(s.conn.rtoMillis, nowMillis)
	return sleepMillis
}

func (s *Stream) ReadFull() ([]byte, error) {
	var buf []byte
	for {
		b := make([]byte, 1024)
		n, err := s.ReadAt(b, 0)
		if err != nil {
			return nil, err
		}
		buf = append(buf, b[:n]...)
		if n < len(b) {
			break
		}
	}
	return buf, nil
}

func (s *Stream) Read(b []byte) (int, error) {
	return s.ReadAt(b, 0)
}

func (s *Stream) ReadAt(b []byte, offset int) (int, error) {
	slog.Debug("ReadAt", debugGoroutineID(), s.debug(), slog.Int("offset", offset))
	s.mu.Lock()
	defer s.mu.Unlock()

	//wait until a segment becomes available
	segment := s.rbRcv.RemoveBlocking()

	if segment == nil {
		return 0, nil
	}

	offset = copy(b[offset:], segment.data)

	slog.Debug("ReadAt", debugGoroutineID(), s.debug(), slog.Int("new offset", offset))
	return offset, nil
}

func (s *Stream) Write(b []byte) (n int, err error) {
	slog.Debug(
		"Write",
		debugGoroutineID(),
		s.debug(),
		slog.String("data", string(b)),
		slog.Int("n", len(b)))

	s.mu.Lock()
	defer s.mu.Unlock()

	for len(b) > 0 {
		remainingBuffer := s.writeBufferSize - len(s.writeBuffer)
		if remainingBuffer > 0 {
			// Fill the buffer
			if len(b) > remainingBuffer {
				s.writeBuffer = append(s.writeBuffer, b[:remainingBuffer]...)
				b = b[remainingBuffer:]
				n += remainingBuffer
			} else {
				s.writeBuffer = append(s.writeBuffer, b...)
				n += len(b)
				b = nil
			}

			// If buffer is full, flush it
			if len(s.writeBuffer) == s.writeBufferSize {
				if nn, err := s.flush(); err != nil {
					return n, err
				} else {
					n += nn
				}
			}
		} else {
			// Buffer is full, flush
			if nn, err := s.flush(); err != nil {
				return n, err
			} else {
				n += nn
			}

			// Then, write directly
			t, nn, err := s.doWrite(b)
			if err != nil {
				return n, err
			}
			n += nn
			s.bytesWritten += t

			b = b[nn:]
		}
	}

	return n, nil
}

func (s *Stream) Flush() (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err = s.flush()
	return err
}

func (s *Stream) flush() (n int, err error) {
	slog.Debug(
		"Flush",
		debugGoroutineID(),
		s.debug(),
		slog.String("data", string(s.writeBuffer)),
		slog.Int("n", len(s.writeBuffer)))

	if len(s.writeBuffer) > 0 {
		var t int
		t, n, err = s.doWrite(s.writeBuffer)
		if err != nil {
			return n, err
		}

		s.bytesWritten += t

		if s.writeBufferSize != startMtu-(MinMsgSize+protoHeaderSize) {
			//after first write, enlarge the buffer
			s.writeBufferSize = startMtu - (MinMsgSize + protoHeaderSize)
		}
		s.writeBuffer = s.writeBuffer[:0]
	}
	return n, nil
}

func (s *Stream) doEncode(b []byte) (t int, packet []byte, err error) {
	var buffer bytes.Buffer
	var buffer2 bytes.Buffer

	rbFree := uint64(0)
	rbAck := uint64(0)
	if s.rbRcv != nil {
		rbFree = s.rbRcv.Free()
		rbAck = s.rbRcv.NextAck()
	}
	sn := uint64(0)
	if s.rbSnd != nil {
		sn = s.rbSnd.maxSn
	}

	if s.sender && s.state == StreamStarting { // stream init, can be closing already
		if s.closing {
			s.state = StreamEnding
		}

		maxWrite := startMtu - (MinMsgInitSize + protoHeaderSize)
		if len(b) > maxWrite {
			return 0, nil, errors.New("init payload too large to send")
		}

		_, err = EncodePayload(
			s.streamId,
			s.closing,
			rbFree,
			rbAck,
			b,
			&buffer)
		if err != nil {
			return 0, nil, err
		}

		slog.Debug(
			"EncPayload",
			debugGoroutineID(),
			s.debug(),
			slog.Any("state", s.state))

		t, err = EncodeWriteInit(
			s.conn.pubKeyIdRcv,
			s.conn.listener.pubKeyId,
			s.conn.privKeyEpSnd,
			sn,
			buffer.Bytes(),
			&buffer2)
		if err != nil {
			return 0, nil, err
		}
		slog.Debug("EncodeWriteInit", debugGoroutineID(), s.debug(), slog.Int("t", t))
	} else if !s.sender && s.state == StreamStarting {
		if s.closing {
			s.state = StreamEnding
		}

		maxWrite := startMtu - (MinMsgInitReplySize + protoHeaderSize)
		if len(b) > maxWrite {
			return 0, nil, errors.New("init reply payload too large to send")
		}

		_, err = EncodePayload(
			s.streamId,
			s.closing,
			rbFree,
			rbAck,
			b,
			&buffer)
		if err != nil {
			return 0, nil, err
		}

		slog.Debug(
			"EncPayload",
			debugGoroutineID(),
			s.debug(),
			slog.Any("state", s.state))

		t, err = EncodeWriteInitReply(
			s.conn.pubKeyIdRcv,
			s.conn.listener.privKeyId,
			s.conn.privKeyEpSnd,
			s.conn.sharedSecret,
			sn,
			buffer.Bytes(),
			&buffer2)
		if err != nil {
			return 0, nil, err
		}
		slog.Debug("EncodeWriteInitReply", debugGoroutineID(), s.debug(), slog.Int("t", t))
	} else {

		if s.closing {
			s.state = StreamEnding
		}

		maxWrite := startMtu - (MinMsgSize + protoHeaderSize)
		if len(b) > maxWrite {
			return 0, nil, errors.New("payload too large to send")
		}

		_, err = EncodePayload(
			s.streamId,
			s.closing,
			rbFree,
			rbAck,
			b,
			&buffer)
		if err != nil {
			return 0, nil, err
		}

		slog.Debug(
			"EncPayload",
			debugGoroutineID(),
			s.debug(),
			slog.Any("state", s.state))

		t, err = EncodeWriteMsg(
			s.sender,
			s.conn.pubKeyIdRcv,
			s.conn.listener.pubKeyId,
			s.conn.sharedSecret,
			sn,
			buffer.Bytes(),
			&buffer2)
		if err != nil {
			return 0, nil, err
		}
		slog.Debug("encoded msg", debugGoroutineID(), s.debug(), slog.Int("t", t))
	}

	return t, buffer2.Bytes(), nil
}

func (s *Stream) doWrite(b []byte) (t int, n int, err error) {

	t, b2, err := s.doEncode(b)

	sn, stat := s.rbSnd.InsertBlocking(b2)
	if stat != SndInserted {
		return 0, 0, fmt.Errorf("status: %v", stat)
	}

	slog.Debug("InsertBlockSndSegment", debugGoroutineID(), s.debug(), slog.Any("sn", sn))
	return t, len(b), nil
}

func (s *Stream) debug() slog.Attr {
	localAddr := s.conn.listener.localConn.LocalAddr().String()

	if remoteAddr, ok := s.conn.remoteAddr.(*net.UDPAddr); ok {
		lastColonIndex := strings.LastIndex(localAddr, ":")
		return slog.String("net", localAddr[lastColonIndex+1:]+"=>"+strconv.Itoa(remoteAddr.Port))
	} else {
		return slog.String("net", localAddr+"=>"+s.conn.remoteAddr.String())
	}
}

func debugGoroutineID() slog.Attr {
	buf := make([]byte, 64)
	n := runtime.Stack(buf, false)
	buf = buf[:n]
	idField := bytes.Fields(buf)[1]
	var id int64
	fmt.Sscanf(string(idField), "%d", &id)
	return slog.String("gid", fmt.Sprintf("0x%02x", id))
}
