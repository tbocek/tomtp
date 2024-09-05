package tomtp

import (
	"bytes"
	"fmt"
	"log/slog"
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
	streamId      uint32
	closing       bool
	sender        bool
	state         StreamState
	currentSndSn  uint32
	currentRcvSn  uint32
	conn          *Connection
	rbRcv         *RingBufferRcv[[]byte]
	rbSnd         *RingBufferSnd[[]byte]
	totalOutgoing int
	totalIncoming int
	bytesWritten  int //statistics
	mu            *sync.Mutex
}

func (c *Connection) New(streamId uint32) (*Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var mu sync.Mutex
	if _, ok := c.streams[streamId]; !ok {
		s := &Stream{
			streamId: streamId,
			sender:   true,
			state:    StreamStarting,
			conn:     c,
			rbRcv:    NewRingBufferRcv[[]byte](maxRingBuffer, maxRingBuffer),
			rbSnd:    NewRingBufferSnd[[]byte](maxRingBuffer, maxRingBuffer),
			mu:       &mu,
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
			streamId: streamId,
			sender:   false,
			state:    StreamStarting,
			conn:     c,
			rbRcv:    NewRingBufferRcv[[]byte](1, maxRingBuffer),
			rbSnd:    NewRingBufferSnd[[]byte](1, maxRingBuffer),
			mu:       &mu,
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
	//var segment *SndSegment[[]byte]
	//sleepMillis, segment = s.rbSnd.ReadyToSend(s.conn.rtoMillis, nowMillis)

	//if the stream ends, send now at least one packet, if we already
	//have packets that we will send anyway then send those.
	/*needSendAtLeastOne := s.state == StreamEnding || s.state == StreamRcvStarting
	//check if there is something in the write queue
	segment := s.rbSnd.ReadyToSend(s.conn.ptoMillis, nowMillis)
	if segment != nil {
		n, err := s.conn.listener.handleOutgoingUDP(segment.data, s.conn.remoteAddr)
		if err != nil {
			slog.Info("outgoing msg failed", slog.Any("error", err))
			s.Close()
		}

		if s.state == StreamRcvStarting || s.state == StreamSndStarting {
			s.state = StreamOpen
			needSendAtLeastOne = false
		}

		if s.state == StreamEnding {
			s.state = StreamEnded
			needSendAtLeastOne = false
		}

		slog.Debug("SndUDP", debugGoroutineID(), s.debug(), slog.Int("n", n), slog.Any("sn", segment.sn))
		s.totalOutgoing += n
	} else {
		slog.Debug("NoSegment", debugGoroutineID(), s.debug())
	}
	if needSendAtLeastOne {
		slog.Debug("send empty packet", debugGoroutineID(), s.debug())
		_, err := s.writeAt([]byte{}, 0)
		if err != nil {
			slog.Error("send empty packet failed", debugGoroutineID(), s.debug(), slog.Any("error", err))
		}
		//TODO: give it a bit time
		if s.state == StreamEnding {
			s.state = StreamEnded
		}
	}*/

	return 0
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

func (s *Stream) Write(data []byte) (n int, err error) {
	t := 0
	for len(data) > 0 {
		n, err := s.WriteAt(data, t)
		if err != nil {
			return n, err
		}
		data = data[n:]
		t += n
	}
	return t, nil
}

func (s *Stream) WriteAt(b []byte, offset int) (n int, err error) {
	slog.Debug(
		"WriteAt",
		debugGoroutineID(),
		s.debug(),
		slog.String("data", string(b)),
		slog.Int("n", len(b)),
		slog.Int("offset", offset))

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.writeAt(b, offset)
}

func (s *Stream) writeAt(b []byte, offset int) (n int, err error) {
	var buffer bytes.Buffer

	var buffer2 bytes.Buffer
	if s.sender && s.state == StreamStarting { // stream init, can be closing already
		if s.closing {
			s.state = StreamEnding
		}

		maxWrite := startMtu - (MinMsgInitSize + protoHeaderSize)
		l := min(maxWrite, len(b)-offset)
		startSn, rleAck, _ := s.rbRcv.CalcRleAck() //TODO: include isFull

		n, err = EncodePayload(
			s.streamId,
			s.closing,
			s.rbRcv.Free(),
			startSn,
			rleAck,
			s.currentSndSn,
			b[offset:offset+l],
			&buffer)
		if err != nil {
			return n, err
		}

		slog.Debug(
			"EncPayload",
			debugGoroutineID(),
			s.debug(),
			slog.Int("n", n),
			slog.Int("overhead", n-len(b)),
			slog.Any("state", s.state))

		n, err = EncodeWriteInit(
			s.conn.pubKeyIdRcv,
			s.conn.listener.pubKeyId,
			s.conn.privKeyEpSnd,
			buffer.Bytes(),
			&buffer2)
		if err != nil {
			return n, err
		}
		slog.Debug("EncodeWriteInit", debugGoroutineID(), s.debug(), slog.Int("n", n))
	} else if !s.sender && s.state == StreamStarting {
		if s.closing {
			s.state = StreamEnding
		}

		maxWrite := startMtu - (MinMsgInitReplySize + protoHeaderSize)
		l := min(maxWrite, len(b)-offset)
		startSn, rleAck, _ := s.rbRcv.CalcRleAck() //TODO: include isFull

		n, err = EncodePayload(
			s.streamId,
			s.closing,
			s.rbRcv.Free(),
			startSn,
			rleAck,
			s.currentSndSn,
			b[offset:offset+l],
			&buffer)
		if err != nil {
			return n, err
		}

		slog.Debug(
			"EncPayload",
			debugGoroutineID(),
			s.debug(),
			slog.Int("n", n),
			slog.Int("overhead", n-len(b)),
			slog.Any("state", s.state))

		n, err = EncodeWriteInitReply(
			s.conn.pubKeyIdRcv,
			s.conn.listener.privKeyId,
			s.conn.pubKeyEpRcv,
			s.conn.privKeyEpSnd,
			buffer.Bytes(),
			&buffer2)
		if err != nil {
			return n, err
		}
		slog.Debug("EncodeWriteInitReply", debugGoroutineID(), s.debug(), slog.Int("n", n))

		privKeyIdCurve := ed25519PrivateKeyToCurve25519(s.conn.listener.privKeyId)
		secret, err := privKeyIdCurve.ECDH(s.conn.pubKeyEpRcv)
		if err != nil {
			return 0, err
		}
		sharedSecret := secret[:]

		s.conn.sharedSecret = sharedSecret
		slog.Debug("SetSecret", debugGoroutineID(), s.debug(), slog.Any("sec", sharedSecret[:5]), slog.Any("conn", s.conn))
	} else {

		if s.closing {
			s.state = StreamEnding
		}

		maxWrite := startMtu - (MinMsgSize + protoHeaderSize)
		l := min(maxWrite, len(b)-offset)
		startSn, rleAck, _ := s.rbRcv.CalcRleAck() //TODO: include isFull

		n, err = EncodePayload(
			s.streamId,
			s.closing,
			s.rbRcv.Free(),
			startSn,
			rleAck,
			s.currentSndSn,
			b[offset:offset+l],
			&buffer)
		if err != nil {
			return n, err
		}

		slog.Debug(
			"EncPayload",
			debugGoroutineID(),
			s.debug(),
			slog.Int("n", n),
			slog.Int("overhead", n-len(b)),
			slog.Any("state", s.state))

		n, err = EncodeWriteMsg(
			s.sender,
			s.conn.pubKeyIdRcv,
			s.conn.listener.pubKeyId,
			s.conn.sharedSecret,
			buffer.Bytes(),
			&buffer2)
		if err != nil {
			return n, err
		}
		slog.Debug("encoded msg", debugGoroutineID(), s.debug(), slog.Int("n", n))
	}

	seg := SndSegment[[]byte]{
		sn:   s.currentSndSn,
		data: buffer2.Bytes(),
	}
	stat := s.rbSnd.InsertBlocking(&seg)
	if stat != SndInserted {
		return 0, fmt.Errorf("status: %v", stat)
	}

	s.currentSndSn++
	s.bytesWritten += n
	slog.Debug("InsertBlckSndSegment", debugGoroutineID(), s.debug(), slog.Int("n", len(buffer2.Bytes())), slog.Any("sn", seg.sn))
	//we do not report n, as this is how many bytes was sent on wire, we
	//want how much data was sent from the buffer the user provided
	return offset + n, nil
}

func (s *Stream) push(p *Payload, nowMillis uint64) RcvInsertStatus {
	slog.Debug("push", debugGoroutineID(), s.debug())
	s.mu.Lock()
	defer s.mu.Unlock()

	return RcvNothing
}

func (s *Stream) debug() slog.Attr {
	localAddr := s.conn.listener.localConn.LocalAddr().String()
	lastColonIndex := strings.LastIndex(localAddr, ":")
	return slog.String("net", localAddr[lastColonIndex+1:]+"=>"+strconv.Itoa(s.conn.remoteAddr.Port))
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
