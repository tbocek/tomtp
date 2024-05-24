package tomtp

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type StreamState uint8

const (
	StreamSndStarting StreamState = iota
	StreamRcvStarting
	StreamOpen //from here on, it does not matter who opened the stream
	StreamEnding
	StreamEnded
)

type Stream struct {
	streamId      uint32
	state         StreamState
	currentSndSn  uint32
	currentRcvSn  uint32
	conn          *Connection
	rbRcv         *RingBufferRcv[[]byte]
	rbSnd         *RingBufferSnd[[]byte]
	totalOutgoing int
	totalIncoming int
	bytesWritten  int //statistics
	loop          bool
	mu            *sync.Mutex
	cond          *sync.Cond
	closed        bool
	closeCond     *sync.Cond
	isInitialSnd  bool
}

func (c *Connection) New(streamId uint32, state StreamState, startLoop bool, isInitialSnd bool) (*Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	var mu sync.Mutex
	if _, ok := c.streams[streamId]; !ok {
		s := &Stream{
			streamId:     streamId,
			state:        state,
			conn:         c,
			rbRcv:        NewRingBufferRcv[[]byte](maxRingBuffer, maxRingBuffer),
			rbSnd:        NewRingBufferSnd[[]byte](maxRingBuffer, maxRingBuffer),
			mu:           &mu,
			loop:         true,
			cond:         sync.NewCond(&mu),
			closed:       false,
			closeCond:    sync.NewCond(&mu),
			isInitialSnd: isInitialSnd,
		}
		c.streams[streamId] = s
		if startLoop {
			slog.Debug("StartLoop", debugGoroutineID(), s.debug())
			go s.updateLoop()
		}
		return s, nil
	} else {
		return nil, fmt.Errorf("stream %x already exists", streamId)
	}
}

func (c *Connection) Get(streamId uint32) (*Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if stream, ok := c.streams[streamId]; !ok {
		return nil, fmt.Errorf("stream %x does not exist", streamId)
	} else {
		return stream, nil
	}
}

func (c *Connection) Has(streamId uint32) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, ok := c.streams[streamId]
	return ok
}

func (s *Stream) Close() {
	slog.Debug("close stream", debugGoroutineID(), s.debug())
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = StreamEnding
	s.cond.Signal()
	s.closeCond.Wait()
	slog.Debug("close stream done", debugGoroutineID(), s.debug())
}

func (s *Stream) updateLoop() {

	for s.loop {
		duration := s.Update(timeMilli())
		s.waitWithTimeout(duration)
	}
	//now we are closed if we exit the loop
	s.conn.streams[s.streamId] = nil
	s.closeCond.Signal()
}

func (s *Stream) Update(nowMillis int64) time.Duration {
	slog.Debug("Update", debugGoroutineID(), s.debug(), slog.Any("nowMillis", nowMillis))
	s.mu.Lock()
	defer s.mu.Unlock()
	//if the stream ends, send now at least one packet, if we already
	//have packets that we will send anyway then send those.
	needSendAtLeastOne := s.state == StreamEnding || s.state == StreamRcvStarting
	//check if there is something in the write queue
	segment := s.rbSnd.ReadyToSend(s.conn.ptoMillis, nowMillis)
	nextTime := time.Second
	if segment != nil {
		n, err := s.conn.listener.handleOutgoingUDP(segment.data, s.conn.remoteAddr)
		if err != nil {
			slog.Info("outgoing msg failed", slog.Any("error", err))
			s.Close()
		}

		if segment.state == StreamRcvStarting || segment.state == StreamSndStarting {
			s.state = StreamOpen
			needSendAtLeastOne = false
		}

		if segment.state == StreamEnding {
			s.state = StreamEnded
			needSendAtLeastOne = false
			s.loop = false
		}

		slog.Debug("SndUDP", debugGoroutineID(), s.debug(), slog.Int("n", n), slog.Any("sn", segment.sn))
		s.totalOutgoing += n
		nextTime = 0
	} else {
		slog.Debug("NoSegment", debugGoroutineID(), s.debug())
	}
	if needSendAtLeastOne {
		slog.Debug("send empty packet", debugGoroutineID(), s.debug())
		_, err := s.writeAt([]byte{}, 0)
		if err != nil {
			slog.Error("send empty packet failed", debugGoroutineID(), s.debug(), slog.Any("error", err))
		}
		nextTime = 0
	}

	return nextTime
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
	//send single packet
	if len(data) == 0 {
		return s.WriteAt(data, 0)
	}
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

	maxWrite := startMtu - MinMsgInitSize
	l := min(maxWrite, len(b)-offset)

	n, err = EncodePayload(
		s.streamId,
		s.rbRcv.lastOrderedSn,
		s.rbRcv.lastSackRange,
		s.rbRcv.Free(),
		s.state == StreamEnding,
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
		slog.Int("overhead", n-len(b)))

	var buffer2 bytes.Buffer
	if s.state == StreamSndStarting { // stream init, can be closing already
		n, err = EncodeWriteInit(
			s.conn.pubKeyIdRcv,
			s.conn.listener.pubKeyId,
			s.conn.privKeyEp,
			buffer.Bytes(),
			&buffer2)
		if err != nil {
			return n, err
		}
		slog.Debug("EncodeWriteInit", debugGoroutineID(), s.debug(), slog.Int("n", n))
	} else if s.state == StreamRcvStarting {
		n, err = EncodeWriteInitReply(
			s.conn.pubKeyIdRcv,
			s.conn.listener.privKeyId,
			s.conn.pubKeyEpRcv,
			s.conn.privKeyEp,
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
	} else {
		n, err = EncodeWriteMsg(
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
		sn:           s.currentSndSn,
		data:         buffer2.Bytes(),
		queuedMillis: timeMilli(),
		state:        s.state,
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
	s.cond.Signal() //if we wait, signal to process
	return offset + l, nil
}

func (s *Stream) push(p *Payload) RcvInsertStatus {
	slog.Debug("push", debugGoroutineID(), s.debug())
	s.mu.Lock()
	defer s.mu.Unlock()

	if p.Sn != nil {
		segment := &RcvSegment[[]byte]{
			sn:   *p.Sn,
			data: p.Data,
		}
		status := s.rbRcv.Insert(segment)
		if status == RcvInserted {
			if p.Close {
				s.Close()
			}
		}
		return status
	}
	s.rbSnd.RemoveUntil(p.LastGoodSn)
	s.rbSnd.RemoveSack(p.SackRanges)

	return RcvNothing
}

func (s *Stream) updateAckRcv(sn *uint32, ranges []SackRange) {

}

// WaitWithTimeout waits on the given condition variable until it is signaled or the timeout expires.
// It returns true if the condition variable was signaled, and false if the timeout expired.
func (s *Stream) waitWithTimeout(timeout time.Duration) bool {
	if timeout == 0 {
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create a channel to wait for the condition signal
	done := make(chan struct{})

	go func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.cond.Wait()
		close(done)
	}()

	select {
	case <-done:
		return true // Condition was signaled
	case <-ctx.Done():
		s.cond.Signal() // Signal the goroutine to stop waiting
		<-done          // Wait until channel is closed
		return false    // Timeout expired
	}
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
