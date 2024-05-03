package tomtp

import (
	"bytes"
	"fmt"
	"log/slog"
	"sync"
)

type StreamState uint8

const (
	StreamRunning StreamState = iota
	StreamEnd
)

type Stream struct {
	streamId      uint32
	state         StreamState
	currentSeqNum uint32
	conn          *Connection
	mu            sync.Mutex
	rbRcv         *RingBufferRcv[[]byte]
	rbSnd         *RingBufferSnd[[]byte]
	totalOutgoing int
	totalIncoming int
}

func (c *Connection) New(streamId uint32) (*Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.streams[streamId]; !ok {
		c.streams[streamId] = &Stream{
			streamId:      streamId,
			state:         StreamRunning,
			currentSeqNum: 0,
			mu:            sync.Mutex{},
			conn:          c,
			rbRcv:         NewRingBufferRcv[[]byte](maxRingBuffer, maxRingBuffer),
			rbSnd:         NewRingBufferSnd[[]byte](maxRingBuffer, maxRingBuffer),
		}
		return c.streams[streamId], nil
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
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = StreamEnd
	s.update()
}

func (s *Stream) update() {
	//if the stream ends, send now at least one packet, if we already have packets that we will send anyway
	//then send those.
	needSendAtLeastOne := s.state == StreamEnd
	//check if there is something in the write queue
	segments := s.rbSnd.ReadyToSend(s.conn.ptoMillis, timeMilli())
	if segments != nil && len(segments) > 0 {
		for _, v := range segments {
			n, err := s.conn.listener.handleOutgoingUDP(v.data, s.conn.remoteAddr)
			if err != nil {
				slog.Info("outgoing msg failed", slog.Any("error", err))
				s.Close()
			}
			if n > 0 {
				slog.Debug("write", slog.Int("n", n))
				needSendAtLeastOne = false
				s.totalOutgoing += n
			}
		}
	}
	if needSendAtLeastOne {
		//TODO: make sure this will call update again
		s.Write([]byte{})
	} else if s.state == StreamEnd {
		s.conn.streams[s.streamId] = nil
	}

}

func (s *Stream) updateAckRcv(sn *uint32, ranges []SackRange) {
	//called when we got an ack for data we sent. Thus, we can remove those SN
	//TODO:
}

func (s *Stream) updateAckSnd(sn uint32) {
	//called when we get data that we need to acknowledge
	//TODO:
}

func (s *Stream) Read(b []byte) (int, error) {
	return s.ReadOffset(b, 0)
}

func (s *Stream) ReadOffset(b []byte, n int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	//wait until a segment becomes available
	segment := s.rbRcv.RemoveBlocking()

	if segment == nil {
		return 0, nil
	}

	n = copy(b[n:], segment.data)

	slog.Debug("read", slog.Int("n", n))
	return n, nil
}

func (s *Stream) Write(b []byte) (n int, err error) {
	return s.WriteOffset(b, 0)
}

func (s *Stream) WriteOffset(b []byte, offset int) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var buffer bytes.Buffer

	maxWrite := startMtu - MinMsgInitSize
	nr := min(maxWrite, len(b)-offset)

	fin := s.state == StreamEnd

	if s.currentSeqNum == 0 { // stream init, can be closing already

		n, err = EncodePayload(
			s.streamId,
			nil,
			nil,
			s.rbRcv.Free(),
			fin,
			s.currentSeqNum,
			b[offset:nr],
			&buffer)
		if err != nil {
			return n, err
		}

		var buffer2 bytes.Buffer
		n, err = EncodeWriteInit(
			s.conn.pubKeyIdRcv,
			s.conn.listener.PubKeyId(),
			s.conn.privKeyEpSnd,
			buffer.Bytes(),
			&buffer2)
		if err != nil {
			return n, err
		}

		seg := SndSegment[[]byte]{
			sn:         s.currentSeqNum,
			data:       buffer2.Bytes(),
			sentMillis: timeMilli(),
			fin:        s.state == StreamEnd,
		}
		stat := s.rbSnd.InsertBlocking(&seg)

		if stat != SndInserted {
			//TODO: handle error
		}

		s.currentSeqNum = s.currentSeqNum + 1

	} else {

	}

	return n, err
}

func (s *Stream) ReadAll() (data []byte, err error) {
	var buf []byte
	for {
		b := make([]byte, 1024)
		n, err := s.ReadOffset(b, 0)
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

func (s *Stream) WriteAll(data []byte) (n int, err error) {
	for len(data) > 0 {
		m, err := s.WriteOffset(data, 0)
		if err != nil {
			return n, err
		}
		data = data[m:]
		n += m
	}
	return n, nil
}

func (s *Stream) push(m *Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	segment := &RcvSegment[[]byte]{
		sn:   0,
		data: m.Payload.Data,
	}

	s.rbRcv.Insert(segment)
	return nil
}
