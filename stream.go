package tomtp

import (
	"bytes"
	"fmt"
	"sync"
)

type StreamState uint8

const (
	StreamRunning StreamState = iota
	StreamEndGracefully
	StreamReset
	StreamStopped
)

type Stream struct {
	streamId      uint32
	state         StreamState
	currentSeqNum uint32
	conn          *Connection
	mu            sync.Mutex
	rbRcv         *RingBufferRcv[[]byte]
	rbSnd         *RingBufferSnd[[]byte]
}

func (s *Connection) New(streamId uint32) (*Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.streams[streamId]; !ok {
		s.streams[streamId] = &Stream{
			streamId:      streamId,
			currentSeqNum: 0,
			mu:            sync.Mutex{},
			conn:          s,
			rbRcv:         NewRingBufferRcv[[]byte](maxRingBuffer, maxRingBuffer),
			rbSnd:         NewRingBufferSnd[[]byte](maxRingBuffer, maxRingBuffer),
		}
		return s.streams[streamId], nil
	} else {
		return nil, fmt.Errorf("stream %v already exists", streamId)
	}
}

func (s *Connection) Get(streamId uint32) (*Stream, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if stream, ok := s.streams[streamId]; !ok {
		return nil, fmt.Errorf("stream %v does not exist", streamId)
	} else {
		return stream, nil
	}
}

func (s *Connection) Has(streamId uint32) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, ok := s.streams[streamId]
	return ok
}

func (s *Stream) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = StreamEndGracefully
	return nil
}

func (s *Stream) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = StreamReset
	return nil
}

func (s *Stream) Read(b []byte) (int, error) {
	return s.ReadOffset(b, 0)
}

func (s *Stream) ReadOffset(b []byte, n int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	segment := s.rbRcv.Remove()

	if segment == nil {
		return 0, nil
	}

	if segment != nil {
		n = copy(b[n:], segment.data)
	}

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

	fin := false
	if (nr <= maxWrite && s.state == StreamEndGracefully) || (s.state == StreamReset) {
		fin = true
	}

	if s.currentSeqNum == 0 { // stream init, can be closing already

		n, err = EncodePayload(
			s.streamId,
			nil,
			nil,
			s.rbRcv.Size(),
			false,
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

		snd := buffer2.Bytes()
		n, err = s.conn.listener.localConn.WriteToUDP(snd, s.conn.remoteAddr)
		if err != nil {
			return n, err
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
