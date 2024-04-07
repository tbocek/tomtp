package tomtp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
)

type StreamState uint8

const (
	StreamInit StreamState = iota
	StreamFlow
	StreamEnd
)

type Stream struct {
	streamId      uint32
	state         StreamState
	currentSeqNum uint32
	privKeyEpSnd  *ecdh.PrivateKey
	pubKeyIdRcv   ed25519.PublicKey
	pukKeyIdSnd   ed25519.PublicKey
	conn          *Connection
	muRead        sync.Mutex
	muWrite       sync.Mutex
	rbRcv         *RingBufferRcv[[]byte]
	rbSnd         *RingBufferSnd[[]byte]
}

func (s *Connection) NewOrGetStream(streamId uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()

	if stream, ok := s.streams[streamId]; !ok {
		s.streams[streamId] = &Stream{
			currentSeqNum: 0,
			muRead:        sync.Mutex{},
			muWrite:       sync.Mutex{},
			conn:          s,
			rbRcv:         NewRingBufferRcv[[]byte](maxRingBuffer, maxRingBuffer),
			rbSnd:         NewRingBufferSnd[[]byte](maxRingBuffer, maxRingBuffer),
		}
		return s.streams[streamId]
	} else {
		return stream
	}
}

func (s *Stream) Close() error {
	//TODO: send close hint to remote peer
	return nil
}

func (s *Stream) Read(b []byte, n int) int {
	s.muRead.Lock()
	defer s.muRead.Unlock()

	segment := s.rbRcv.Remove()

	if segment == nil {
		return 0
	}

	if segment != nil {
		n = copy(b[n:], segment.data)
	}

	return n
}

func (s *Stream) Write(b []byte, offset int) (n int, err error) {
	s.muWrite.Lock()
	defer s.muWrite.Unlock()

	var buffer bytes.Buffer
	if s.state == StreamInit {
		s.privKeyEpSnd, err = ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return 0, err
		}

		n, err = EncodePayload(
			s.streamId,
			nil,
			nil,
			s.rbRcv.Size(),
			false,
			false,
			0,
			b[offset:1],
			&buffer)

	}

	n, err = EncodeWriteInit(s.pubKeyIdRcv, s.pukKeyIdSnd, s.privKeyEpSnd, []byte("hallo"), &buffer)
	if err != nil {
		return 0, err
	}

	/*n, err = EncodeWriteInit(
		s.conn.pubKeyIdRcv,
		s.conn.listener.privKeyId.Public().(ed25519.PublicKey),
		b,
		nonce,
		privKeyEpSnd,
		s.conn.remoteConn,
	)*/
	return n, err
}

func (s *Stream) ReadAll() (data []byte, err error) {
	var buf []byte
	for {
		b := make([]byte, 1024)
		n := s.Read(b, 0)
		buf = append(buf, b[:n]...)
		if n < len(b) {
			break
		}
	}
	return buf, nil
}

func (s *Stream) WriteAll(data []byte) (n int, err error) {
	for len(data) > 0 {
		m, err := s.Write(data, 0)
		if err != nil {
			return n, err
		}
		data = data[m:]
		n += m
	}
	return n, nil
}

func (s *Stream) push(m *Message) error {
	s.muRead.Lock()
	defer s.muRead.Unlock()

	segment := &RcvSegment[[]byte]{
		sn:   0,
		data: m.Payload,
	}

	s.rbRcv.Insert(segment)
	return nil
}
