package tomtp

import (
	"crypto/ecdh"
	"crypto/rand"
	"sync"
)

type Stream struct {
	// Tracks sent packets that are not yet acknowledged. True if acknowledged, false if not.
	sentPackets map[uint32]bool
	nextSeqNum  uint32
	parent      *MultiStreams
	muRead      sync.Mutex
	muWrite     sync.Mutex
	rbRcv       *RingBufferRcv[*Payload]
	rbSnd       *RingBufferSnd[*Payload]
}

func (s *Stream) Close() error {
	//TODO: send close hint to remote peer
	return nil
}

func (s *Stream) Read(b []byte) (n int, err error) {
	s.muRead.Lock()
	defer s.muRead.Unlock()

	segment := s.rbRcv.Remove()

	if segment != nil {
		n = copy(b[n:], segment.data.EncryptedData)
	}

	return n, err
}

func (s *Stream) Write(b []byte) (n int, err error) {
	s.muWrite.Lock()
	defer s.muWrite.Unlock()

	nonce, err := generateRandomNonce24()
	s.parent.currentNonce = nonce
	epPrivKeyCurve, err := ecdh.X25519().GenerateKey(rand.Reader)
	s.parent.epPrivKeyCurve = epPrivKeyCurve

	/*n, err = EncodeWriteInit(
		s.parent.pubKeyIdRcv,
		s.parent.listener.privKeyId.Public().(ed25519.PublicKey),
		b,
		nonce,
		epPrivKeyCurve,
		s.parent.remoteConn,
	)*/
	return n, err
}

func (s *Stream) ReadAll() (data []byte, err error) {
	var buf []byte
	for {
		b := make([]byte, 1024)
		n, err := s.Read(b)
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
		m, err := s.Write(data)
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

	segment := &RcvSegment[*Payload]{
		sn:   0,
		data: m.Payload,
	}

	s.rbRcv.Insert(segment)
	return nil
}
