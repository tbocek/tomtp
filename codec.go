package tomtp

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
)

func (s *Stream) encode(b []byte, n int, err error) (int, error) {
	if s.state == StreamEnded || s.conn.state == ConnectionEnded {
		return 0, ErrStreamClosed
	}

	p := &Payload{
		StreamId:            s.streamId,
		StreamFlagClose:     s.state == StreamEnding,
		CloseConnectionFlag: s.conn.state == ConnectionEnding,
		IsRecipient:         !s.conn.sender,
		RcvWndSize:          uint32(s.rbRcv.Size()), //TODO: make it 32bit
		AckSns:              s.rbRcv.toAckSnConn,
		SnStream:            s.streamSnNext,
		Data:                []byte{},
		Filler:              nil,
	}

	var encodeFunc func(snConn uint64) ([]byte, int, error)

	switch {
	case s.conn.firstPaket && s.conn.sender:
		p.Filler = []byte{}
		overhead := CalcOverhead(p) + MsgInitSndSize
		// Calculate how much space we have left in the MTU
		remainingSpace := s.conn.mtu - (len(b) + overhead)
		// If we have space left, fill it
		if remainingSpace > 0 {
			p.Filler = make([]byte, remainingSpace)
			n = len(b)
		} else {
			n = s.conn.mtu - overhead
		}
		p.Data = b[:n]

		encodeFunc = func(snConn uint64) ([]byte, int, error) {
			payRaw, err := EncodePayload(p)
			if err != nil {
				return nil, 0, err
			}
			slog.Debug("EncodeWriteInitSnd", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
			enc, err := EncodeWriteInitSnd(s.conn.pubKeyIdRcv, s.conn.listener.pubKeyId, s.conn.prvKeyEpSnd, payRaw)

			if err != nil {
				return nil, 0, err
			}

			return enc, len(enc), nil
		}

	case s.conn.firstPaket && !s.conn.sender:
		overhead := CalcOverhead(p)
		if overhead < 8 {
			p.Filler = make([]byte, 8-2-n)
			overhead += 8 - n
		}

		n = min(len(b), s.conn.mtu-(overhead+MinMsgInitRcvSize))
		p.Data = b[:n]

		encodeFunc = func(snConn uint64) ([]byte, int, error) {
			payRaw, err := EncodePayload(p)
			if err != nil {
				return nil, 0, err
			}
			slog.Debug("EncodeWriteInitRcv", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
			enc, err := EncodeWriteInitRcv(s.conn.pubKeyIdRcv, s.conn.listener.pubKeyId, s.conn.pubKeyEpRcv, s.conn.prvKeyEpSnd, payRaw)

			if err != nil {
				return nil, 0, err
			}

			return enc, len(enc), nil
		}

	default:
		overhead := CalcOverhead(p)
		if overhead < 8 {
			p.Filler = make([]byte, 8-2-n)
			overhead += 8 - n
		}

		n = min(len(b), s.conn.mtu-(overhead+MinMsgSize))
		p.Data = b[:n]

		encodeFunc = func(snConn uint64) ([]byte, int, error) {
			payRaw, err := EncodePayload(p)
			if err != nil {
				return nil, 0, err
			}
			slog.Debug("EncodeWriteData", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
			enc, err := EncodeWriteData(s.conn.prvKeyEpSnd.PublicKey(), s.conn.pubKeyIdRcv, s.conn.sender, s.conn.sharedSecret, snConn, payRaw)
			if err != nil {
				return nil, 0, err
			}

			return enc, len(enc), nil
		}
	}

	dataLen, status, err := s.conn.rbSnd.InsertProducerBlocking(encodeFunc)
	if err != nil {
		return 0, err
	}
	if status != SndInserted {
		return 0, errors.New("not inserted")
	}

	slog.Debug("EncodeWriteData done", debugGoroutineID(), s.debug(), slog.Int("dataLen", dataLen))

	if s.conn.firstPaket {
		s.conn.firstPaket = false
	}

	if s.state == StreamEnding {
		s.state = StreamEnded
	}

	if s.conn.state == ConnectionEnding {
		s.conn.state = ConnectionEnded
	}

	//only if we send data, increase the sequence number of the stream
	if len(p.Data) > 0 {
		s.streamSnNext = (s.streamSnNext + 1) % MaxUint48
	}
	return n, nil
}

func (l *Listener) decode(buffer []byte, n int, remoteAddr net.Addr) error {
	connId, msgType, err := decodeConnId(buffer)
	conn := l.connMap[connId]

	var m *Message
	if conn == nil && msgType == InitSndMsgType {
		m, conn, err = l.decodeCryptoNew(buffer[:n], remoteAddr)
	} else if conn != nil {
		m, err = l.decodeCryptoExisting(buffer[:n], remoteAddr, conn, msgType)
	} else {
		return errors.New("unknown state")
	}
	if err != nil {
		slog.Info("error from decode crypto", slog.Any("error", err))
		return err
	}

	p, err := DecodePayload(m.PayloadRaw)
	if err != nil {
		slog.Info("error in decoding payload from new connection", slog.Any("error", err))
		return err
	}

	slog.Debug("we decoded the payload, handle stream", debugGoroutineID(), l.debug(remoteAddr), slog.Any("sn", m.SnConn))
	s, isNew := conn.GetOrNewStreamRcv(p.StreamId)

	if len(p.Data) > 0 {
		r := RcvSegment[[]byte]{
			snConn:   m.SnConn,
			snStream: p.SnStream,
			data:     p.Data,
		}
		s.rbRcv.Insert(&r)
	} else {

	}

	if len(p.AckSns) > 0 {
		for _, snConnAcks := range p.AckSns {
			conn.rbSnd.Remove(snConnAcks)
		}
	}

	if isNew {
		l.accept(s)
	}

	return nil
}

func (l *Listener) decodeCryptoNew(buffer []byte, remoteAddr net.Addr) (*Message, *Connection, error) {
	var m *Message
	var err error

	//new connection
	prvKeyEpSnd, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		slog.Info("error in rnd from new connection", slog.Any("error", err))
		return nil, nil, err
	}

	slog.Debug("DecodeNew Snd", debugGoroutineID(), l.debug(remoteAddr), debugPrvKey("privKeyId", l.prvKeyId), debugPrvKey("prvKeyEpSnd", prvKeyEpSnd))
	pubKeyIdSnd, pukKeyEpSnd, m, err := DecodeInit(buffer, l.prvKeyId, prvKeyEpSnd)
	if err != nil {
		slog.Info("error in decode", slog.Any("error", err))
		return nil, nil, err
	}

	conn, err := l.newConn(remoteAddr, pubKeyIdSnd, prvKeyEpSnd, pukKeyEpSnd, false)
	if err != nil {
		slog.Info("error in newConn from new connection 1", slog.Any("error", err))
		return nil, nil, err
	}
	conn.sharedSecret = m.SharedSecret

	return m, conn, nil
}

func (l *Listener) decodeCryptoExisting(buffer []byte, remoteAddr net.Addr, conn *Connection, msgType MsgType) (*Message, error) {
	var m *Message
	var err error

	switch msgType {
	case InitRcvMsgType:
		slog.Debug("DecodeNew Rcv", debugGoroutineID(), l.debug(remoteAddr))
		m, err = DecodeInitReply(buffer, conn.prvKeyEpSnd)
		if err != nil {
			slog.Info("error in decoding from new connection 2", debugGoroutineID(), slog.Any("error", err), slog.Any("conn", conn))
			return nil, err
		}
		conn.rbSnd.Remove(0)
		conn.sharedSecret = m.SharedSecret
	case DataMsgType:
		slog.Debug("Decode DataMsgType", debugGoroutineID(), l.debug(remoteAddr), slog.Any("len(b)", len(buffer)))
		m, err = DecodeMsg(buffer, conn.sender, conn.sharedSecret)
		if err != nil {
			slog.Info("error in decoding from new connection 3", debugGoroutineID(), slog.Any("error", err), slog.Any("conn", conn))
			return nil, err
		}
	default:
		return nil, errors.New("unknown type")
	}

	return m, nil
}
