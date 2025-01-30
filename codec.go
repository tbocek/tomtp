package tomtp

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
)

func (s *Stream) encode(b []byte, n int) (int, error) {
	if s.state == StreamEnded || s.conn.state == ConnectionEnded {
		return 0, ErrStreamClosed
	}

	p := &Payload{
		CloseOp:      GetCloseOp(s.state == StreamEnding, s.conn.state == ConnectionEnding),
		IsSender:     s.conn.sender,
		RcvWndSize:   uint64(s.rbRcv.Size()),
		Acks:         s.rbRcv.GetAcks(),
		StreamId:     s.streamId,
		StreamOffset: s.streamSnNext,
		Data:         []byte{},
	}

	var encodeFunc func(snConn uint64) ([]byte, int, error)

	switch {
	case s.conn.firstPaket && s.conn.sender && s.conn.snConn == 0 && !s.conn.isRollover:
		overhead := CalcOverhead(p) + MsgInitSndSize
		n = s.conn.mtu - overhead
		p.Data = b[:n]

		encodeFunc = func(snConn uint64) ([]byte, int, error) {
			payRaw, _, err := EncodePayload(p)
			if err != nil {
				return nil, 0, err
			}
			slog.Debug("EncodeWriteInitSnd", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
			enc, err := EncodeWriteInitS0(s.conn.pubKeyIdRcv, s.conn.listener.pubKeyId, s.conn.prvKeyEpSnd, s.conn.prvKeyEpSndRollover, payRaw)
			if err != nil {
				return nil, 0, err
			}

			return enc, len(enc), nil
		}

	case s.conn.firstPaket && !s.conn.sender && s.conn.snConn == 0 && !s.conn.isRollover:
		overhead := CalcOverhead(p)

		n = min(len(b), s.conn.mtu-(overhead+MinMsgInitRcvSize))
		p.Data = b[:n]

		encodeFunc = func(snConn uint64) ([]byte, int, error) {
			payRaw, _, err := EncodePayload(p)
			if err != nil {
				return nil, 0, err
			}
			slog.Debug("EncodeWriteInitRcv", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
			enc, err := EncodeWriteInitR0(s.conn.pubKeyIdRcv, s.conn.listener.pubKeyId, s.conn.pubKeyEpRcv, s.conn.prvKeyEpSnd, s.conn.prvKeyEpSndRollover, payRaw)
			if err != nil {
				return nil, 0, err
			}

			return enc, len(enc), nil
		}

	case s.conn.firstPaket && s.conn.sender && s.conn.snConn == 1: //rollover

	case s.conn.firstPaket && !s.conn.sender && s.conn.snConn == 1: //rollover

	default:
		overhead := CalcOverhead(p)

		n = min(len(b), s.conn.mtu-(overhead+MinMsgSize))
		p.Data = b[:n]

		encodeFunc = func(snConn uint64) ([]byte, int, error) {
			payRaw, _, err := EncodePayload(p)
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

	slog.Debug("%v", slog.Any("aoeu", encodeFunc))

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
	if conn == nil && msgType == InitS0MsgType {
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

	p, _, err := DecodePayload(m.PayloadRaw)
	if err != nil {
		slog.Info("error in decoding payload from new connection", slog.Any("error", err))
		return err
	}

	slog.Debug("we decoded the payload, handle stream", debugGoroutineID(), l.debug(remoteAddr), slog.Any("sn", m.SnConn))

	// Get or create stream using StreamId from Data
	s, isNew := conn.GetOrNewStreamRcv(p.StreamId)

	if p.Data != nil && len(p.Data) > 0 {
		r := RcvSegment{
			streamId: p.StreamId,
			offset:   p.StreamOffset,
			data:     p.Data,
		}
		s.rbRcv.Insert(&r)
	}

	if len(p.Acks) > 0 {
		for _, ack := range p.Acks {
			conn.rbSnd.AcknowledgeRange(ack.StreamId, ack.StreamOffset, ack.Len)
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
		return nil, nil, err
	}

	prvKeyEpSndRollover, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	slog.Debug("DecodeNew Snd", debugGoroutineID(), l.debug(remoteAddr), debugPrvKey("privKeyId", l.prvKeyId), debugPrvKey("prvKeyEpSnd", prvKeyEpSnd))
	pubKeyIdSnd, pukKeyEpSnd, pubKeyEpSndRollover, m, err := DecodeInitS0(buffer, l.prvKeyId, prvKeyEpSnd)
	if err != nil {
		slog.Info("error in decode", slog.Any("error", err))
		return nil, nil, err
	}

	conn, err := l.newConn(remoteAddr, pubKeyIdSnd, prvKeyEpSnd, prvKeyEpSndRollover, pubKeyEpSndRollover, pukKeyEpSnd, false)
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
	case InitR0MsgType:
		slog.Debug("DecodeNew Rcv", debugGoroutineID(), l.debug(remoteAddr))
		pubKeyEpRcv, pubKeyEpRcvRollover, m, err := DecodeInitR0(buffer, conn.prvKeyEpSnd)
		if err != nil {
			slog.Info("error in decoding from new connection 2", debugGoroutineID(), slog.Any("error", err), slog.Any("conn", conn))
			return nil, err
		}

		conn.pubKeyEpRcv = pubKeyEpRcv
		conn.pubKeyEpRcvRollover = pubKeyEpRcvRollover

		//conn.rbSnd.Remove(0)
		conn.sharedSecret = m.SharedSecret
	case DataMsgType:
		slog.Debug("Decode DataMsgType", debugGoroutineID(), l.debug(remoteAddr), slog.Any("len(b)", len(buffer)))
		m, err = DecodeData(buffer, conn.sender, conn.sharedSecret)
		if err != nil {
			slog.Info("error in decoding from new connection 3", debugGoroutineID(), slog.Any("error", err), slog.Any("conn", conn))
			return nil, err
		}
	default:
		return nil, errors.New("unknown type")
	}

	return m, nil
}
