package tomtp

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"log/slog"
	"net"
)

func (s *Stream) encode(b []byte) (enc []byte, offset int, err error) {
	if s.state == StreamEnded || s.conn.state == ConnectionEnded {
		return nil, 0, ErrStreamClosed
	}

	p := &Payload{
		CloseOp:      GetCloseOp(s.state == StreamEnding, s.conn.state == ConnectionEnding),
		IsSender:     s.conn.sender,
		RcvWndSize:   uint64(s.rbRcv.Size()),
		Acks:         s.rbRcv.GetAcks(),
		StreamId:     s.streamId,
		StreamOffset: s.streamOffsetNext,
		Data:         []byte{},
	}

	switch {
	case s.conn.firstPaket && s.conn.sender && s.conn.snCrypto == 0 && !s.conn.isRollover:
		overhead := CalcOverhead(p) + MsgInitSndSize
		offset = min(s.conn.mtu-overhead, len(b))
		p.Data = b[:offset]

		payRaw, _, err := EncodePayload(p)
		if err != nil {
			return nil, 0, err
		}
		slog.Debug("EncodeWriteInitS0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		enc, err = EncodeWriteInitS0(s.conn.pubKeyIdRcv, s.conn.listener.prvKeyId.PublicKey(), s.conn.prvKeyEpSnd, s.conn.prvKeyEpSndRollover, payRaw)
	case s.conn.firstPaket && !s.conn.sender && s.conn.snCrypto == 0 && !s.conn.isRollover:
		overhead := CalcOverhead(p) + MinMsgInitRcvSize
		offset = min(s.conn.mtu-overhead, len(b))
		p.Data = b[:offset]

		payRaw, _, err := EncodePayload(p)
		if err != nil {
			return nil, 0, err
		}
		slog.Debug("EncodeWriteInitR0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		enc, err = EncodeWriteInitR0(s.conn.pubKeyIdRcv, s.conn.listener.prvKeyId.PublicKey(), s.conn.pubKeyEpRcv, s.conn.prvKeyEpSnd, s.conn.prvKeyEpSndRollover, payRaw)
	case !s.conn.firstPaket && s.conn.sender && s.conn.snCrypto == 0: //rollover
		overhead := CalcOverhead(p) + MinMsgData0Size
		offset = min(s.conn.mtu-overhead, len(b))
		p.Data = b[:offset]

		payRaw, _, err := EncodePayload(p)
		if err != nil {
			return nil, 0, err
		}
		slog.Debug("EncodeWriteData0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		enc, err = EncodeWriteData0(s.conn.pubKeyIdRcv, s.conn.listener.prvKeyId.PublicKey(), s.conn.sender, s.conn.pubKeyEpRcv, s.conn.prvKeyEpSndRollover, payRaw)
	case !s.conn.firstPaket && !s.conn.sender && s.conn.snCrypto == 0: //rollover
		overhead := CalcOverhead(p) + MinMsgData0Size
		offset = min(s.conn.mtu-overhead, len(b))
		p.Data = b[:offset]

		payRaw, _, err := EncodePayload(p)
		if err != nil {
			return nil, 0, err
		}
		slog.Debug("EncodeWriteData0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		enc, err = EncodeWriteData0(s.conn.pubKeyIdRcv, s.conn.listener.prvKeyId.PublicKey(), s.conn.sender, s.conn.pubKeyEpRcv, s.conn.prvKeyEpSndRollover, payRaw)
	default:
		overhead := CalcOverhead(p) + MinMsgSize
		offset = min(s.conn.mtu-overhead, len(b))
		p.Data = b[:offset]

		payRaw, _, err := EncodePayload(p)
		if err != nil {
			return nil, 0, err
		}
		slog.Debug("EncodeWriteData", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		enc, err = EncodeWriteData(s.conn.prvKeyEpSnd.PublicKey(), s.conn.pubKeyIdRcv, s.conn.sender, s.conn.sharedSecret, s.conn.snCrypto, payRaw)
	}

	if err != nil {
		return nil, 0, err
	}

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
		s.streamOffsetNext += uint64(offset)
	}
	return enc, offset, nil
}

func (l *Listener) decode(buffer []byte, n int, remoteAddr net.Addr) (conn *Connection, payload *Payload, err error) {
	connId, msgType, err := decodeConnId(buffer)
	conn = l.connMap[connId]

	var m *Message
	if conn == nil && msgType == InitS0MsgType {
		m, conn, err = l.decodeCryptoNew(buffer[:n], remoteAddr)
	} else if conn != nil {
		m, err = l.decodeCryptoExisting(buffer[:n], remoteAddr, conn, msgType)
	} else {
		return conn, nil, errors.New("unknown state")
	}
	if err != nil {
		slog.Info("error from decode crypto", slog.Any("error", err))
		return conn, nil, err
	}

	p, _, err := DecodePayload(m.PayloadRaw)
	if err != nil {
		slog.Info("error in decoding payload from new connection", slog.Any("error", err))
		return conn, nil, err
	}

	slog.Debug("we decoded the payload, handle stream", debugGoroutineID(), l.debug(remoteAddr), slog.Any("sn", m.SnConn))

	return conn, p, nil
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
