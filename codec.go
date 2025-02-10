package tomtp

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/netip"
)

func (s *Stream) Overhead(ackLen int) (overhead int) {
	protoOverhead := CalcProtoOverhead(ackLen)
	switch {
	case s.conn.firstPaket && s.conn.sender && s.conn.snCrypto == 0 && !s.conn.isRollover:
		return protoOverhead + MsgInitSndSize
	case s.conn.firstPaket && !s.conn.sender && s.conn.snCrypto == 0 && !s.conn.isRollover:
		return protoOverhead + MinMsgInitRcvSize
	case !s.conn.firstPaket && s.conn.sender && s.conn.snCrypto == 0: //rollover
		return protoOverhead + MinMsgData0Size
	case !s.conn.firstPaket && !s.conn.sender && s.conn.snCrypto == 0: //rollover
		return protoOverhead + MinMsgData0Size
	default:
		return protoOverhead + MinMsgSize
	}
}

func (s *Stream) encode(origData []byte, acks []Ack) (encData []byte, err error) {
	if s.state == StreamEnded || s.conn.state == ConnectionEnded {
		return nil, ErrStreamClosed
	}

	p := &PayloadMeta{
		CloseOp:    GetCloseOp(s.state == StreamEnding, s.conn.state == ConnectionEnding),
		IsSender:   s.conn.sender,
		RcvWndSize: s.conn.maxRcvWndSize - uint64(s.conn.rbRcv.Size()),
		Acks:       acks,
		StreamId:   s.streamId,
	}

	switch {
	case s.conn.firstPaket && s.conn.sender && s.conn.snCrypto == 0 && !s.conn.isRollover:
		var payRaw []byte
		payRaw, _, err = EncodePayload(p, origData)
		if err != nil {
			return nil, err
		}
		slog.Debug("EncodeWriteInitS0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		encData, err = EncodeWriteInitS0(s.conn.pubKeyIdRcv, s.conn.listener.prvKeyId.PublicKey(), s.conn.prvKeyEpSnd, s.conn.prvKeyEpSndRollover, payRaw)
	case s.conn.firstPaket && !s.conn.sender && s.conn.snCrypto == 0 && !s.conn.isRollover:
		var payRaw []byte
		payRaw, _, err = EncodePayload(p, origData)
		if err != nil {
			return nil, err
		}
		slog.Debug("EncodeWriteInitR0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		encData, err = EncodeWriteInitR0(s.conn.pubKeyIdRcv, s.conn.listener.prvKeyId.PublicKey(), s.conn.pubKeyEpRcv, s.conn.prvKeyEpSnd, s.conn.prvKeyEpSndRollover, payRaw)
	case !s.conn.firstPaket && s.conn.sender && s.conn.snCrypto == 0: //rollover
		var payRaw []byte
		payRaw, _, err = EncodePayload(p, origData)
		if err != nil {
			return nil, err
		}
		slog.Debug("EncodeWriteData0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		encData, err = EncodeWriteData0(s.conn.pubKeyIdRcv, s.conn.listener.prvKeyId.PublicKey(), s.conn.sender, s.conn.pubKeyEpRcv, s.conn.prvKeyEpSndRollover, payRaw)
	case !s.conn.firstPaket && !s.conn.sender && s.conn.snCrypto == 0: //rollover
		var payRaw []byte
		payRaw, _, err = EncodePayload(p, origData)
		if err != nil {
			return nil, err
		}
		slog.Debug("EncodeWriteData0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		encData, err = EncodeWriteData0(s.conn.pubKeyIdRcv, s.conn.listener.prvKeyId.PublicKey(), s.conn.sender, s.conn.pubKeyEpRcv, s.conn.prvKeyEpSndRollover, payRaw)
	default:
		var payRaw []byte
		payRaw, _, err = EncodePayload(p, origData)
		if err != nil {
			return nil, err
		}
		slog.Debug("EncodeWriteData", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		encData, err = EncodeWriteData(s.conn.pubKeyIdRcv, s.conn.listener.prvKeyId.PublicKey(), s.conn.sender, s.conn.sharedSecret, s.conn.snCrypto, payRaw)
	}

	if err != nil {
		return nil, err
	}

	s.conn.snCrypto++

	if s.conn.firstPaket {
		s.conn.firstPaket = false
	}

	if s.state == StreamEnding {
		s.state = StreamEnded
	}

	if s.conn.state == ConnectionEnding {
		s.conn.state = ConnectionEnded
	}

	return encData, nil
}

func (l *Listener) decode(buffer []byte, remoteAddr netip.AddrPort) (conn *Connection, m *Message, err error) {
	connId, msgType, err := decodeConnId(buffer)
	conn = l.connMap[connId]

	if conn == nil && msgType == InitS0MsgType {
		m, conn, err = l.decodeCryptoNew(buffer, remoteAddr)
	} else if conn != nil {
		m, err = l.decodeCryptoExisting(buffer, remoteAddr, conn, msgType)
	} else {
		return conn, nil, errors.New("unknown state")
	}
	if err != nil {
		slog.Info("error from decode crypto", slog.Any("error", err))
		return conn, nil, err
	}

	return conn, m, nil
}

func (l *Listener) decodeCryptoNew(buffer []byte, remoteAddr netip.AddrPort) (*Message, *Connection, error) {
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

func (l *Listener) decodeCryptoExisting(buffer []byte, remoteAddr netip.AddrPort, conn *Connection, msgType MsgType) (*Message, error) {
	var m *Message
	var err error

	switch msgType {
	case InitR0MsgType:
		slog.Debug("DecodeNew Rcv", debugGoroutineID(), l.debug(remoteAddr))
		var pubKeyEpRcv *ecdh.PublicKey
		var pubKeyEpRcvRollover *ecdh.PublicKey
		pubKeyEpRcv, pubKeyEpRcvRollover, m, err = DecodeInitR0(buffer, conn.prvKeyEpSnd)
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
