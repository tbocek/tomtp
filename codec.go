package tomtp

import (
	"crypto/ecdh"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
)

func (s *Stream) Overhead(hasAck bool) (overhead int) {
	protoOverhead := CalcProtoOverhead(hasAck)
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

func (s *Stream) encode(origData []byte, ack *Ack) ([]byte, error) {
	if s.closed || s.conn.closed {
		return nil, ErrStreamClosed
	}

	p := &PayloadMeta{
		CloseOp:    GetCloseOp(s.closed, s.conn.closed),
		IsSender:   s.conn.sender,
		RcvWndSize: s.conn.maxRcvWndSize - uint64(s.conn.rbRcv.Size()),
		Ack:        ack,
		StreamId:   s.streamId,
	}

	encData, err := s.encodePacket(p, origData)
	if err != nil {
		return nil, err
	}

	s.updateState()
	return encData, nil
}

func (s *Stream) encodePacket(p *PayloadMeta, origData []byte) ([]byte, error) {
	isInitialHandshake := s.conn.firstPaket && s.conn.snCrypto == 0 && !s.conn.isRollover

	switch {
	case s.conn.isHandshake || s.conn.pubKeyIdRcv == nil && isInitialHandshake:
		s.conn.isHandshake = true
		return s.encodeInitialHandshake(p, origData)
	case s.conn.pubKeyIdRcv != nil && isInitialHandshake:
		return s.encodeInitialWithCrypto(p, origData)
	case !s.conn.firstPaket && s.conn.snCrypto == 0:
		return s.encodeRollover(p, origData)
	default:
		return s.encodeData(p, origData)
	}
}

func (s *Stream) encodeInitialHandshake(p *PayloadMeta, origData []byte) ([]byte, error) {
	if s.conn.sender {
		slog.Debug("EncodeInitHandshakeS0", debugGoroutineID(), s.debug())
		return EncodeInitHandshakeS0(
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.prvKeyEpSnd,
			s.conn.prvKeyEpSndRollover,
			s.conn.connId,
		), nil
	}

	payRaw, _, err := EncodePayload(p, origData)
	if err != nil {
		return nil, err
	}

	slog.Debug("EncodeInitHandshakeR0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
	return EncodeInitHandshakeR0(
		s.conn.pubKeyIdRcv,
		s.conn.listener.prvKeyId.PublicKey(),
		s.conn.pubKeyEpRcv,
		s.conn.prvKeyEpSnd,
		s.conn.prvKeyEpSndRollover,
		s.conn.connId,
		payRaw,
	)
}

func (s *Stream) encodeInitialWithCrypto(p *PayloadMeta, origData []byte) ([]byte, error) {
	payRaw, _, err := EncodePayload(p, origData)
	if err != nil {
		return nil, err
	}

	if s.conn.sender {
		slog.Debug("EncodeInitWithCryptoS0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
		return EncodeInitWithCryptoS0(
			s.conn.pubKeyIdRcv,
			s.conn.listener.prvKeyId.PublicKey(),
			s.conn.prvKeyEpSnd,
			s.conn.prvKeyEpSndRollover,
			payRaw,
		)
	}

	slog.Debug("EncodeInitWithCryptoR0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
	return EncodeInitWithCryptoR0(
		s.conn.pubKeyIdRcv,
		s.conn.listener.prvKeyId.PublicKey(),
		s.conn.pubKeyEpRcv,
		s.conn.prvKeyEpSnd,
		s.conn.prvKeyEpSndRollover,
		payRaw,
	)
}

func (s *Stream) encodeRollover(p *PayloadMeta, origData []byte) ([]byte, error) {
	payRaw, _, err := EncodePayload(p, origData)
	if err != nil {
		return nil, err
	}

	slog.Debug("EncodeData0", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
	return EncodeData0(
		s.conn.pubKeyIdRcv,
		s.conn.listener.prvKeyId.PublicKey(),
		s.conn.sender,
		s.conn.pubKeyEpRcv,
		s.conn.prvKeyEpSndRollover,
		payRaw,
	)
}

func (s *Stream) encodeData(p *PayloadMeta, origData []byte) ([]byte, error) {
	payRaw, _, err := EncodePayload(p, origData)
	if err != nil {
		return nil, err
	}

	slog.Debug("EncodeData", debugGoroutineID(), s.debug(), slog.Int("len(payRaw)", len(payRaw)))
	return EncodeData(
		s.conn.pubKeyIdRcv,
		s.conn.listener.prvKeyId.PublicKey(),
		s.conn.sender,
		s.conn.sharedSecret,
		s.conn.snCrypto,
		payRaw,
	)
}

func (s *Stream) updateState() {
	s.conn.snCrypto++
	if s.conn.firstPaket {
		s.conn.firstPaket = false
	}
}

func (l *Listener) decode(buffer []byte, remoteAddr netip.AddrPort) (*Connection, *Message, error) {
	connId, msgType, err := decodeHeader(buffer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode header: %w", err)
	}

	message, conn, err := l.decodeByMessageType(buffer, remoteAddr, connId, msgType)
	if err != nil {
		slog.Info("decode error", slog.Any("error", err))
		return conn, nil, err
	}

	return conn, message, nil
}

func (l *Listener) decodeByMessageType(buffer []byte, remoteAddr netip.AddrPort, connId uint64, msgType MsgType) (*Message, *Connection, error) {
	switch msgType {
	case InitHandshakeS0MsgType:
		return l.handleInitHandshakeS0(buffer, remoteAddr, connId)
	case InitHandshakeR0MsgType:
		conn := l.connMap[connId]
		if conn == nil {
			return nil, nil, errors.New("connection not found for InitHandshakeR0MsgType")
		}
		delete(l.connMap, connId) //this is the random connId, which we do not need anymore, we now have a proper connId
		return l.handleInitHandshakeR0(buffer, remoteAddr, conn.prvKeyEpSnd, conn.prvKeyEpSndRollover)
	case InitWithCryptoS0MsgType:
		return l.handleInitWithCryptoS0(buffer, remoteAddr)
	case InitWithCryptoR0MsgType:
		conn := l.connMap[connId]
		if conn == nil {
			return nil, nil, errors.New("connection not found for InitWithCryptoR0")
		}
		message, err := l.handleInitWithCryptoR0(buffer, remoteAddr, conn)
		return message, conn, err
	case Data0MsgType:
		conn := l.connMap[connId]
		if conn == nil {
			return nil, nil, errors.New("connection not found for Data0")
		}
		message, err := l.handleData0Message(buffer, remoteAddr, conn)
		return message, conn, err
	case DataMsgType:
		conn := l.connMap[connId]
		if conn == nil {
			return nil, nil, errors.New("connection not found for DataMessage")
		}
		message, err := l.handleDataMessage(buffer, remoteAddr, conn)
		return message, conn, err
	default:
		return nil, nil, fmt.Errorf("unknown message type: %v", msgType)
	}
}

func (l *Listener) handleInitHandshakeS0(buffer []byte, remoteAddr netip.AddrPort, connId uint64) (*Message, *Connection, error) {
	prvKeyEpRcv, prvKeyEpRcvRollover, err := generateTwoKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate keys: %w", err)
	}

	slog.Debug("DecodeInitHandshakeS0",
		debugGoroutineID(),
		l.debug(remoteAddr),
		debugPrvKey("prvKeyEpRcv", prvKeyEpRcv))

	pubKeyIdSnd, pubKeyEpSnd, pubKeyEpSndRollover, message, err := DecodeInitHandshakeS0(
		buffer,
		prvKeyEpRcv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode InitHandshakeS0: %w", err)
	}

	conn, err := l.newConn(
		remoteAddr,
		prvKeyEpRcv,
		prvKeyEpRcvRollover,
		pubKeyIdSnd,
		pubKeyEpSnd,
		pubKeyEpSndRollover,
		false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create connection: %w", err)
	}

	conn.isHandshake = true
	conn.sharedSecret = message.SharedSecret
	conn.connId = connId
	return message, conn, nil
}

func (l *Listener) handleInitHandshakeR0(
	buffer []byte,
	remoteAddr netip.AddrPort,
	prvKeyEpSnd *ecdh.PrivateKey,
	prvKeyEpSndRollover *ecdh.PrivateKey) (*Message, *Connection, error) {
	slog.Debug("DecodeInitHandshakeR0",
		debugGoroutineID(),
		l.debug(remoteAddr),
		debugPrvKey("prvKeyEpSnd", prvKeyEpSnd))

	pubKeyIdRcv, pubKeyEpRcv, pubKeyEpRcvRollover, message, err := DecodeInitHandshakeR0(
		buffer,
		prvKeyEpSnd)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode InitHandshakeR0: %w", err)
	}

	conn, err := l.newConn(
		remoteAddr,
		prvKeyEpSnd,
		prvKeyEpSndRollover,
		pubKeyIdRcv,
		pubKeyEpRcv,
		pubKeyEpRcvRollover,
		true)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create connection: %w", err)
	}

	conn.sharedSecret = message.SharedSecret
	return message, conn, nil
}

func (l *Listener) handleInitWithCryptoS0(buffer []byte, remoteAddr netip.AddrPort) (*Message, *Connection, error) {
	prvKeyEpRcv, prvKeyEpRcvRollover, err := generateTwoKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate keys: %w", err)
	}

	slog.Debug("DecodeInitWithCryptoS0",
		debugGoroutineID(),
		l.debug(remoteAddr),
		debugPrvKey("privKeyId", l.prvKeyId),
		debugPrvKey("prvKeyEpRcv", prvKeyEpRcv))

	pubKeyIdSnd, pubKeyEpSnd, pubKeyEpSndRollover, message, err := DecodeInitWithCryptoS0(
		buffer,
		l.prvKeyId,
		prvKeyEpRcv)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode InitWithCryptoS0: %w", err)
	}

	conn, err := l.newConn(
		remoteAddr,
		prvKeyEpRcv,
		prvKeyEpRcvRollover,
		pubKeyIdSnd,
		pubKeyEpSnd,
		pubKeyEpSndRollover,
		false)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create connection: %w", err)
	}

	conn.sharedSecret = message.SharedSecret
	return message, conn, nil
}

func (l *Listener) handleInitWithCryptoR0(buffer []byte, remoteAddr netip.AddrPort, conn *Connection) (*Message, error) {
	slog.Debug("DecodeInitWithCryptoR0", debugGoroutineID(), l.debug(remoteAddr))

	pubKeyEpRcv, pubKeyEpRcvRollover, message, err := DecodeInitWithCryptoR0(buffer, conn.prvKeyEpSnd)
	if err != nil {
		return nil, fmt.Errorf("failed to decode InitWithCryptoR0: %w", err)
	}

	conn.pubKeyEpRcv = pubKeyEpRcv
	conn.pubKeyEpRcvRollover = pubKeyEpRcvRollover
	conn.sharedSecret = message.SharedSecret

	return message, nil
}

func (l *Listener) handleData0Message(buffer []byte, remoteAddr netip.AddrPort, conn *Connection) (*Message, error) {
	slog.Debug("DecodeData0",
		debugGoroutineID(),
		l.debug(remoteAddr),
		slog.Int("len(buffer)", len(buffer)))

	pubKeyEpRollover, message, err := DecodeData0(buffer, conn.sender, conn.prvKeyEpSnd)
	if err != nil {
		return nil, fmt.Errorf("failed to decode Data0: %w", err)
	}

	conn.pubKeyEpRcvRollover = pubKeyEpRollover
	conn.sharedSecret = message.SharedSecret

	return message, nil
}

func (l *Listener) handleDataMessage(buffer []byte, remoteAddr netip.AddrPort, conn *Connection) (*Message, error) {
	slog.Debug("DecodeDataMessage",
		debugGoroutineID(),
		l.debug(remoteAddr),
		slog.Int("len(buffer)", len(buffer)))

	message, err := DecodeData(buffer, conn.sender, conn.sharedSecret)
	if err != nil {
		return nil, err
	}

	return message, nil
}
