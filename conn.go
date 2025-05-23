package tomtp

import (
	"crypto/ecdh"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
)

// tmpRollover is used during rollover to temporarily store new rollover material. In case of perfect rollover,
// this is not needed. If you still have packets to send before the rollover and after, we need to temporarily store
// the new values, until all packets from the before rollover are sent.
type tmpRollover struct {
	connIdRollover       uint64
	prvKeyEpSndRollover  *ecdh.PrivateKey
	sharedSecretRollover []byte
}

type Connection struct {
	connId                uint64
	connIdRollover        uint64
	remoteAddr            netip.AddrPort
	streams               *skipList[uint32, *Stream]
	listener              *Listener
	pubKeyIdRcv           *ecdh.PublicKey
	prvKeyEpSnd           *ecdh.PrivateKey
	prvKeyEpSndRollover   *ecdh.PrivateKey
	pubKeyEpRcv           *ecdh.PublicKey
	pubKeyEpRcvRollover   *ecdh.PublicKey
	sharedSecret          []byte
	sharedSecretRollover  []byte
	rbSnd                 *SendBuffer // Send buffer for outgoing dataToSend, handles the global sn
	rbRcv                 *ReceiveBuffer
	bytesWritten          uint64
	mtu                   uint64
	isSender              bool
	isRollover            bool
	isHandshakeComplete   bool
	isFirstPacketProduced bool
	withCrypto            bool
	snCrypto              uint64 //this is 48bit
	tmpRollover           *tmpRollover

	// Flow control
	rcvWndSize uint64 // Receive window Size

	BBR
	RTT
	mu sync.Mutex
}

func (c *Connection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	next := c.streams.Min()
	for next != nil {
		next.value.Close()
		next = next.Next()
	}
}

func (c *Connection) Stream(streamId uint32) (s *Stream) {
	c.mu.Lock()
	defer c.mu.Unlock()

	p := c.streams.Get(streamId)
	if p != nil {
		s = p.value
		if s != nil {
			return s
		}
	}

	s = &Stream{
		streamId: streamId,
		conn:     c,
		mu:       sync.Mutex{},
		state:    StreamStateOpen,
	}
	c.streams.Put(streamId, s)
	return s
}

func (c *Connection) decode(decryptedData []byte, msgType MsgType, nowMicros uint64) (s *Stream, err error) {
	p, _, payloadData, err := DecodePayload(decryptedData)
	if err != nil {
		slog.Info("error in decoding payload from new connection", slog.Any("error", err))
		return nil, err
	}

	if p.RcvWndSize > 0 {
		c.rcvWndSize = p.RcvWndSize
	}

	// Get or create stream using StreamId from Data
	s = c.Stream(p.StreamId)

	if p.Ack != nil {
		ackStatus, sentTimeMicros := c.rbSnd.AcknowledgeRange(p.Ack) //remove data from rbSnd if we got the ack

		if nowMicros > sentTimeMicros {
			rttMicros := nowMicros - sentTimeMicros
			c.UpdateRTT(rttMicros)
			if ackStatus == AckStatusOk {
				c.UpdateBBR(rttMicros, uint64(p.Ack.len), nowMicros)
			} else if ackStatus == AckDup {
				c.OnDuplicateAck()
			} else {
				return nil, errors.New("stream does not exist")
			}
		}
	}

	if len(payloadData) > 0 || p.IsClose {
		c.rbRcv.Insert(s.streamId, p.StreamOffset, payloadData, p.IsClose)
	}

	return s, nil
}

func (c *Connection) updateState(s *Stream, isClose bool) {
	//update state
	if s.state == StreamStateOpen && isClose {
		s.state = StreamStateCloseReceived
	}
	if s.state == StreamStateCloseRequest && isClose {
		s.state = StreamStateClosed
	}
}

type streamEncData struct {
	encData []byte
	m       *MetaData
}

func (t *streamEncData) Update(nowMicros uint64) {
	if t.m != nil {
		t.m.afterSendMicros = nowMicros
	}
}

func (c *Connection) Flush(nowMicros uint64) (streamData []streamEncData, err error) {
	stream := c.streams.MinValue()
	for stream != nil {

		//update state for receiver
		if stream.state == StreamStateCloseReceived {
			//by now we have sent our ack back, so we set the stream to closed, in case of a dup,
			//we just ack with the close flag
			stream.state = StreamStateClosed
		}

		ack := c.rbRcv.GetSndAck()
		hasAck := ack != nil

		maxData := uint16(startMtu - stream.Overhead(hasAck))

		splitData, m, err := c.rbSnd.ReadyToRetransmit(stream.streamId, maxData, c.rtoMicros(), nowMicros)
		if err != nil {
			return nil, err
		}

		if m != nil && splitData != nil {
			c.OnPacketLoss()
			encData, msgType, err := stream.encode(splitData, m.offset, ack, m.msgType)
			if msgType != m.msgType {
				panic("cryptoType changed")
			}
			if err != nil {
				return nil, err
			}
			streamData = append(streamData, streamEncData{encData: encData, m: m})
			slog.Debug("UpdateSnd/ReadyToRetransmit", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
		} else if !c.isHandshakeComplete && c.isFirstPacketProduced {
			//we are in handshake mode, and we already sent the first paket, so we can only retransmit atm, but
			//not send. We also can ack dup pakets
			if ack != nil {
				encData, _, err := stream.encode([]byte{}, stream.currentOffset(), ack, -1)
				if err != nil {
					return nil, err
				}
				streamData = append(streamData, streamEncData{encData: encData, m: nil})
				slog.Debug("UpdateSnd/Acks1", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
			} else {
				return streamData, nil //we need to wait, so go to next connection
			}
		} else {
			splitData, m = c.rbSnd.ReadyToSend(stream.streamId, maxData, nowMicros)
			if m != nil && splitData != nil {
				encData, msgType, err := stream.encode(splitData, m.offset, ack, -1)
				if err != nil {
					return nil, err
				}
				m.msgType = msgType
				streamData = append(streamData, streamEncData{encData: encData, m: m})
				c.isFirstPacketProduced = true
				slog.Debug("UpdateSnd/ReadyToSend/splitData", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
			} else {
				//here we check if we have just acks to send
				if ack != nil {
					encData, _, err := stream.encode([]byte{}, stream.currentOffset(), ack, -1)
					if err != nil {
						return nil, err
					}
					streamData = append(streamData, streamEncData{encData: encData, m: nil})
					slog.Debug("UpdateSnd/Acks2", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
				} else {
					pair := c.streams.Get(stream.streamId)
					stream = pair.NextValue()
				}
			}
		}

	}

	return streamData, nil //go to next stream
}
