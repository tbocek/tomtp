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
	connId               uint64
	connIdRollover       uint64
	remoteAddr           netip.AddrPort
	streams              map[uint32]*Stream
	listener             *Listener
	pubKeyIdRcv          *ecdh.PublicKey
	prvKeyEpSnd          *ecdh.PrivateKey
	prvKeyEpSndRollover  *ecdh.PrivateKey
	pubKeyEpRcv          *ecdh.PublicKey
	pubKeyEpRcvRollover  *ecdh.PublicKey
	sharedSecret         []byte
	sharedSecretRollover []byte
	rbSnd                *SendBuffer // Send buffer for outgoing dataToSend, handles the global sn
	rbRcv                *ReceiveBuffer
	bytesWritten         uint64
	mtu                  uint64
	isSender             bool
	isRollover           bool
	isHandshakeComplete  bool
	withCrypto           bool
	snCrypto             uint64 //this is 48bit
	tmpRollover          *tmpRollover

	// Flow control
	rcvWndSize uint64 // Receive window Size

	BBR
	RTT
	mu sync.Mutex
}

func (c *Connection) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, s := range c.streams {
		s.Close()
	}
}

func (c *Connection) Stream(streamId uint32) (s *Stream) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.streams == nil {
		c.streams = make(map[uint32]*Stream)
	}

	if stream, ok := c.streams[streamId]; !ok {
		s := &Stream{
			streamId: streamId,
			conn:     c,
			mu:       sync.Mutex{},
			state:    StreamStateOpen,
		}
		c.streams[streamId] = s
		return s
	} else {
		return stream
	}
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

func (c *Connection) Flush(nowMicros uint64) (err error) {
	//TODO: this looks ugly, try to clean up
	start := c.bytesWritten
	for _, stream := range c.streams {
		for {
			ack := c.rbRcv.GetSndAck()
			hasAck := ack != nil

			maxData := uint16(startMtu - stream.Overhead(hasAck))

			splitData, m, err := c.rbSnd.ReadyToRetransmit(stream.streamId, maxData, c.rtoMicros(), nowMicros)
			if err != nil {
				return err
			}

			var encData []byte
			var msgType MsgType
			if m != nil && splitData != nil {
				c.OnPacketLoss()
				encData, msgType, err = stream.encode(splitData, m.offset, ack, m.msgType)
				if msgType != m.msgType {
					panic("cryptoType changed")
				}
				slog.Debug("UpdateSnd/ReadyToRetransmit", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
			} else if !c.isHandshakeComplete && c.bytesWritten > 0 {
				//we are in handshake mode, and we already sent the first paket, so we can only retransmit atm, but
				//not send. We also can ack dup pakets
				if ack != nil {
					encData, _, err = stream.encode([]byte{}, stream.currentOffset(), ack, -1)
					if err != nil {
						return err
					}
					slog.Debug("UpdateSnd/Acks1", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
				} else {
					break // nothing to do...
				}
			} else {
				splitData, m = c.rbSnd.ReadyToSend(stream.streamId, maxData, nowMicros)
				if m != nil && splitData != nil {
					encData, msgType, err = stream.encode(splitData, m.offset, ack, -1)
					if err != nil {
						return err
					}
					m.msgType = msgType
					slog.Debug("UpdateSnd/ReadyToSend/splitData", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
				} else {
					//here we check if we have just acks to send
					if ack != nil {
						encData, _, err = stream.encode([]byte{}, stream.currentOffset(), ack, -1)
						if err != nil {
							return err
						}
						slog.Debug("UpdateSnd/Acks2", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
					} else {
						break // nothing to do...
					}
				}
			}

			if len(encData) > 0 {
				n, err := c.listener.localConn.WriteToUDPAddrPort(encData, c.remoteAddr)
				if err != nil {
					return err
				}

				//update state
				c.bytesWritten += uint64(n)
				if c.bytesWritten-start+startMtu > c.cwnd || !c.isHandshakeComplete {
					break
				}
			}

			//update state for receiver
			if stream.state == StreamStateCloseReceived {
				//by now we have sent our ack back, so we set the stream to closed, in case of a dup,
				//we just ack with the close flag
				stream.state = StreamStateClosed
			}
		}
	}

	return nil
}
