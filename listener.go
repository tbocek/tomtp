package tomtp

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

const ReadDeadLine uint64 = 200

type Listener struct {
	// this is the port we are listening to
	localConn    NetworkConn
	prvKeyId     *ecdh.PrivateKey
	connMap      map[uint64]*Connection // here we store the connection to remote peers, we can have up to
	closed       bool
	readDeadline uint64
	mu           sync.Mutex
}

type ListenOption struct {
	seed      *[32]byte
	prvKeyId  *ecdh.PrivateKey
	localConn NetworkConn
}

type ListenFunc func(*ListenOption) error

func WithSeed(seed [32]byte) ListenFunc {
	return func(c *ListenOption) error {
		if c.seed != nil {
			return errors.New("seed already set")
		}
		c.seed = &seed
		return nil
	}
}

func WithNetworkConn(localConn NetworkConn) ListenFunc {
	return func(c *ListenOption) error {
		c.localConn = localConn
		return nil
	}
}

func WithPrvKeyId(prvKeyId *ecdh.PrivateKey) ListenFunc {
	return func(c *ListenOption) error {
		if c.prvKeyId != nil {
			return errors.New("prvKeyId already set")
		}
		if prvKeyId == nil {
			return errors.New("prvKeyId not set")
		}

		c.prvKeyId = prvKeyId
		return nil
	}
}

func WithSeedStrHex(seedStrHex string) ListenFunc {
	return func(c *ListenOption) error {
		if c.seed != nil {
			return errors.New("seed already set")
		}

		seed, err := decodeHex(seedStrHex)
		if err != nil {
			return err
		}
		copy(c.seed[:], seed)
		return nil
	}
}

func WithSeedStr(seedStr string) ListenFunc {
	return func(c *ListenOption) error {
		if c.seed != nil {
			return errors.New("seed already set")
		}

		hashSum := sha256.Sum256([]byte(seedStr))
		c.seed = &hashSum
		return nil
	}
}

func ListenString(listenAddrStr string, options ...ListenFunc) (*Listener, error) {
	listenAddr, err := net.ResolveUDPAddr("udp", listenAddrStr)
	if err != nil {
		return nil, err
	}
	return Listen(listenAddr, options...)
}

func fillListenOpts(listenAddr *net.UDPAddr, options ...ListenFunc) (*ListenOption, error) {
	lOpts := &ListenOption{
		seed:     nil,
		prvKeyId: nil,
	}
	for _, opt := range options {
		err := opt(lOpts)
		if err != nil {
			return nil, err
		}
	}

	if lOpts.seed != nil {
		prvKeyId, err := ecdh.X25519().NewPrivateKey(lOpts.seed[:])
		if err != nil {
			return nil, err
		}
		lOpts.prvKeyId = prvKeyId
	}
	if lOpts.prvKeyId == nil {
		prvKeyId, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		lOpts.prvKeyId = prvKeyId
	}
	if lOpts.localConn == nil {
		conn, err := net.ListenUDP("udp", listenAddr)
		if err != nil {
			return nil, err
		}

		err = setDF(conn)
		if err != nil {
			return nil, err
		}

		lOpts.localConn = NewUDPNetworkConn(conn)
	}

	return lOpts, nil
}

func Listen(listenAddr *net.UDPAddr, options ...ListenFunc) (*Listener, error) {
	lOpts, err := fillListenOpts(listenAddr, options...)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		localConn: lOpts.localConn,
		prvKeyId:  lOpts.prvKeyId,
		connMap:   make(map[uint64]*Connection),
		mu:        sync.Mutex{},
	}

	slog.Info(
		"Listen",
		slog.Any("listenAddr", lOpts.localConn.LocalAddrString()),
		slog.String("privKeyId", "0x"+hex.EncodeToString(l.prvKeyId.Bytes()[:3])+"…"),
		slog.String("pubKeyId", "0x"+hex.EncodeToString(l.prvKeyId.PublicKey().Bytes()[:3])+"…"))

	return l, nil
}

func (l *Listener) Close() error {
	slog.Debug("ListenerClose", debugGoroutineID())
	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed = true

	for _, conn := range l.connMap {
		conn.Close()
	}
	clear(l.connMap)

	err := l.localConn.CancelRead()
	if err != nil {
		return err
	}
	return l.localConn.Close()
}

func (l *Listener) Listen(timeout time.Duration, nowMicros int64) (s *Stream, isNew bool, err error) {
	buffer, remoteAddr, err := l.ReadUDP(timeout)
	if err != nil {
		return nil, false, err
	}

	if buffer == nil || len(buffer) == 0 {
		return nil, false, nil
	}
	slog.Debug("RcvUDP", debugGoroutineID(), l.debug(remoteAddr))

	conn, m, err := l.decode(buffer, remoteAddr)
	if err != nil {
		return nil, false, err
	}

	return conn.decode(m.PayloadRaw, nowMicros)

}

func (l *Listener) Flush(nowMicros int64) (pacingDelay time.Duration, err error) {
	//timeouts, retries, ping, sending packets
	for _, c := range l.connMap {
		for _, stream := range c.streams {
			ack := c.rbRcv.GetAck()
			hasAck := ack != nil

			maxData := uint16(startMtu - stream.Overhead(hasAck))

			splitData, m, err := c.rbSnd.ReadyToRetransmit(stream.streamId, maxData, c.RTO(), nowMicros)
			if err != nil {
				return 0, err
			}

			var encData []byte
			var msgType MsgType
			if m != nil && splitData != nil {
				c.OnPacketLoss()
				encData, msgType, err = stream.encode(splitData, ack, m.msgType)
				if msgType != m.msgType {
					panic("cryptoType changed")
				}
				slog.Debug("UpdateSnd/ReadyToRetransmit", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
			} else {
				splitData, m = c.rbSnd.ReadyToSend(stream.streamId, maxData, nowMicros)
				if m != nil && splitData != nil {
					encData, msgType, err = stream.encode(splitData, ack, -1)
					if err != nil {
						return 0, err
					}
					m.msgType = msgType
					slog.Debug("UpdateSnd/ReadyToSend/splitData", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
				} else {
					//here we check if we have just acks to send
					if ack != nil {
						encData, _, err = stream.encode([]byte{}, ack, -1)
						if err != nil {
							return 0, err
						}
						slog.Debug("UpdateSnd/Acks", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
					}
				}
			}

			if len(encData) > 0 {
				n, err := l.localConn.WriteToUDPAddrPort(encData, c.remoteAddr)
				if err != nil {
					return 0, err
				}
				c.bytesWritten += uint64(n)
				pacingDelay := c.GetPacingDelay(len(encData))
				return pacingDelay, nil
			}
		}
	}
	return 0, nil
}

func (l *Listener) newConn(
	remoteAddr netip.AddrPort,
	prvKeyEpSnd *ecdh.PrivateKey,
	prvKeyEpSndRollover *ecdh.PrivateKey,
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyEdRcv *ecdh.PublicKey,
	pubKeyEpRcvRollover *ecdh.PublicKey,
	isSender bool,
	withCrypto bool) (*Connection, error) {
	var connId uint64
	pukKeyIdSnd := l.prvKeyId.Public().(*ecdh.PublicKey)

	if pubKeyIdRcv != nil && pukKeyIdSnd != nil {
		connId = binary.LittleEndian.Uint64(pubKeyIdRcv.Bytes()) ^ binary.LittleEndian.Uint64(pukKeyIdSnd.Bytes())
	} else {
		//we do not know the recipient keys yet, so only use our ephemeral key
		connId = binary.LittleEndian.Uint64(prvKeyEpSnd.Bytes())
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if conn, ok := l.connMap[connId]; ok {
		slog.Warn("conn already exists", slog.Any("connId", connId))
		return conn, errors.New("conn already exists")
	}

	l.connMap[connId] = &Connection{
		connId:              connId,
		streams:             make(map[uint32]*Stream),
		remoteAddr:          remoteAddr,
		pubKeyIdRcv:         pubKeyIdRcv,
		prvKeyEpSnd:         prvKeyEpSnd,
		prvKeyEpSndRollover: prvKeyEpSndRollover,
		pubKeyEpRcvRollover: pubKeyEpRcvRollover,
		pubKeyEpRcv:         pubKeyEdRcv,
		mu:                  sync.Mutex{},
		listener:            l,
		isSender:            isSender,
		isHandshake:         true,
		withCrypto:          withCrypto,
		mtu:                 startMtu,
		rbSnd:               NewSendBuffer(initBufferCapacity),
		rbRcv:               NewReceiveBuffer(initBufferCapacity),
		BBR:                 NewBBR(),
		rcvWndSize:          initBufferCapacity,
	}

	return l.connMap[connId], nil
}

func (l *Listener) ReadUDP(timeout time.Duration) ([]byte, netip.AddrPort, error) {
	buffer := make([]byte, maxBuffer)

	numRead, remoteAddr, err := l.localConn.ReadFromUDPAddrPort(buffer, timeout)

	if err != nil {
		var netErr net.Error
		ok := errors.As(err, &netErr)

		if ok && netErr.Timeout() {
			slog.Debug("ReadUDP - net.Timeout")
			return nil, netip.AddrPort{}, nil // Timeout is normal, return no dataToSend/error
		} else {
			slog.Error("ReadUDP - error during read", slog.Any("error", err))
			return nil, netip.AddrPort{}, err
		}
	}

	slog.Debug("ReadUDP - dataAvailable")
	return buffer[:numRead], remoteAddr, nil
}

func (l *Listener) debug(addr netip.AddrPort) slog.Attr {
	if l.localConn == nil {
		return slog.String("net", "nil->"+addr.String())
	}

	localAddrString := l.localConn.LocalAddrString()
	lastColonIndex := strings.LastIndex(localAddrString, ":")

	return slog.String("net", strconv.Itoa(int(addr.Port()))+"->"+localAddrString[lastColonIndex+1:])
}
