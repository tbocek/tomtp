package tomtp

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
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
	accept       func(s *Stream)
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

func ListenString(listenAddrStr string, accept func(s *Stream), options ...ListenFunc) (*Listener, error) {
	listenAddr, err := net.ResolveUDPAddr("udp", listenAddrStr)
	if err != nil {
		return nil, err
	}
	return Listen(listenAddr, accept, options...)
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

func Listen(listenAddr *net.UDPAddr, accept func(s *Stream), options ...ListenFunc) (*Listener, error) {
	lOpts, err := fillListenOpts(listenAddr, options...)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		localConn: lOpts.localConn,
		prvKeyId:  lOpts.prvKeyId,
		connMap:   make(map[uint64]*Connection),
		accept:    accept,
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

	l.localConn.CancelRead()
	return l.localConn.Close()
}

func (l *Listener) UpdateRcv(nowMicros int64) (err error) {
	buffer, remoteAddr, err := l.ReadUDP(nowMicros)
	if err != nil {
		return err
	}

	if buffer == nil || len(buffer) == 0 {
		return nil
	}
	slog.Debug("RcvUDP", debugGoroutineID(), l.debug(remoteAddr))

	conn, m, err := l.decode(buffer, remoteAddr)
	if err != nil {
		return err
	}

	s, isNew, err := conn.decode(m.PayloadRaw, nowMicros)
	if err != nil {
		return err
	}

	slog.Debug("we decoded the payload, handle stream", debugGoroutineID(), l.debug(remoteAddr), slog.Any("sn", m.SnConn))

	if isNew {
		l.accept(s)
	}

	return nil
}

func (l *Listener) UpdateSnd(nowMicros int64) (err error) {
	//timeouts, retries, ping, sending packets
	for _, c := range l.connMap {
		for _, stream := range c.streams {
			acks := c.rbRcv.GetAcks()
			maxData := stream.calcLen(startMtu, len(acks))
			splitData := c.rbSnd.ReadyToRetransmit(stream.streamId, maxData, c.RTT.rto.Milliseconds(), nowMicros)
			if splitData != nil {
				encData, err := stream.encode(splitData, acks)
				if err != nil {
					return err
				}

				slog.Debug("UpdateSnd/ReadyToRetransmit", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
				n, err := l.localConn.WriteToUDPAddrPort(encData, c.remoteAddr)
				if err != nil {
					return err
				}
				c.bytesWritten += uint64(n)

				//we detected a packet loss, reduce ssthresh by 2
				c.BBR.ssthresh = c.BBR.cwnd / 2
				if c.BBR.ssthresh < uint64(2*c.mtu) {
					c.BBR.ssthresh = uint64(2 * c.mtu)
				}
				continue
			}

			splitData = c.rbSnd.ReadyToSend(stream.streamId, maxData, nowMicros)
			if splitData != nil {
				encData, err := stream.encode(splitData, acks)
				if err != nil {
					return err
				}

				slog.Debug("UpdateSnd/ReadyToSend", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
				n, err := l.localConn.WriteToUDPAddrPort(encData, c.remoteAddr)
				if err != nil {
					return c.Close()
				}
				c.bytesWritten += uint64(n)
				continue
			}

			//here we check if we have just acks to send
			if len(acks) > 0 {
				encData, err := stream.encode([]byte{}, acks)
				if err != nil {
					return err
				}

				slog.Debug("UpdateSnd/Acks", debugGoroutineID(), slog.Any("len(dataToSend)", len(encData)))
				n, err := l.localConn.WriteToUDPAddrPort(encData, c.remoteAddr)
				if err != nil {
					return c.Close()
				}
				c.bytesWritten += uint64(n)
				continue
			}
		}
	}
	return nil
}

func (l *Listener) Update(nowMicros int64) error {
	err := l.UpdateRcv(nowMicros)
	if err != nil {
		return err
	}

	err = l.UpdateSnd(nowMicros)
	if err != nil {
		return err
	}
	return nil
}

func (l *Listener) newConnHandshake(remoteAddr netip.AddrPort,
	prvKeyEpSnd *ecdh.PrivateKey,
	prvKeyEpSndRollover *ecdh.PrivateKey) (*Connection, error) {

	l.mu.Lock()
	defer l.mu.Unlock()

	connId, err := findUniqueConnId(l)
	if err != nil {
		return nil, err
	}

	l.connMap[connId] = &Connection{
		connId:              connId,
		streams:             make(map[uint32]*Stream),
		remoteAddr:          remoteAddr,
		pubKeyIdRcv:         nil,
		prvKeyEpSnd:         prvKeyEpSnd,
		prvKeyEpSndRollover: prvKeyEpSndRollover,
		pubKeyEpRcvRollover: nil,
		pubKeyEpRcv:         nil,
		mu:                  sync.Mutex{},
		nextSleepMillis:     l.readDeadline,
		listener:            l,
		sender:              true,
		firstPaket:          true,
		isHandshake:         true,
		mtu:                 startMtu,
		rbSnd:               NewSendBuffer(rcvBufferCapacity),
		rbRcv:               NewReceiveBuffer(rcvBufferCapacity),
		RTT: RTT{
			alpha:  0.125,
			beta:   0.25,
			minRTO: 1 * time.Second,
			maxRTO: 60 * time.Second,
		},
		BBR: NewBBR(),
	}

	return l.connMap[connId], nil
}

func (l *Listener) newConn(
	remoteAddr netip.AddrPort,
	prvKeyEpSnd *ecdh.PrivateKey,
	prvKeyEpSndRollover *ecdh.PrivateKey,
	pubKeyIdRcv *ecdh.PublicKey,
	pubKeyEdRcv *ecdh.PublicKey,
	pubKeyEpRcvRollover *ecdh.PublicKey,
	sender bool) (*Connection, error) {
	var connId uint64
	pukKeyIdSnd := l.prvKeyId.Public().(*ecdh.PublicKey)
	connId = binary.LittleEndian.Uint64(pubKeyIdRcv.Bytes()) ^ binary.LittleEndian.Uint64(pukKeyIdSnd.Bytes())

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
		nextSleepMillis:     l.readDeadline,
		listener:            l,
		sender:              sender,
		firstPaket:          true,
		mtu:                 startMtu,
		rbSnd:               NewSendBuffer(rcvBufferCapacity),
		rbRcv:               NewReceiveBuffer(rcvBufferCapacity),
		RTT: RTT{
			alpha:  0.125,
			beta:   0.25,
			minRTO: 1 * time.Second,
			maxRTO: 60 * time.Second,
		},
		BBR: NewBBR(),
	}

	return l.connMap[connId], nil
}

func (l *Listener) ReadUDP(nowMicros int64) ([]byte, netip.AddrPort, error) {
	buffer := make([]byte, maxBuffer)

	// Set the read deadline
	err := l.localConn.SetReadDeadline(time.UnixMicro(nowMicros + (100 * 1000)))
	if err != nil {
		slog.Error("error setting read deadline", slog.Any("error", err))
		return nil, netip.AddrPort{}, err
	}

	numRead, remoteAddr, err := l.localConn.ReadFromUDPAddrPort(buffer, nowMicros)

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

const maxAttempts = 10000

func findUniqueConnId(l *Listener) (uint64, error) {
	for i := 0; i < maxAttempts; i++ {
		connId, err := generateRandomUint64()
		if err != nil {
			return 0, err
		}
		if _, exists := l.connMap[connId]; !exists {
			return connId, nil
		}
		slog.Debug("collision on connId, retrying", slog.Any("connId", connId), slog.Int("attempt", i+1))
	}
	return 0, fmt.Errorf("failed to generate unique connId after %d attempts", maxAttempts)
}

func (l *Listener) debug(addr netip.AddrPort) slog.Attr {
	if l.localConn == nil {
		return slog.String("net", "nil->"+addr.String())
	}

	localAddrString := l.localConn.LocalAddrString()
	lastColonIndex := strings.LastIndex(localAddrString, ":")

	return slog.String("net", strconv.Itoa(int(addr.Port()))+"->"+localAddrString[lastColonIndex+1:])
}
