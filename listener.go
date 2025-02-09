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

type ListenFunc func(*ListenOption)

func WithSeed(seed [32]byte) ListenFunc {
	return func(c *ListenOption) {
		c.seed = &seed
	}
}

func WithNetworkConn(localConn NetworkConn) ListenFunc {
	return func(c *ListenOption) {
		c.localConn = localConn
	}
}

func WithPrivKeyId(prvKeyId *ecdh.PrivateKey) ListenFunc {
	return func(c *ListenOption) {
		if c.seed != nil {
			slog.Warn("overwriting seed with this key")
		}

		c.prvKeyId = prvKeyId
	}
}

func WithSeedStrHex(seedStrHex string) ListenFunc {
	return func(c *ListenOption) {
		if c.prvKeyId != nil {
			slog.Warn("overwriting privKeyId with this seed")
		}
		if c.seed != nil {
			slog.Warn("overwriting old seed with this new seed")
		}

		if strings.HasPrefix(seedStrHex, "0x") {
			seedStrHex = strings.Replace(seedStrHex, "0x", "", 1)
		}
		seed, err := hex.DecodeString(seedStrHex)
		if err != nil {
			slog.Error(
				"cannot decode seedStrHex",
				slog.Any("error", err),
				slog.Any("seed", string(seed[:6])))
		}
		copy(c.seed[:], seed)
	}
}

func WithSeedStr(seedStr string) ListenFunc {
	return func(c *ListenOption) {
		if c.prvKeyId != nil {
			slog.Warn("overwriting privKeyId with this seed")
		}
		if c.seed != nil {
			slog.Warn("overwriting old seed with this new seed")
		}

		hashSum := sha256.Sum256([]byte(seedStr))
		c.seed = &hashSum
	}
}

func ListenString(listenAddrStr string, accept func(s *Stream), options ...ListenFunc) (*Listener, error) {
	listenAddr, err := net.ResolveUDPAddr("udp", listenAddrStr)
	if err != nil {
		slog.Error(
			"error resolving remote address",
			slog.Any("error", err),
			slog.String("address", listenAddrStr))
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
		opt(lOpts)
	}

	if lOpts.seed != nil {
		prvKeyId, err := ecdh.X25519().NewPrivateKey(lOpts.seed[:])
		if err != nil {
			slog.Error(
				"error generating private id key from seed",
				slog.Any("error", err))
			return nil, err
		}
		lOpts.prvKeyId = prvKeyId
	}
	if lOpts.prvKeyId == nil {
		prvKeyId, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			slog.Error(
				"error generating private id key random",
				slog.Any("error", err))
			return nil, err
		}
		lOpts.prvKeyId = prvKeyId
	}
	if lOpts.localConn == nil {
		conn, err := net.ListenUDP("udp", listenAddr)
		if err != nil {
			slog.Error(
				"cannot listen to UDP",
				slog.Any("error", err),
				slog.Any("listenAddr", listenAddr))
			return nil, err
		}

		err = setDF(conn)
		if err != nil {
			slog.Error(
				"cannot set do-not-fragment",
				slog.Any("error", err))
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
		slog.Any("listenAddr", lOpts.localConn.LocalAddr()),
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

func (l *Listener) UpdateRcv(nowMillis uint64) (err error) {
	buffer, remoteAddr, err := l.ReadUDP()
	if err != nil {
		return err
	}

	if buffer == nil {
		return nil
	}
	slog.Debug("RcvUDP", debugGoroutineID(), l.debug(remoteAddr))

	conn, m, err := l.decode(buffer, remoteAddr)
	if err != nil {
		return err
	}

	s, isNew, err := conn.decode(m.PayloadRaw, nowMillis)
	if err != nil {
		return err
	}

	slog.Debug("we decoded the payload, handle stream", debugGoroutineID(), l.debug(remoteAddr), slog.Any("sn", m.SnConn))

	if isNew {
		l.accept(s)
	}

	return nil
}

func (l *Listener) UpdateSnd(nowMillis uint64) (err error) {
	//timeouts, retries, ping, sending packets
	for _, c := range l.connMap {
		_, _, data, _ := c.rbSnd.ReadyToSend(startMtu, nowMillis)

		if data == nil {
			continue
		}

		slog.Debug("handleOutgoingUDP", debugGoroutineID(), slog.Any("len(data)", len(data)))
		n, err := l.localConn.WriteToUDPAddrPort(data, c.remoteAddr)
		if err != nil {
			return c.Close()
		}
		c.bytesWritten += uint64(n)
	}
	return nil
}

func (l *Listener) Update(nowMillis uint64) error {
	err := l.UpdateRcv(nowMillis)
	if err != nil {
		return err
	}

	err = l.UpdateSnd(nowMillis)
	if err != nil {
		return err
	}
	return nil
}

func (l *Listener) newConn(
	remoteAddr netip.AddrPort,
	pubKeyIdRcv *ecdh.PublicKey,
	prvKeyEpSnd *ecdh.PrivateKey,
	prvKeyEpSndRollover *ecdh.PrivateKey,
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
		rbSnd:               NewSendBuffer(maxRingBuffer),
		RTT: RTT{
			alpha:  0.125,
			beta:   0.25,
			minRTO: 1 * time.Second,
			maxRTO: 60 * time.Second,
		},
	}

	return l.connMap[connId], nil
}

func (l *Listener) ReadUDP() ([]byte, netip.AddrPort, error) {
	buffer := make([]byte, maxBuffer)

	// Set the read deadline
	err := l.localConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if err != nil {
		slog.Error("error setting read deadline", slog.Any("error", err))
		return nil, netip.AddrPort{}, err
	}

	numRead, remoteAddr, err := l.localConn.ReadFromUDPAddrPort(buffer)

	if err != nil {
		var netErr net.Error
		ok := errors.As(err, &netErr)

		if ok && netErr.Timeout() {
			slog.Debug("ReadUDP - net.Timeout")
			return nil, netip.AddrPort{}, nil // Timeout is normal, return no data/error
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

	localAddr := l.localConn.LocalAddr()
	lastColonIndex := strings.LastIndex(localAddr.String(), ":")

	return slog.String("net", strconv.Itoa(int(addr.Port()))+"->"+localAddr.String()[lastColonIndex+1:])
}
