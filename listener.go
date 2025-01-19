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
	"strconv"
	"strings"
	"sync"
	"time"
)

const ReadDeadLine uint64 = 200

type Listener struct {
	// this is the port we are listening to
	localConn    NetworkConn
	pubKeyId     *ecdh.PublicKey
	prvKeyId     *ecdh.PrivateKey
	connMap      map[uint64]*Connection // here we store the connection to remote peers, we can have up to
	accept       func(s *Stream)
	closed       bool
	readDeadline uint64
	mu           sync.Mutex
}

type ListenOption struct {
	seed         *[32]byte
	prvKeyId     *ecdh.PrivateKey
	readDeadline uint64
}

type ListenFunc func(*ListenOption)

func WithSeed(seed [32]byte) ListenFunc {
	return func(c *ListenOption) {
		c.seed = &seed
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

func WithReadDeadline(readDeadline uint64) ListenFunc {
	return func(c *ListenOption) {
		c.readDeadline = readDeadline
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

func Listen(listenAddr *net.UDPAddr, accept func(s *Stream), options ...ListenFunc) (*Listener, error) {
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

	return ListenNetwork(
		NewUDPNetworkConn(conn),
		accept,
		options...,
	)
}

func fillListenOpts(options ...ListenFunc) *ListenOption {
	lOpts := &ListenOption{
		seed:         nil,
		prvKeyId:     nil,
		readDeadline: ReadDeadLine,
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
		}
		lOpts.prvKeyId = prvKeyId
	}
	if lOpts.prvKeyId == nil {
		prvKeyId, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			slog.Error(
				"error generating private id key random",
				slog.Any("error", err))
		}
		lOpts.prvKeyId = prvKeyId
	}

	return lOpts
}

func ListenNetwork(localConn NetworkConn, accept func(s *Stream), options ...ListenFunc) (*Listener, error) {
	lOpts := fillListenOpts(options...)
	prvKeyId := lOpts.prvKeyId
	l := &Listener{
		localConn:    localConn,
		pubKeyId:     prvKeyId.Public().(*ecdh.PublicKey),
		prvKeyId:     prvKeyId,
		connMap:      make(map[uint64]*Connection),
		accept:       accept,
		readDeadline: lOpts.readDeadline,
		mu:           sync.Mutex{},
	}

	slog.Info(
		"Listen",
		slog.Any("listenAddr", localConn.LocalAddr()),
		slog.String("privKeyId", "0x"+hex.EncodeToString(l.prvKeyId.Bytes()[:3])+"…"),
		slog.String("pubKeyId", "0x"+hex.EncodeToString(l.pubKeyId.Bytes()[:3])+"…"))

	return l, nil
}

func (l *Listener) Close() error {
	slog.Debug("ListenerClose", debugGoroutineID(), l.debug(nil))
	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed = true

	for _, conn := range l.connMap {
		conn.Close()
	}

	remoteConnError := l.localConn.Close()
	l.connMap = make(map[uint64]*Connection)

	return remoteConnError
}

func (l *Listener) UpdateRcv(sleepMillis uint64) (err error) {
	buffer := make([]byte, maxBuffer)

	if sleepMillis > 0 {
		err := l.localConn.SetReadDeadline(timeNow().Add(time.Duration(sleepMillis) * time.Millisecond))
		if err != nil {
			slog.Error("error setting deadline for connection", slog.Any("error", err))
			return err
		}
	}

	n, remoteAddr, err := l.localConn.ReadFromUDP(buffer)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && !netErr.Timeout() {
			// Ignore timeout error
			return err
		}
	}
	if n > 0 {
		slog.Debug("RcvUDP", debugGoroutineID(), l.debug(remoteAddr), slog.Int("n", n))

		err2 := l.decode(buffer, n, remoteAddr)
		if err2 != nil {
			return err2
		}
	}
	return nil
}

func (l *Listener) UpdateSnd(nowMillis uint64) (err error) {
	//timeouts, retries, ping, sending packets
	minSleep := uint64(200)
	for _, c := range l.connMap {
		s, seg := c.rbSnd.ReadyToSend(nowMillis)
		if s < minSleep {
			minSleep = s
		}
		if seg == nil {
			continue
		}

		slog.Debug("handleOutgoingUDP", debugGoroutineID(), slog.Any("len(data)", len(seg.data)))
		n, err := l.localConn.WriteToUDP(seg.data, c.remoteAddr)
		if err != nil {
			return c.Close()
		}
		c.bytesWritten += uint64(n)
	}

	//TODO: if ReadyToSend gets a new paket, interrupt this sleep
	time.Sleep(time.Duration(minSleep) * time.Millisecond)

	return nil
}

func (l *Listener) newConn(remoteAddr net.Addr, pubKeyIdRcv *ecdh.PublicKey, prvKeyEpSnd *ecdh.PrivateKey, pubKeyEdRcv *ecdh.PublicKey, sender bool) (*Connection, error) {
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
		streams:         make(map[uint32]*Stream),
		remoteAddr:      remoteAddr,
		pubKeyIdRcv:     pubKeyIdRcv,
		prvKeyEpSnd:     prvKeyEpSnd,
		pubKeyEpRcv:     pubKeyEdRcv,
		rtoMillis:       1000,
		mu:              sync.Mutex{},
		nextSleepMillis: l.readDeadline,
		listener:        l,
		sender:          sender,
		firstPaket:      true,
		mtu:             startMtu,
		rbSnd:           NewRingBufferSnd[[]byte](maxRingBuffer, maxRingBuffer),
	}

	return l.connMap[connId], nil
}

func (l *Listener) debug(addr net.Addr) slog.Attr {
	localAddr := l.localConn.LocalAddr()
	lastColonIndex := strings.LastIndex(localAddr.String(), ":")

	if cAddr, ok := addr.(*net.UDPAddr); ok {
		return slog.String("net", strconv.Itoa(cAddr.Port)+"->"+localAddr.String()[lastColonIndex+1:])
	} else {
		if addr == nil {
			return slog.String("net", localAddr.String()+"->nil")
		} else {
			return slog.String("net", localAddr.String()+"->"+addr.String())
		}
	}
}
