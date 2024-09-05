package tomtp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

type acceptor func(s *Stream)

type Listener struct {
	// this is the port we are listening to
	localConn      *net.UDPConn
	localAddr      *net.UDPAddr
	pubKeyId       ed25519.PublicKey
	privKeyId      ed25519.PrivateKey
	privKeyIdCurve *ecdh.PrivateKey
	connMap        map[uint64]*Connection // here we store the connection to remote peers, we can have up to
	incomingStream chan *Stream
	accept         acceptor
	closed         bool
	mu             sync.Mutex
}

type ListenOption struct {
	seed         *[32]byte
	privKeyId    *ed25519.PrivateKey
	manualUpdate bool
}

type ListenFunc func(*ListenOption)

func WithSeed(seed [32]byte) ListenFunc {
	return func(c *ListenOption) {
		c.seed = &seed
	}
}

func WithPrivKeyId(privKeyId *ed25519.PrivateKey) ListenFunc {
	return func(c *ListenOption) {
		if c.seed != nil {
			slog.Warn("overwriting seed with this key")
		}

		c.privKeyId = privKeyId
	}
}

func WithSeedStrHex(seedStrHex string) ListenFunc {
	return func(c *ListenOption) {
		if c.privKeyId != nil {
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
		if c.privKeyId != nil {
			slog.Warn("overwriting privKeyId with this seed")
		}
		if c.seed != nil {
			slog.Warn("overwriting old seed with this new seed")
		}

		hashSum := sha256.Sum256([]byte(seedStr))
		c.seed = &hashSum
	}
}

func WithManualUpdate() ListenFunc {
	return func(c *ListenOption) {
		c.manualUpdate = true
	}
}

func Listen(listenAddrStr string, accept acceptor, options ...ListenFunc) (*Listener, error) {
	listenAddr, err := net.ResolveUDPAddr("udp", listenAddrStr)
	if err != nil {
		slog.Error(
			"error resolving remote address",
			slog.Any("error", err),
			slog.String("address", listenAddrStr))
		return nil, err
	}
	return ListenTP(listenAddr, accept, options...)
}

func ListenTP(listenAddr *net.UDPAddr, accept acceptor, options ...ListenFunc) (*Listener, error) {
	lOpts := &ListenOption{
		seed:         nil,
		privKeyId:    nil,
		manualUpdate: false,
	}
	for _, opt := range options {
		opt(lOpts)
	}

	if lOpts.seed != nil {
		privKeyId := ed25519.NewKeyFromSeed(lOpts.seed[:])
		lOpts.privKeyId = &privKeyId
	}
	if lOpts.privKeyId == nil {
		_, privKeyId, err := ed25519.GenerateKey(rand.Reader)
		slog.Error(
			"error generating private id key",
			slog.Any("error", err))
		lOpts.privKeyId = &privKeyId
	}

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

	priv := *lOpts.privKeyId
	l := &Listener{
		localConn:      conn,
		localAddr:      listenAddr,
		pubKeyId:       priv.Public().(ed25519.PublicKey),
		privKeyId:      priv,
		privKeyIdCurve: ed25519PrivateKeyToCurve25519(priv),
		incomingStream: make(chan *Stream),
		connMap:        make(map[uint64]*Connection),
		accept:         accept,
		mu:             sync.Mutex{},
	}

	slog.Info(
		"Listen",
		slog.Any("listenAddr", conn.LocalAddr()),
		slog.String("privKeyId", "0x"+hex.EncodeToString(l.privKeyId[:3])+"…"),
		slog.String("pubKeyId", "0x"+hex.EncodeToString(l.pubKeyId[:3])+"…"))

	if !lOpts.manualUpdate {
		go func() {
			var err error
			sleepMillis := uint64(0)
			for err == nil {
				sleepMillis, err = l.Update(timeMilli(), sleepMillis)
			}
		}()
	}

	return l, nil
}

func (l *Listener) Close() (error, []error) {
	slog.Debug("ListenerClose", debugGoroutineID(), l.debug(nil))
	l.mu.Lock()
	defer l.mu.Unlock()

	l.closed = true

	var streamErrors []error

	for _, conn := range l.connMap {
		for _, stream := range conn.streams {
			stream.Close()
		}
	}

	remoteConnError := l.localConn.Close()
	l.connMap = make(map[uint64]*Connection)
	close(l.incomingStream)

	return remoteConnError, streamErrors
}

func (l *Listener) Update(nowMillis uint64, sleepMillis uint64) (newSleepMillis uint64, err error) {
	//incoming packets
	err = l.handleIncomingUDP(nowMillis, sleepMillis)
	if err != nil {
		return 0, err
	}

	//timeouts, retries, ping, ending packets
	nextSleepMillis := l.handleOutgoing(nowMillis)
	if nextSleepMillis > sleepMillis {
		newSleepMillis = nextSleepMillis - sleepMillis
	} else {
		newSleepMillis = 0
	}

	return newSleepMillis, nil
}

func (l *Listener) handleOutgoingUDP(b []byte, remoteAddr *net.UDPAddr) (int, error) {
	return l.localConn.WriteToUDP(b, remoteAddr)
}

func (l *Listener) handleIncomingUDP(nowMillis uint64, sleepMillis uint64) error {
	buffer := make([]byte, maxBuffer)

	if sleepMillis > 0 {
		err := l.localConn.SetReadDeadline(timeNow().Add(time.Duration(sleepMillis) * time.Millisecond))
		if err != nil {
			slog.Info("error setting deadline for connection", slog.Any("error", err))
			return err
		}
	}

	n, remoteAddr, err := l.localConn.ReadFromUDP(buffer)
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
			slog.Info("the connection was closed", slog.Any("error", err))
		} else {
			slog.Info("error reading from connection", slog.Any("error", err))
			return err
		}
	}
	slog.Debug("RcvUDP", debugGoroutineID(), l.debug(remoteAddr), slog.Int("n", n))

	err = l.startDecode(buffer, remoteAddr, n, nowMillis)
	if err != nil {
		slog.Info("error from decode", slog.Any("error", err))
	}
	return nil
}

func (l *Listener) handleOutgoing(nowMillis uint64) (nextSleepMillis uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	nextSleepMillis = uint64(math.MaxUint64)
	for _, c := range l.connMap {
		for _, s := range c.streams {
			sleepMillis := s.Update(nowMillis)
			if sleepMillis < nextSleepMillis {
				nextSleepMillis = sleepMillis
			}
		}
	}
	return nextSleepMillis
}

func (l *Listener) startDecode(buffer []byte, remoteAddr *net.UDPAddr, n int, nowMillis uint64) error {
	header, connId, nH, err := DecodeConnId(buffer)
	if err != nil {
		slog.Info("error in decoding id from new connection", slog.Any("error", err))
		return err
	}
	conn := l.connMap[connId]

	var m *Message
	if conn == nil {
		privKeyEpRcv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			slog.Info("error in rnd from new connection", slog.Any("error", err))
			return err
		}

		slog.Debug("DecodeNew", debugGoroutineID(), l.debug(remoteAddr), slog.Any("connId", connId))
		m, err = Decode(buffer, nH, n, header, connId, l.privKeyId, privKeyEpRcv, nil, nil)
		if err != nil {
			slog.Info("error in decode", slog.Any("error", err))
			return err
		}

		conn, err = l.newConn(remoteAddr, m.PukKeyIdSnd, privKeyEpRcv, m.PukKeyEpSnd)
		if err != nil {
			slog.Info("error in newConn from new connection", slog.Any("error", err))
			return err
		}

	} else {
		slog.Debug("DecodeExisting", debugGoroutineID(), l.debug(remoteAddr), slog.Any("connId", connId))
		m, err = Decode(buffer, nH, n, header, connId, l.privKeyId, conn.privKeyEpSnd, conn.pubKeyIdRcv, conn.sharedSecret)
	}
	if err != nil {
		slog.Info("error in decoding from new connection", debugGoroutineID(), slog.Any("error", err), slog.Any("conn", conn))
		return err
	}

	p, err := DecodePayload(bytes.NewBuffer(m.PayloadRaw), 0)
	if err != nil {
		slog.Info("error in decoding payload from new connection", slog.Any("error", err))
		return err
	}

	slog.Debug("DecodedData", debugGoroutineID(), l.debug(remoteAddr), slog.Any("sn", p.Sn), slog.Any("typ", m.MessageHeader.Type))

	m.Payload = p

	if m.Type == InitReply || m.Type == Init {
		slog.Debug("SetSecret", debugGoroutineID(), l.debug(remoteAddr), slog.Any("sec", m.SharedSecret[:5]))
		conn.sharedSecret = m.SharedSecret
	}

	s, isNew := conn.GetOrCreate(p.StreamId)
	s.push(m.Payload, nowMillis)

	if isNew {
		l.accept(s)
	}
	return nil
}

func (l *Listener) isOpen() bool {
	return !l.closed
}

func (l *Listener) debug(addr *net.UDPAddr) slog.Attr {
	localAddr := l.localConn.LocalAddr().String()
	lastColonIndex := strings.LastIndex(localAddr, ":")
	if addr == nil {
		return slog.String("net", "->"+localAddr[lastColonIndex+1:])
	}
	return slog.String("net", strconv.Itoa(addr.Port)+"->"+localAddr[lastColonIndex+1:])
}
