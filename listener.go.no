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
)

type Listener struct {
	// this is the port we are listening to
	localConn      *net.UDPConn
	localAddr      *net.UDPAddr
	pubKeyId       ed25519.PublicKey
	privKeyId      ed25519.PrivateKey
	privKeyIdCurve *ecdh.PrivateKey
	connMap        map[[8]byte]*Connection // here we store the connection to remote peers, we can have up to
	streamChan     chan *Stream
	errorChan      chan error
	noListenLoop   bool
	mu             sync.Mutex
}

type ListenOption struct {
	noListenLoop bool
	seed         *[32]byte
	privKeyId    *ed25519.PrivateKey
}

type ListenFunc func(*ListenOption)

func WithNoListenLoop() ListenFunc {
	return func(c *ListenOption) {
		c.noListenLoop = true
	}
}

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

func Listen(listenAddrStr string, options ...ListenFunc) (*Listener, error) {
	listenAddr, err := net.ResolveUDPAddr("udp", listenAddrStr)
	if err != nil {
		slog.Error(
			"error resolving remote address",
			slog.Any("error", err),
			slog.String("address", listenAddrStr))
		return nil, err
	}
	return ListenTP(listenAddr, options...)
}

func ListenTP(listenAddr *net.UDPAddr, options ...ListenFunc) (*Listener, error) {
	lOpts := &ListenOption{
		noListenLoop: false,
		seed:         nil,
		privKeyId:    nil,
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
		streamChan:     make(chan *Stream),
		errorChan:      make(chan error),
		noListenLoop:   lOpts.noListenLoop,
		connMap:        make(map[[8]byte]*Connection),
		mu:             sync.Mutex{},
	}

	slog.Info(
		"Listen",
		slog.Any("listenAddr", conn.LocalAddr()),
		slog.String("privKeyId", "0x"+hex.EncodeToString(l.privKeyId[:3])+"…"),
		slog.String("pubKeyId", "0x"+hex.EncodeToString(l.pubKeyId[:3])+"…"))

	go l.handleIncomingUDP()
	return l, nil
}

func (l *Listener) Close() (error, []error) {
	slog.Debug("ListenerClose", debugGoroutineID(), l.debug(nil))
	l.mu.Lock()
	defer l.mu.Unlock()

	var streamErrors []error

	for _, conn := range l.connMap {
		for _, stream := range conn.streams {
			stream.Close()
		}
	}

	remoteConnError := l.localConn.Close()
	l.connMap = make(map[[8]byte]*Connection)
	close(l.errorChan)
	close(l.streamChan)

	return remoteConnError, streamErrors
}

func (l *Listener) Accept() (*Stream, error) {
	select {
	case stream := <-l.streamChan:
		slog.Debug("incoming new stream", debugGoroutineID())
		return stream, nil
	case err := <-l.errorChan:
		slog.Error("received an error in accept", slog.Any("error", err))
		return nil, err
	}
}

func (l *Listener) handleOutgoingUDP(b []byte, remoteAddr *net.UDPAddr) (int, error) {
	return l.localConn.WriteToUDP(b, remoteAddr)
}

func (l *Listener) handleIncomingUDP() {
	buffer := make([]byte, maxBuffer)
	for {
		n, remoteAddr, err := l.localConn.ReadFromUDP(buffer)
		if err != nil {
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				slog.Info("the connection was closed", slog.Any("error", err))
			} else {
				slog.Info("error reading from connection", slog.Any("error", err))
				l.errorChan <- err
			}
			return
		}
		slog.Debug("RcvUDP", debugGoroutineID(), l.debug(remoteAddr), slog.Int("n", n))

		connId, err := DecodeConnId(buffer)
		if err != nil {
			slog.Info("error in decoding id from new connection", slog.Any("error", err))
			l.errorChan <- err //TODO: distinguish between error and warning
			continue
		}
		conn := l.connMap[connId]

		privKeyEpRcv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			slog.Info("error in rnd from new connection", slog.Any("error", err))
			l.errorChan <- err //TODO: distinguish between error and warning
			continue
		}

		var m *Message
		if conn == nil {
			slog.Debug("DecodeNew", debugGoroutineID(), l.debug(remoteAddr), slog.Any("connId", connId))
			m, err = Decode(buffer, n, l.privKeyId, privKeyEpRcv, nil, nil)
		} else {
			slog.Debug("DecodeExisting", debugGoroutineID(), l.debug(remoteAddr), slog.Any("connId", connId))
			m, err = Decode(buffer, n, l.privKeyId, conn.privKeyEp, conn.pubKeyIdRcv, conn.sharedSecret)
		}
		if err != nil {
			slog.Info("error in decoding from new connection", debugGoroutineID(), slog.Any("error", err), slog.Any("conn", conn))
			l.errorChan <- err //TODO: distinguish between error and warning
			continue
		}

		p, err := DecodePayload(bytes.NewBuffer(m.PayloadRaw), 0)
		if err != nil {
			slog.Info("error in decoding payload from new connection", slog.Any("error", err))
			l.errorChan <- err
			continue
		}
		if p.Sn != nil {
			slog.Debug("DecodedData", debugGoroutineID(), l.debug(remoteAddr), slog.Any("sn", *p.Sn), slog.Any("typ", m.MessageHeader.Type))
		} else {
			slog.Debug("DecodedEmpty", debugGoroutineID(), l.debug(remoteAddr), slog.Any("typ", m.MessageHeader.Type))
		}
		m.Payload = p

		if conn == nil {
			conn, err = l.newConn(remoteAddr, m.PukKeyIdSnd, privKeyEpRcv, m.PukKeyEpSnd)
			if err != nil {
				slog.Info("error in newConn from new connection", slog.Any("error", err))
				l.errorChan <- err //TODO: distinguish between error and warning
				continue
			}
		}

		if m.Type == InitReply || m.Type == Init {
			slog.Debug("SetSecret", debugGoroutineID(), l.debug(remoteAddr), slog.Any("sec", m.SharedSecret[:5]))
			conn.sharedSecret = m.SharedSecret
		}

		var s *Stream
		if conn.Has(p.StreamId) {
			s, err = conn.Get(p.StreamId)
			if err != nil {
				slog.Info("error fetching stream from new connection", slog.Any("error", err))
				l.errorChan <- err
				continue
			}
		} else {
			s, err = conn.New(p.StreamId, StreamRcvStarting, !l.noListenLoop, false)
			if err != nil {
				slog.Info("error creating stream from new connection", slog.Any("error", err))
				l.errorChan <- err
				continue
			}
			l.streamChan <- s //we have a new stream that must be accepted
		}

		s.push(m.Payload)
	}
}

func (l *Listener) debug(addr *net.UDPAddr) slog.Attr {
	localAddr := l.localConn.LocalAddr().String()
	lastColonIndex := strings.LastIndex(localAddr, ":")
	if addr == nil {
		return slog.String("net", "->"+localAddr[lastColonIndex+1:])
	}
	return slog.String("net", strconv.Itoa(addr.Port)+"->"+localAddr[lastColonIndex+1:])
}

func (l *Listener) Update(nowMillis uint64) uint64 {
	//first check what needs to be done in any streams
	sleepMillisMin := math.MaxUint32
	for _, conn := range l.connMap {
		for _, stream := range conn.streams {
			sleepMillis := stream.Update(nowMillis)
			sleepMillisMin = min(sleepMillisMin, sleepMillis)
		}
	}

}
