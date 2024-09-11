package tomtp

import (
	"bytes"
	"crypto/ecdh"
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

type Listener struct {
	// this is the port we are listening to
	localConn      NetworkConn
	pubKeyId       *ecdh.PublicKey
	privKeyId      *ecdh.PrivateKey
	connMap        map[uint64]*Connection // here we store the connection to remote peers, we can have up to
	incomingStream chan *Stream
	accept         func(s *Stream)
	closed         bool
	mu             sync.Mutex
}

type ListenOption struct {
	seed         *[32]byte
	privKeyId    *ecdh.PrivateKey
	manualUpdate bool
}

type ListenFunc func(*ListenOption)

func WithSeed(seed [32]byte) ListenFunc {
	return func(c *ListenOption) {
		c.seed = &seed
	}
}

func WithPrivKeyId(privKeyId *ecdh.PrivateKey) ListenFunc {
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

func Listen(listenAddrStr string, accept func(s *Stream), options ...ListenFunc) (*Listener, error) {

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

func ListenTP(listenAddr *net.UDPAddr, accept func(s *Stream), options ...ListenFunc) (*Listener, error) {
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

	return ListenTPNetwork(
		NewUDPNetworkConn(conn),
		accept,
		options...,
	)
}

func fillListenOpts(options ...ListenFunc) *ListenOption {
	lOpts := &ListenOption{
		seed:         nil,
		privKeyId:    nil,
		manualUpdate: false,
	}
	for _, opt := range options {
		opt(lOpts)
	}

	if lOpts.seed != nil {
		privKeyId, err := ecdh.X25519().NewPrivateKey(lOpts.seed[:])
		if err != nil {
			slog.Error(
				"error generating private id key from seed",
				slog.Any("error", err))
		}
		lOpts.privKeyId = privKeyId
	}
	if lOpts.privKeyId == nil {
		privKeyId, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			slog.Error(
				"error generating private id key random",
				slog.Any("error", err))
		}
		lOpts.privKeyId = privKeyId
	}

	return lOpts
}

func ListenTPNetwork(localConn NetworkConn, accept func(s *Stream), options ...ListenFunc) (*Listener, error) {
	lOpts := fillListenOpts(options...)
	privKeyId := *lOpts.privKeyId
	l := &Listener{
		localConn:      localConn,
		pubKeyId:       privKeyId.Public().(*ecdh.PublicKey),
		privKeyId:      &privKeyId,
		incomingStream: make(chan *Stream),
		connMap:        make(map[uint64]*Connection),
		accept:         accept,
		mu:             sync.Mutex{},
	}

	slog.Info(
		"Listen",
		slog.Any("listenAddr", localConn.LocalAddr()),
		slog.String("privKeyId", "0x"+hex.EncodeToString(l.privKeyId.Bytes()[:3])+"…"),
		slog.String("pubKeyId", "0x"+hex.EncodeToString(l.pubKeyId.Bytes()[:3])+"…"))

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

	//timeouts, retries, ping, sending packets
	nextSleepMillis := maxIdleMillis
	for _, c := range l.connMap {
		for _, s := range c.streams {
			if s.streamId == math.MaxUint32 {
				continue
			}
			sleepMillis := s.Update(nowMillis)
			if sleepMillis < nextSleepMillis {
				nextSleepMillis = sleepMillis
			}
		}

		//connection ping if nothing was sent in s.Update
		if nowMillis-c.lastSentMillis > 200 {
			s := c.streams[math.MaxUint32]
			t, b, err := s.doEncode([]byte{})
			if err != nil {
				slog.Info("outgoing msg failed", slog.Any("error", err))
				s.Close()
			}
			s.bytesWritten += t
			segment := &SndSegment[[]byte]{
				sn:         0,
				data:       b,
				sentMillis: 0,
			}
			n, err := s.conn.listener.handleOutgoingUDP(segment.data, s.conn.remoteAddr)
			s.conn.lastSentMillis = nowMillis
			if err != nil {
				slog.Info("outgoing msg failed", slog.Any("error", err))
				s.Close()
			}
			slog.Debug("SndUDP", debugGoroutineID(), s.debug(), slog.Int("n", n), slog.Any("sn", segment.sn))
		}
	}

	if nextSleepMillis > sleepMillis {
		newSleepMillis = nextSleepMillis - sleepMillis
	} else {
		newSleepMillis = 0
	}

	return newSleepMillis, nil
}

func (l *Listener) handleOutgoingUDP(data []byte, remoteAddr net.Addr) (int, error) {
	return l.localConn.WriteToUDP(data, remoteAddr)
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
	if n > 0 {
		slog.Debug("RcvUDP", debugGoroutineID(), l.debug(remoteAddr), slog.Int("n", n))

		err = l.startDecode(buffer[:n], remoteAddr, n, nowMillis)
		if err != nil {
			slog.Info("error from decode", slog.Any("error", err))
		}
	}
	return nil
}

func (l *Listener) startDecode(buffer []byte, remoteAddr net.Addr, n int, nowMillis uint64) error {
	header, connId, _, err := DecodeConnId(buffer)
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
		m, err = Decode(buffer, header, connId, l.privKeyId, privKeyEpRcv, nil, nil)
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
		m, err = Decode(buffer, header, connId, l.privKeyId, conn.privKeyEpSnd, conn.pubKeyIdRcv, conn.sharedSecret)
	}
	if err != nil {
		slog.Info("error in decoding from new connection", debugGoroutineID(), slog.Any("error", err), slog.Any("conn", conn))
		return err
	}

	p, err := DecodePayload(bytes.NewBuffer(m.PayloadRaw))
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

	if s.rbSnd != nil {
		//channel ping does not have acks
		s.rbSnd.Remove(p.AckSn)
	}

	if len(m.Payload.Data) > 0 {
		r := RcvSegment[[]byte]{
			sn:         m.Payload.Sn,
			data:       m.Payload.Data,
			insertedAt: nowMillis,
		}
		s.rbRcv.Insert(&r) //todo: handle dups
	}

	if isNew {
		l.accept(s)
	}

	conn.lastSentMillis = nowMillis

	return nil
}

func (l *Listener) isOpen() bool {
	return !l.closed
}

func (l *Listener) debug(addr net.Addr) slog.Attr {
	localAddr := l.localConn.LocalAddr()
	lastColonIndex := strings.LastIndex(localAddr.String(), ":")

	if cAddr, ok := addr.(*net.UDPAddr); ok {
		return slog.String("net", strconv.Itoa(cAddr.Port)+"->"+localAddr.String()[lastColonIndex+1:])
	} else {
		return slog.String("net", addr.String()+"->"+localAddr.String())
	}
}
