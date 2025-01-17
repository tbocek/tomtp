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
	privKeyId    *ecdh.PrivateKey
	connMap      map[uint64]*Connection // here we store the connection to remote peers, we can have up to
	accept       func(s *Stream)
	closed       bool
	readDeadline uint64
	mu           sync.Mutex
}

type ListenOption struct {
	seed         *[32]byte
	privKeyId    *ecdh.PrivateKey
	readDeadline uint64
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
		privKeyId:    nil,
		readDeadline: ReadDeadLine,
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

func ListenNetwork(localConn NetworkConn, accept func(s *Stream), options ...ListenFunc) (*Listener, error) {
	lOpts := fillListenOpts(options...)
	privKeyId := lOpts.privKeyId
	l := &Listener{
		localConn:    localConn,
		pubKeyId:     privKeyId.Public().(*ecdh.PublicKey),
		privKeyId:    privKeyId,
		connMap:      make(map[uint64]*Connection),
		accept:       accept,
		readDeadline: lOpts.readDeadline,
		mu:           sync.Mutex{},
	}

	slog.Info(
		"Listen",
		slog.Any("listenAddr", localConn.LocalAddr()),
		slog.String("privKeyId", "0x"+hex.EncodeToString(l.privKeyId.Bytes()[:3])+"…"),
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

func (l *Listener) UpdateRcv(nowMillis uint64) (err error) {
	return l.handleIncomingUDP(nowMillis, l.readDeadline) //incoming packets
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

		n, err := l.handleOutgoingUDP(seg.data, c.remoteAddr)
		if err != nil {
			return c.Close()
		}
		c.bytesWritten += uint64(n)
	}

	//TODO: if ReadyToSend gets a new paket, interrupt this sleep
	time.Sleep(time.Duration(minSleep) * time.Millisecond)

	return nil
}

func (l *Listener) handleOutgoingUDP(data []byte, remoteAddr net.Addr) (int, error) {
	slog.Debug("handleOutgoingUDP", debugGoroutineID(), slog.Any("len(data)", len(data)))
	return l.localConn.WriteToUDP(data, remoteAddr)
}

func (l *Listener) handleIncomingUDP(nowMillis uint64, sleepMillis uint64) error {
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

		connId, msgType, err := decodeConnId(buffer)
		conn := l.connMap[connId]

		var m *Message
		if conn == nil && msgType == InitSndMsgType {
			m, conn, err = l.decodeCryptoNew(buffer[:n], remoteAddr)
		} else if conn != nil {
			m, err = l.decodeCryptoExisting(buffer[:n], remoteAddr, conn, msgType)
		} else {
			return errors.New("unknown state")
		}
		if err != nil {
			slog.Info("error from decode crypto", slog.Any("error", err))
			return err
		}

		p, err := DecodePayload(m.PayloadRaw)
		if err != nil {
			slog.Info("error in decoding payload from new connection", slog.Any("error", err))
			return err
		}

		err = l.handle(p, m.SnConn, remoteAddr, conn)
		if err != nil {
			slog.Info("error from decode crypto", slog.Any("error", err))
			return err
		}
	}
	return nil
}

func (l *Listener) decodeCryptoNew(buffer []byte, remoteAddr net.Addr) (*Message, *Connection, error) {
	var m *Message
	var err error

	//new connection
	prvKeyEpSnd, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		slog.Info("error in rnd from new connection", slog.Any("error", err))
		return nil, nil, err
	}

	slog.Debug("DecodeNew Snd", debugGoroutineID(), l.debug(remoteAddr), debugPrvKey("privKeyId", l.privKeyId), debugPrvKey("prvKeyEpSnd", prvKeyEpSnd))
	m, err = Decode(InitSndMsgType, buffer, l.privKeyId, prvKeyEpSnd, nil)
	if err != nil {
		slog.Info("error in decode", slog.Any("error", err))
		return nil, nil, err
	}

	conn, err := l.newConn(remoteAddr, m.PukKeyIdSnd, prvKeyEpSnd, m.PukKeyEpSnd, false)
	if err != nil {
		slog.Info("error in newConn from new connection 1", slog.Any("error", err))
		return nil, nil, err
	}
	conn.sharedSecret = m.SharedSecret

	return m, conn, nil
}

func (l *Listener) decodeCryptoExisting(buffer []byte, remoteAddr net.Addr, conn *Connection, msgType MsgType) (*Message, error) {
	var m *Message
	var err error

	switch msgType {
	case InitSndMsgType:
		m, err = Decode(InitSndMsgType, buffer, l.privKeyId, conn.prvKeyEpSnd, nil)
		if err != nil {
			slog.Info("error in decode", slog.Any("error", err))
			return nil, err
		}
	case InitRcvMsgType:
		slog.Debug("DecodeNew Rcv", debugGoroutineID(), l.debug(remoteAddr))
		m, err = Decode(InitRcvMsgType, buffer, l.privKeyId, conn.prvKeyEpSnd, conn.sharedSecret)
		if err != nil {
			slog.Info("error in decoding from new connection 2", debugGoroutineID(), slog.Any("error", err), slog.Any("conn", conn))
			return nil, err
		}
		conn.rbSnd.Remove(0)
		conn.sharedSecret = m.SharedSecret
	case DataMsgType:
		slog.Debug("Decode DataMsgType", debugGoroutineID(), l.debug(remoteAddr), slog.Any("len(b)", len(buffer)))
		m, err = Decode(DataMsgType, buffer, l.privKeyId, conn.prvKeyEpSnd, conn.sharedSecret)
		if err != nil {
			slog.Info("error in decoding from new connection 3", debugGoroutineID(), slog.Any("error", err), slog.Any("conn", conn))
			return nil, err
		}

	case UnknownType:
		return nil, errors.New("unknown type")
	}

	return m, nil
}

func (l *Listener) handle(p *Payload, snConn uint64, remoteAddr net.Addr, conn *Connection) error {
	slog.Debug("handle", debugGoroutineID(), l.debug(remoteAddr), slog.Any("sn", snConn))

	s, isNew := conn.GetOrNewStreamRcv(p.StreamId)

	if len(p.Data) > 0 {
		r := RcvSegment[[]byte]{
			snConn:   snConn,
			snStream: p.SnStream,
			data:     p.Data,
		}
		s.rbRcv.Insert(&r)
	} else {

	}

	if len(p.AckSns) > 0 {
		for _, snConnAcks := range p.AckSns {
			conn.rbSnd.Remove(snConnAcks)
		}
	}

	if isNew {
		l.accept(s)
	}

	return nil
}

func (l *Listener) newConn(remoteAddr net.Addr, pubKeyIdRcv *ecdh.PublicKey, prvKeyEpSnd *ecdh.PrivateKey, pubKeyEdRcv *ecdh.PublicKey, sender bool) (*Connection, error) {
	var connId uint64
	pukKeyIdSnd := l.privKeyId.Public().(*ecdh.PublicKey)
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
