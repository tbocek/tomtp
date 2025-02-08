package tomtp

import (
	"context"
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
	prvKeyId     *ecdh.PrivateKey
	connMap      map[uint64]*Connection // here we store the connection to remote peers, we can have up to
	accept       func(s *Stream)
	closed       bool
	readDeadline uint64
	ctx          context.Context
	cancel       context.CancelFunc
	sendSignal   chan struct{} // Channel to signal when data is ready to send
	mu           sync.Mutex
}

type ListenOption struct {
	seed     *[32]byte
	prvKeyId *ecdh.PrivateKey
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

	ctx, cancel := context.WithCancel(context.Background()) // Create context here

	l := &Listener{
		localConn: localConn,
		//pubKeyId:     prvKeyId.Public().(*ecdh.PublicKey),
		prvKeyId:   prvKeyId,
		connMap:    make(map[uint64]*Connection),
		accept:     accept,
		ctx:        ctx,                    // Assign the created context
		cancel:     cancel,                 // Assign the created cancel func
		sendSignal: make(chan struct{}, 1), // Buffered to prevent blocking
		mu:         sync.Mutex{},
	}

	slog.Info(
		"Listen",
		slog.Any("listenAddr", localConn.LocalAddr()),
		slog.String("privKeyId", "0x"+hex.EncodeToString(l.prvKeyId.Bytes()[:3])+"…"),
		slog.String("pubKeyId", "0x"+hex.EncodeToString(l.prvKeyId.PublicKey().Bytes()[:3])+"…"))

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
	clear(l.connMap)

	l.cancel()

	return l.localConn.Close()
}

func (l *Listener) UpdateRcv() (err error) {
	buffer, remoteAddr, err := l.ReadUDP(l.ctx)
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

	s, isNew, err := conn.decode(m.PayloadRaw)
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
		n, err := l.localConn.WriteToUDP(data, c.remoteAddr)
		if err != nil {
			return c.Close()
		}
		c.bytesWritten += uint64(n)
	}
	return nil
}

func (l *Listener) Update(nowMillis uint64) error {
	err := l.UpdateRcv()
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
	remoteAddr net.Addr,
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

type DataAddr struct {
	data       []byte
	remoteAddr net.Addr
	err        error
}

func (l *Listener) ReadUDP(ctx context.Context) ([]byte, net.Addr, error) {
	buffer := make([]byte, maxBuffer)
	dataAvailable := make(chan DataAddr, 1) // Buffered channel

	err := l.localConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if err != nil {
		slog.Error("error setting read deadline", slog.Any("error", err))
		return nil, nil, err
	}

	go func() {
		defer close(dataAvailable)

		numRead, remoteAddr, err := l.localConn.ReadFromUDP(buffer)
		if err != nil {
			var netErr net.Error
			ok := errors.As(err, &netErr)
			if ok && netErr.Timeout() {
				slog.Debug("ReadUDPUnix - net.Timeout - normal operation")
				//It has timed out, but it's a normal operation
				return
			} else {
				slog.Error("ReadUDPUnix - error during read", slog.Any("error", err))
				select {
				case dataAvailable <- DataAddr{err: err}: // Pass on the error
				default:
					slog.Error("dropped data") // Handle dropped data if channel is full
				}

				return // Exit goroutine due to error
			}
		}

		// Read successful, send the data and remote address (non-blocking)
		select {
		case dataAvailable <- DataAddr{
			data:       buffer[:numRead],
			remoteAddr: remoteAddr,
			err:        nil,
		}:
		default:
			slog.Error("dropped data") // Handle dropped data if channel is full
		}

	}()

	select {
	case <-ctx.Done():
		slog.Debug("ReadUDPUnix - ctx.Done")
		// Context cancelled.  Attempt to unblock ReadFromUDP.
		err := l.localConn.SetReadDeadline(time.Now())
		if err != nil {
			slog.Error("error setting immediate read deadline on cancel", slog.Any("error", err))
		}

		return nil, nil, ctx.Err()

	case <-l.sendSignal:
		slog.Debug("ReadUDPUnix - l.sendSignal")
		// Send signal received. Attempt to unblock ReadFromUDP.
		err := l.localConn.SetReadDeadline(time.Now())
		if err != nil {
			slog.Error("error setting immediate read deadline on sendSignal", slog.Any("error", err))
		}

		select {
		case dataAddr := <-dataAvailable:
			return dataAddr.data, dataAddr.remoteAddr, dataAddr.err
		default:
			//do nothing, as we are going to send the signal
			slog.Debug("ReadUDPUnix - l.sendSignal - proceeding, no data")
		}

		return nil, nil, nil // No error
	case dataAddr := <-dataAvailable:
		slog.Debug("ReadUDPUnix - dataAvailable")
		return dataAddr.data, dataAddr.remoteAddr, dataAddr.err // Return data or error
	}
}

func (l *Listener) debug(addr net.Addr) slog.Attr {
	if l.localConn == nil {
		if addr == nil {
			return slog.String("net", "nil->nil")
		} else {
			return slog.String("net", "nil->"+addr.String())
		}
	}

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
