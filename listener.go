package tomtp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/MatusOllah/slogcolor"
	"github.com/fatih/color"
	"golang.org/x/sys/unix"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	//maxConnections = 1000
	maxBuffer     = 9000 //support large packets
	maxRingBuffer = 100
	startMtu      = 1400
	//
	alpha  = 0.125 // Factor for SRTT
	beta   = 0.25  // Factor for RTTVAR
	k      = 4     // Multiplier for RTTVAR in the PTO calculation
	minPto = 1     // Timer granularity
)

var (
	logger = slog.New(slogcolor.NewHandler(os.Stderr, &slogcolor.Options{
		Level:         slog.LevelDebug,
		TimeFormat:    "15:04:05.000",
		SrcFileMode:   slogcolor.ShortFile,
		SrcFileLength: 16,
		MsgPrefix:     color.HiWhiteString("|"),
		MsgColor:      color.New(color.FgHiWhite),
		MsgLength:     16,
	}))
	CurrentTimeDebug int64 = 0
)

// PubKey is the public key that identifies an peer
type PubKey [32]byte

type Listener struct {
	// this is the port we are listening to
	localConn      *net.UDPConn
	localAddr      *net.UDPAddr
	privKeyId      ed25519.PrivateKey
	privKeyIdCurve *ecdh.PrivateKey
	connMap        map[[8]byte]*Connection // here we store the connection to remote peers, we can have up to
	streamChan     chan *Stream
	errorChan      chan error
	mu             sync.Mutex
}

type Connection struct {
	remoteAddr   *net.UDPAddr       // the remote address
	streams      map[uint32]*Stream // 2^32 connections to a single peer
	mu           sync.Mutex
	listener     *Listener
	pubKeyIdRcv  ed25519.PublicKey
	privKeyEpSnd *ecdh.PrivateKey
	pubKeyEpRcv  *ecdh.PublicKey
	sharedSecret [32]byte
	srttMillis   int64 //measurements
	rttVarMillis int64
	ptoMillis    int64
}

func init() {
	color.NoColor = false
	slog.SetDefault(logger)
}

func Listen(addr string, seed [32]byte) (*Listener, error) {
	privKeyId := ed25519.NewKeyFromSeed(seed[:])
	return ListenPrivateKey(addr, privKeyId)
}

func ListenPrivateKey(addr string, privKeyId ed25519.PrivateKey) (*Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	err = setDF(conn)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		localConn:      conn,
		localAddr:      udpAddr,
		privKeyId:      privKeyId,
		privKeyIdCurve: ed25519PrivateKeyToCurve25519(privKeyId),
		streamChan:     make(chan *Stream),
		errorChan:      make(chan error),
		connMap:        make(map[[8]byte]*Connection),
		mu:             sync.Mutex{},
	}

	slog.Debug(
		"listening",
		debugGoroutineID(),
		slog.Any("listening address/port", conn.LocalAddr()),
		slog.String("private key id", "0x"+hex.EncodeToString(privKeyId[:3])+"..."))

	go l.handleIncomingUDP()
	return l, nil
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
		slog.Debug("udp packet received", debugGoroutineID(), l.debug(remoteAddr), slog.Int("n", n), slog.Any("rAddr", remoteAddr))

		connId, err := DecodeConnId(buffer)
		if err != nil {
			slog.Info("error in decoding id from new connection", slog.Any("error", err))
			l.errorChan <- err //TODO: distinguish between error and warning
			continue
		}
		conn := l.connMap[connId]

		var m *Message
		if conn == nil {
			m, err = Decode(buffer, n, l.privKeyId, nil, [32]byte{})
		} else {
			m, err = Decode(buffer, n, l.privKeyId, conn.privKeyEpSnd, conn.sharedSecret)
		}
		if err != nil {
			slog.Info("error in decoding from new connection", slog.Any("error", err))
			l.errorChan <- err //TODO: distinguish between error and warning
			continue
		}

		p, err := DecodePayload(bytes.NewBuffer(m.PayloadRaw), 0)
		if err != nil {
			slog.Info("error in decoding payload from new connection", slog.Any("error", err))
			l.errorChan <- err
			continue
		}
		m.Payload = p

		if conn == nil {
			conn, err = l.newConn(remoteAddr, m.PukKeyIdSnd)
			if err != nil {
				slog.Info("error in newConn from new connection", slog.Any("error", err))
				l.errorChan <- err //TODO: distinguish between error and warning
				continue
			}
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
			s, err = conn.New(p.StreamId)
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

func (l *Listener) PubKeyId() ed25519.PublicKey {
	return l.privKeyId.Public().(ed25519.PublicKey)
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

func (l *Listener) newConn(remoteAddr *net.UDPAddr, pubKeyIdRcv ed25519.PublicKey) (*Connection, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var arr [8]byte
	copy(arr[0:3], pubKeyIdRcv[0:4])
	pubKey := l.privKeyId.Public().(ed25519.PublicKey)
	copy(arr[3:7], pubKey[0:4])

	if conn, ok := l.connMap[arr]; ok {
		return conn, errors.New("conn already exists")
	}

	privKeyEpSnd, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	l.connMap[arr] = &Connection{
		streams:      make(map[uint32]*Stream),
		remoteAddr:   remoteAddr,
		pubKeyIdRcv:  pubKeyIdRcv,
		privKeyEpSnd: privKeyEpSnd,
		mu:           sync.Mutex{},
		listener:     l,
		srttMillis:   1000,
		rttVarMillis: 500,
		ptoMillis:    3000,
	}
	return l.connMap[arr], nil
}

func (c *Connection) updateRTT(rttSample int64) {
	if c.srttMillis == 0 {
		// First measurement
		c.srttMillis = rttSample
		c.rttVarMillis = rttSample / 2
	} else {
		// Calculate new rttVar
		rttDiff := rttSample - c.srttMillis
		if rttDiff < 0 {
			rttDiff = -rttDiff
		}
		c.rttVarMillis = int64((1-beta)*float64(c.rttVarMillis) + beta*float64(rttDiff))

		// Calculate new srtt
		c.srttMillis = int64((1-alpha)*float64(c.srttMillis) + alpha*float64(rttSample))
	}

	// Update PTO
	c.ptoMillis = c.srttMillis + k*c.rttVarMillis
	if c.ptoMillis == 0 {
		c.ptoMillis = minPto
	}
}

// based on: https://github.com/quic-go/quic-go/blob/d540f545b0b70217220eb0fbd5278ece436a7a20/sys_conn_df_linux.go#L15
func setDF(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}

	var errDFIPv4, errDFIPv6 error
	if err := rawConn.Control(func(fd uintptr) {
		errDFIPv4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_MTU_DISCOVER, unix.IP_PMTUDISC_DO)
		errDFIPv6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_MTU_DISCOVER, unix.IPV6_PMTUDISC_DO)
	}); err != nil {
		return err
	}

	switch {
	case errDFIPv4 == nil && errDFIPv6 == nil:
		slog.Info("setting DF for IPv4 and IPv6")
		//TODO: expose this and don't probe for higher MTU when not DF not supported
	case errDFIPv4 == nil && errDFIPv6 != nil:
		slog.Info("setting DF for IPv4 only")
	case errDFIPv4 != nil && errDFIPv6 == nil:
		slog.Info("setting DF for IPv6 only")
	case errDFIPv4 != nil && errDFIPv6 != nil:
		slog.Error("setting DF failed for both IPv4 and IPv6")
	}

	return nil
}

func (l *Listener) getConn(pubKeyIdRcv ed25519.PublicKey) *Connection {
	l.mu.Lock()
	defer l.mu.Unlock()

	var arr [8]byte
	copy(arr[0:3], pubKeyIdRcv[0:4])
	pubKey := l.privKeyId.Public().(ed25519.PublicKey)
	copy(arr[3:7], pubKey[0:4])
	return l.connMap[arr]
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

func (l *Listener) Dial(remoteAddrString string, pubKeyIdHex string, streamId uint32) (*Stream, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", remoteAddrString)
	if err != nil {
		slog.Info("error resolving remote address", slog.Any("error", err))
		return nil, err
	}

	if strings.HasPrefix(pubKeyIdHex, "0x") {
		pubKeyIdHex = strings.Replace(pubKeyIdHex, "0x", "", 1)
	}

	b, err := hex.DecodeString(pubKeyIdHex)
	if err != nil {
		slog.Info("error decoding hex string", slog.Any("error", err))
		return nil, err
	}
	pubKeyId := ed25519.PublicKey(b)
	return l.DialPublicKey(remoteAddr, pubKeyId, streamId)
}

func Dial(remoteAddrString string, pubKeyIdHex string, streamId uint32) (*Stream, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", remoteAddrString)
	if err != nil {
		slog.Info("error resolving remote address", slog.Any("error", err))
		return nil, err
	}

	if strings.HasPrefix(pubKeyIdHex, "0x") {
		pubKeyIdHex = strings.Replace(pubKeyIdHex, "0x", "", 1)
	}

	b, err := hex.DecodeString(pubKeyIdHex)
	if err != nil {
		slog.Info("error decoding hex string", slog.Any("error", err))
		return nil, err
	}
	pubKeyId := ed25519.PublicKey(b)
	return DialPublicKeyRandomId(remoteAddr, pubKeyId, streamId)
}

func DialPublicKeyRandomId(remoteAddr *net.UDPAddr, pukKeyIdSnd ed25519.PublicKey, streamId uint32) (*Stream, error) {
	seed, err := generateRandom32()
	if err != nil {
		slog.Error("error in RNG", slog.Any("error", err))
		return nil, err
	}

	//create listener on random port
	l, err := Listen(":0", seed)
	if err != nil {
		slog.Error("error  decoding hex string", slog.Any("error", err))
		return nil, err
	}
	return l.DialPublicKey(remoteAddr, pukKeyIdSnd, streamId)
}

func DialPublicKeyWithId(remoteAddr *net.UDPAddr, pukKeyIdSnd ed25519.PublicKey, privKeyId ed25519.PrivateKey, streamId uint32) (*Stream, error) {
	//create listener on random port
	l, err := ListenPrivateKey(":0", privKeyId)
	if err != nil {
		slog.Error("error  decoding hex string", slog.Any("error", err))
		return nil, err
	}
	return l.DialPublicKey(remoteAddr, pukKeyIdSnd, streamId)
}

func (l *Listener) DialPublicKey(remoteAddr *net.UDPAddr, pukKeyIdSnd ed25519.PublicKey, streamId uint32) (*Stream, error) {
	c, err := l.newConn(remoteAddr, pukKeyIdSnd)
	if err != nil {
		slog.Error("error  decoding hex string", slog.Any("error", err))
		return nil, err
	}
	return c.New(streamId)
}

func timeMilli() int64 {
	if CurrentTimeDebug != 0 {
		return CurrentTimeDebug
	}
	return time.Now().UnixMilli()
}

func (l *Listener) debug(addr *net.UDPAddr) slog.Attr {
	localAddr := l.localConn.LocalAddr().String()
	lastColonIndex := strings.LastIndex(localAddr, ":")
	if addr == nil {
		return slog.String("net", "->"+localAddr[lastColonIndex+1:])
	}
	return slog.String("net", strconv.Itoa(addr.Port)+"->"+localAddr[lastColonIndex+1:])
}
