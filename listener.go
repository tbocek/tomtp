package tomtp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"syscall"
)

const (
	maxConnections = 1000
	maxBuffer      = 9000 //support large packets
	maxRingBuffer  = 100
	startMtu       = 1400
)

var ListenerCount int

// PubKey is the public key that identifies an peer
type PubKey [32]byte

type Listener struct {
	// this is the port we are listening to
	localConn      *net.UDPConn
	localAddr      *net.UDPAddr
	privKeyId      ed25519.PrivateKey
	privKeyIdCurve *ecdh.PrivateKey
	connMap        map[[8]byte]*Connection // here we store the connection to remote peers, we can have up to
	mu             sync.Mutex
}

type Connection struct {
	remoteConn   *net.UDPConn       // this is the remote connection we are connected
	remoteAddr   *net.UDPAddr       // the remote address
	streams      map[uint32]*Stream // 2^32 connections to a single peer
	mu           sync.Mutex
	listener     *Listener
	pubKeyIdRcv  ed25519.PublicKey
	privKeyEpSnd *ecdh.PrivateKey
	pubKeyEpRcv  *ecdh.PublicKey
	send         io.Writer
}

func NewListenerString(addr string, accept func(*Stream), privKeyIdString string) (*Listener, error) {
	h := sha256.Sum256([]byte(privKeyIdString))
	privKeyId := ed25519.NewKeyFromSeed(h[:])
	return NewListener(addr, accept, privKeyId)
}

func NewListener(addr string, accept func(*Stream), privKeyId ed25519.PrivateKey) (*Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, err
	}

	l := &Listener{
		localConn:      conn,
		localAddr:      udpAddr,
		privKeyId:      privKeyId,
		privKeyIdCurve: ed25519PrivateKeyToCurve25519(privKeyId),
		mu:             sync.Mutex{},
		connMap:        make(map[[8]byte]*Connection),
	}

	go handleConnection(conn, l, accept)
	return l, nil
}

func handleConnection(conn *net.UDPConn, l *Listener, accept func(*Stream)) {
	buffer := make([]byte, maxBuffer)
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			fmt.Println("Error reading from connection:", err)
			return
		}

		//we need to get the connection id
		DecodeConnectionId(buffer)
		l.connMap[]

		m, err := Decode(buffer, n, l.privKeyId, nil, [32]byte{}) //TODO: fix
		if err != nil {
			fmt.Println("Error reading from connection:", err)
			return
		}

		p, err := DecodePayload(bytes.NewBuffer(m.Payload), 0)
		if err != nil {
			fmt.Println("Error reading from connection2:", err)
			return
		}

		s, err := l.getOrCreateStream(p.StreamId, m.PukKeyIdSnd, remoteAddr)
		if err != nil {
			fmt.Println("Error reading from connection:", err)
			return
		}

		err = s.push(m)
		accept(s)
	}
}

func DecodeConnectionId(b []byte) [8]byte {
	buf := bytes.NewBuffer(b)

	// Read the header byte
	header, err := buf.ReadByte()

	var ret [8]byte
	buf.Read(ret)

	return ret
}

func (l *Listener) PubKeyId() ed25519.PublicKey {
	return l.privKeyId.Public().(ed25519.PublicKey)
}

func (l *Listener) Close() (error, []error, []error) {
	l.mu.Lock()
	defer func() {
		l.mu.Unlock()
	}()

	var streamErrors []error
	var remoteConnErrors []error

	for _, multiStream := range l.connMap {
		for _, stream := range multiStream.streams {
			if err := stream.Close(); err != nil {
				streamErrors = append(streamErrors, err)
			}
		}
		if err := multiStream.remoteConn.Close(); err != nil {
			remoteConnErrors = append(remoteConnErrors, err)
		}
		ListenerCount--
	}
	l.connMap = make(map[[8]byte]*Connection)

	return l.localConn.Close(), streamErrors, remoteConnErrors
}

func (l *Listener) NewConnectionString(pubKeyIdRcv ed25519.PublicKey, remoteAddrString string) (*Connection, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", remoteAddrString)
	if err != nil {
		fmt.Println("Error resolving remote address:", err)
		return nil, err
	}
	return l.NewOrGetConnection(pubKeyIdRcv, remoteAddr)
}

func (l *Listener) NewOrGetConnection(pubKeyIdRcv ed25519.PublicKey, remoteAddr *net.UDPAddr) (*Connection, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var arr [8]byte
	copy(arr[:], pubKeyIdRcv)

	if conn, ok := l.connMap[arr]; ok {
		return conn, nil
	}

	if ListenerCount >= maxConnections {
		return nil, errors.New("maximum number of listeners reached")
	}

	remoteConn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return nil, err
	}
	err = setDF(remoteConn)
	if err != nil {
		return nil, err
	}

	privKeyEpSnd, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	l.connMap[arr] = &Connection{
		streams:      make(map[uint32]*Stream),
		remoteAddr:   remoteAddr,
		remoteConn:   remoteConn,
		pubKeyIdRcv:  pubKeyIdRcv,
		privKeyEpSnd: privKeyEpSnd,
		mu:           sync.Mutex{},
		listener:     l,
		send:         remoteConn,
	}
	ListenerCount++
	return l.connMap[arr], nil
}

// based on: https://github.com/quic-go/quic-go/blob/d540f545b0b70217220eb0fbd5278ece436a7a20/sys_conn_df_linux.go#L15
func setDF(remoteConn *net.UDPConn) error {
	fd, err := remoteConn.File()
	if err != nil {
		return err
	}

	var errDFIPv4, errDFIPv6 error
	errDFIPv4 = syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_DO)
	errDFIPv6 = syscall.SetsockoptInt(int(fd.Fd()), syscall.IPPROTO_IPV6, syscall.IPV6_MTU_DISCOVER, syscall.IPV6_PMTUDISC_DO)

	switch {
	case errDFIPv4 == nil && errDFIPv6 == nil:
		slog.Debug("Setting DF for IPv4 and IPv6.")
	case errDFIPv4 == nil && errDFIPv6 != nil:
		slog.Debug("Setting DF for IPv4.")
	case errDFIPv4 != nil && errDFIPv6 == nil:
		slog.Debug("Setting DF for IPv6.")
	case errDFIPv4 != nil && errDFIPv6 != nil:
		slog.Debug("setting DF failed for both IPv4 and IPv6")
	}

	return nil
}

func (l *Listener) getOrCreateStream(streamId uint32, pukKeyIdSnd ed25519.PublicKey, remoteAddr *net.UDPAddr) (*Stream, error) {
	conn, err := l.NewOrGetConnection(pukKeyIdSnd, remoteAddr)
	if err != nil {
		return nil, err
	}

	if conn.Has(streamId) {
		return conn.Get(streamId)
	}

	return conn.New(streamId)
}
