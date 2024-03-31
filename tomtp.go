package tomtp

import (
	"crypto/ecdh"
	"crypto/ed25519"
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
	// here we store the connection to remote peers, we can have up to
	multiStreams map[[8]byte]*MultiStreams
	mu           sync.Mutex
}

type MultiStreams struct {
	// this is the remote connection we are connected
	remoteConn *net.UDPConn
	// the remote address
	remoteAddr *net.UDPAddr
	// 2^32 connections to a single peer
	streams map[uint32]*Stream
	mu      sync.Mutex
	// parent listener
	listener       *Listener
	epPrivKeyCurve *ecdh.PrivateKey
	currentNonce   [24]byte
	pubKeyIdRcv    ed25519.PublicKey
	send           io.Writer
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
		multiStreams:   make(map[[8]byte]*MultiStreams),
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

		m, err := Decode(buffer, n, l.privKeyId, [32]byte{}) //TODO: fix
		if err != nil {
			fmt.Println("Error reading from connection:", err)
			return
		}
		s, err := l.getOrCreateStream(m, remoteAddr)
		if err != nil {
			fmt.Println("Error reading from connection:", err)
			return
		}

		err = s.push(m)
		accept(s)
	}
}

func (l *Listener) PubKeyId() ed25519.PublicKey {
	return l.privKeyId.Public().(ed25519.PublicKey)
}

func (l *Listener) NewMultiStreamString(pubId ed25519.PublicKey, remoteAddrString string) (*MultiStreams, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", remoteAddrString)
	if err != nil {
		fmt.Println("Error resolving remote address:", err)
		return nil, err
	}
	return l.NewOrGetMultiStream(pubId, remoteAddr)
}

func (l *Listener) NewOrGetMultiStream(pubKeyIdRcv ed25519.PublicKey, remoteAddr *net.UDPAddr) (*MultiStreams, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	var arr [8]byte
	copy(arr[:], pubKeyIdRcv)

	if multiStream, ok := l.multiStreams[arr]; ok {
		return multiStream, nil
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

	l.multiStreams[arr] = &MultiStreams{
		streams:     make(map[uint32]*Stream),
		remoteAddr:  remoteAddr,
		remoteConn:  remoteConn,
		pubKeyIdRcv: pubKeyIdRcv,
		mu:          sync.Mutex{},
		listener:    l,
		send:        remoteConn,
	}
	ListenerCount++
	return l.multiStreams[arr], nil
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

func (s *MultiStreams) NewOrGetStream(streamNr uint32) *Stream {
	s.mu.Lock()
	defer s.mu.Unlock()

	if stream, ok := s.streams[streamNr]; !ok {
		s.streams[streamNr] = &Stream{
			sentPackets: make(map[uint32]bool),
			nextSeqNum:  0,
			muRead:      sync.Mutex{},
			muWrite:     sync.Mutex{},
			parent:      s,
			rbRcv:       NewRingBufferRcv[*Payload](maxRingBuffer, maxRingBuffer),
			rbSnd:       NewRingBufferSnd[*Payload](maxRingBuffer, maxRingBuffer),
		}
		return s.streams[streamNr]
	} else {
		return stream
	}
}

func (l *Listener) Close() (error, []error, []error) {
	l.mu.Lock()
	defer func() {
		l.mu.Unlock()
	}()

	var streamErrors []error
	var remoteConnErrors []error

	for _, multiStream := range l.multiStreams {
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
	l.multiStreams = make(map[[8]byte]*MultiStreams)

	return l.localConn.Close(), streamErrors, remoteConnErrors
}

func (l *Listener) getOrCreateStream(m *Message, remoteAddr *net.UDPAddr) (*Stream, error) {
	multiStream, err := l.NewOrGetMultiStream(m.PukKeyIdSnd, remoteAddr)
	if err != nil {
		return nil, err
	}

	stream := multiStream.NewOrGetStream(m.Payload.StreamId)
	return stream, nil
}
