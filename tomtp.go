package tomtp

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
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
	// here we store the connection to remote peers, we can have up to
	multiStreams map[[8]byte]*Connection
	mu           sync.Mutex
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
		multiStreams:   make(map[[8]byte]*Connection),
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
	l.multiStreams = make(map[[8]byte]*Connection)

	return l.localConn.Close(), streamErrors, remoteConnErrors
}

func (l *Listener) getOrCreateStream(streamId uint32, pukKeyIdSnd ed25519.PublicKey, remoteAddr *net.UDPAddr) (*Stream, error) {
	conn, err := l.NewOrGetConnection(pukKeyIdSnd, remoteAddr)
	if err != nil {
		return nil, err
	}

	stream := conn.NewOrGetStream(streamId)
	return stream, nil
}
