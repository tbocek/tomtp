package tomtp

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net"
	"sync"
)

type Connection struct {
	remoteAddr     *net.UDPAddr
	streams        map[uint32]*Stream
	listener       *Listener
	pubKeyIdRcv    ed25519.PublicKey
	privKeyEpSnd   *ecdh.PrivateKey
	pubKeyEpRcv    *ecdh.PublicKey
	sharedSecret   []byte
	rtoMillis      uint64
	lastSentMillis uint64
	mu             sync.Mutex
}

func (l *Listener) newConn(remoteAddr *net.UDPAddr, pubKeyIdRcv ed25519.PublicKey, privKeyEpSnd *ecdh.PrivateKey, pubKeyEdRcv *ecdh.PublicKey) (*Connection, error) {
	var connId uint64
	pukKeyIdSnd := l.privKeyId.Public().(ed25519.PublicKey)
	connId = encodeXor(pubKeyIdRcv, pukKeyIdSnd)

	l.mu.Lock()
	defer l.mu.Unlock()

	if conn, ok := l.connMap[connId]; ok {
		slog.Warn("conn already exists", slog.Any("connId", connId))
		return conn, errors.New("conn already exists")
	}

	l.connMap[connId] = &Connection{
		streams:      make(map[uint32]*Stream),
		remoteAddr:   remoteAddr,
		pubKeyIdRcv:  pubKeyIdRcv,
		privKeyEpSnd: privKeyEpSnd,
		pubKeyEpRcv:  pubKeyEdRcv,
		rtoMillis:    1000,
		mu:           sync.Mutex{},
		listener:     l,
	}
	return l.connMap[connId], nil
}
