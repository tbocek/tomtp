package tomtp

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"math"
	"net"
	"sync"
)

type Connection struct {
	remoteAddr     net.Addr
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

func (l *Listener) newConn(remoteAddr net.Addr, pubKeyIdRcv ed25519.PublicKey, privKeyEpSnd *ecdh.PrivateKey, pubKeyEdRcv *ecdh.PublicKey) (*Connection, error) {
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
	sMaintenance, err := l.connMap[connId].NewMaintenance()
	if err != nil {
		return nil, err
	}
	l.connMap[connId].streams[math.MaxUint32] = sMaintenance

	return l.connMap[connId], nil
}
