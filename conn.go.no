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
	remoteAddr  *net.UDPAddr       // the remote address
	streams     map[uint32]*Stream // 2^32 connections to a single peer
	listener    *Listener
	pubKeyIdRcv ed25519.PublicKey
	privKeyEp   *ecdh.PrivateKey
	pubKeyEpRcv *ecdh.PublicKey
	//we have 2 shared secrets, the first where we derive the shared secret with their public key
	//which is not perfect forward secrecy
	sharedSecret1 []byte
	//from here on we have perfect forward secrecy
	sharedSecret2 []byte
	srttMillis    int64 //measurements
	rttVarMillis  int64
	ptoMillis     int64
	mu            sync.Mutex
}

func (l *Listener) newConn(remoteAddr *net.UDPAddr, pubKeyIdRcv ed25519.PublicKey, privKeyEp *ecdh.PrivateKey, pubKeyEdRcv *ecdh.PublicKey) (*Connection, error) {
	var connId [8]byte
	pubKey := l.privKeyId.Public().(ed25519.PublicKey)
	copy(connId[0:4], pubKey[0:4])
	copy(connId[4:8], pubKeyIdRcv[0:4])

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
		privKeyEp:    privKeyEp,
		pubKeyEpRcv:  pubKeyEdRcv,
		mu:           sync.Mutex{},
		listener:     l,
		srttMillis:   1000,
		rttVarMillis: 500,
		ptoMillis:    3000,
	}
	return l.connMap[connId], nil
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
