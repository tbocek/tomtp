package tomtp

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
)

type Connection struct {
	remoteAddr     net.Addr
	streams        map[uint32]*Stream
	listener       *Listener
	pubKeyIdRcv    *ecdh.PublicKey
	privKeyEpSnd   *ecdh.PrivateKey
	pubKeyEpRcv    *ecdh.PublicKey
	sharedSecret   []byte
	rtoMillis      uint64
	lastSentMillis uint64
	sn             uint64
	mu             sync.Mutex
}

func (l *Listener) newConn(remoteAddr net.Addr, pubKeyIdRcv *ecdh.PublicKey, privKeyEpSnd *ecdh.PrivateKey, pubKeyEdRcv *ecdh.PublicKey) (*Connection, error) {
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

func (c *Connection) NewStream(streamId uint32) (*Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.streams[streamId]; !ok {
		s := &Stream{
			streamId:    streamId,
			sender:      true,
			state:       StreamStarting,
			conn:        c,
			rbRcv:       NewRingBufferRcv[[]byte](maxRingBuffer, maxRingBuffer),
			rbSnd:       NewRingBufferSnd[[]byte](maxRingBuffer, maxRingBuffer),
			writeBuffer: []byte{},
			mu:          sync.Mutex{},
		}
		c.streams[streamId] = s
		return s, nil
	} else {
		return nil, fmt.Errorf("stream %x already exists", streamId)
	}
}

func (c *Connection) NewOrGetStream(streamId uint32) (*Stream, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if stream, ok := c.streams[streamId]; !ok {
		s := &Stream{
			streamId:    streamId,
			sender:      false,
			state:       StreamStarting,
			conn:        c,
			rbRcv:       NewRingBufferRcv[[]byte](1, maxRingBuffer),
			rbSnd:       NewRingBufferSnd[[]byte](1, maxRingBuffer),
			writeBuffer: []byte{},
			mu:          sync.Mutex{},
		}
		c.streams[streamId] = s
		return s, true
	} else {
		return stream, false
	}
}
