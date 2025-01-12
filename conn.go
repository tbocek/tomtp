package tomtp

import (
	"crypto/ecdh"
	"fmt"
	"net"
	"sync"
)

type Connection struct {
	remoteAddr      net.Addr
	streams         map[uint32]*Stream
	listener        *Listener
	pubKeyIdRcv     *ecdh.PublicKey
	prvKeyEpSnd     *ecdh.PrivateKey
	pubKeyEpRcv     *ecdh.PublicKey
	sharedSecret    []byte
	rtoMillis       uint64
	lastSentMillis  uint64
	nextSleepMillis uint64
	sn              uint64
	mu              sync.Mutex
}

func (c *Connection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, stream := range c.streams {
		//pick first stream, send close flag to close all streams
		stream.CloseAll()
		break
	}

	clear(c.streams)
	return nil
}

func (c *Connection) NewStreamSnd(streamId uint32) (*Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.streams[streamId]; !ok {
		s := &Stream{
			streamId:    streamId,
			streamSn:    0,
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

func (c *Connection) GetOrNewStreamRcv(streamId uint32) (*Stream, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if stream, ok := c.streams[streamId]; !ok {
		s := &Stream{
			streamId:    streamId,
			streamSn:    0,
			sender:      false,
			state:       StreamStarting,
			conn:        c,
			rbRcv:       NewRingBufferRcv[[]byte](1, maxRingBuffer),
			rbSnd:       NewRingBufferSnd[[]byte](maxRingBuffer, maxRingBuffer),
			writeBuffer: []byte{},
			mu:          sync.Mutex{},
		}
		c.streams[streamId] = s
		return s, true
	} else {
		return stream, false
	}
}
