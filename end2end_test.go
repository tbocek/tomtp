package tomtp

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// inMemoryNetworkConn simulates a network connection in memory.
type inMemoryNetworkConn struct {
	localAddr    net.Addr
	remoteAddr   netip.AddrPort
	sendBuffer   bytes.Buffer // Buffers outgoing dataToSend
	recvBuffer   bytes.Buffer // Buffers incoming dataToSend
	mu           sync.Mutex   // Protects both buffers
	closeChan    chan struct{}
	closed       atomic.Bool
	readDeadline time.Time
}

func newInMemoryNetworkConn(localAddr net.Addr, remoteAddr netip.AddrPort) *inMemoryNetworkConn {
	return &inMemoryNetworkConn{
		localAddr:  localAddr,
		remoteAddr: remoteAddr,
		closeChan:  make(chan struct{}),
		// Buffers are initialized automatically
	}
}

func (c *inMemoryNetworkConn) ReadFromUDPAddrPort(p []byte, nowMillis int64) (int, netip.AddrPort, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed.Load() {
		return 0, netip.AddrPort{}, errors.New("connection closed")
	}
	if c.recvBuffer.Len() == 0 {
		if !c.readDeadline.IsZero() && time.Now().After(c.readDeadline) {
			return 0, netip.AddrPort{}, errors.New("i/o timeout") //return timeout on empty recvBuffer
		}
		return 0, netip.AddrPort{}, nil // return without blocking, but no error
	}

	n, err := c.recvBuffer.Read(p)
	return n, c.remoteAddr, err
}

func (c *inMemoryNetworkConn) CancelRead() error {
	// No-op in this implementation; CancelRead is not necessary.
	return nil
}

func (c *inMemoryNetworkConn) WriteToUDPAddrPort(p []byte, remoteAddr netip.AddrPort) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed.Load() {
		return 0, errors.New("connection closed")
	}

	n, err := c.sendBuffer.Write(p)
	return n, err
}

func (c *inMemoryNetworkConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.closeChan)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.recvBuffer.Reset()
		c.sendBuffer.Reset()
	}
	return nil
}

func (c *inMemoryNetworkConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

func (c *inMemoryNetworkConn) LocalAddrString() string {
	return c.localAddr.String()
}

// setupInMemoryPair creates two inMemoryNetworkConn connections that are directly linked.
// There are NO goroutines used for relaying dataToSend.  The test must explicitly transfer dataToSend between the connections.
func setupInMemoryPair() (*NetworkConn, *NetworkConn) {
	connPair := NewConnPair("addr1", "addr2")
	return &connPair.Conn1, &connPair.Conn2
}

func createTwoStreams(
	nConnA *NetworkConn,
	nConnB *NetworkConn,
	prvKeyA *ecdh.PrivateKey,
	prvKeyB *ecdh.PrivateKey,
	acceptB func(s *Stream),
) (streamA *Stream, listenerB *Listener, err error) {

	var listenerA *Listener

	acceptA := func(s *Stream) {
		slog.Info("A: accept connection")
	}
	listenAddrA := nConnA.LocalAddrString()
	listenerA, err = ListenString(listenAddrA, acceptA, WithNetworkConn(nConnA), WithPrvKeyId(prvKeyA))
	if err != nil {
		return nil, nil, errors.New("failed to create listener A: " + err.Error())
	}

	listenAddrB := nConnB.LocalAddrString()
	listenerB, err = ListenString(listenAddrB, acceptB, WithNetworkConn(nConnB), WithPrvKeyId(prvKeyB))
	if err != nil {
		//Important: close listener A here as listener B might not close it
		listenerA.Close()
		return nil, nil, errors.New("failed to create listener B: " + err.Error())
	}

	connA, err := listenerA.DialWithCryptoString(nConnB.LocalAddrString(), hexPubKey2)
	if err != nil {
		listenerA.Close() // clean up everything here!
		listenerB.Close()
		return nil, nil, errors.New("failed to dial A from B: " + err.Error())
	}
	if connA == nil {
		listenerA.Close()
		listenerB.Close()
		return nil, nil, errors.New("connection should not be nil")
	}

	streamA, _ = connA.GetOrNewStreamRcv(0)

	return streamA, listenerB, nil
}

func TestEndToEndInMemory(t *testing.T) {
	nConnA, nConnB := setupInMemoryPair()
	defer nConnA.Close()
	defer nConnB.Close()

	var streamB *Stream
	streamA, listenerB, err := createTwoStreams(nConnA, nConnB, testPrvKey1, testPrvKey2, func(s *Stream) { streamB = s })
	assert.Nil(t, err)

	a := []byte("hallo")
	_, err = streamA.Write(a)
	assert.Nil(t, err)
	err = streamA.conn.listener.Update(0)
	assert.Nil(t, err)
	_, err = relayData(nConnA, nConnB, startMtu)
	assert.Nil(t, err)
	err = listenerB.Update(0)
	assert.Nil(t, err)
	b, err := streamB.ReadBytes()
	assert.Nil(t, err)
	assert.Equal(t, a, b)
}

func TestSlowStart(t *testing.T) {
	nConnA, nConnB := setupInMemoryPair()
	assert.Nil(t, err)
	defer nConnA.Close()
	defer nConnB.Close()

	var streamB *Stream
	streamA, listenerB, err := createTwoStreams(nConnA, nConnB, testPrvKey1, testPrvKey2, func(s *Stream) { streamB = s })
	assert.Nil(t, err)

	msgSize := 500
	msgA := make([]byte, msgSize)

	// Send dataToSend from A to B
	_, err = streamA.Write(msgA)
	assert.Nil(t, err)

	err = streamA.conn.listener.Update(0)
	assert.Nil(t, err)
	_, err = relayData(nConnA, nConnB, startMtu)
	assert.Nil(t, err)

	err = listenerB.Update(0)
	assert.Nil(t, err)
	_, err = relayData(nConnB, nConnA, startMtu)
	assert.Nil(t, err)

	err = streamA.conn.listener.Update(0)
	assert.Nil(t, err)

	//read stream
	msgB := make([]byte, msgSize)
	_, err = streamB.Read(msgB)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			t.Error(err)
		}
	}
	//Assert in order to make test not crash for stream B
	assert.Equal(t, msgA, msgB)

	fmt.Println("cwnd", streamA.conn.BBR.cwnd, "sthress", streamA.conn.BBR.ssthresh, "streamB-Read", streamB.bytesRead)

	lastRead := streamB.bytesRead

	if streamA.conn.BBR.ssthresh <= lastRead {
		t.Error("Did not happen what supposed to happen")
	}
}
