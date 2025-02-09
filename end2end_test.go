package tomtp

import (
	"bytes"
	"crypto/ecdh"
	"errors"
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
	sendBuffer   bytes.Buffer // Buffers outgoing data
	recvBuffer   bytes.Buffer // Buffers incoming data
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

func (c *inMemoryNetworkConn) ReadFromUDPAddrPort(p []byte) (int, netip.AddrPort, error) {
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

func (c *inMemoryNetworkConn) LocalAddr() net.Addr {
	return c.localAddr
}

// setupInMemoryPair creates two inMemoryNetworkConn connections that are directly linked.
// There are NO goroutines used for relaying data.  The test must explicitly transfer data between the connections.
func setupInMemoryPair() (*inMemoryNetworkConn, *inMemoryNetworkConn, error) {
	addrA, err := net.ResolveUDPAddr("udp", "127.0.0.1:10000")
	if err != nil {
		return nil, nil, err
	}
	addrB, err := net.ResolveUDPAddr("udp", "127.0.0.1:20000")
	if err != nil {
		return nil, nil, err
	}

	addrPortA, err := netip.ParseAddrPort(addrA.String())
	if err != nil {
		return nil, nil, err
	}
	addrPortB, err := netip.ParseAddrPort(addrB.String())
	if err != nil {
		return nil, nil, err
	}

	nConnA := newInMemoryNetworkConn(addrA, addrPortB)
	nConnB := newInMemoryNetworkConn(addrB, addrPortA)

	return nConnA, nConnB, nil
}

// relayData simulates sending the data one way
func relayData(connSrc, connDest *inMemoryNetworkConn, maxBytes int) (int, error) {
	connSrc.mu.Lock()
	defer connSrc.mu.Unlock()
	connDest.mu.Lock()
	defer connDest.mu.Unlock()

	// Check how many bytes are available to relay
	availableBytes := connSrc.sendBuffer.Len()

	// Limit the relay to maxBytes if specified and if there's data available
	if maxBytes > 0 && availableBytes > maxBytes {
		availableBytes = maxBytes
	}
	// Exit, if nothing to relay
	if availableBytes == 0 {
		return 0, nil
	}

	// Create a limited reader to read only the availableBytes
	limitedReader := io.LimitReader(&connSrc.sendBuffer, int64(availableBytes))

	// Copy the limited amount of data from source's send buffer into destination's recv buffer.
	bytesWritten, err := io.Copy(&connDest.recvBuffer, limitedReader)
	if err != nil {
		return 0, err
	}

	// Reset the sendBuffer to remove the relayed data
	// Create a new buffer and write remaining data into it.
	remainingData := connSrc.sendBuffer.Bytes()
	newBuffer := bytes.NewBuffer(remainingData)
	connSrc.sendBuffer = *newBuffer

	return int(bytesWritten), nil
}

func createConnectedStreams(
	nConnA *inMemoryNetworkConn,
	nConnB *inMemoryNetworkConn,
	prvKeyA *ecdh.PrivateKey,
	prvKeyB *ecdh.PrivateKey,
	acceptB func(s *Stream),
) (streamA *Stream, listenerB *Listener, err error) {

	var listenerA *Listener

	acceptA := func(s *Stream) {
		slog.Info("A: accept connection")
	}
	listenAddrA := nConnA.LocalAddr().String()
	listenerA, err = ListenString(listenAddrA, acceptA, WithNetworkConn(nConnA), WithPrivKeyId(prvKeyA))
	if err != nil {
		return nil, nil, errors.New("failed to create listener A: " + err.Error())
	}

	listenAddrB := nConnB.LocalAddr().String()
	listenerB, err = ListenString(listenAddrB, acceptB, WithNetworkConn(nConnB), WithPrivKeyId(prvKeyB))
	if err != nil {
		//Important: close listener A here as listener B might not close it
		listenerA.Close()
		return nil, nil, errors.New("failed to create listener B: " + err.Error())
	}

	connA, err := listenerA.DialString(nConnB.LocalAddr().String(), hexPublicKey2)
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
	nConnA, nConnB, err := setupInMemoryPair()
	if err != nil {
		t.Fatalf("failed to setup in-memory connections: %v", err)
	}
	defer nConnA.Close()
	defer nConnB.Close()

	var streamB *Stream
	acceptB := func(s *Stream) {
		slog.Info("A: accept connection")
		streamB = s
	}

	streamA, listenerB, err := createConnectedStreams(nConnA, nConnB, testPrivateKey1, testPrivateKey2, acceptB)
	assert.Nil(t, err)

	a := []byte("hallo")
	streamA.Write(a)
	streamA.conn.listener.Update(0)
	relayData(nConnA, nConnB, startMtu)
	listenerB.Update(0)
	b, err := streamB.ReadBytes()
	assert.Nil(t, err)
	assert.Equal(t, a, b)
}
