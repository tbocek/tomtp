package tomtp

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// ConnPair represents a pair of connected NetworkConn implementations
type ConnPair struct {
	Conn1 NetworkConn
	Conn2 NetworkConn
}

// PairedConn implements the NetworkConn interface and connects to a partner
type PairedConn struct {
	localAddr   string
	partner     *PairedConn
	readQueue   []packetData
	readQueueMu sync.Mutex
	readCancel  chan struct{}
	readNotify  chan struct{}
	closed      bool
	closeMu     sync.Mutex
	deadline    time.Time
}

// packetData represents a UDP packet
type packetData struct {
	data       []byte
	remoteAddr string
}

// NewConnPair creates a pair of connected NetworkConn implementations
func NewConnPair(addr1 string, addr2 string) *ConnPair {
	conn1 := newPairedConn(addr1)
	conn2 := newPairedConn(addr2)

	// Connect the two connections
	conn1.partner = conn2
	conn2.partner = conn1

	return &ConnPair{
		Conn1: conn1,
		Conn2: conn2,
	}
}

// newPairedConn creates a new PairedConn instance
func newPairedConn(localAddr string) *PairedConn {
	return &PairedConn{
		localAddr:  localAddr,
		readQueue:  make([]packetData, 0),
		readCancel: make(chan struct{}),
		readNotify: make(chan struct{}, 1),
	}
}

// ReadFromUDPAddrPort reads data from the read queue
func (p *PairedConn) ReadFromUDPAddrPort(buf []byte, nowMicros int64) (int, netip.AddrPort, error) {
	if p.isClosed() {
		return 0, netip.AddrPort{}, errors.New("connection closed")
	}

	if !p.deadline.IsZero() && time.Now().After(p.deadline) {
		return 0, netip.AddrPort{}, errors.New("read deadline exceeded")
	}

	// Create a timer for deadline if needed
	var deadlineTimer <-chan time.Time
	if !p.deadline.IsZero() {
		deadlineTimer = time.After(time.Until(p.deadline))
	}

	for {
		// Check if there's data in the queue
		p.readQueueMu.Lock()
		if len(p.readQueue) > 0 {
			packet := p.readQueue[0]
			p.readQueue = p.readQueue[1:]
			p.readQueueMu.Unlock()

			n := copy(buf, packet.data)
			return n, netip.AddrPort{}, nil
		}
		p.readQueueMu.Unlock()

		// Wait for new data or cancellation
		select {
		case <-p.readNotify:
			// New data available, try reading again
			continue
		case <-p.readCancel:
			return 0, netip.AddrPort{}, errors.New("read canceled")
		case <-deadlineTimer:
			if !p.deadline.IsZero() {
				return 0, netip.AddrPort{}, errors.New("read deadline exceeded")
			}
		}
	}
}

// CancelRead cancels any pending read operation
func (p *PairedConn) CancelRead() error {
	select {
	case p.readCancel <- struct{}{}:
	default:
	}
	return nil
}

// WriteToUDPAddrPort writes data to the partner connection
func (p *PairedConn) WriteToUDPAddrPort(data []byte, remoteAddr netip.AddrPort) (int, error) {
	if p.isClosed() {
		return 0, errors.New("connection closed")
	}

	if p.partner == nil || p.partner.isClosed() {
		return 0, errors.New("no partner connection or partner closed")
	}

	// Make a copy of the data
	dataCopy := make([]byte, len(data))
	n := copy(dataCopy, data)

	// Add to partner's read queue
	p.partner.readQueueMu.Lock()
	p.partner.readQueue = append(p.partner.readQueue, packetData{
		data:       dataCopy,
		remoteAddr: p.localAddr,
	})
	p.partner.readQueueMu.Unlock()

	// Notify partner of new data
	select {
	case p.partner.readNotify <- struct{}{}:
	default:
	}

	return n, nil
}

// Close closes the connection
func (p *PairedConn) Close() error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()

	if p.closed {
		return errors.New("connection already closed")
	}

	p.closed = true
	close(p.readCancel)
	close(p.readNotify)
	return nil
}

// SetReadDeadline sets the deadline for future Read calls
func (p *PairedConn) SetReadDeadline(t time.Time) error {
	p.deadline = t
	return nil
}

// LocalAddr returns the local address
func (p *PairedConn) LocalAddrString() string {
	return p.localAddr
}

// Helper method to check if connection is closed
func (p *PairedConn) isClosed() bool {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	return p.closed
}

//************************************* TESTS

func TestNewConnPair(t *testing.T) {
	// Test creating a new connection pair
	connPair := NewConnPair("addr1", "addr2")

	// Assert connections were created
	assert.NotNil(t, connPair)
	assert.NotNil(t, connPair.Conn1)
	assert.NotNil(t, connPair.Conn2)

	// Assert connections are properly linked
	conn1 := connPair.Conn1.(*PairedConn)
	conn2 := connPair.Conn2.(*PairedConn)

	assert.Equal(t, "addr1", conn1.localAddr)
	assert.Equal(t, "addr2", conn2.localAddr)
	assert.Equal(t, conn2, conn1.partner)
	assert.Equal(t, conn1, conn2.partner)
}

func TestWriteAndReadUDP(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("sender", "receiver")
	sender := connPair.Conn1
	receiver := connPair.Conn2

	// Test data
	testData := []byte("hello world")

	// Write from sender to receiver
	n, err := sender.WriteToUDPAddrPort(testData, netip.AddrPort{})
	assert.NoError(t, err)
	assert.Equal(t, len(testData), n)

	// Read on receiver side
	buffer := make([]byte, 100)
	n, _, err = receiver.(*PairedConn).ReadFromUDPAddrPort(buffer, time.Now().UnixMicro())
	assert.NoError(t, err)
	assert.Equal(t, len(testData), n)
	assert.Equal(t, testData, buffer[:n])
}

func TestWriteAndReadUDPBidirectional(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("endpoint1", "endpoint2")
	endpoint1 := connPair.Conn1
	endpoint2 := connPair.Conn2

	// Test data
	dataFromEndpoint1 := []byte("message from endpoint 1")
	dataFromEndpoint2 := []byte("response from endpoint 2")

	// Endpoint 1 writes to Endpoint 2
	n1, err := endpoint1.WriteToUDPAddrPort(dataFromEndpoint1, netip.AddrPort{})
	assert.NoError(t, err)
	assert.Equal(t, len(dataFromEndpoint1), n1)

	// Endpoint 2 reads from Endpoint 1
	buffer := make([]byte, 100)
	n2, _, err := endpoint2.(*PairedConn).ReadFromUDPAddrPort(buffer, time.Now().UnixMicro())
	assert.NoError(t, err)
	assert.Equal(t, len(dataFromEndpoint1), n2)
	assert.Equal(t, dataFromEndpoint1, buffer[:n2])

	// Endpoint 2 writes back to Endpoint 1
	n3, err := endpoint2.WriteToUDPAddrPort(dataFromEndpoint2, netip.AddrPort{})
	assert.NoError(t, err)
	assert.Equal(t, len(dataFromEndpoint2), n3)

	// Endpoint 1 reads response from Endpoint 2
	buffer = make([]byte, 100)
	n4, _, err := endpoint1.(*PairedConn).ReadFromUDPAddrPort(buffer, time.Now().UnixMicro())
	assert.NoError(t, err)
	assert.Equal(t, len(dataFromEndpoint2), n4)
	assert.Equal(t, dataFromEndpoint2, buffer[:n4])
}

func TestCancelRead(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("conn1", "conn2")
	conn := connPair.Conn1.(*PairedConn)

	// Start a goroutine to read
	readDone := make(chan struct{})
	var readErr error

	go func() {
		buffer := make([]byte, 100)
		_, _, readErr = conn.ReadFromUDPAddrPort(buffer, time.Now().UnixMicro())
		close(readDone)
	}()

	// Small delay to ensure read is blocked
	time.Sleep(50 * time.Millisecond)

	// Cancel the read
	err := conn.CancelRead()
	assert.NoError(t, err)

	// Wait for read to complete
	select {
	case <-readDone:
		assert.Error(t, readErr)
		assert.Contains(t, readErr.Error(), "read canceled")
	case <-time.After(1 * time.Second):
		t.Fatal("Read was not canceled within timeout")
	}
}

func TestSetReadDeadline(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("conn1", "conn2")
	conn := connPair.Conn1.(*PairedConn)

	// Set a short deadline
	deadline := time.Now().Add(100 * time.Millisecond)
	err := conn.SetReadDeadline(deadline)
	assert.NoError(t, err)

	// Start a goroutine to read
	readDone := make(chan struct{})
	var readErr error

	go func() {
		buffer := make([]byte, 100)
		_, _, readErr = conn.ReadFromUDPAddrPort(buffer, time.Now().UnixMicro())
		close(readDone)
	}()

	// Wait for read to complete (should timeout)
	select {
	case <-readDone:
		assert.Error(t, readErr)
		assert.Contains(t, readErr.Error(), "read deadline exceeded")
	case <-time.After(1 * time.Second):
		t.Fatal("Read deadline did not trigger timeout")
	}
}

func TestWriteToClosedConnection(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("conn1", "conn2")
	conn1 := connPair.Conn1
	conn2 := connPair.Conn2

	// Close one connection
	err := conn2.Close()
	assert.NoError(t, err)

	// Attempt to write to the closed connection
	_, err = conn1.WriteToUDPAddrPort([]byte("test data"), netip.AddrPort{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestReadFromClosedConnection(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("conn1", "conn2")
	conn := connPair.Conn1.(*PairedConn)

	// Close the connection
	err := conn.Close()
	assert.NoError(t, err)

	// Attempt to read from the closed connection
	buffer := make([]byte, 100)
	_, _, err = conn.ReadFromUDPAddrPort(buffer, time.Now().UnixMicro())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "connection closed")
}

func TestCloseTwice(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("conn1", "conn2")
	conn := connPair.Conn1

	// Close the connection once
	err := conn.Close()
	assert.NoError(t, err)

	// Close the connection again
	err = conn.Close()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already closed")
}

func TestLargeDataTransfer(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("sender", "receiver")
	sender := connPair.Conn1
	receiver := connPair.Conn2.(*PairedConn)

	// Create large test data (100 KB)
	testData := make([]byte, 100*1024)
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	// Write large data
	n, err := sender.WriteToUDPAddrPort(testData, netip.AddrPort{})
	assert.NoError(t, err)
	assert.Equal(t, len(testData), n)

	// Read large data
	buffer := make([]byte, 110*1024) // Larger buffer than data
	n, _, err = receiver.ReadFromUDPAddrPort(buffer, time.Now().UnixMicro())
	assert.NoError(t, err)
	assert.Equal(t, len(testData), n)
	assert.Equal(t, testData, buffer[:n])
}

func TestMultipleWrites(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("sender", "receiver")
	sender := connPair.Conn1
	receiver := connPair.Conn2.(*PairedConn)

	// Test data
	messages := [][]byte{
		[]byte("message 1"),
		[]byte("message 2"),
		[]byte("message 3"),
	}

	// Send all messages
	for _, msg := range messages {
		n, err := sender.WriteToUDPAddrPort(msg, netip.AddrPort{})
		assert.NoError(t, err)
		assert.Equal(t, len(msg), n)
	}

	// Read and verify all messages in order
	buffer := make([]byte, 100)
	for _, expectedMsg := range messages {
		n, _, err := receiver.ReadFromUDPAddrPort(buffer, time.Now().UnixMicro())
		assert.NoError(t, err)
		assert.Equal(t, len(expectedMsg), n)
		assert.Equal(t, expectedMsg, buffer[:n])
	}
}

func TestConcurrentReadWrite(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("endpoint1", "endpoint2")
	endpoint1 := connPair.Conn1
	endpoint2 := connPair.Conn2

	// Number of messages to exchange
	numMessages := 50

	// Channel to signal test completion
	done := make(chan struct{})

	// Goroutine for endpoint1
	go func() {
		buffer := make([]byte, 100)
		for i := 0; i < numMessages; i++ {
			// Send message
			msg := []byte("message from endpoint1")
			_, err := endpoint1.WriteToUDPAddrPort(msg, netip.AddrPort{})
			require.NoError(t, err)

			// Read response
			n, _, err := endpoint1.(*PairedConn).ReadFromUDPAddrPort(buffer, time.Now().UnixMicro())
			require.NoError(t, err)
			require.Equal(t, []byte("response from endpoint2"), buffer[:n])
		}
	}()

	// Goroutine for endpoint2
	go func() {
		buffer := make([]byte, 100)
		for i := 0; i < numMessages; i++ {
			// Read message
			n, _, err := endpoint2.(*PairedConn).ReadFromUDPAddrPort(buffer, time.Now().UnixMicro())
			require.NoError(t, err)
			require.Equal(t, []byte("message from endpoint1"), buffer[:n])

			// Send response
			resp := []byte("response from endpoint2")
			_, err = endpoint2.WriteToUDPAddrPort(resp, netip.AddrPort{})
			require.NoError(t, err)
		}
		close(done)
	}()

	// Wait for test to complete with timeout
	select {
	case <-done:
		// Test completed successfully
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out")
	}
}

func TestLocalAddrString(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("addr1", "addr2")
	conn1 := connPair.Conn1.(*PairedConn)
	conn2 := connPair.Conn2.(*PairedConn)

	// Check local addresses
	assert.Equal(t, "addr1<->addr2", conn1.LocalAddrString())
	assert.Equal(t, "addr2<->addr1", conn2.LocalAddrString())
}
