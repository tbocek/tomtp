package tomtp

import (
	"errors"
	"github.com/stretchr/testify/assert"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// ConnPair represents a pair of connected NetworkConn implementations
type ConnPair struct {
	Conn1 *PairedConn
	Conn2 *PairedConn

	localAddr string
}

// PairedConn implements the NetworkConn interface and connects to a partner
type PairedConn struct {
	localAddr string
	partner   *PairedConn

	// Write buffer
	writeQueue   []packetData
	writeQueueMu sync.Mutex

	// Read buffer
	readQueue   []packetData
	readQueueMu sync.Mutex

	cancelReadTime int64 // Time when CancelRead was called

	closed         bool
	closeMu        sync.Mutex
	deadlineMicros int64
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

func (c *ConnPair) senderRawToRecipient(addr string, raw []byte) error {
	return c.Conn1.CopyDataRaw(addr, raw)
}

func (c *ConnPair) senderToRecipient(sequence ...int) error {
	return c.Conn1.CopyData(sequence...)
}

func (c *ConnPair) senderToRecipientAll() error {
	return c.Conn1.SimpleDataCopy()
}

func (c *ConnPair) recipientToSenderAll() error {
	return c.Conn2.SimpleDataCopy()
}

func (c *ConnPair) recipientRawToSender(addr string, raw []byte) error {
	return c.Conn2.CopyDataRaw(addr, raw)
}

func (c *ConnPair) recipientToSender(sequence ...int) error {
	return c.Conn2.CopyData(sequence...)
}

func (c *ConnPair) nrOutgoingPacketsSender() int {
	return len(c.Conn1.writeQueue)
}

func (c *ConnPair) nrOutgoingPacketsReceiver() int {
	return len(c.Conn2.writeQueue)
}

func (c *ConnPair) nrIncomingPacketsRecipient() int {
	return len(c.Conn2.readQueue)
}

func (c *ConnPair) nrIncomingPacketsSender() int {
	return len(c.Conn1.readQueue)
}

// newPairedConn creates a new PairedConn instance
func newPairedConn(localAddr string) *PairedConn {
	return &PairedConn{
		localAddr:      localAddr,
		writeQueue:     make([]packetData, 0),
		readQueue:      make([]packetData, 0),
		cancelReadTime: 0,
	}
}

// ReadFromUDPAddrPort reads data from the read queue
func (p *PairedConn) ReadFromUDPAddrPort(buf []byte, _ time.Duration) (int, netip.AddrPort, error) {
	if p.isClosed() {
		return 0, netip.AddrPort{}, errors.New("connection closed")
	}

	// Check if there's data in the queue
	p.readQueueMu.Lock()
	defer p.readQueueMu.Unlock()

	// Find the first packet that is available based on timing constraints
	for i, packet := range p.readQueue {

		// Remove the packet from the queue
		p.readQueue = append(p.readQueue[:i], p.readQueue[i+1:]...)

		n := copy(buf, packet.data)
		return n, netip.AddrPort{}, nil

	}

	// No packets available at this time
	return 0, netip.AddrPort{}, nil
}

// CancelRead cancels any pending read operation
func (p *PairedConn) CancelRead() error {
	return nil
}

// WriteToUDPAddrPort writes data to the partner connection
func (p *PairedConn) WriteToUDPAddrPort(data []byte, remoteAddr netip.AddrPort) (int, error) {
	if p.isClosed() {
		return 0, errors.New("connection closed")
	}

	// Make a copy of the data
	dataCopy := make([]byte, len(data))
	n := copy(dataCopy, data)

	// Add to local write queue with the current timestamp
	p.writeQueueMu.Lock()
	p.writeQueue = append(p.writeQueue, packetData{
		data:       dataCopy,
		remoteAddr: remoteAddr.String(),
	})
	p.writeQueueMu.Unlock()

	return n, nil
}

func (p *PairedConn) CopyDataRaw(addr string, raw []byte) error {
	if p.isClosed() {
		return errors.New("connection closed")
	}
	if p.partner == nil || p.partner.isClosed() {
		return errors.New("no partner connection or partner closed")
	}

	// Create a new packetData with the raw bytes
	packet := packetData{
		data:       raw,
		remoteAddr: addr,
	}

	// Lock partner's read queue to ensure atomicity when appending
	p.partner.readQueueMu.Lock()
	defer p.partner.readQueueMu.Unlock()

	// Append the packet to partner's read queue
	p.partner.readQueue = append(p.partner.readQueue, packet)

	return nil
}

func (p *PairedConn) CopyData(sequence ...int) error {
	if p.isClosed() {
		return errors.New("connection closed")
	}
	if p.partner == nil || p.partner.isClosed() {
		return errors.New("no partner connection or partner closed")
	}

	// Lock write queue to ensure atomicity
	p.writeQueueMu.Lock()
	defer p.writeQueueMu.Unlock()

	// Early return if no data to process
	if len(p.writeQueue) == 0 {
		return nil
	}

	currentPos := 0

	for _, count := range sequence {
		// Skip zero values (do nothing)
		if count == 0 {
			continue
		}

		// Check if we've reached the end of the queue
		if currentPos >= len(p.writeQueue) {
			break
		}

		if count > 0 {
			// Positive: Copy 'count' packets
			copyCount := count
			// Adjust if trying to copy more than available
			if currentPos+copyCount > len(p.writeQueue) {
				copyCount = len(p.writeQueue) - currentPos
			}

			// Copy packets to partner's read queue
			p.partner.readQueueMu.Lock()
			p.partner.readQueue = append(p.partner.readQueue,
				p.writeQueue[currentPos:currentPos+copyCount]...)
			p.partner.readQueueMu.Unlock()

			// Move current position forward
			currentPos += copyCount

		} else {
			// Negative: Drop 'abs(count)' packets
			dropCount := -count // Convert to positive
			// Adjust if trying to drop more than available
			if currentPos+dropCount > len(p.writeQueue) {
				dropCount = len(p.writeQueue) - currentPos
			}

			// Just advance position (effectively dropping packets)
			currentPos += dropCount
		}
	}

	// Remove processed packets from write queue
	if currentPos >= len(p.writeQueue) {
		p.writeQueue = p.writeQueue[:0] // Clear the queue
	} else {
		p.writeQueue = p.writeQueue[currentPos:] // Keep remaining packets
	}

	return nil
}

// SimpleDataCopy is a convenience wrapper for copying all packets
func (p *PairedConn) SimpleDataCopy() error {
	return p.CopyData(len(p.writeQueue))
}

// Close closes the connection
func (p *PairedConn) Close() error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()

	if p.closed {
		return errors.New("connection already closed")
	}

	p.closed = true
	return nil
}

// LocalAddr returns the local address
func (p *PairedConn) LocalAddrString() string {
	// Format the address as local<->remote
	if p.partner != nil {
		return p.localAddr + "<->" + p.partner.localAddr
	}
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
	conn1 := connPair.Conn1
	conn2 := connPair.Conn2

	assert.Equal(t, "addr1", conn1.localAddr)
	assert.Equal(t, "addr2", conn2.localAddr)
	assert.Equal(t, conn2, conn1.partner)
	assert.Equal(t, conn1, conn2.partner)
}

func TestWriteAndReadUDP(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("isSender", "receiver")
	sender := connPair.Conn1
	receiver := connPair.Conn2

	// Test data
	testData := []byte("hello world")

	// Write from isSender to receiver
	n, err := sender.WriteToUDPAddrPort(testData, netip.AddrPort{})
	assert.NoError(t, err)
	assert.Equal(t, len(testData), n)

	err = connPair.senderToRecipient(1)
	assert.NoError(t, err)

	// Read on receiver side
	buffer := make([]byte, 100)
	n, _, err = receiver.ReadFromUDPAddrPort(buffer, 0)
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

	err = connPair.senderToRecipient(1)
	assert.NoError(t, err)

	// Endpoint 2 reads from Endpoint 1
	buffer := make([]byte, 100)
	n2, _, err := endpoint2.ReadFromUDPAddrPort(buffer, 0)
	assert.NoError(t, err)
	assert.Equal(t, len(dataFromEndpoint1), n2)
	assert.Equal(t, dataFromEndpoint1, buffer[:n2])

	// Endpoint 2 writes back to Endpoint 1
	n3, err := endpoint2.WriteToUDPAddrPort(dataFromEndpoint2, netip.AddrPort{})
	assert.NoError(t, err)
	assert.Equal(t, len(dataFromEndpoint2), n3)

	err = connPair.recipientToSender(1)
	assert.NoError(t, err)

	// Endpoint 1 reads response from Endpoint 2
	buffer = make([]byte, 100)
	n4, _, err := endpoint1.ReadFromUDPAddrPort(buffer, 0)
	assert.NoError(t, err)
	assert.Equal(t, len(dataFromEndpoint2), n4)
	assert.Equal(t, dataFromEndpoint2, buffer[:n4])
}

func TestWriteToClosedConnection(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("conn1", "conn2")
	conn1 := connPair.Conn1

	// Close one connection
	err := conn1.Close()
	assert.NoError(t, err)

	// Attempt to write to the closed connection
	_, err = conn1.WriteToUDPAddrPort([]byte("test data"), netip.AddrPort{})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestReadFromClosedConnection(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("conn1", "conn2")
	conn := connPair.Conn1

	// Close the connection
	err := conn.Close()
	assert.NoError(t, err)

	// Attempt to read from the closed connection
	buffer := make([]byte, 100)
	_, _, err = conn.ReadFromUDPAddrPort(buffer, 0)
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

func TestMultipleWrites(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("isSender", "receiver")
	sender := connPair.Conn1
	receiver := connPair.Conn2

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

	err := connPair.senderToRecipient(3)
	assert.NoError(t, err)

	// Read and verify all messages in order
	buffer := make([]byte, 100)
	for _, expectedMsg := range messages {
		n, _, err := receiver.ReadFromUDPAddrPort(buffer, 0)
		assert.NoError(t, err)
		assert.Equal(t, len(expectedMsg), n)
		assert.Equal(t, expectedMsg, buffer[:n])
	}
}

func TestLocalAddrString(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("addr1", "addr2")
	conn1 := connPair.Conn1
	conn2 := connPair.Conn2

	// Check local addresses
	assert.Equal(t, "addr1<->addr2", conn1.LocalAddrString())
	assert.Equal(t, "addr2<->addr1", conn2.LocalAddrString())
}

func TestWriteAndReadUDPWithDrop(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("isSender", "receiver")
	sender := connPair.Conn1
	receiver := connPair.Conn2

	// Test data - two packets
	testData1 := []byte("packet 1")
	testData2 := []byte("packet 2")

	// Write both packets from isSender to receiver
	n1, err := sender.WriteToUDPAddrPort(testData1, netip.AddrPort{})
	assert.NoError(t, err)
	assert.Equal(t, len(testData1), n1)

	n2, err := sender.WriteToUDPAddrPort(testData2, netip.AddrPort{})
	assert.NoError(t, err)
	assert.Equal(t, len(testData2), n2)

	// Copy the first packet and drop the second one
	err = connPair.senderToRecipient(1, -1) // Copy packet 1, Drop packet 2
	assert.NoError(t, err)

	// Read on receiver side - should only receive packet 1
	buffer := make([]byte, 100)
	n, _, err := receiver.ReadFromUDPAddrPort(buffer, 0)
	assert.NoError(t, err)
	assert.Equal(t, len(testData1), n)
	assert.Equal(t, testData1, buffer[:n])

	// Verify that packet 2 was not received (no more data in the queue)
	n, _, err = receiver.ReadFromUDPAddrPort(buffer, 0)
	assert.NoError(t, err) // Should return no error but zero bytes
	assert.Equal(t, 0, n)
}
