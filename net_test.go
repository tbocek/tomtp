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
	Conn1 NetworkConn
	Conn2 NetworkConn

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
	closedTime     int64 // Time when Close was called

	closed         bool
	closeMu        sync.Mutex
	deadlineMicros int64
}

// packetData represents a UDP packet
type packetData struct {
	data        []byte
	remoteAddr  string
	writeMicros int64 // Timestamp when the packet was written
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

func (c *ConnPair) senderToRecipient(sequence ...int) error {
	return c.Conn1.(*PairedConn).CopyData(sequence...)
}

func (c *ConnPair) recipientToSender(sequence ...int) error {
	return c.Conn2.(*PairedConn).CopyData(sequence...)
}

// newPairedConn creates a new PairedConn instance
func newPairedConn(localAddr string) *PairedConn {
	return &PairedConn{
		localAddr:      localAddr,
		writeQueue:     make([]packetData, 0),
		readQueue:      make([]packetData, 0),
		cancelReadTime: 0,
		closedTime:     0,
	}
}

// ReadFromUDPAddrPort reads data from the read queue
func (p *PairedConn) ReadFromUDPAddrPort(buf []byte, nowMicros int64) (int, netip.AddrPort, error) {
	if p.isClosed() {
		return 0, netip.AddrPort{}, errors.New("connection closed")
	}

	if p.deadlineMicros != 0 && p.deadlineMicros < nowMicros {
		p.deadlineMicros = 0
		return 0, netip.AddrPort{}, errors.New("read deadline exceeded")
	}

	// Check if read was canceled before current time
	if p.cancelReadTime != 0 && p.cancelReadTime <= nowMicros {
		p.cancelReadTime = 0
		return 0, netip.AddrPort{}, errors.New("read canceled")
	}

	// Check if there's data in the queue
	p.readQueueMu.Lock()
	defer p.readQueueMu.Unlock()

	// Find the first packet that is available based on timing constraints
	for i, packet := range p.readQueue {
		// A packet is available if it was written before the current time
		if packet.writeMicros <= nowMicros {
			// Remove the packet from the queue
			p.readQueue = append(p.readQueue[:i], p.readQueue[i+1:]...)

			n := copy(buf, packet.data)
			return n, netip.AddrPort{}, nil
		}
	}

	// No packets available at this time
	return 0, netip.AddrPort{}, nil
}

// CancelRead cancels any pending read operation
func (p *PairedConn) CancelRead(nowMicros int64) error {
	p.cancelReadTime = nowMicros
	return nil
}

// WriteToUDPAddrPort writes data to the partner connection
func (p *PairedConn) WriteToUDPAddrPort(data []byte, remoteAddr netip.AddrPort, nowMicros int64) (int, error) {
	if p.isClosed() {
		return 0, errors.New("connection closed")
	}

	// Make a copy of the data
	dataCopy := make([]byte, len(data))
	n := copy(dataCopy, data)

	// Add to local write queue with the current timestamp
	p.writeQueueMu.Lock()
	p.writeQueue = append(p.writeQueue, packetData{
		data:        dataCopy,
		remoteAddr:  remoteAddr.String(),
		writeMicros: nowMicros, // Store the current time
	})
	p.writeQueueMu.Unlock()

	return n, nil
}

func (p *PairedConn) CopyData(sequence ...int) error {
	if p.isClosed() {
		return errors.New("connection closed")
	}

	if p.partner == nil || p.partner.isClosed() {
		return errors.New("no partner connection or partner closed")
	}

	// Lock both queues to ensure atomicity
	p.writeQueueMu.Lock()
	defer p.writeQueueMu.Unlock()

	if len(p.writeQueue) == 0 {
		return nil // Nothing to copy
	}

	currentPos := 0

	for _, count := range sequence {
		// Skip zero values
		if count == 0 {
			continue
		}

		// Check if we've reached the end of the queue
		if currentPos >= len(p.writeQueue) {
			break
		}

		// Positive value means copy
		if count > 0 {
			copyCount := count
			// Adjust if we're trying to copy more than what's available
			if currentPos+copyCount > len(p.writeQueue) {
				copyCount = len(p.writeQueue) - currentPos
			}

			// Copy packets to partner's read queue
			p.partner.readQueueMu.Lock()
			for i := 0; i < copyCount; i++ {
				if currentPos < len(p.writeQueue) {
					p.partner.readQueue = append(p.partner.readQueue, p.writeQueue[currentPos])
					currentPos++
				}
			}
			p.partner.readQueueMu.Unlock()
		} else { // Negative value means drop
			dropCount := -count // Convert negative to positive
			// Adjust if we're trying to drop more than what's available
			if currentPos+dropCount > len(p.writeQueue) {
				dropCount = len(p.writeQueue) - currentPos
			}
			// Simply advance the position (effectively dropping the packets)
			currentPos += dropCount
		}
	}

	// If we processed all packets, clear the queue
	if currentPos >= len(p.writeQueue) {
		p.writeQueue = p.writeQueue[:0]
	} else {
		// Keep any remaining packets
		p.writeQueue = p.writeQueue[currentPos:]
	}

	return nil
}

// SimpleDataCopy is a convenience wrapper for copying all packets
func (p *PairedConn) SimpleDataCopy() error {
	return p.CopyData(len(p.writeQueue))
}

// Close closes the connection
func (p *PairedConn) Close(nowMicros int64) error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()

	if p.closed && p.closedTime <= nowMicros {
		return errors.New("connection already closed")
	}

	p.closed = true
	p.closedTime = nowMicros
	return nil
}

// SetReadDeadline sets the deadline for future Read calls
func (p *PairedConn) SetReadDeadline(deadlineMicros int64) error {
	p.deadlineMicros = deadlineMicros
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
	n, err := sender.WriteToUDPAddrPort(testData, netip.AddrPort{}, 0)
	assert.NoError(t, err)
	assert.Equal(t, len(testData), n)

	err = connPair.senderToRecipient(1)
	assert.NoError(t, err)

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
	n1, err := endpoint1.WriteToUDPAddrPort(dataFromEndpoint1, netip.AddrPort{}, 0)
	assert.NoError(t, err)
	assert.Equal(t, len(dataFromEndpoint1), n1)

	err = connPair.senderToRecipient(1)
	assert.NoError(t, err)

	// Endpoint 2 reads from Endpoint 1
	buffer := make([]byte, 100)
	n2, _, err := endpoint2.(*PairedConn).ReadFromUDPAddrPort(buffer, time.Now().UnixMicro())
	assert.NoError(t, err)
	assert.Equal(t, len(dataFromEndpoint1), n2)
	assert.Equal(t, dataFromEndpoint1, buffer[:n2])

	// Endpoint 2 writes back to Endpoint 1
	n3, err := endpoint2.WriteToUDPAddrPort(dataFromEndpoint2, netip.AddrPort{}, 0)
	assert.NoError(t, err)
	assert.Equal(t, len(dataFromEndpoint2), n3)

	err = connPair.recipientToSender(1)
	assert.NoError(t, err)

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

	// Set fixed timestamps (in microseconds)
	cancelTime := int64(100 * 1000)     // 100 milliseconds
	readTime := int64(150 * 1000)       // 150 milliseconds
	writeTime := int64(200 * 1000)      // 200 milliseconds
	secondReadTime := int64(250 * 1000) // 250 milliseconds

	// Set the cancel read time
	err := conn.CancelRead(cancelTime)
	assert.NoError(t, err)

	// Attempt to read after cancellation
	buffer := make([]byte, 100)
	_, _, readErr := conn.ReadFromUDPAddrPort(buffer, readTime)

	// Verify read was canceled
	assert.Error(t, readErr)
	assert.Contains(t, readErr.Error(), "read canceled")

	// Test that reads work again if we try after the cancel time
	// Write some data to read
	testData := []byte("test data")
	_, err = connPair.Conn2.WriteToUDPAddrPort(testData, netip.AddrPort{}, writeTime)
	assert.NoError(t, err)

	// Copy data from conn2 to conn1
	err = connPair.recipientToSender(1)
	assert.NoError(t, err)

	// Read should succeed with a later timestamp
	n, _, readErr := conn.ReadFromUDPAddrPort(buffer, secondReadTime)
	assert.NoError(t, readErr)
	assert.Equal(t, len(testData), n)
	assert.Equal(t, testData, buffer[:n])
}

func TestSetReadDeadline(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("conn1", "conn2")
	conn := connPair.Conn1.(*PairedConn)

	// Set fixed timestamps (in microseconds)
	deadlineTime := int64(100 * 1000) // 100 milliseconds
	readTime := int64(150 * 1000)     // 150 milliseconds (after deadline)

	// Set the read deadline
	err := conn.SetReadDeadline(deadlineTime)
	assert.NoError(t, err)

	// Attempt to read after the deadline
	buffer := make([]byte, 100)
	_, _, readErr := conn.ReadFromUDPAddrPort(buffer, readTime)

	// Verify read failed due to deadline
	assert.Error(t, readErr)
	assert.Contains(t, readErr.Error(), "read deadline exceeded")

	// Test that reads work with a new deadline
	newDeadlineTime := int64(300 * 1000) // 300 milliseconds
	err = conn.SetReadDeadline(newDeadlineTime)
	assert.NoError(t, err)

	// Write some data to read
	testData := []byte("test data")
	_, err = connPair.Conn2.WriteToUDPAddrPort(testData, netip.AddrPort{}, readTime)
	assert.NoError(t, err)

	// Copy data from conn2 to conn1
	err = connPair.recipientToSender(1)
	assert.NoError(t, err)

	// Read should succeed with timestamp before the new deadline
	newReadTime := int64(200 * 1000) // 200 milliseconds (before new deadline)
	n, _, readErr := conn.ReadFromUDPAddrPort(buffer, newReadTime)
	assert.NoError(t, readErr)
	assert.Equal(t, len(testData), n)
	assert.Equal(t, testData, buffer[:n])
}

func TestWriteToClosedConnection(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("conn1", "conn2")
	conn1 := connPair.Conn1

	// Close one connection
	err := conn1.Close(0)
	assert.NoError(t, err)

	// Attempt to write to the closed connection
	_, err = conn1.WriteToUDPAddrPort([]byte("test data"), netip.AddrPort{}, 0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "closed")
}

func TestReadFromClosedConnection(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("conn1", "conn2")
	conn := connPair.Conn1.(*PairedConn)

	// Close the connection
	err := conn.Close(0)
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
	err := conn.Close(0)
	assert.NoError(t, err)

	// Close the connection again
	err = conn.Close(0)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already closed")
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
		n, err := sender.WriteToUDPAddrPort(msg, netip.AddrPort{}, 0)
		assert.NoError(t, err)
		assert.Equal(t, len(msg), n)
	}

	err := connPair.senderToRecipient(3)
	assert.NoError(t, err)

	// Read and verify all messages in order
	buffer := make([]byte, 100)
	for _, expectedMsg := range messages {
		n, _, err := receiver.ReadFromUDPAddrPort(buffer, time.Now().UnixMicro())
		assert.NoError(t, err)
		assert.Equal(t, len(expectedMsg), n)
		assert.Equal(t, expectedMsg, buffer[:n])
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

func TestWriteAndReadUDPWithDrop(t *testing.T) {
	// Create a connection pair
	connPair := NewConnPair("sender", "receiver")
	sender := connPair.Conn1
	receiver := connPair.Conn2.(*PairedConn)

	// Test data - two packets
	testData1 := []byte("packet 1")
	testData2 := []byte("packet 2")

	// Write both packets from sender to receiver
	n1, err := sender.WriteToUDPAddrPort(testData1, netip.AddrPort{}, 0)
	assert.NoError(t, err)
	assert.Equal(t, len(testData1), n1)

	n2, err := sender.WriteToUDPAddrPort(testData2, netip.AddrPort{}, 0)
	assert.NoError(t, err)
	assert.Equal(t, len(testData2), n2)

	// Copy the first packet and drop the second one
	err = connPair.senderToRecipient(1, -1) // Copy packet 1, Drop packet 2
	assert.NoError(t, err)

	// Read on receiver side - should only receive packet 1
	buffer := make([]byte, 100)
	n, _, err := receiver.ReadFromUDPAddrPort(buffer, time.Now().UnixMicro())
	assert.NoError(t, err)
	assert.Equal(t, len(testData1), n)
	assert.Equal(t, testData1, buffer[:n])

	// Verify that packet 2 was not received (no more data in the queue)
	n, _, err = receiver.ReadFromUDPAddrPort(buffer, time.Now().UnixMicro())
	assert.NoError(t, err) // Should return no error but zero bytes
	assert.Equal(t, 0, n)
}
