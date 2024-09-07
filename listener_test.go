package tomtp

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
	"time"
)

var (
	testPrivateSeed1 = [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	testPrivateSeed2 = [32]byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	testPrivateKey1  = ed25519.NewKeyFromSeed(testPrivateSeed1[:])
	testPrivateKey2  = ed25519.NewKeyFromSeed(testPrivateSeed2[:])
	hexPublicKey1    = fmt.Sprintf("0x%x", testPrivateKey1.Public())
	hexPublicKey2    = fmt.Sprintf("0x%x", testPrivateKey2.Public())
)

func TestNewListener(t *testing.T) {
	// Test case 1: Create a new listener with a valid address
	addr := "localhost:8080"
	listener, err := Listen(addr, func(s *Stream) {}, WithSeed(testPrivateSeed1))
	defer listener.Close()
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
	if listener == nil {
		t.Errorf("Expected a listener, but got nil")
	}

	// Test case 2: Create a new listener with an invalid address
	invalidAddr := "localhost:99999"
	_, err = Listen(invalidAddr, func(s *Stream) {}, WithSeed(testPrivateSeed1))
	if err == nil {
		t.Errorf("Expected an error, but got nil")
	}
}

func TestNewStream(t *testing.T) {
	// Test case 1: Create a new multi-stream with a valid remote address
	listener, err := Listen("localhost:9080", func(s *Stream) {}, WithSeed(testPrivateSeed1))
	defer listener.Close()
	assert.Nil(t, err)
	conn, _ := listener.Dial("localhost:9081", hexPublicKey1)
	if conn == nil {
		t.Errorf("Expected a multi-stream, but got nil")
	}

	// Test case 2: Create a new multi-stream with an invalid remote address
	conn, err = listener.Dial("localhost:99999", hexPublicKey1)
	if conn != nil {
		t.Errorf("Expected nil, but got a multi-stream")
	}

}

func TestClose(t *testing.T) {
	// Test case 1: Close a listener with no multi-streams
	listener, err := Listen("localhost:9080", func(s *Stream) {}, WithSeed(testPrivateSeed1))
	assert.NoError(t, err)
	// Test case 2: Close a listener with multi-streams
	listener.Dial("localhost:9081", hexPublicKey1)
	err, _ = listener.Close()
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
}

func TestEcho(t *testing.T) {
	listener1, err := Listen(
		"localhost:9001",
		func(s *Stream) {
			b, err := s.ReadFull()
			assert.NoError(t, err)
			_, err = s.Write(b)
			assert.NoError(t, err)
		},
		WithSeed(testPrivateSeed1),
		WithManualUpdate())
	assert.NoError(t, err)

	listener2, err := Listen("localhost:9002",
		func(s *Stream) {},
		WithSeed(testPrivateSeed2),
		WithManualUpdate())
	assert.NoError(t, err)

	s, err := listener1.Dial("localhost:9002", hexPublicKey2)
	assert.NoError(t, err)

	_, err = s.Write([]byte("hallo"))
	assert.NoError(t, err)

	err, _ = listener1.Close()
	assert.NoError(t, err)

	err, _ = listener2.Close()
	assert.NoError(t, err)

}

func TestEcho2(t *testing.T) {
	nc1, nc2 := NewTestChannel(
		TestAddr{network: "net1", address: "addr1"},
		TestAddr{network: "net2", address: "addr2"})

	l1, err := ListenTPNetwork(
		nc1,
		func(s *Stream) {},
		WithSeed(testPrivateSeed1),
		WithManualUpdate())
	assert.NoError(t, err)

	l2, err := ListenTPNetwork(
		nc2,
		func(s *Stream) {},
		WithSeed(testPrivateSeed1),
		WithManualUpdate())
	assert.NoError(t, err)

	s1, err := l1.DialTP(nc2.LocalAddr(), l2.pubKeyId)
	assert.NoError(t, err)

	n, err := s1.Write([]byte("test1234"))
	assert.NoError(t, err)
	assert.Equal(t, 8, n)
}

type ChannelNetworkConn struct {
	in           chan []byte
	out          chan *SndSegment[[]byte]
	localAddr    net.Addr
	readDeadline time.Time
}

// TestAddr struct implements the Addr interface
type TestAddr struct {
	network string
	address string
}

// Network returns the network type (e.g., "tcp", "udp")
func (a TestAddr) Network() string {
	return a.network
}

// String returns the address in string format
func (a TestAddr) String() string {
	return a.address
}

func (c *ChannelNetworkConn) ReadFromUDP(p []byte) (int, net.Addr, error) {
	select {
	case msg := <-c.in:
		copy(p, msg)
		return len(msg), nil, nil
	case <-time.After(time.Until(c.readDeadline)):
		return 0, nil, errors.New("read deadline exceeded")
	}
}

func (c *ChannelNetworkConn) WriteToUDP(p []byte, addr net.Addr) (int, error) {
	// Sends the message on the out channel.
	c.out <- &SndSegment[[]byte]{data: p}
	return len(p), nil
}

func (c *ChannelNetworkConn) Close() error {
	close(c.out)
	close(c.in)
	return nil
}

func (c *ChannelNetworkConn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

func (c *ChannelNetworkConn) LocalAddr() net.Addr {
	return c.localAddr
}

// NewTestChannel creates two connected ChannelNetworkConn instances.
func NewTestChannel(localAddr1, localAddr2 net.Addr) (NetworkConn, NetworkConn) {
	// Channels to connect read1-write2 and write1-read2
	in1 := make(chan []byte)
	out1 := make(chan *SndSegment[[]byte])
	in2 := make(chan []byte)
	out2 := make(chan *SndSegment[[]byte])

	// Side 1: Conn 1
	conn1 := &ChannelNetworkConn{
		localAddr: localAddr1,
		in:        in1,  // Conn 1 reads from in1
		out:       out2, // Conn 1 writes to out2 (which goes to conn2's in channel)
	}

	// Side 2: Conn 2
	conn2 := &ChannelNetworkConn{
		localAddr: localAddr2,
		in:        in2,  // Conn 2 reads from in2
		out:       out1, // Conn 2 writes to out1 (which goes to conn1's in channel)
	}

	// Goroutine to forward messages from conn1's out to conn2's in
	go func() {
		for msg := range out2 {
			in2 <- msg.data
		}
	}()

	// Goroutine to forward messages from conn2's out to conn1's in
	go func() {
		for msg := range out1 {
			in1 <- msg.data
		}
	}()

	return NetworkConn(conn1), NetworkConn(conn2)
}
