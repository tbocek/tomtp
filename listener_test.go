package tomtp

import (
	"crypto/ecdh"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net"
	"sync"
	"testing"
	"time"
)

var (
	testPrvSeed1   = [32]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	testPrvSeed2   = [32]byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	testPrvKey1, _ = ecdh.X25519().NewPrivateKey(testPrvSeed1[:])
	testPrvKey2, _ = ecdh.X25519().NewPrivateKey(testPrvSeed2[:])

	hexPubKey1 = fmt.Sprintf("0x%x", testPrvKey1.PublicKey().Bytes())
	hexPubKey2 = fmt.Sprintf("0x%x", testPrvKey2.PublicKey().Bytes())
)

func TestNewListener(t *testing.T) {
	// Test case 1: Create a new listener with a valid address
	addr := "127.0.0.1:8080"
	listener, err := ListenString(addr, WithSeed(testPrvSeed1))
	defer listener.Close()
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
	if listener == nil {
		t.Errorf("Expected a listener, but got nil")
	}

	// Test case 2: Create a new listener with an invalid address
	invalidAddr := "127.0.0.1:99999"
	_, err = ListenString(invalidAddr, WithSeed(testPrvSeed1))
	if err == nil {
		t.Errorf("Expected an error, but got nil")
	}
}

func TestNewStream(t *testing.T) {
	// Test case 1: Create a new multi-stream with a valid remote address
	listener, err := ListenString("127.0.0.1:9080", WithSeed(testPrvSeed1))
	defer listener.Close()
	assert.Nil(t, err)
	conn, err := listener.DialWithCryptoString("127.0.0.1:9081", hexPubKey1)
	assert.Nil(t, err)
	if conn == nil {
		t.Errorf("Expected a multi-stream, but got nil")
	}

	// Test case 2: Create a new multi-stream with an invalid remote address
	conn, err = listener.DialWithCryptoString("127.0.0.1:99999", hexPubKey1)
	if conn != nil {
		t.Errorf("Expected nil, but got a multi-stream")
	}

}

func TestClose(t *testing.T) {
	// Test case 1: Close a listener with no multi-streams
	listener, err := ListenString("127.0.0.1:9080", WithSeed(testPrvSeed1))
	assert.NoError(t, err)
	// Test case 2: Close a listener with multi-streams
	listener.DialWithCryptoString("127.0.0.1:9081", hexPubKey1)
	err = listener.Close()
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
}

type ChannelNetworkConn struct {
	in             chan []byte
	out            chan *SendBuffer
	localAddr      net.Addr
	readDeadline   time.Time
	messageCounter int        // Tracks number of messages sent
	cond           *sync.Cond // Used to wait for messages
	mu             sync.Mutex // Protects messageCounter
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
		return len(msg), TestAddr{
			network: "remote-of-" + c.localAddr.Network(),
			address: "remote-of-" + c.localAddr.String(),
		}, nil
	default:
		return 0, TestAddr{
			network: "remote-of-" + c.localAddr.Network(),
			address: "remote-of-" + c.localAddr.String(),
		}, nil
	}
}

func (c *ChannelNetworkConn) WriteToUDP(p []byte, addr net.Addr) (int, error) {
	// Sends the message on the out channel.
	//c.out <- &SendBuffer{dataToSend: p}
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
func NewTestChannel(localAddr1, localAddr2 net.Addr) (*ChannelNetworkConn, *ChannelNetworkConn) {
	// Channels to connect read1-write2 and write1-read2
	in1 := make(chan []byte, 1)
	out1 := make(chan *SendBuffer, 1)
	in2 := make(chan []byte, 1)
	out2 := make(chan *SendBuffer, 1)

	conn1 := &ChannelNetworkConn{
		localAddr: localAddr1,
		in:        in1,
		out:       out2,
	}
	conn1.cond = sync.NewCond(&conn1.mu)

	conn2 := &ChannelNetworkConn{
		localAddr: localAddr2,
		in:        in2,
		out:       out1,
	}
	conn2.cond = sync.NewCond(&conn2.mu)

	go forwardMessages(conn1, conn2)
	go forwardMessages(conn2, conn1)

	return conn1, conn2
}

func forwardMessages(sender, receiver *ChannelNetworkConn) {
	/*for msg := range isSender.out {
		select {
		case receiver.in <- msg.dataToSend:
			receiver.mu.Lock()
			receiver.messageCounter++
			receiver.cond.Broadcast()
			receiver.mu.Unlock()
		default:
			// Handle the case where the receiver's input channel is full
			// You might want to log this or handle it according to your needs
		}
	}*/
}

func (c *ChannelNetworkConn) WaitRcv(nr int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for c.messageCounter < nr {
		c.cond.Wait() // Wait until the desired number of messages is reached
	}
}
