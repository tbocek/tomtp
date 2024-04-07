package tomtp_test

import (
	"crypto/ed25519"
	"fmt"
	"github.com/stretchr/testify/assert"
	"net"
	"sync"
	"testing"
	"tomtp"
)

func TestNewListener(t *testing.T) {
	// Test case 1: Create a new listener with a valid address
	addr := "localhost:8080"
	listener, err := tomtp.NewListenerString(addr, nil, "tom")
	defer listener.Close()
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
	if listener == nil {
		t.Errorf("Expected a listener, but got nil")
	}

	// Test case 2: Create a new listener with an invalid address
	invalidAddr := "localhost:99999"
	_, err = tomtp.NewListenerString(invalidAddr, nil, "tom")
	if err == nil {
		t.Errorf("Expected an error, but got nil")
	}
}

func TestNewMultiStream(t *testing.T) {
	// Test case 1: Create a new multi-stream with a valid remote address
	listener, err := tomtp.NewListenerString("localhost:9080", nil, "tom")
	defer listener.Close()
	assert.Nil(t, err)
	remoteAddr, _ := net.ResolveUDPAddr("udp", "localhost:9081")
	multiStream, _ := listener.NewOrGetConnection(ed25519.PublicKey{}, remoteAddr)
	if multiStream == nil {
		t.Errorf("Expected a multi-stream, but got nil")
	}

	// Test case 2: Create a new multi-stream with an invalid remote address
	invalidRemoteAddr, _ := net.ResolveUDPAddr("udp", "localhost:99999")
	multiStream, _ = listener.NewOrGetConnection(ed25519.PublicKey{}, invalidRemoteAddr)
	if multiStream == nil {
		t.Errorf("Expected nil, but got a multi-stream")
	}

}

func TestNewStream(t *testing.T) {
	// Test case 1: Create a new stream with a valid stream number
	listener, _ := tomtp.NewListenerString("localhost:9080", nil, "tom")
	defer listener.Close()
	remoteAddr, _ := net.ResolveUDPAddr("udp", "localhost:9081")
	multiStream, _ := listener.NewOrGetConnection(ed25519.PublicKey{}, remoteAddr)
	stream := multiStream.NewOrGetStream(1)
	if stream == nil {
		t.Errorf("Expected a stream, but got nil")
	}
}

func TestClose(t *testing.T) {
	// Test case 1: Close a listener with no multi-streams
	listener, _ := tomtp.NewListenerString("localhost:9080", nil, "tom")
	// Test case 2: Close a listener with multi-streams
	remoteAddr, _ := net.ResolveUDPAddr("udp", "localhost:9081")
	multiStream, _ := listener.NewOrGetConnection(ed25519.PublicKey{}, remoteAddr)
	multiStream.NewOrGetStream(1)
	err, _, _ := listener.Close()
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
}

func TestData(t *testing.T) {
	var wg sync.WaitGroup

	accept := func(s *tomtp.Stream) {
		defer wg.Done()
		b, _ := s.ReadAll()
		assert.Equal(t, []byte("Hello"), b)
	}

	// Create a listener on a specific address
	listenerPeer1, err := tomtp.NewListenerString("localhost:9080", accept, "tom")
	assert.Nil(t, err)
	defer listenerPeer1.Close()
	multiStreamPeer1, err := listenerPeer1.NewConnectionString(ed25519.PublicKey{}, "localhost:9081")
	assert.Nil(t, err)

	listenerPeer2, err := tomtp.NewListenerString("localhost:9081", accept, "tom")
	assert.Nil(t, err)
	defer listenerPeer2.Close()
	wg.Add(1)

	// Create a new stream
	streamPeer1 := multiStreamPeer1.NewOrGetStream(1)

	// Write some bytes to the stream
	_, err = streamPeer1.Write([]byte("Hello"), 0)
	if err != nil {
		fmt.Println("Error writing to stream:", err)
		return
	}

	wg.Wait()
}

func TestBigData(t *testing.T) {
	var wg sync.WaitGroup

	accept := func(s *tomtp.Stream) {
		defer wg.Done()
		b, _ := s.ReadAll()
		assert.Equal(t, repeatStringToBytesWithLength("hallo123", 2000), b)
	}

	// Create a listener on a specific address
	listenerPeer1, err := tomtp.NewListenerString("localhost:9080", accept, "tom")
	assert.Nil(t, err)
	defer listenerPeer1.Close()
	multiStreamPeer1, err := listenerPeer1.NewConnectionString(ed25519.PublicKey{}, "localhost:9081")
	assert.Nil(t, err)

	listenerPeer2, err := tomtp.NewListenerString("localhost:9081", accept, "tom")
	assert.Nil(t, err)
	defer listenerPeer2.Close()
	wg.Add(1)

	// Create a new stream
	streamPeer1 := multiStreamPeer1.NewOrGetStream(1)

	// Write some bytes to the stream
	_, err = streamPeer1.Write(repeatStringToBytesWithLength("hallo123", 2000), 0)
	if err != nil {
		fmt.Println("Error writing to stream:", err)
		return
	}

	wg.Wait()
}

func repeatStringToBytesWithLength(s string, targetLength int) []byte {
	repeatedString := ""
	// Repeat the string until the length of the repeatedString is just less or equal to targetLength.
	for len(repeatedString) < targetLength {
		repeatedString += s
	}
	// If the final string is longer than targetLength, truncate it.
	if len(repeatedString) > targetLength {
		repeatedString = repeatedString[:targetLength]
	}
	// Convert to slice of bytes and return.
	return []byte(repeatedString)
}
