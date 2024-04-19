package tomtp_test

import (
	"crypto/ed25519"
	"fmt"
	"github.com/stretchr/testify/assert"
	"sync"
	"testing"
	"tomtp"
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
	listener, err := tomtp.Listen(addr, testPrivateSeed1)
	defer listener.Close()
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
	if listener == nil {
		t.Errorf("Expected a listener, but got nil")
	}

	// Test case 2: Create a new listener with an invalid address
	invalidAddr := "localhost:99999"
	_, err = tomtp.Listen(invalidAddr, testPrivateSeed1)
	if err == nil {
		t.Errorf("Expected an error, but got nil")
	}
}

func TestNewStream(t *testing.T) {
	// Test case 1: Create a new multi-stream with a valid remote address
	listener, err := tomtp.Listen("localhost:9080", testPrivateSeed1)
	defer listener.Close()
	assert.Nil(t, err)
	conn, _ := listener.Dial("localhost:9081", hexPublicKey1, 0)
	if conn == nil {
		t.Errorf("Expected a multi-stream, but got nil")
	}

	// Test case 2: Create a new multi-stream with an invalid remote address
	conn, _ = listener.Dial("localhost:99999", hexPublicKey1, 0)
	if conn != nil {
		t.Errorf("Expected nil, but got a multi-stream")
	}

}

func TestClose(t *testing.T) {
	// Test case 1: Close a listener with no multi-streams
	listener, _ := tomtp.Listen("localhost:9080", testPrivateSeed1)
	// Test case 2: Close a listener with multi-streams
	listener.Dial("localhost:9081", hexPublicKey1, 0)
	err, _ := listener.Close()
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
}

func TestEcho(t *testing.T) {
	var wg sync.WaitGroup

	// Create a listener on a specific address
	listenerPeer1, err := tomtp.Listen(":9082", testPrivateSeed1)
	assert.Nil(t, err)
	defer listenerPeer1.Close()

	wg.Add(1)
	errorChan := make(chan error, 1)
	defer close(errorChan)

	go func() {
		defer wg.Done()
		s, err := listenerPeer1.Accept()
		if err != nil {
			errorChan <- err
			return
		}
		b, _ := s.ReadAll()
		assert.Equal(t, "Hello", b)
		//fmt.Fprint(s, b)
	}()

	listenerPeer2, err := tomtp.Listen(":9081", testPrivateSeed2)
	assert.Nil(t, err)
	defer listenerPeer2.Close()

	// Create a new stream
	streamPeer1, _ := listenerPeer2.Dial("localhost:9082", hexPublicKey1, 0)

	// Write some bytes to the stream
	_, err = streamPeer1.Write([]byte("Hello"))
	if err != nil {
		fmt.Println("Error writing to stream:", err)
		return
	}

	wg.Wait()
	handleErrors(t, errorChan)
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

func handleErrors(t *testing.T, errorChan <-chan error) {
	for {
		select {
		case err := <-errorChan:
			assert.Nil(t, err) // Handle the error or perform assertions
		default:
			// No more errors in the channel, exit the loop
			return
		}
	}
}
