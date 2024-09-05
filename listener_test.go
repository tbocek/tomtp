package tomtp_test

import (
	"crypto/ed25519"
	"fmt"
	"github.com/stretchr/testify/assert"
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
	listener, err := tomtp.Listen(addr, func(s *tomtp.Stream) {}, tomtp.WithSeed(testPrivateSeed1))
	defer listener.Close()
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
	if listener == nil {
		t.Errorf("Expected a listener, but got nil")
	}

	// Test case 2: Create a new listener with an invalid address
	invalidAddr := "localhost:99999"
	_, err = tomtp.Listen(invalidAddr, func(s *tomtp.Stream) {}, tomtp.WithSeed(testPrivateSeed1))
	if err == nil {
		t.Errorf("Expected an error, but got nil")
	}
}

func TestNewStream(t *testing.T) {
	// Test case 1: Create a new multi-stream with a valid remote address
	listener, err := tomtp.Listen("localhost:9080", func(s *tomtp.Stream) {}, tomtp.WithSeed(testPrivateSeed1))
	defer listener.Close()
	assert.Nil(t, err)
	conn, _ := listener.Dial("localhost:9081", hexPublicKey1)
	if conn == nil {
		t.Errorf("Expected a multi-stream, but got nil")
	}

	// Test case 2: Create a new multi-stream with an invalid remote address
	conn, _ = listener.Dial("localhost:99999", hexPublicKey1)
	if conn != nil {
		t.Errorf("Expected nil, but got a multi-stream")
	}

}

func TestClose(t *testing.T) {
	// Test case 1: Close a listener with no multi-streams
	listener, err := tomtp.Listen("localhost:9080", func(s *tomtp.Stream) {}, tomtp.WithSeed(testPrivateSeed1))
	assert.NoError(t, err)
	// Test case 2: Close a listener with multi-streams
	listener.Dial("localhost:9081", hexPublicKey1)
	err, _ = listener.Close()
	if err != nil {
		t.Errorf("Expected no error, but got: %v", err)
	}
}

func TestEcho(t *testing.T) {
	listener1, err := tomtp.Listen(
		"localhost:9001",
		func(s *tomtp.Stream) {
			b, err := s.ReadFull()
			assert.NoError(t, err)
			_, err = s.Write(b)
			assert.NoError(t, err)
		},
		tomtp.WithSeed(testPrivateSeed1),
		tomtp.WithManualUpdate())
	assert.NoError(t, err)

	listener2, err := tomtp.Listen("localhost:9002",
		func(s *tomtp.Stream) {},
		tomtp.WithSeed(testPrivateSeed2),
		tomtp.WithManualUpdate())
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
