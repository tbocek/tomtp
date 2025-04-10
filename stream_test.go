package tomtp

import (
	"crypto/ecdh"
	"errors"
	"github.com/stretchr/testify/assert"
	"log/slog"
	"net/netip"
	"testing"
)

func createTwoStreams(
	nConnA NetworkConn,
	nConnB NetworkConn,
	prvKeyA *ecdh.PrivateKey,
	prvKeyB *ecdh.PrivateKey,
) (streamA *Stream, listenerB *Listener, err error) {

	var listenerA *Listener

	acceptA := func(s *Stream) {
		slog.Info("A: accept connection")
	}
	listenerA, err = Listen(nil, acceptA, WithNetworkConn(nConnA), WithPrvKeyId(prvKeyA))
	if err != nil {
		return nil, nil, errors.New("failed to create listener A: " + err.Error())
	}

	listenerB, err = Listen(nil, nil, WithNetworkConn(nConnB), WithPrvKeyId(prvKeyB))
	if err != nil {
		//Important: close listener A here as listener B might not close it
		listenerA.Close(0)
		return nil, nil, errors.New("failed to create listener B: " + err.Error())
	}

	pubKeyIdRcv, err := decodeHexPubKey(hexPubKey2)
	if err != nil {
		return nil, nil, err
	}
	connA, err := listenerA.DialWithCrypto(netip.AddrPort{}, pubKeyIdRcv)
	if err != nil {
		listenerA.Close(0) // clean up everything here!
		listenerB.Close(0)
		return nil, nil, errors.New("failed to dial A from B: " + err.Error())
	}
	if connA == nil {
		listenerA.Close(0)
		listenerB.Close(0)
		return nil, nil, errors.New("connection should not be nil")
	}

	streamA, _ = connA.GetOrNewStreamRcv(0)

	return streamA, listenerB, nil
}

func TestEndToEndInMemory(t *testing.T) {
	connPair := NewConnPair("addr1", "addr2")
	defer connPair.Conn1.Close()
	defer connPair.Conn2.Close()

	streamA, listenerB, err := createTwoStreams(connPair.Conn1, connPair.Conn2, testPrvKey1, testPrvKey2)
	assert.Nil(t, err)

	// Send data from A to B
	a := []byte("hallo")
	_, _, err = streamA.ReadWrite(a, 0)
	assert.Nil(t, err)

	// Process and forward the data
	err = connPair.senderToRecipient(1)
	assert.Nil(t, err)

	// Received data
	var streamB *Stream
	err = listenerB.ListenNew(0, func(s *Stream) { streamB = s })
	assert.Nil(t, err)
	b, _, err := streamB.ReadWrite(nil, 0)
	assert.Nil(t, err)

	//Verification
	assert.Equal(t, a, b)
}
